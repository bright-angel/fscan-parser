"""CSV / JSON 结果解析，字段结构与 fscan 源码 writers.go 一一对应。

CSV（v2.x CSVWriter.Close）::

    # Hosts
    Target
    192.168.1.1

    # Ports
    Target,Port,Status
    192.168.1.1,22,open

    # Services
    Target,Service,Version,Title,Status,Server,Fingerprints,Banner

    # Vulns
    Target,Type,Details

注意：CSV 的 ``# Vulns`` 段里 ``Details`` 列写的是 ``result.Status`` 或漏洞名，
弱口令的账号密码并不在 CSV 中（源码 formatVulnRecord 的限制），这点在 Excel 里会留空。

JSON（v2.x JSONWriter.Close）::

    {
      "scan_time": "...",
      "summary": {"total_hosts": 2, ...},
      "hosts":    [{"time","type","target","status","details"}],
      "ports":    [...],
      "services": [...],
      "vulns":    [...]
    }

另外也兼容 ``.realtime.tmp``（NDJSON，每行一个 ScanResult）以及旧版 ``-json`` 输出的
``{"type": "...", "text": "..."}`` 行式记录。
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Optional

from ..models import Record, RecordType
from ..targets import guess_scheme, normalize_target
from .txt import TxtParser

_CSV_SECTION_MAP = {
    "# hosts": RecordType.HOST,
    "# ports": RecordType.PORT,
    "# services": RecordType.SERVICE,
    "# vulns": RecordType.VULN,
    "# vulnerabilities": RecordType.VULN,
    "# 存活主机": RecordType.HOST,
    "# 开放端口": RecordType.PORT,
    "# 服务信息": RecordType.SERVICE,
    "# 漏洞信息": RecordType.VULN,
}


class CsvParser:
    format_name = "csv"

    def parse(self, text: str, source: str = "") -> tuple[List[Record], int, int]:
        records: List[Record] = []
        skipped = 0
        failed = 0

        reader = csv.reader(io.StringIO(text))
        section: Optional[RecordType] = None
        headers: List[str] = []
        expect_header = False

        for line_no, row in enumerate(reader, start=1):
            if not row or all(not (c or "").strip() for c in row):
                continue
            first = (row[0] or "").strip()

            if first.startswith("#"):
                section = _CSV_SECTION_MAP.get(first.lower())
                headers = []
                expect_header = True
                continue

            if section is None:
                skipped += 1
                continue

            if expect_header:
                headers = [h.strip().lower() for h in row]
                expect_header = False
                continue

            data: Dict[str, str] = {}
            for i, value in enumerate(row):
                key = headers[i] if i < len(headers) else f"col{i}"
                data[key] = (value or "").strip()

            try:
                rec = _record_from_csv_row(section, data, source, line_no, ",".join(row))
            except Exception:
                failed += 1
                continue
            if rec is None:
                skipped += 1
            else:
                records.append(rec)

        # 没有分段标题的 CSV（用户自行整理的端口表）退化为逐行解析
        if not records and not headers and text.strip():
            records, skipped, failed = TxtParser().parse(text, source)
        return records, skipped, failed


def _record_from_csv_row(
    section: RecordType, data: Dict[str, str], source: str, line_no: int, raw: str
) -> Optional[Record]:
    target_text = data.get("target", "")
    if not target_text:
        return None

    if section is RecordType.HOST:
        return Record(
            type=RecordType.HOST,
            target=normalize_target(target_text),
            status="alive",
            source=source,
            line_no=line_no,
            raw=raw,
        )

    if section is RecordType.PORT:
        port = _to_int(data.get("port"))
        target = normalize_target(target_text, default_port=port)
        details = {"port": port} if port else {}
        return Record(
            type=RecordType.PORT,
            target=target,
            status=data.get("status") or "open",
            details=details,
            source=source,
            line_no=line_no,
            raw=raw,
        )

    if section is RecordType.SERVICE:
        target = normalize_target(target_text)
        service = data.get("service", "")
        details: Dict[str, Any] = {}
        if service:
            details["service"] = service
        if target.port:
            details["port"] = target.port
        if data.get("version"):
            details["version"] = data["version"]
        if data.get("title"):
            details["title"] = data["title"]
        if data.get("status"):
            details["status"] = data["status"]
        if data.get("server"):
            details["server"] = data["server"]
        if data.get("fingerprints"):
            details["fingerprints"] = [p for p in data["fingerprints"].split(",") if p]
        if data.get("banner"):
            details["banner"] = data["banner"]
        if details.get("title") or details.get("status") or details.get("server"):
            details["is_web"] = True
            if not details.get("service"):
                details["service"] = guess_scheme(target_text, port=target.port)
        return Record(
            type=RecordType.SERVICE,
            target=target,
            status="web" if details.get("is_web") else "identified",
            details=details,
            source=source,
            line_no=line_no,
            raw=raw,
        )

    # Vuln：CSV 只给了 Target / Type / Details 三列
    vuln_type = data.get("type", "")
    detail_text = data.get("details", "")
    details: Dict[str, Any] = {}
    if vuln_type:
        details["type"] = vuln_type
    # 源码 formatVulnRecord 的第 3 列取的是 result.Status，
    # 因此常见值是 'vulnerable' 而非漏洞名，这种情况不写成漏洞名。
    if detail_text and detail_text.lower() not in ("vulnerable", "vuln", "identified"):
        if vuln_type == "weak_credential" and "/" in detail_text:
            user, _, pwd = detail_text.partition("/")
            details["username"] = user
            details["password"] = pwd
        else:
            details["vulnerability_name"] = detail_text
    return Record(
        type=RecordType.VULN,
        target=normalize_target(target_text),
        status=detail_text or vuln_type or "vulnerable",
        details=details,
        source=source,
        line_no=line_no,
        raw=raw,
        extra={"vuln_name": details.get("vulnerability_name") or vuln_type or "漏洞"},
    )


class JsonParser:
    format_name = "json"

    def parse(self, text: str, source: str = "") -> tuple[List[Record], int, int]:
        stripped = text.strip()
        if not stripped:
            return [], 0, 0

        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return self._parse_ndjson(stripped, source)

        records: List[Record] = []
        skipped = 0
        failed = 0

        if isinstance(payload, dict) and any(k in payload for k in ("hosts", "ports", "services", "vulns")):
            for key, rtype in (
                ("hosts", RecordType.HOST),
                ("ports", RecordType.PORT),
                ("services", RecordType.SERVICE),
                ("vulns", RecordType.VULN),
            ):
                for item in payload.get(key) or []:
                    rec = _record_from_scan_result(item, rtype, source)
                    if rec is None:
                        skipped += 1
                    else:
                        records.append(rec)
            return records, skipped, failed

        if isinstance(payload, dict):
            payload = [payload]

        for idx, item in enumerate(payload if isinstance(payload, list) else [], start=1):
            rec = _record_from_scan_result(item, None, source, line_no=idx)
            if rec is None:
                if isinstance(item, dict) and "text" in item:  # 旧版 -json
                    rec = _record_from_legacy_json(item, source, idx)
            if rec is None:
                skipped += 1
            else:
                records.append(rec)
        return records, skipped, failed

    def _parse_ndjson(self, text: str, source: str) -> tuple[List[Record], int, int]:
        """解析 .realtime.tmp 这类一行一个 JSON 对象的文件。"""
        records: List[Record] = []
        skipped = 0
        failed = 0
        for idx, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                failed += 1
                continue
            rec = _record_from_scan_result(item, None, source, line_no=idx)
            if rec is None:
                if isinstance(item, dict) and "text" in item:
                    rec = _record_from_legacy_json(item, source, idx)
            if rec is None:
                skipped += 1
            else:
                records.append(rec)
        if failed and not records:
            # 整份文件不是 NDJSON，交给 TXT 解析器兜底
            return TxtParser().parse(text, source)
        return records, skipped, failed


_TYPE_MAP = {
    "HOST": RecordType.HOST,
    "PORT": RecordType.PORT,
    "SERVICE": RecordType.SERVICE,
    "VULN": RecordType.VULN,
}


def _record_from_scan_result(
    item: Any, expect: Optional[RecordType], source: str, line_no: int = 0
) -> Optional[Record]:
    if not isinstance(item, dict):
        return None
    rtype = _TYPE_MAP.get(str(item.get("type", "")).upper()) or expect
    if rtype is None:
        return None
    target_text = str(item.get("target") or "")
    if not target_text:
        return None
    details = item.get("details") or {}
    if not isinstance(details, dict):
        details = {"value": details}
    target = normalize_target(target_text)
    if rtype is RecordType.PORT:
        port = _to_int(details.get("port"))
        if port:
            target.port = port
    if rtype is RecordType.SERVICE and target.port is None:
        port = _to_int(details.get("port"))
        if port:
            target.port = port
    return Record(
        type=rtype,
        target=target,
        status=str(item.get("status") or ""),
        details=dict(details),
        source=source,
        line_no=line_no,
        raw=json.dumps(item, ensure_ascii=False),
        time=str(item.get("time") or ""),
    )


def _record_from_legacy_json(item: Dict[str, Any], source: str, line_no: int) -> Optional[Record]:
    """旧版 ``-json``：{"type":"msg","text":"192.168.1.1:22 open"}。"""
    text = str(item.get("text") or "")
    if not text:
        return None
    kind = str(item.get("type") or "msg").lower()
    records, _, _ = TxtParser().parse(f"[+] {text}" if kind != "msg" else text, source)
    if not records:
        return None
    rec = records[0]
    rec.line_no = line_no
    return rec


def _to_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None
