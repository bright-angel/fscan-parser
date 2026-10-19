"""解析器注册与格式自动识别。"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

from ..models import Record, ParseStats
from ..version import FormatDetection, detect_format_and_version, detect_from_records
from .csvjson import CsvParser, JsonParser
from .txt import TxtParser

TXT_FORMATS = {"txt", "text"}
CSV_FORMATS = {"csv"}
JSON_FORMATS = {"json", "ndjson", "jsonl"}

_ALL_PARSERS = (TxtParser(), CsvParser(), JsonParser())


def sniff_format(path: str, content: str) -> str:
    """按扩展名 + 内容嗅探判断格式，返回 'txt' / 'csv' / 'json'。"""
    name = os.path.basename(path).lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if ext in CSV_FORMATS:
        return "csv"
    if ext in JSON_FORMATS:
        return "json"
    if ext in TXT_FORMATS:
        return "txt"

    head = content.lstrip()
    if not head:
        return "txt"
    if head[0] == "{" or (head[0] == "[" and not head.startswith("[+]")):
        return "json"
    if head.startswith("# Hosts") or head.startswith("# Ports") or head.startswith("# Services"):
        return "csv"
    first_line = head.splitlines()[0]
    if first_line.count(",") >= 2 and "Target" in first_line:
        return "csv"
    return "txt"


def parse_text(
    content: str,
    path: str = "",
    fmt: str = "auto",
    version_spec: str = "",
    detection: Optional[FormatDetection] = None,
) -> Tuple[List[Record], ParseStats]:
    """解析一份文本内容。fmt 传 'auto' 时自动判断。

    detection 传入可复用的识别结果（批量解析时避免重复扫描全文）；
    为空则内部按需识别。版本识别结果会写进 ``ParseStats.versions``。
    """
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        fmt = sniff_format(path, content)

    stats = ParseStats(files=1)
    stats.lines = content.count("\n") + (0 if content.endswith("\n") or not content else 1)

    parser = _pick_parser(fmt)
    if detection is None:
        detection = detect_format_and_version(
            content,
            format_hint=parser.format_name,
            version_spec=version_spec,
            has_json_summary=_has_json_summary(content),
        )
    records, skipped, failed = parser.parse(content, source=path)
    detection = detect_from_records(records, detection)

    stats.records = len(records)
    stats.skipped = skipped
    stats.failed = failed
    stats.formats[parser.format_name] = len(records)
    stats.versions[detection.era.value] = 1
    stats.detection = detection
    return records, stats


def _has_json_summary(content: str) -> bool:
    head = content.lstrip()[:4096]
    return '"summary"' in head or ('"hosts"' in head and '"ports"' in head)


def _pick_parser(fmt: str):
    if fmt in CSV_FORMATS:
        return CsvParser()
    if fmt in JSON_FORMATS:
        return JsonParser()
    if fmt in TXT_FORMATS:
        return TxtParser()
    raise ValueError(f"不支持的格式: {fmt}")


def parse_file(
    path: str, fmt: str = "auto", version_spec: str = ""
) -> Tuple[List[Record], ParseStats]:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        content = fh.read()
    records, stats = parse_text(content, path=path, fmt=fmt, version_spec=version_spec)
    return records, stats
