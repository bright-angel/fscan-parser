"""记录聚合：去重 + 按主机归并，生成「资产视图」。

fscan 的 txt 结果把端口、服务、漏洞放在不同段落，且服务段用的是 URL 形式、
漏洞段用的是 ip:port 形式，人工核对很费劲。这里把它们串成一行一台主机。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set

from .models import Record, RecordType
from .targets import guess_scheme


@dataclass
class HostAsset:
    host: str
    open_ports: Set[int] = field(default_factory=set)
    services: List[Record] = field(default_factory=list)
    vulns: List[Record] = field(default_factory=list)
    web_titles: List[Record] = field(default_factory=list)
    is_alive: bool = False

    @property
    def service_set(self) -> List[str]:
        """服务名去重；openssh 之类指纹型名称归并到 ssh。"""
        alias = {"openssh": "ssh", "tomcat": "http", "nginx": "http", "iis": "http", "apache": "http"}
        names = set()
        for rec in self.services:
            name = rec.service.lower()
            if not name:
                continue
            names.add(alias.get(name, name))
        return sorted(names)

    @property
    def port_list(self) -> str:
        return ",".join(str(p) for p in sorted(self.open_ports))

    @property
    def web_urls(self) -> List[str]:
        urls: List[str] = []
        for rec in self.services + self.web_titles:
            if rec.details.get("is_web") or rec.details.get("title") or rec.details.get("status"):
                url = rec.details.get("url") or rec.target.url or (
                    f"{guess_scheme(rec.target.raw, rec.service, rec.port)}://{rec.target.endpoint}"
                )
                if url not in urls:
                    urls.append(url)
        return urls

    @property
    def highest_severity(self) -> str:
        order = {"高危": 3, "中危": 2, "低危": 1, "信息": 0}
        if not self.vulns:
            return ""
        return max((v.severity.value for v in self.vulns), key=lambda s: order.get(s, 0))


def record_key(rec: Record) -> str:
    """去重键：同类型 + 同目标 + 同端口 + 同服务/漏洞名视为重复。"""
    if rec.type is RecordType.HOST:
        return f"HOST|{rec.target.host.lower()}"
    if rec.type is RecordType.PORT:
        return f"PORT|{rec.target.host.lower()}|{rec.port}"
    if rec.type is RecordType.SERVICE:
        fp = ",".join(sorted(rec.fingerprint_list))
        return (
            f"SERVICE|{rec.target.host.lower()}|{rec.port}|{rec.service.lower()}"
            f"|{rec.version}|{rec.title}|{fp}"
        )
    if rec.type is RecordType.WEBTITLE:
        return (
            f"WEBTITLE|{rec.target.host.lower()}|{rec.port}"
            f"|{rec.title}|{rec.details.get('status', '')}"
        )
    name = rec.vuln_name or rec.status
    cred = rec.credential
    return f"VULN|{rec.target.host.lower()}|{rec.port}|{name}|{cred}"


def dedupe(records: Iterable[Record]) -> tuple[List[Record], int]:
    seen: Set[str] = set()
    out: List[Record] = []
    dropped = 0
    for rec in records:
        key = record_key(rec)
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        out.append(rec)
    return out, dropped


def merge_web_records(records: List[Record]) -> List[Record]:
    """把 TXT 末尾「Web服务」段落并入服务记录，避免同一 URL 出现两次。"""
    web_targets = {
        (r.target.host.lower(), r.target.port) for r in records if r.type is RecordType.WEB
    }
    if not web_targets:
        return [r for r in records if r.type is not RecordType.WEB]

    kept: List[Record] = []
    for rec in records:
        if rec.type is RecordType.WEB:
            continue
        if rec.type is RecordType.SERVICE:
            key = (rec.target.host.lower(), rec.target.port)
            if key in web_targets:
                rec.details.setdefault("is_web", True)
        kept.append(rec)

    # 只有 Web 段落里出现、但服务段落缺失的 URL，补一条 SERVICE
    service_keys = {
        (r.target.host.lower(), r.target.port) for r in kept if r.type is RecordType.SERVICE
    }
    for rec in records:
        if rec.type is RecordType.WEB:
            key = (rec.target.host.lower(), rec.target.port)
            if key not in service_keys:
                rec.type = RecordType.SERVICE
                kept.append(rec)
                service_keys.add(key)
    return kept


def build_assets(records: Iterable[Record]) -> List[HostAsset]:
    assets: Dict[str, HostAsset] = {}
    for rec in records:
        host = rec.target.host
        if not host:
            continue
        asset = assets.setdefault(host, HostAsset(host=host))
        if rec.type is RecordType.HOST:
            asset.is_alive = True
        elif rec.type is RecordType.PORT:
            if rec.port:
                asset.open_ports.add(rec.port)
        elif rec.type in (RecordType.SERVICE, RecordType.WEB):
            asset.services.append(rec)
            if rec.port:
                asset.open_ports.add(rec.port)
        elif rec.type is RecordType.VULN:
            asset.vulns.append(rec)
            if rec.port:
                asset.open_ports.add(rec.port)
        elif rec.type is RecordType.WEBTITLE:
            # WebTitle 单独成表，但仍算作该主机的一个 Web 入口
            if rec.port:
                asset.open_ports.add(rec.port)
            asset.web_titles.append(rec)
    return sorted(assets.values(), key=_host_sort_key)


def _host_sort_key(asset: HostAsset):
    import ipaddress

    try:
        return (0, int(ipaddress.ip_address(asset.host)), asset.host)
    except ValueError:
        return (1, 0, asset.host)


def sort_records(records: List[Record]) -> List[Record]:
    """稳定排序：类型 → 主机 → 端口，让表格呈现有条理。"""
    order = {
        RecordType.HOST: 0,
        RecordType.PORT: 1,
        RecordType.SERVICE: 2,
        RecordType.WEBTITLE: 3,
        RecordType.VULN: 4,
        RecordType.WEB: 5,
    }
    host_order = {a.host: i for i, a in enumerate(build_assets(records))}
    return sorted(
        records,
        key=lambda r: (
            order.get(r.type, 9),
            host_order.get(r.target.host, 10**6),
            r.port or 0,
            r.service,
        ),
    )
