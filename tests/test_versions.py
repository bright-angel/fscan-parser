"""版本识别 + 全版本格式兼容测试。"""

import os

import pytest

from fscan_parser.models import RecordType
from fscan_parser.parsers import parse_text
from fscan_parser.version import (
    FscanEra,
    detect_format_and_version,
    resolve_version_spec,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


def _parse(name):
    return parse_text(_load(name), path=name, fmt="txt")


# ---------------------------------------------------------------- 版本识别
@pytest.mark.parametrize(
    "spec,era",
    [
        ("1.8.0", FscanEra.V1_EARLY),
        ("v1.8.2", FscanEra.V1_EARLY),
        ("1.8.10", FscanEra.V1_LATE),  # 数值比较，不应被字符串比较误判
        ("1.8.3", FscanEra.V1_LATE),
        ("1.8.4", FscanEra.V1_LATE),
        ("2.0.0", FscanEra.V2_0),
        ("2.1", FscanEra.V2_1_PLUS),
        ("2.2.0", FscanEra.V2_1_PLUS),
        ("latest", FscanEra.V2_1_PLUS),
        ("early", FscanEra.V1_EARLY),
    ],
)
def test_resolve_version_spec(spec, era):
    assert resolve_version_spec(spec) is era


def test_resolve_version_spec_invalid():
    assert resolve_version_spec("abc") is None


@pytest.mark.parametrize(
    "fixture,era",
    [
        ("v180.txt", FscanEra.V1_EARLY),
        ("v183.txt", FscanEra.V1_LATE),
        ("v200.txt", FscanEra.V2_0),
        ("v210.txt", FscanEra.V2_1_PLUS),
        ("result.txt", FscanEra.V2_1_PLUS),
    ],
)
def test_detect_era(fixture, era):
    det = detect_format_and_version(_load(fixture), format_hint="txt")
    assert det.era is era
    assert det.confidence > 0.5


def test_version_spec_overrides_detection():
    det = detect_format_and_version(_load("v210.txt"), format_hint="txt", version_spec="1.8.0")
    assert det.era is FscanEra.V1_EARLY
    assert det.forced is True


def test_stats_carries_detection():
    _records, stats = _parse("v200.txt")
    assert stats.versions == {"2.0.0": 1}
    assert stats.detection is not None and stats.detection.era is FscanEra.V2_0


# ---------------------------------------------------------------- 各版本解析
def test_v180_colon_templates():
    records, stats = _parse("v180.txt")
    services = [r for r in records if r.type is RecordType.SERVICE]
    vulns = [r for r in records if r.type is RecordType.VULN]

    # InfoScan:（带冒号、无空格）也要解析出目标，不能把冒号吃进 target
    targets = {r.target.endpoint for r in services}
    assert "192.168.1.5:80" in targets
    assert "192.168.1.1:22" in targets
    assert all(not r.target.host.startswith(":") for r in services)

    # SSH:/mysql: 带冒号的凭据行
    creds = {r.target.endpoint: r.credential for r in vulns if r.credential}
    assert creds["192.168.1.1:22"] == "root/123456"
    assert creds["192.168.1.5:3306"] == "root/root"

    # ftp://host:port:user:pass
    ftp = [r for r in vulns if r.service == "ftp"]
    assert ftp and ftp[0].target.port == 21 and ftp[0].credential == "anonymous/anonymous"

    # 'Redis:host:port unauthorized'
    assert any(r.service == "redis" and "未授权" in r.vuln_name for r in vulns)

    # WebScan 行没有 PocScan 标识，靠 poc-yaml- 前缀认出
    poc = [r for r in vulns if r.vuln_name.startswith("poc-yaml-")]
    assert poc and poc[0].target.endpoint == "192.168.1.5:80"

    assert stats.failed == 0


def test_v183_space_templates():
    records, _stats = _parse("v183.txt")
    creds = {r.target.endpoint: r.credential for r in records if r.type is RecordType.VULN and r.credential}
    assert creds["192.168.1.1:22"] == "root/123456"
    assert creds["192.168.1.5:3306"] == "root/root"
    assert creds["192.168.1.9:21"] == "anonymous/anonymous"

    # 'InfoScan host [fp] 200 Server [fp]' 要拆出状态码与 Server
    svc = next(r for r in records if r.type is RecordType.SERVICE and r.target.endpoint == "192.168.1.5:80")
    assert svc.details.get("status") == "200"
    assert "tomcat" in svc.fingerprint_list

    # OsInfo 落到存活主机的 os 字段
    hosts = {r.target.host: r for r in records if r.type is RecordType.HOST}
    assert "2008" in hosts["192.168.1.1"].details.get("os", "")


def test_v200_chinese_templates():
    records, _stats = _parse("v200.txt")

    ports = [r for r in records if r.type is RecordType.PORT]
    assert {r.target.endpoint for r in ports} == {"192.168.1.1:22", "192.168.1.1:445", "192.168.1.5:80"}
    # '[+] 端口开放 X' 不能被当成漏洞名「端口开放」
    assert not any(r.type is RecordType.VULN and r.vuln_name == "端口开放" for r in records)

    # [✓] 前缀的认证成功
    creds = {r.target.endpoint: r.credential for r in records if r.credential}
    assert creds["192.168.1.1:22"] == "root/123456"
    assert creds["192.168.1.1:445"] == "administrator/Admin@123"
    assert creds["192.168.1.5:3306"] == "root/root"

    # 中文未授权访问
    unauth = {r.service for r in records if "未授权" in (r.vuln_name or "")}
    assert {"redis", "memcached", "mongodb"} <= unauth

    # '发现漏洞 目标: ... 名称: ...'
    assert any(r.vuln_name == "Tomcat 弱口令" for r in records)

    # '发现指纹 目标: ... 指纹: [...]'
    svc = next(r for r in records if r.type is RecordType.SERVICE and r.target.endpoint == "192.168.1.5:80")
    assert "tomcat" in [f.lower() for f in svc.fingerprint_list]


def test_v210_sections():
    records, stats = _parse("v210.txt")
    kinds = {r.type for r in records}
    assert {RecordType.HOST, RecordType.PORT, RecordType.SERVICE, RecordType.VULN} <= kinds
    assert stats.skipped == 0


# ---------------------------------------------------------------- WebTitle 独立成表
@pytest.mark.parametrize("fixture", ["v180.txt", "v183.txt", "v200.txt"])
def test_webtitle_is_separate_type(fixture):
    records, _stats = _parse(fixture)
    titles = [r for r in records if r.type is RecordType.WEBTITLE]
    assert len(titles) == 1
    rec = titles[0]
    assert rec.target.endpoint == "192.168.1.5:80"
    assert rec.title == "Tomcat 欢迎页"
    assert rec.details.get("status") == "200"
    # 不再混进漏洞表
    assert not any(r.type is RecordType.VULN and "WebTitle" in r.raw for r in records)


@pytest.mark.parametrize("fixture", ["v180.txt", "v183.txt", "v200.txt"])
def test_no_unknown_leftovers(fixture):
    """各版本样本除统计行外不应留下未解析的行。"""
    records, stats = _parse(fixture)
    assert stats.failed == 0
    assert stats.skipped <= 2
    assert len(records) >= 12


def test_bare_port_lines_without_prefix():
    """手工整理/去前缀后的 '1.2.3.4:80 open' 也要解析成开放端口。"""
    records, _stats = parse_text("192.168.1.1:22 open\n192.168.1.1 open\n", path="plain.txt", fmt="txt")
    ports = [r for r in records if r.type is RecordType.PORT]
    assert len(ports) == 2
    assert ports[0].target.endpoint == "192.168.1.1:22"
    assert ports[1].target.host == "192.168.1.1"
