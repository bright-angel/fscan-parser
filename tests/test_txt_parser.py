"""TXT 解析器单元测试。"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fscan_parser.models import RecordType, Severity  # noqa: E402
from fscan_parser.parsers.txt import TxtParser, detect_section  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def read(name: str) -> str:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.parametrize(
    "line,expected",
    [
        ("# ===== 存活主机 =====", RecordType.HOST),
        ("# ===== 开放端口 =====", RecordType.PORT),
        ("# ===== 服务信息 =====", RecordType.SERVICE),
        ("# ===== 漏洞信息 =====", RecordType.VULN),
        ("# ===== Web服务 =====", RecordType.WEB),
        ("# ===== Alive Hosts =====", RecordType.HOST),
        ("# ===== Open Ports =====", RecordType.PORT),
        ("# ===== Services =====", RecordType.SERVICE),
        ("# ===== Vulnerabilities =====", RecordType.VULN),
        ("# ===== Web Services =====", RecordType.WEB),
        ("192.168.1.1", None),
    ],
)
def test_detect_section(line, expected):
    assert detect_section(line) == expected


def test_parse_v2_txt():
    records, skipped, failed = TxtParser().parse(read("result.txt"), "result.txt")
    assert failed == 0
    assert skipped == 0
    counts = {}
    for rec in records:
        counts[rec.type] = counts.get(rec.type, 0) + 1
    assert counts[RecordType.HOST] == 2
    assert counts[RecordType.PORT] == 3
    assert counts[RecordType.SERVICE] == 4
    assert counts[RecordType.VULN] == 3
    # Web 汇总段落不应产生额外记录
    assert RecordType.WEB not in counts


def test_parse_web_service_fields():
    records, _, _ = TxtParser().parse(read("result.txt"))
    web = [r for r in records if r.type is RecordType.SERVICE and r.details.get("title")][0]
    assert web.target.host == "192.168.1.5"
    assert web.port == 80
    assert web.details["status"] == "200"
    assert web.details["server"] == "Apache-Coyote/1.1"
    assert web.fingerprint_list == ["tomcat", "java"]


def test_parse_non_web_service_banner():
    records, _, _ = TxtParser().parse(read("result.txt"))
    ssh = [r for r in records if r.service == "ssh"][0]
    assert ssh.port == 22
    assert ssh.version
    assert ssh.details.get("is_web") is None


def test_parse_weak_credential():
    records, _, _ = TxtParser().parse(read("result.txt"))
    cred = [r for r in records if r.credential][0]
    assert cred.type is RecordType.VULN
    assert cred.details["service"] == "mysql"
    assert cred.credential == "root/123456"
    assert cred.severity is Severity.HIGH


def test_parse_legacy_v1():
    records, _, failed = TxtParser().parse(read("legacy_v1.txt"))
    assert failed == 0
    types = [r.type for r in records]
    assert types.count(RecordType.PORT) == 4
    assert types.count(RecordType.SERVICE) == 2
    # 统计行（LiveTop）不应成为记录
    assert all("LiveTop" not in r.raw for r in records)
    # 多行结果（FCGI）应生成一条记录且保持原始行序
    fcgis = [r for r in records if r.target.host == "192.168.1.5" and r.port == 9000]
    assert len(fcgis) == 1
    assert "stderr" in fcgis[0].raw


def test_legacy_credential_with_domain():
    records, _, _ = TxtParser().parse("[+] RDP 10.0.0.5:3389:ADMIN\\Administrator:P@ssw0rd")
    assert records
    rec = records[0]
    assert rec.type is RecordType.VULN
    assert rec.port == 3389
    assert rec.details["username"] == "ADMIN\\Administrator"


def test_no_section_plain_port_list():
    text = "10.0.0.1:22\n10.0.0.1:80\n"
    records, _, _ = TxtParser().parse(text)
    assert len(records) == 2
    assert all(r.type is RecordType.PORT for r in records)
    assert records[0].port == 22


def test_realtime_tmp_ndjson_falls_back():
    text = '{"type": "PORT", "target": "10.0.0.1", "status": "open", "details": {"port": 6379}}\n'
    # TXT 解析器遇到 NDJSON 会跳过，不应抛异常
    records, skipped, failed = TxtParser().parse(text)
    assert failed == 0
    assert all(r.type is not RecordType.SERVICE for r in records)


def test_ipv6_target():
    records, _, _ = TxtParser().parse("# ===== 开放端口 =====\n[2001:db8::1]:22\n")
    assert records[0].target.host == "2001:db8::1"
    assert records[0].port == 22
    # 段落标题未被误判为记录
    assert len(records) == 1
