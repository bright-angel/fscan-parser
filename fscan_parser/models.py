"""数据模型：贯穿解析、归一化、导出三个环节的统一记录结构。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

# 归一化后的目标拆分结果：host / port / scheme
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")


class RecordType(str, Enum):
    """与 fscan 源码 output.ResultType 保持一致。"""

    HOST = "HOST"
    PORT = "PORT"
    SERVICE = "SERVICE"
    VULN = "VULN"
    WEB = "WEB"  # 仅 TXT 的 Web服务 汇总段落会出现，用于去重合并
    WEBTITLE = "WEBTITLE"  # 旧版 [*] WebTitle 行 / v2.0 [*] 网站标题

    @property
    def label(self) -> str:
        return {
            "HOST": "存活主机",
            "PORT": "开放端口",
            "SERVICE": "服务信息",
            "VULN": "漏洞信息",
            "WEB": "Web服务",
            "WEBTITLE": "WebTitle",
        }[self.value]


class Severity(str, Enum):
    """由记录类型推导的风险等级，便于在表格中排序/筛选。"""

    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "信息"


@dataclass
class Target:
    """目标拆解结果。"""

    raw: str
    host: str = ""
    port: Optional[int] = None
    scheme: str = ""

    @property
    def is_ip(self) -> bool:
        return bool(_IPV4_RE.match(self.host) or _IPV6_RE.match(self.host))

    @property
    def endpoint(self) -> str:
        """host:port 形式，无端口时退化为 host。"""
        if self.port is None:
            return self.host
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        if not self.scheme:
            return ""
        return f"{self.scheme}://{self.endpoint}"


@dataclass
class Record:
    """一条解析结果。

    attributes 保留 details 中的全部原始键值（如 product/os/references），
    导出时可展开为「属性」列，避免信息丢失。
    """

    type: RecordType
    target: Target
    status: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    source: str = ""  # 来源文件
    line_no: int = 0  # 来源行号
    raw: str = ""  # 原始文本行 / JSON 片段，便于溯源
    time: str = ""  # JSON 输入时存在
    extra: Dict[str, str] = field(default_factory=dict)  # 解析补充字段

    # ---- 常用字段快捷读取 ----
    def get(self, key: str, default: Any = "") -> Any:
        val = self.details.get(key, default)
        return default if val is None else val

    @property
    def service(self) -> str:
        for key in ("service", "name", "plugin"):
            val = self.details.get(key)
            if isinstance(val, str) and val:
                return val
        return self.extra.get("service", "")

    @property
    def port(self) -> Optional[int]:
        val = self.details.get("port")
        if isinstance(val, int):
            return val
        if isinstance(val, str) and val.isdigit():
            return int(val)
        return self.target.port

    @property
    def version(self) -> str:
        return str(self.details.get("version") or "")

    @property
    def title(self) -> str:
        return str(self.details.get("title") or "")

    @property
    def banner(self) -> str:
        return str(self.details.get("banner") or "")

    @property
    def fingerprint_list(self) -> List[str]:
        fp = self.details.get("fingerprints")
        if isinstance(fp, list):
            return [str(x) for x in fp if str(x)]
        if isinstance(fp, str) and fp:
            return [p for p in fp.split(",") if p]
        return []

    @property
    def severity(self) -> Severity:
        if self.type is not RecordType.VULN:
            return Severity.INFO
        vuln_type = str(self.details.get("type") or self.details.get("vulnerability_type") or "")
        if vuln_type == "weak_credential":
            return Severity.HIGH
        if vuln_type in ("vulnerability",) or self.details.get("vulnerability"):
            return Severity.HIGH
        if "unauthorized" in self.raw.lower() or "未授权" in self.raw:
            return Severity.HIGH
        return Severity.MEDIUM

    @property
    def vuln_name(self) -> str:
        if str(self.details.get("type") or "") == "weak_credential":
            return "弱口令"
        for key in ("vulnerability_name", "vulnerability", "vulnerability_type"):
            val = self.details.get(key)
            if isinstance(val, str) and val:
                return val
        if self.type is RecordType.VULN:
            return self.extra.get("vuln_name") or self.status
        return ""

    @property
    def credential(self) -> str:
        user = self.details.get("username")
        pwd = self.details.get("password")
        if user is None and pwd is None:
            return ""
        return f"{user if user is not None else ''}/{pwd if pwd is not None else ''}"


@dataclass
class ParseStats:
    """解析统计，用于 CLI 汇总与问题排查。"""

    files: int = 0
    lines: int = 0
    records: int = 0
    skipped: int = 0
    failed: int = 0
    formats: Dict[str, int] = field(default_factory=dict)
    versions: Dict[str, int] = field(default_factory=dict)  # 识别到的 fscan 版本区间 → 文件数
    # 版本识别明细（fscan_parser.version.FormatDetection），导出报告时展示
    detection: Any = None

    def merge(self, other: "ParseStats") -> None:
        self.files += other.files
        self.lines += other.lines
        self.records += other.records
        self.skipped += other.skipped
        self.failed += other.failed
        for k, v in other.formats.items():
            self.formats[k] = self.formats.get(k, 0) + v
        for k, v in other.versions.items():
            self.versions[k] = self.versions.get(k, 0) + v
        if self.detection is None:
            self.detection = other.detection
