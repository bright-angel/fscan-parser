"""fscan 输出版本识别。

fscan 的历史版本里，``-o`` 输出文件的**行格式**变化过几次，而文件里并不写版本号，
因此只能靠内容特征反推。逐步核对的结论（源码 common/log.go、Plugins/*.go、WebScan）：

===============  ==========================================  ==================================
版本区间          特征                                        示例
===============  ==========================================  ==================================
1.8.0 - 1.8.2    ``InfoScan:``（带冒号）、``SSH:%v:%v:%v``    ``[+] SSH:1.2.3.4:22:root:pwd``
                 ``WebTitle:``、WebScan 无 ``PocScan`` 标识   ``[+] http://x  poc-name 结果名``
1.8.3 - 1.8.4    ``InfoScan `` 空格、``SSH %v:%v:%v``       ``[+] SSH 1.2.3.4:22:root:pwd``
                 ``WebTitle ``、``[+] PocScan ``              ``[+] PocScan http://x poc-name``
2.0.0            全中文模板                                  ``[+] 端口开放 1.2.3.4:22``
                 ``[✓] SMB认证成功``、``网站标题``            ``[✓] SMB认证成功 1.2.3.4:445 User:a Pass:b``
2.1.0 及以上      分段区（``# ===== 存活主机 =====``）          见 writers.go TXTWriter
                 JSON 带 summary/hosts/ports/services/vulns
===============  ==========================================  ==================================

识别不修改解析结果（各版本语法都已在解析器里兼容），只用于报告标注与提示。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence

from .models import RecordType


class FscanEra(str, Enum):
    """按输出版本划分的时代。"""

    V1_EARLY = "1.8.0-1.8.2"
    V1_LATE = "1.8.3-1.8.4"
    V2_0 = "2.0.0"
    V2_1_PLUS = "2.1.0+"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return {
            "1.8.0-1.8.2": "fscan 1.8.0 - 1.8.2（旧版行式，冒号分隔）",
            "1.8.3-1.8.4": "fscan 1.8.3 - 1.8.4（旧版行式，空格分隔）",
            "2.0.0": "fscan 2.0.0（中文行式）",
            "2.1.0+": "fscan 2.1.0 及以上（分段格式）",
            "unknown": "未识别的格式",
        }[self.value]


@dataclass
class VersionFingerprint:
    """单条特征的命中情况。"""

    key: str
    description: str
    era: FscanEra
    weight: int
    sample: str = ""


@dataclass
class FormatDetection:
    """版本识别结果。"""

    era: FscanEra = FscanEra.UNKNOWN
    format: str = ""  # txt / csv / json
    confidence: float = 0.0
    evidence: List[VersionFingerprint] = field(default_factory=list)
    scores: Dict[str, int] = field(default_factory=dict)
    forced: bool = False  # 是否由 --version-spec 指定
    notes: List[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.era.label

    def evidence_lines(self, limit: int = 6) -> List[str]:
        return [f"{e.description}：{e.sample}" for e in self.evidence[:limit]]


# ---------------------------------------------------------------------------
# 特征规则：(正则, 时代, 权重, 说明)
# 权重按「该特征对该版本的唯一性」给分：3 = 强特征，1 = 弱特征。
# ---------------------------------------------------------------------------
_RULES: Sequence[tuple[str, FscanEra, int, str]] = (
    # ---- 2.1.0+ 分段格式 ----
    (r"^#\s*=+\s*(?:存活主机|开放端口|服务信息|漏洞信息|Web服务)", FscanEra.V2_1_PLUS, 5, "中文分段标题"),
    (r"^#\s*=+\s*(?:Alive Hosts|Open Ports|Services|Vulnerabilities|Web Services)", FscanEra.V2_1_PLUS, 5, "英文分段标题"),
    # ---- 2.0.0 中文模板 ----
    (r"^\[[+\-*✓]\]\s*端口开放\s", FscanEra.V2_0, 5, "[+] 端口开放"),
    (r"^\[[+\-*✓]\]\s*发现指纹\s*目标", FscanEra.V2_0, 5, "[+] 发现指纹 目标"),
    (r"^\[[+\-*✓]\]\s*(?:SMB|SMB2|WmiExec|MSSQL|MySQL|Oracle|PostgreSQL|Redis|RDP|ftp)\s+\S+:\d+", FscanEra.V2_0, 1, "2.0 插件行"),
    (r"^\[[+\-*✓]\]\s+\S+\s+认证成功\s", FscanEra.V2_0, 5, "[✓] 认证成功"),
    (r"^\[[+\-*✓]\]\s*发现漏洞\s*目标", FscanEra.V2_0, 5, "[+] 发现漏洞 目标"),
    (r"^\[[+\-*✓]\]\s*FastCGI", FscanEra.V2_0, 4, "[+] FastCGI"),
    (r"发现未授权访问|未授权访问$", FscanEra.V2_0, 4, "中文未授权访问"),
    (r"^\s*\[\*\]\s*网站标题\s", FscanEra.V2_0, 5, "[*] 网站标题"),
    (r"^\[\*\]\s*(?:B段|C段)\s", FscanEra.V2_0, 4, "[*] B段/C段 统计"),
    (r"^\[\*\]\s*(?:SMB2共享信息|NetInfo|OsInfo)", FscanEra.V2_0, 3, "2.0 中文辅助信息"),
    # ---- 1.8.3 - 1.8.4 ----
    (r"^\[[+\-*✓]\]\s*PocScan\s", FscanEra.V1_LATE, 5, "[+] PocScan"),
    (r"^\[[+\-*✓]\]\s*InfoScan\s+\S", FscanEra.V1_LATE, 3, "[+] InfoScan（空格）"),
    (r"^\[\*\]\s*WebTitle\s+\S", FscanEra.V1_LATE, 3, "[*] WebTitle（空格）"),
    (r"^\[[+\-*✓]\]\s*(?:SSH|mysql|mssql|RDP|SMB2?|ftp|Postgres|Mongodb|Redis)\s+\S+:\d+:\S+", FscanEra.V1_LATE, 2, "旧版空格分隔凭据行"),
    (r"^\[\*\]\s*OsInfo\s", FscanEra.V1_LATE, 2, "[*] OsInfo"),
    # ---- 1.8.0 - 1.8.2 ----
    (r"^\[[+\-*✓]\]\s*InfoScan:", FscanEra.V1_EARLY, 5, "[+] InfoScan:（带冒号）"),
    (r"^\[\*\]\s*WebTitle:\s?\S", FscanEra.V1_EARLY, 5, "[*] WebTitle:（带冒号）"),
    (r"^\[[+\-*✓]\]\s*(?:SSH|mysql|mssql|RDP|SMB|ftp|Postgres|Mongodb|Redis|oracle)\s*:\s*\S+:\d+", FscanEra.V1_EARLY, 4, "旧版冒号分隔凭据行"),
    (r"^\[[+\-*✓]\]\s*ftp://\S+:\d+", FscanEra.V1_EARLY, 4, "[+] ftp:// 前缀"),
    # ---- 通用（不判版本，只用于判"是旧版行式"） ----
    (r"^\s*\[[+\-*✓]\]\s+", FscanEra.UNKNOWN, 1, "旧版 [+] 行式"),
)

_COMPILED = [(re.compile(p, re.MULTILINE), e, w, d) for p, e, w, d in _RULES]

# 强制指定时可接受的别名
_VERSION_ALIASES: Dict[str, FscanEra] = {
    "1.8.0": FscanEra.V1_EARLY,
    "1.8.1": FscanEra.V1_EARLY,
    "1.8.2": FscanEra.V1_EARLY,
    "1.8.3": FscanEra.V1_LATE,
    "1.8.4": FscanEra.V1_LATE,
    "2.0.0": FscanEra.V2_0,
    "2.0": FscanEra.V2_0,
    "2.1": FscanEra.V2_1_PLUS,
    "2.1.0": FscanEra.V2_1_PLUS,
    "2.2": FscanEra.V2_1_PLUS,
    "latest": FscanEra.V2_1_PLUS,
    "early": FscanEra.V1_EARLY,
    "late": FscanEra.V1_LATE,
    "v2_late": FscanEra.V2_1_PLUS,
}

_CSV_SECTION_RE = re.compile(r"^#\s*(?:Hosts|Ports|Services|Vulns)\s*$", re.MULTILINE)


def resolve_version_spec(spec: str) -> Optional[FscanEra]:
    """把用户给的版本号/别名映射到版本区间，无法识别返回 None。"""
    key = str(spec).strip().lower().lstrip("v")
    if key in _VERSION_ALIASES:
        return _VERSION_ALIASES[key]
    # 形如 1.8.x / 2.x
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", key)
    if m:
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3)) if m.group(3) is not None else 0
        if (major, minor) >= (2, 1):
            return FscanEra.V2_1_PLUS
        if (major, minor) == (2, 0):
            return FscanEra.V2_0
        if (major, minor) == (1, 8):
            # 1.8.3 是格式分界点
            return FscanEra.V1_EARLY if patch <= 2 else FscanEra.V1_LATE
        if major <= 1:
            return FscanEra.V1_EARLY
    return None


def detect_format_and_version(
    content: str,
    format_hint: str = "",
    version_spec: str = "",
    has_json_summary: bool = False,
) -> FormatDetection:
    """识别输入格式与 fscan 版本区间。

    :param content: 文件全文
    :param format_hint: 'txt'/'csv'/'json'，空则由调用方已判定的格式传入
    :param version_spec: 用户强制指定的版本（优先于自动识别）
    :param has_json_summary: JSON 输入里是否存在 summary/hosts 结构
    """
    result = FormatDetection(format=format_hint)

    if version_spec:
        era = resolve_version_spec(version_spec)
        if era is not None:
            result.era = era
            result.forced = True
            result.confidence = 1.0
            result.notes.append(f"按 --version-spec 指定为 {era.value}")
            return result
        result.notes.append(f"无法识别的 --version-spec: {version_spec}，改为自动识别")

    # JSON / CSV：结构本身就是 v2.1+ 的标志
    if format_hint == "json":
        if has_json_summary:
            result.era = FscanEra.V2_1_PLUS
            result.confidence = 0.95
            result.evidence.append(
                VersionFingerprint("json_summary", "JSON 含 summary/hosts 结构", FscanEra.V2_1_PLUS, 5, "summary")
            )
            return result
        if re.search(r'"type"\s*:\s*"(?:HOST|PORT|SERVICE|VULN)"', content[:20000]):
            result.era = FscanEra.V2_1_PLUS
            result.confidence = 0.9
            result.evidence.append(
                VersionFingerprint("json_typed", "JSON 含 ScanResult 类型字段", FscanEra.V2_1_PLUS, 4, '"type": "PORT"')
            )
            return result
        if re.search(r'"text"\s*:\s*"', content[:4000]):
            result.era = FscanEra.V1_LATE
            result.confidence = 0.6
            result.evidence.append(
                VersionFingerprint("json_legacy", "旧版 -json 的 {type,text} 结构", FscanEra.V1_LATE, 3, '"text": "..."')
            )
            return result
        return result

    if format_hint == "csv":
        if _CSV_SECTION_RE.search(content):
            result.era = FscanEra.V2_1_PLUS
            result.confidence = 0.9
            result.evidence.append(
                VersionFingerprint("csv_section", "CSV 含 Hosts/Ports/Services/Vulns 分段", FscanEra.V2_1_PLUS, 4, "# Services")
            )
            return result
        return result

    # TXT：逐条特征打分
    scores: Dict[FscanEra, int] = {}
    for pattern, era, weight, desc in _COMPILED:
        m = pattern.search(content)
        if not m:
            continue
        sample = m.group(0).strip()[:60]
        if era is FscanEra.UNKNOWN:
            continue
        scores[era] = scores.get(era, 0) + weight
        result.evidence.append(VersionFingerprint(pattern.pattern, desc, era, weight, sample))

    result.scores = {k.value: v for k, v in scores.items()}
    if not scores:
        result.notes.append("未匹配到任何版本特征，按通用行式解析")
        return result

    best_era, best_score = max(scores.items(), key=lambda kv: kv[1])
    total = sum(scores.values())
    result.era = best_era
    result.confidence = round(best_score / total, 2) if total else 0.0

    # 相邻版本靠得近时给出提示，避免误标
    rivals = [(e, s) for e, s in scores.items() if e is not best_era and s >= best_score * 0.8]
    for era, _score in rivals:
        result.notes.append(f"同时命中 {era.value} 的若干特征，版本判断可能不准确，可用 --version-spec 指定")
    return result


def detect_from_records(records: Sequence, detection: FormatDetection) -> FormatDetection:
    """结合解析结果补充判断：出现 HOST/PORT 分段记录说明是 v2.x。"""
    if detection.forced or not records:
        return detection
    types = {getattr(r, "type", None) for r in records}
    if detection.era is FscanEra.UNKNOWN and RecordType.HOST in types:
        detection.era = FscanEra.V2_1_PLUS
        detection.confidence = max(detection.confidence, 0.6)
        detection.notes.append("检测到 HOST 类型记录，推测为 v2.x 分段输出")
    return detection


__all__ = [
    "FscanEra",
    "FormatDetection",
    "VersionFingerprint",
    "detect_format_and_version",
    "detect_from_records",
    "resolve_version_spec",
]
