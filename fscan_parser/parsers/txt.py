"""TXT 结果解析。

覆盖面：fscan 1.8.0 至今全部 ``-o`` 输出格式（详见 ``..version`` 的版本表）。

1. v2.1+（当前 main 分支，``common/output/writers.go`` 的 TXTWriter）
   按分类分段，段落之间空行分隔::

       # ===== 存活主机 =====
       192.168.1.1

       # ===== 开放端口 =====
       192.168.1.1:22

       # ===== 服务信息 =====
       192.168.1.1:22 ssh SSH-2.0-OpenSSH_7.4
       http://192.168.1.5:80 [Apache Tomcat/9.0] 200 Apache-Coyote/1.1 [tomcat,java]

       # ===== 漏洞信息 =====
       192.168.1.5:80 mysql root/123456

       # ===== Web服务 =====
       http://192.168.1.5:80

   中英文段落标题都会出现（取决于 ``-lang`` 参数）。

2. 旧版行式（1.8.0 - 1.8.4 / 2.0.0），带 ``[+]``/``[*]``/``[✓]`` 前缀。
   三代的差异只在**分隔符与语言**：

   =============  ==========================================  ========================================
   版本            服务识别 / 指纹                              弱口令 / 未授权
   =============  ==========================================  ========================================
   1.8.0 - 1.8.2  ``[+] InfoScan: 1.2.3.4:80 [Apache]``        ``[+] SSH:1.2.3.4:22:root:pwd``
                  ``[*] WebTitle: http://x  len:1  code:200``  ``[+] ftp://1.2.3.4:21:u:p``
   1.8.3 - 1.8.4  ``[+] InfoScan 1.2.3.4:80 [Apache]``         ``[+] SSH 1.2.3.4:22:root:pwd``
                  ``[*] WebTitle http://x  len:1  code:200``   ``[+] ftp 1.2.3.4:21:u:p``
   2.0.0          ``[+] 发现指纹 目标: 1.2.3.4:80 指纹: [x]``  ``[✓] SMB认证成功 1.2.3.4:445 User:a Pass:b``
                  ``[*] 网站标题 http://x 状态码:200 标题:x``   ``[+] Redis 1.2.3.4:6379 发现未授权访问``
   =============  ==========================================  ========================================

   旧版 WebTitle 行不再混进漏洞表，而是解析成 ``RecordType.WEBTITLE``，单独成表。

另外也接受 ``.realtime.tmp`` 中断备份文件（只有行、没有分段标题）。
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional

from ..models import Record, RecordType
from ..targets import guess_scheme, looks_like_host, normalize_target

# 段落标题：'# ===== 存活主机 =====' / '===== Alive Hosts =====' / '# ====== 存活主机 ======' 等
_SECTION_RE = re.compile(r"^\s*[#=\-\s]*(?:[\w\s\u4e00-\u9fa5]+?)\s*[=\-]{2,}\s*$")

_SECTION_KEYWORDS = (
    (("存活主机", "alive host", "alive hosts", "存活"), RecordType.HOST),
    (("开放端口", "open port", "open ports", "端口"), RecordType.PORT),
    (("服务信息", "services", "service", "服务"), RecordType.SERVICE),
    (("漏洞信息", "vulnerabilities", "vulnerability", "vulns", "漏洞"), RecordType.VULN),
    (("web服务", "web services", "web"), RecordType.WEB),
)

# 旧版前缀：1.8.x 用 [+]/[*]/[-]/[!]，2.0.0 的认证成功用 [✓]
_PREFIX_RE = re.compile(r"^\s*(?:\[\+\]|\[\*\]|\[-\]|\[!\]|\[✓\]|\[√\])\s*")
# 端口开放：'1.2.3.4:80 open'
_OPEN_RE = re.compile(r"^(?P<target>\S+)\s+(?P<status>open|开放)\s*$", re.IGNORECASE)
# 服务行：'1.2.3.4:22 ssh SSH-2.0-OpenSSH_7.4'
_SERVICE_RE = re.compile(r"^(?P<target>\S+)\s+(?P<service>[A-Za-z][\w.+-]*)(?:\s+(?P<banner>.+))?$")
# Web 服务行：'http://1.2.3.4:80 [title] 200 server [fp1,fp2]'
_WEB_RE = re.compile(
    r"^(?P<url>(?:(?:https?)://)?[^\s\[]+?)"
    r"(?:\s+\[(?P<title>[^\]]*)\])?"
    r"(?:\s+(?P<status>\d{3}))?"
    r"(?:\s+(?P<server>[^\s\[]+))?"
    r"(?:\s+\[(?P<fingerprints>[^\]]*)\])?"
    r"\s*$",
    re.IGNORECASE,
)
# 弱口令（v2 TXT）：'1.2.3.4:80 mysql root/123456' 或 '1.2.3.4:80 root/123456'
_WEAK_RE = re.compile(
    r"^(?P<target>\S+)(?:\s+(?P<service>[A-Za-z][\w.+-]*))?\s+(?P<user>[^\s/:]+)/(?P<pwd>\S*)$"
)
# 旧版弱口令：'SSH 1.2.3.4:22:root:123456' / 'SSH: 1.2.3.4:22:root:123456'
# 1.8.x 的凭据行：服务名与目标之间 1.8.0-1.8.2 用冒号、1.8.3+ 用空格，
# 两种都要吃下，否则 '[+] SSH 1.2.3.4:22:root:123456' 会被拆错。
_LEGACY_CRED_RE = re.compile(
    r"^(?P<service>[A-Za-z][\w.+-]*)\s*:?\s+"
    r"(?P<host>\[[0-9a-fA-F:]+\]|[^\s:]+):(?P<port>\d+)"
    r"(?::(?P<user>[^:\s]+):(?P<pwd>\S+))?"
    r"(?:\s+.*)?$"
)
# 冒号紧贴目标的写法：'[+] SSH:1.2.3.4:22:root:123456'
_LEGACY_CRED_TIGHT_RE = re.compile(
    r"^(?P<service>[A-Za-z][\w.+-]*):"
    r"(?P<host>\[[0-9a-fA-F:]+\]|[^\s:]+):(?P<port>\d+)"
    r"(?::(?P<user>[^:\s]+):(?P<pwd>\S+))?"
    r"(?:\s+.*)?$"
)
# 1.8.0-1.8.2 的 FTP 行是 '[+] ftp://1.2.3.4:21:user:pass'
_FTP_URL_CRED_RE = re.compile(
    r"^ftp://(?P<host>\[[0-9a-fA-F:]+\]|[^\s:/]+)(?::(?P<port>\d+))?"
    r"(?::(?P<user>[^:\s/]+):(?P<pwd>[^\s/]+))?\s*$"
)
# 漏洞行（v2 TXT）：'1.2.3.4:445 MS17-010' / 'http://x/y Tomcat 弱口令'
_VULN_TEXT_RE = re.compile(r"^(?P<target>\S+)\s+(?P<name>.+?)\s*$")
# 旧版插件行：'[+] MS17-010 1.2.3.4\t(Windows 7)' / '[+] Redis 1.2.3.4:6379 unauthorized'
_LEGACY_PLUGIN_RE = re.compile(
    r"^(?P<plugin>[A-Za-z][\w.+-]*)\s+(?P<rest>.+)$"
)


def detect_section(line: str) -> Optional[RecordType]:
    """识别分段标题行，返回该段对应的记录类型。"""
    stripped = line.strip()
    if not stripped or stripped[0] not in "#=-":
        return None
    if not _SECTION_RE.match(stripped):
        return None
    lowered = stripped.lower()
    # 按关键词长度降序匹配，避免 'web服务' 被 '服务' 抢先命中
    candidates = [
        (kw, rtype) for keywords, rtype in _SECTION_KEYWORDS for kw in keywords if kw in lowered
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: len(item[0]))[1]


class TxtParser:
    """TXT 解析器。"""

    format_name = "txt"

    def parse(self, text: str, source: str = "") -> tuple[List[Record], int, int]:
        records: List[Record] = []
        skipped = 0
        failed = 0
        section: Optional[RecordType] = None
        web_only: List[str] = []  # TXT 末尾「Web服务」段落里的 URL 行
        multiline: List[str] = []
        multiline_start = 0
        pending_at = [0]  # 多行记录应插入的位置（保持原始行序）
        last: List[Optional[Record]] = [None]  # 上一条落成的记录，用于「续行携带目标」

        def flush_multiline() -> None:
            nonlocal multiline, skipped
            if not multiline:
                return
            rec = _parse_legacy_block(multiline, source, multiline_start)
            if rec is not None:
                records.insert(pending_at[0], rec)
                pending_at[0] += 1
                last[0] = rec
            else:
                skipped += 1
            multiline = []

        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.replace("\r", "")
            stripped = line.strip()

            if not stripped:
                flush_multiline()
                continue

            new_section = detect_section(stripped)
            if new_section is not None:
                flush_multiline()
                section = new_section
                continue

            if stripped.startswith("#") and len(stripped) > 1:
                # '#' 开头的段内注释（v2.1 的 '# ===== 存活主机 =====' 已在上一步处理）
                flush_multiline()
                continue

            # Web 汇总段落只是服务信息的 URL 列表，不产生独立记录
            if section is RecordType.WEB and WEB_RE_URL.match(stripped):
                web_only.append(stripped)
                continue

            # 旧插件多行输出的首行：先挂起，等确认没有续行后再落成单条记录
            if section is None and _is_block_head(stripped):
                flush_multiline()
                multiline = [stripped]
                multiline_start = idx
                pending_at[0] = len(records)
                continue

            try:
                if section is RecordType.HOST:
                    rec = _parse_host(stripped, source, idx)
                elif section is RecordType.PORT:
                    rec = _parse_port(stripped, source, idx)
                elif section is RecordType.SERVICE:
                    rec = _parse_service(stripped, source, idx)
                elif section is RecordType.VULN:
                    rec = _parse_vuln(stripped, source, idx)
                elif section is RecordType.WEB:
                    rec = None
                else:
                    rec = _parse_legacy_line(stripped, source, idx)
            except Exception:  # 单行异常不影响整体解析
                failed += 1
                continue

            if rec is not None:
                flush_multiline()
                records.append(rec)
                pending_at[0] = len(records)
                last[0] = rec
                continue

            # 续行：上一行是多行结果的首行（含目标），这行只有细节时并进去
            cont = _parse_continuation(stripped, last[0], source, idx)
            if cont is not None:
                flush_multiline()
                records.append(cont)
                pending_at[0] = len(records)
                last[0] = cont
                continue

            if multiline:
                if _IGNORABLE_RE.search(stripped):
                    continue
                multiline.append(stripped)
                continue

            skipped += 1

        flush_multiline()
        return records, skipped, failed


WEB_RE_URL = re.compile(r"^https?://\S+\s*$", re.IGNORECASE)


# 已知会输出多行结果的插件（源码里 LogSuccess 的字符串带 \n）
MULTILINE_PLUGINS = (
    "fcgi",
    "ssh",
    "smb",
    "smb2",
    "wmiexec",
    "ms17010-exp",
    "netbios",
    "redis",
    "local",
)
_MULTILINE_HEAD_RE = re.compile(
    r"^(?P<plugin>[A-Za-z][\w.+-]*)\s*:?\s+(?P<rest>\S.*)$"
)


def _is_block_head(line: str) -> bool:
    """旧版插件多行输出的首行（带 [+] 前缀，如 '[+] FCGI 1.2.3.4:9000 \\nPHP ...'）。

    只有已知会换行输出的插件才挂起，避免把普通单行结果误判成多行块。
    """
    if _IGNORABLE_RE.search(line):
        return False
    body = _PREFIX_RE.sub("", line).strip()
    m = _MULTILINE_HEAD_RE.match(body)
    if not m:
        return False
    return m.group("plugin").split(".")[0].lower() in {p.split("-")[0] for p in MULTILINE_PLUGINS}


def _is_block_terminator(line: str) -> bool:
    """判断续行块后的这一行是否已经是一条新记录（结束多行挂起）。"""
    if _IGNORABLE_RE.search(line):
        return False
    if line.startswith(("[+]", "[*]", "[-]", "[!]", "[✓]", "[√]")):
        return True
    if WEB_RE_URL.match(line):
        return True
    if _OPEN_RE.match(line) and looks_like_host(line.split()[0]):
        return True
    return False


# --------------------------------------------------------------------------
# v2 分段格式
# --------------------------------------------------------------------------
def _parse_host(line: str, source: str, line_no: int) -> Optional[Record]:
    if not looks_like_host(line):
        return None
    return Record(
        type=RecordType.HOST,
        target=normalize_target(line),
        status="alive",
        source=source,
        line_no=line_no,
        raw=line,
    )


def _parse_port(line: str, source: str, line_no: int) -> Optional[Record]:
    m = _OPEN_RE.match(line)
    target_text = m.group("target") if m else line
    target = normalize_target(target_text)
    if target.port is None and not looks_like_host(target_text):
        return None
    return Record(
        type=RecordType.PORT,
        target=target,
        status="open",
        details={"port": target.port} if target.port else {},
        source=source,
        line_no=line_no,
        raw=line,
    )


def _parse_service(line: str, source: str, line_no: int) -> Optional[Record]:
    web = _parse_web_service(line, source, line_no)
    if web is not None:
        return web

    m = _SERVICE_RE.match(line)
    if not m:
        return None
    target_text = m.group("target")
    if not looks_like_host(target_text):
        return None
    target = normalize_target(target_text)
    service = m.group("service")
    banner = (m.group("banner") or "").strip()
    details = {"service": service}
    if banner:
        # writers.go: 非 Web 服务只输出 'target service <banner>'，banner 已被截断到 100 字符。
        # 若 banner 以版本号/数字开头（nmap 常见形式），拆出首段作为版本，其余保留为 banner。
        version, rest = _split_version(banner)
        if version:
            details["version"] = version
            if rest:
                details["banner"] = rest
        else:
            details["banner"] = banner
    return Record(
        type=RecordType.SERVICE,
        target=target,
        status="identified",
        details=details,
        source=source,
        line_no=line_no,
        raw=line,
    )


def _parse_web_service(line: str, source: str, line_no: int) -> Optional[Record]:
    m = _WEB_RE.match(line)
    if not m:
        return None
    url = m.group("url")
    has_scheme = bool(re.match(r"^https?://", url, re.IGNORECASE))
    # 无 scheme 时，只有出现 [标题]/[指纹]/状态码才能确认是 Web 行
    distinctive = bool(m.group("title") is not None or m.group("fingerprints") is not None)
    if not has_scheme and not distinctive:
        return None
    if not has_scheme and not looks_like_host(url):
        return None
    target = normalize_target(url)
    scheme = target.scheme or guess_scheme(url, port=target.port)
    details: dict = {"service": scheme, "is_web": True}
    if target.port:
        details["port"] = target.port
    if m.group("title"):
        details["title"] = m.group("title").strip()
    if m.group("status"):
        details["status"] = m.group("status")
    if m.group("server"):
        details["server"] = m.group("server").strip()
    if m.group("fingerprints"):
        details["fingerprints"] = [p.strip() for p in m.group("fingerprints").split(",") if p.strip()]
    return Record(
        type=RecordType.SERVICE,
        target=target,
        status="web",
        details=details,
        source=source,
        line_no=line_no,
        raw=line,
    )


def _parse_vuln(line: str, source: str, line_no: int) -> Optional[Record]:
    weak = _WEAK_RE.match(line)
    if weak:
        target_text = weak.group("target")
        target = normalize_target(target_text)
        if target.host:
            details = {
                "type": "weak_credential",
                "username": weak.group("user"),
                "password": weak.group("pwd"),
            }
            if weak.group("service"):
                details["service"] = weak.group("service")
            return Record(
                type=RecordType.VULN,
                target=target,
                status="vulnerable",
                details=details,
                source=source,
                line_no=line_no,
                raw=line,
                extra={"vuln_name": "弱口令"},
            )

    m = _VULN_TEXT_RE.match(line)
    if not m:
        return None
    target_text = m.group("target")
    name = m.group("name").strip()
    if not name:
        return None
    target = normalize_target(target_text)
    return Record(
        type=RecordType.VULN,
        target=target,
        status=name,
        details={"vulnerability_name": name, "type": "vulnerability"},
        source=source,
        line_no=line_no,
        raw=line,
        extra={"vuln_name": name},
    )


_VERSION_RE = re.compile(r"^(?P<ver>\d+(?:\.\d+){1,3}[\w.+-]*)(?:$|\s+)(?P<rest>.*)$", re.DOTALL)
_PRODUCT_VER_RE = re.compile(
    r"^(?P<prod>[A-Za-z][\w.+-]*)[\s/_-]v?(?P<ver>\d+(?:\.\d+){1,3}[\w.+-]*)(?:$|\s+)(?P<rest>.*)$",
    re.DOTALL,
)


def _split_version(banner: str) -> tuple[str, str]:
    """从 banner 中拆出版本号，返回 (版本, 剩余描述)。

    以版本号开头时直接取（如 ``5.7.30-0ubuntu0.18.04.1``），
    否则尝试 ``OpenSSH 7.4`` 这种「产品 + 版本」形式。
    """
    text = banner.strip()
    m = _VERSION_RE.match(text)
    if m:
        return m.group("ver").rstrip("."), m.group("rest").strip()
    m = _PRODUCT_VER_RE.match(text)
    if m:
        return f"{m.group('prod')} {m.group('ver')}", m.group("rest").strip()
    return "", text


# --------------------------------------------------------------------------
# 旧版 WebTitle / 网站标题（三代写法不同）
# --------------------------------------------------------------------------
# 1.8.0-1.8.4: '[*] WebTitle http://x  len:8  code:200  title:主页'
#              (1.8.0 为 WebTitle:，字段之间是空格而非两空格)
_WEBTITLE_OLD_RE = re.compile(
    r"^WebTitle\s*:?\s*(?P<url>\S+)"
    r"(?:\s+len\s*:\s*(?P<len>\d+))?"
    r"(?:\s+code\s*:\s*(?P<code>\d+))?"
    r"(?:\s+title\s*:\s*(?P<title>.*?))?"
    r"(?:\s+https\s*:\s*(?P<https>\w+))?"
    r"\s*$",
    re.IGNORECASE,
)
# 2.0.0: '[*] 网站标题 http://x 状态码:200 长度:8 标题:主页'
_WEBTITLE_CN_RE = re.compile(
    r"^网站标题\s*(?P<url>\S+)"
    r"(?:\s+状态码\s*:\s*(?P<code>\d+))?"
    r"(?:\s+长度\s*:\s*(?P<len>\d+))?"
    r"(?:\s+标题\s*:\s*(?P<title>.*?))?"
    r"(?:\s+跳转\s*:\s*(?P<redirect>\S+))?"
    r"\s*$"
)


def _parse_webtitle(body: str, source: str, line_no: int, raw: str) -> Optional[Record]:
    m = _WEBTITLE_OLD_RE.match(body) or _WEBTITLE_CN_RE.match(body)
    if not m:
        return None
    groups = m.groupdict()
    url = (groups.get("url") or "").strip()
    if not url or not looks_like_host(url.split("/")[2] if "://" in url else url.split("/")[0]):
        return None
    target = normalize_target(url)
    if not target.host:
        return None
    details: dict = {"is_web": True, "service": target.scheme or guess_scheme(url, port=target.port),
                     "url": _bare_url(url)}
    if groups.get("title"):
        details["title"] = groups["title"].strip()
    if groups.get("code"):
        details["status"] = groups["code"]
    if groups.get("len"):
        details["length"] = groups["len"]
    if groups.get("redirect"):
        details["redirect"] = groups["redirect"]
    if target.port:
        details["port"] = target.port
    return Record(
        type=RecordType.WEBTITLE,
        target=target,
        status="web",
        details=details,
        source=source,
        line_no=line_no,
        raw=raw,
    )


def _bare_url(url: str) -> str:
    """补上 scheme，便于在表里直接点开。"""
    if re.match(r"^https?://", url, re.IGNORECASE):
        return url
    return f"{guess_scheme(url)}://{url.lstrip('/')}"


# --------------------------------------------------------------------------
# 旧版指纹（InfoScan / 发现指纹）
# --------------------------------------------------------------------------
_INFO_SCAN_RE = re.compile(
    r"^InfoScan\s*:?\s*(?P<target>\S+)\s*(?P<rest>.*)$", re.IGNORECASE | re.DOTALL
)
_FINGERPRINT_CN_RE = re.compile(
    r"^发现指纹\s*目标\s*:\s*(?P<target>\S+)\s*指纹\s*:\s*(?P<rest>.*)$", re.DOTALL
)
# 2.0.0 的指纹行可能是 '[+] 指纹识别 目标:... 指纹:...' 等别名
_FINGERPRINT_CN_ALT_RE = re.compile(
    r"^(?:发现指纹|指纹识别|指纹信息)\s*目标\s*:\s*(?P<target>\S+)(?:\s*指纹\s*:\s*(?P<rest>.*))?$",
    re.DOTALL,
)


def _parse_infoscan(body: str, source: str, line_no: int, raw: str) -> Optional[Record]:
    m = _INFO_SCAN_RE.match(body) or _FINGERPRINT_CN_RE.match(body) or _FINGERPRINT_CN_ALT_RE.match(body)
    if not m:
        return None
    target_text = (m.group("target") or "").strip()
    if not looks_like_host(target_text):
        return None
    target = normalize_target(target_text)
    rest = (m.groupdict().get("rest") or "").strip()

    # '1.2.3.4:80 [Apache Tomcat/9.0] 200 Apache-Coyote/1.1 [tomcat,java]'
    # 指纹可能带方括号，后面跟着状态码 / Server / 指纹列表。
    # 先把方括号段取走，剩下的裸字段里 3 位数字是状态码、形如 Product/1.2 的是 Server。
    fps = _extract_fingerprints(rest)
    status = ""
    server = ""
    bare = re.sub(r"\[[^\]]*\]", " ", rest)
    for token in bare.split():
        if re.fullmatch(r"\d{3}", token):
            status = token
        elif not server and re.fullmatch(r"[A-Za-z][\w.+-]*/[\w.+-]+", token):
            server = token

    is_web = _info_scan_is_web(fps, target_text, rest)
    details: dict = {
        "service": guess_scheme(target_text, port=target.port) if is_web else _service_from_fps(fps),
        "is_web": is_web,
    }
    if fps:
        details["fingerprints"] = fps
    if status:
        details["status"] = status
    if server:
        details["server"] = server
    if target.port:
        details["port"] = target.port
    # 指纹里的 'Apache Tomcat/9.0' 也带版本
    version, _rest = _split_version(fps[0]) if fps else ("", "")
    if not is_web and version:
        details["version"] = version
    return Record(
        type=RecordType.SERVICE,
        target=target,
        status="web" if is_web else "identified",
        details=details,
        source=source,
        line_no=line_no,
        raw=raw,
    )


def _extract_fingerprints(rest: str) -> List[str]:
    """从 InfoScan 行的剩余部分提取指纹。

    形如 ``[Apache Tomcat/9.0] 200 Apache-Coyote/1.1 [tomcat,java]`` 时，
    方括号内容才是指纹；没有方括号时取第一个非状态码的字段。
    """
    if not rest:
        return []
    groups = re.findall(r"\[([^\]]*)\]", rest)
    if groups:
        out: List[str] = []
        for group in groups:
            for part in group.split(","):
                part = part.strip()
                if part and part not in out:
                    out.append(part)
        return out
    # 无方括号：'OpenSSH_7.4' 这类裸指纹
    cleaned = re.sub(r"\b\d{3}\b", " ", rest).strip()
    if not cleaned:
        return []
    return [cleaned.split()[0]]


def _service_from_fps(fps: List[str]) -> str:
    if not fps:
        return ""
    m = _NON_WEB_RE.match(fps[0])
    if m:
        name = m.group(0).lower()
        return "ssh" if name == "openssh" else name
    return fps[0].split("/")[0].split()[0].lower()


# --------------------------------------------------------------------------
# 旧版认证成功（2.0.0 的 [✓] 与 1.8.x 的 'SSH host:port:u:p'）
# --------------------------------------------------------------------------
_CN_AUTH_RE = re.compile(
    r"^(?P<plugin>\S+?)\s*认证成功\s*:?\s*(?P<rest>.*)$", re.DOTALL
)
_CN_USER_RE = re.compile(r"User\s*:\s*(?P<user>[^\s,;]+)", re.IGNORECASE)
_CN_PASS_RE = re.compile(r"Pass(?:word)?\s*:\s*(?P<pwd>[^\s,;]+)", re.IGNORECASE)
_CN_DOMAIN_RE = re.compile(r"Domain\s*:\s*(?P<domain>[^\s,;]+)", re.IGNORECASE)
# '1.2.3.4:445' / '1.2.3.4:1433' / '1.2.3.4' 都出现过
_TARGET_TOKEN_RE = re.compile(r"^(?P<target>\[[0-9a-fA-F:]+\](?::\d+)?|[^\s:]+(?::\d+)?)")


def _parse_cn_auth(body: str, source: str, line_no: int, raw: str) -> Optional[Record]:
    m = _CN_AUTH_RE.match(body)
    if not m:
        return None
    plugin = m.group("plugin")
    rest = m.group("rest").strip()

    user = _CN_USER_RE.search(rest)
    pwd = _CN_PASS_RE.search(rest)
    domain = _CN_DOMAIN_RE.search(rest)
    head = _TARGET_TOKEN_RE.match(rest)
    if not head:
        return None
    target_text = head.group("target")
    if not looks_like_host(target_text):
        return None
    target = normalize_target(target_text)

    details: dict = {
        "type": "weak_credential",
        "service": plugin.split(".")[0].lower(),
    }
    if user:
        details["username"] = user.group("user")
    if pwd:
        details["password"] = pwd.group("pwd")
    if domain:
        details["domain"] = domain.group("domain")
        # Domain:d\user 时 username 形如 'd\administrator'
    if target.port:
        details["port"] = target.port
    return Record(
        type=RecordType.VULN,
        target=target,
        status="vulnerable",
        details=details,
        source=source,
        line_no=line_no,
        raw=raw,
        extra={"vuln_name": "弱口令"},
    )


# 2.0.0 的未授权访问：'Redis 1.2.3.4:6379 发现未授权访问'
_CN_UNAUTH_RE = re.compile(
    r"^(?P<plugin>[A-Za-z][\w.+-]*)\s+(?P<target>\S+)\s+(?:发现)?未授权访问\s*$"
)
# 1.8.3-1.8.4：'Redis 1.2.3.4:6379 unauthorized'
_EN_UNAUTH_RE = re.compile(
    r"^(?P<plugin>[A-Za-z][\w.+-]*)\s*:?\s*(?P<target>\S+)\s+unauthorized\s*$", re.IGNORECASE
)


def _parse_unauthorized(body: str, source: str, line_no: int, raw: str) -> Optional[Record]:
    m = _CN_UNAUTH_RE.match(body) or _EN_UNAUTH_RE.match(body)
    if not m:
        return None
    target_text = m.group("target")
    if not looks_like_host(target_text):
        return None
    target = normalize_target(target_text)
    plugin = m.group("plugin")
    name = f"{plugin} 未授权访问"
    return Record(
        type=RecordType.VULN,
        target=target,
        status=name,
        details={
            "vulnerability_name": name,
            "type": "unauthorized",
            "service": plugin.lower(),
            "port": target.port,
        },
        source=source,
        line_no=line_no,
        raw=raw,
        extra={"vuln_name": name},
    )


# --------------------------------------------------------------------------
# v1.x 行式格式
# --------------------------------------------------------------------------
# 1.8.x 的 WebScan 漏洞行没有 PocScan 标识，直接是 'http://x poc-yaml-xxx 结果名'
_POC_NAME_RE = re.compile(
    r"^(?:poc-yaml-|poc-|cve-\d{4}-|cnvd-|cve_|tomcat-|weblogic-|shiro-|struts|fastjson|"
    r"thinkphp|spring|jenkins|nacos|xxl-job|zabbix|solr|elasticsearch|weblogic)",
    re.IGNORECASE,
)
_POC_NAME_LOOSE_RE = re.compile(r"(?:poc|vuln|weak|unauth|rce|ssrf|lfi|sqli|exposed)", re.IGNORECASE)

# 2.0.0 的 '[+] 发现漏洞 目标: http://x 名称: yyy'
_CN_VULN_RE = re.compile(
    r"^发现漏洞\s*(?:目标\s*:\s*)?(?P<target>\S+)(?:\s*(?:名称|漏洞|详情)\s*:\s*(?P<name>.+))?$",
    re.DOTALL,
)


def _parse_legacy_line(line: str, source: str, line_no: int) -> Optional[Record]:
    if not _PREFIX_RE.match(line):
        # 无前缀的裸行：'1.2.3.4:80 open' 按端口，'1.2.3.4:80'/'1.2.3.4' 按端口/主机
        m = _OPEN_RE.match(line)
        if m and looks_like_host(m.group("target")):
            return _parse_port(line, source, line_no)
        if looks_like_host(line):
            target = normalize_target(line)
            if target.port is not None:
                return _parse_port(line, source, line_no)
            return _parse_host(line, source, line_no)
        return None

    body = _PREFIX_RE.sub("", line).strip()
    if not body:
        return None

    # 统计/提示类行，直接忽略
    if _IGNORABLE_RE.search(body):
        return None

    # ---- 端口开放（2.0.0 中文 / 旧版 open）----
    m = _OPEN_RE.match(body)
    if m and looks_like_host(m.group("target")):
        return _parse_port(body, source, line_no)
    if body.startswith("端口开放"):
        target_text = body[len("端口开放") :].strip()
        if looks_like_host(target_text):
            return _parse_port(target_text, source, line_no)
    if body.startswith("主机存活"):
        target_text = body[len("主机存活") :].strip()
        if looks_like_host(target_text):
            return _parse_host(target_text, source, line_no)

    # ---- WebTitle / 网站标题 ----
    webtitle = _parse_webtitle(body, source, line_no, line)
    if webtitle is not None:
        return webtitle

    # ---- 认证成功（2.0.0）----
    auth = _parse_cn_auth(body, source, line_no, line)
    if auth is not None:
        return auth

    # ---- 未授权访问（2.0.0 / 1.8.3+）----
    unauth = _parse_unauthorized(body, source, line_no, line)
    if unauth is not None:
        return unauth
    # ---- 指纹识别（1.8.x InfoScan / 2.0.0 发现指纹）----
    infoscan = _parse_infoscan(body, source, line_no, line)
    if infoscan is not None:
        return infoscan

    # ---- 1.8.0-1.8.2 的 ftp 行：'ftp://1.2.3.4:21:user:pass' ----
    #     必须排在通用凭据行规则之前：'ftp://...' 会被 _LEGACY_CRED_RE 当成服务名 +
    #     空主机（host 解析成 ''），端口也就丢了。
    ftp = _FTP_URL_CRED_RE.match(body)
    if ftp is not None:
        port = ftp.group("port") or "21"
        # 只把 host:port 交给 normalize_target，整串 'ftp://host:21:u:p' 会把端口解析错
        target = normalize_target(f"{ftp.group('host')}:{port}")
        details = {
            "type": "weak_credential",
            "service": "ftp",
            "port": target.port,
        }
        if ftp.group("user") is not None:
            details["username"] = ftp.group("user")
            details["password"] = ftp.group("pwd")
        return Record(
            type=RecordType.VULN,
            target=target,
            status="vulnerable",
            details=details,
            source=source,
            line_no=line_no,
            raw=line,
            extra={"vuln_name": "弱口令"},
        )

    # ---- 弱口令：'SSH 1.2.3.4:22:root:123456' / 'SSH:1.2.3.4:22:root:123456' ----
    cred = None if "://" in body else (_LEGACY_CRED_RE.match(body) or _LEGACY_CRED_TIGHT_RE.match(body))
    if cred and cred.group("user") is not None:
        host = cred.group("host")
        target = normalize_target(f"{host}:{cred.group('port')}")
        details = {
            "type": "weak_credential",
            "service": (cred.group("service") or "").lower(),
            "username": cred.group("user"),
            "password": cred.group("pwd"),
        }
        details = {k: v for k, v in details.items() if v != ""}
        return Record(
            type=RecordType.VULN,
            target=target,
            status="vulnerable",
            details=details,
            source=source,
            line_no=line_no,
            raw=line,
            extra={"vuln_name": "弱口令"},
        )

    # ---- 2.0.0 的 '[+] 发现漏洞 目标: http://x 名称: yyy' ----
    cn_vuln = _CN_VULN_RE.match(body)
    if cn_vuln:
        target = normalize_target(cn_vuln.group("target"))
        name = (cn_vuln.group("name") or "").strip() or "发现漏洞"
        return Record(
            type=RecordType.VULN,
            target=target,
            status=name,
            details={"vulnerability_name": name, "type": "vulnerability"},
            source=source,
            line_no=line_no,
            raw=line,
            extra={"vuln_name": name},
        )

    # ---- PocScan：'PocScan http://x:80 poc-name' / '检测到漏洞 http://... poc-name' ----
    poc = re.match(
        r"^(?:PocScan|检测到漏洞)\s*:?\s+(?P<url>\S+)\s*(?P<name>\S*)(?:\s+(?P<params>.+))?$", body
    )
    if poc:
        name = poc.group("name") or "POC"
        target = normalize_target(poc.group("url"))
        details = {"vulnerability_name": name, "type": "vulnerability"}
        if poc.group("params"):
            details["parameters"] = poc.group("params").strip()
        return Record(
            type=RecordType.VULN,
            target=target,
            status=name,
            details=details,
            source=source,
            line_no=line_no,
            raw=line,
            extra={"vuln_name": name},
        )

    # ---- 1.8.0-1.8.2 的 WebScan 漏洞行：没有 PocScan 标识 ----
    #      '[+] http://1.2.3.4:80 poc-yaml-tomcat-weak-password 存在默认口令'
    webpoc = re.match(r"^(?P<url>https?://\S+)\s+(?P<rest>.+)$", body)
    if webpoc:
        rest = webpoc.group("rest").strip()
        parts = rest.split(None, 1)
        name = parts[0]
        if _POC_NAME_RE.match(name) or _POC_NAME_LOOSE_RE.search(name):
            target = normalize_target(webpoc.group("url"))
            details = {"vulnerability_name": name, "type": "vulnerability"}
            if len(parts) > 1:
                details["description"] = parts[1].strip()
            return Record(
                type=RecordType.VULN,
                target=target,
                status=name,
                details=details,
                source=source,
                line_no=line_no,
                raw=line,
                extra={"vuln_name": name},
            )

    # ---- OsInfo：'OsInfo 1.2.3.4 (Windows Server 2008 R2)' ----
    osinfo = re.match(r"^OsInfo\s*:?\s*(?P<target>\S+)\s*(?P<os>.+)$", body, re.IGNORECASE)
    if osinfo and looks_like_host(osinfo.group("target")):
        target = normalize_target(osinfo.group("target"))
        return Record(
            type=RecordType.HOST,
            target=target,
            status="alive",
            details={"os": osinfo.group("os").strip("() \t")},
            source=source,
            line_no=line_no,
            raw=line,
        )

    # ---- 插件漏洞：'MS17-010 1.2.3.4\t(Windows 7)' ----
    plugin = _LEGACY_PLUGIN_RE.match(body)
    if plugin:
        name = plugin.group("plugin")
        rest = plugin.group("rest").strip()
        target_text = rest.split()[0] if rest else ""
        note = rest[len(target_text) :].strip() if target_text else ""
        if looks_like_host(target_text) or normalize_target(target_text).host:
            target = normalize_target(target_text)
            details = {"vulnerability_name": name, "type": "vulnerability"}
            if note:
                details["description"] = note.strip("() ")
            return Record(
                type=RecordType.VULN,
                target=target,
                status=name,
                details=details,
                source=source,
                line_no=line_no,
                raw=line,
                extra={"vuln_name": name},
            )

    return None


def _parse_continuation(
    line: str, last: Optional[Record], source: str, line_no: int
) -> Optional[Record]:
    """解析紧跟在结论行后面、自身不带目标的细节行。

    fscan 2.0.0 部分插件把结论和细节拆成两行，例如::

        [+] FastCGI漏洞确认 1.2.3.4:9000
        [+] PHP-FPM 版本: 7.2.1

    这里沿用上一行的目标，把细节补成一条独立记录，避免丢信息。
    """
    if last is None or not last.target.host:
        return None
    if not _PREFIX_RE.match(line):
        return None
    body = _PREFIX_RE.sub("", line).strip()
    if not body or _IGNORABLE_RE.search(body):
        return None
    # 必须自己不含目标（含目标的行交给主流程）
    first = body.split()[0]
    if looks_like_host(first):
        return None
    # 只在上一行是漏洞时接续（服务/Web 行的续行通常是 banner，交给多行块处理）
    if last.type is not RecordType.VULN:
        return None
    detail = body.strip()
    if not detail:
        return None
    return Record(
        type=RecordType.VULN,
        target=last.target,
        status=last.status,
        details={
            "vulnerability_name": last.vuln_name or last.status,
            "type": "vulnerability_detail",
            "description": detail,
        },
        source=source,
        line_no=line_no,
        raw=line,
        extra={"vuln_name": last.vuln_name or last.status},
    )


_IGNORABLE_RE = re.compile(
    r"段存活|存活主机数|LiveTop|从目录加载|exploit end|^\[?\+?\]?\s*扫描完成|^\[?\+?\]?\s*扫描结束"
    r"|^(?:\[.\])?\s*(?:B段|C段|NetBios)\s"
    r"|^(?:B段|C段)\s"
)


_NON_WEB_RE = re.compile(
    r"^(?:ssh|openssh|smtp|ftp|telnet|mysql|mssql|oracle|redis|mongo|memcached|rdp|smb|"
    r"ldap|postgres|elastic|zookeeper|docker|kafka|rabbit|nfs|vnc|ftp)",
    re.IGNORECASE,
)


def _info_scan_is_web(fps: List[str], target_text: str, rest: str = "") -> bool:
    """InfoScan 的指纹若全是服务名（如 OpenSSH），说明不是 Web。"""
    if not fps:
        return bool(re.search(r"\b\d{3}\b", rest)) or "://" in target_text
    return not all(_NON_WEB_RE.match(fp) for fp in fps)


def _parse_legacy_block(lines: Iterable[str], source: str, line_no: int) -> Optional[Record]:
    """处理跨行输出（如 FCGI、SSH 命令执行结果），保留首行结论 + 完整原文。"""
    lines = list(lines)
    joined = "\n".join(lines).strip()
    if not joined:
        return None
    rec = _parse_legacy_line(lines[0], source, line_no)
    if rec is None and _IGNORABLE_RE.search(lines[0]):
        return None
    if rec is None:
        # 退化成"未知类型"的漏洞类记录，避免丢数据
        m = _PREFIX_RE.sub("", lines[0]).strip()
        parts = m.split(None, 1)
        if len(parts) < 2:
            return None
        target_text = parts[1].split()[0]
        if not looks_like_host(target_text):
            return None
        rec = Record(
            type=RecordType.VULN,
            target=normalize_target(target_text),
            status=parts[0],
            details={"vulnerability_name": parts[0], "type": "vulnerability"},
            source=source,
            line_no=line_no,
            extra={"vuln_name": parts[0]},
        )
    rec.raw = joined
    rec.details.setdefault("description", joined)
    return rec
