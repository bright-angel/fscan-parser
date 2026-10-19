"""目标拆解：把 fscan 输出里的各种 host 写法统一成 Target。"""

from __future__ import annotations

import re

from .models import Target

_SCHEME_RE = re.compile(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://(?P<rest>.+)$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalize_target(raw: str, default_port: int | None = None) -> Target:
    """解析形如 1.2.3.4、1.2.3.4:80、http://host:8080/path、[::1]:22 的目标。"""
    target = Target(raw=raw, port=default_port)
    text = (raw or "").strip()
    if not text:
        return target

    scheme = ""
    m = _SCHEME_RE.match(text)
    if m:
        scheme = m.group("scheme").lower()
        text = m.group("rest")
    target.scheme = scheme if scheme in ("http", "https") else ""

    # 去掉 URL 中的路径/查询串
    for sep in ("/", "?", "#"):
        idx = text.find(sep)
        if idx != -1:
            text = text[:idx]

    # 去掉 userinfo
    if "@" in text:
        text = text.rsplit("@", 1)[1]

    host, port = _split_host_port(text)
    target.host = host or text
    if port is not None:
        target.port = port
    return target


def _split_host_port(text: str) -> tuple[str, int | None]:
    if not text:
        return "", None
    if text.startswith("["):  # [IPv6]:port 或 [IPv6]
        end = text.find("]")
        if end != -1:
            host = text[1:end]
            rest = text[end + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, None
    if text.count(":") == 1:  # host:port
        host, _, port_text = text.rpartition(":")
        if port_text.isdigit():
            return host, int(port_text)
        return text, None
    if text.count(":") > 1:  # 裸 IPv6
        return text.strip("[]"), None
    return text, None


def guess_scheme(raw: str, service: str = "", port: int | None = None) -> str:
    """推断 Web 协议：优先原串，其次服务名，最后按端口经验值。"""
    lowered = (raw or "").lower()
    if lowered.startswith("https://"):
        return "https"
    if lowered.startswith("http://"):
        return "http"
    if service.lower() == "https":
        return "https"
    if port is not None and port in (443, 8443, 9443, 4443):
        return "https"
    return "http"


def looks_like_host(text: str) -> bool:
    """判断 TXT 段落里的裸行是否为合法主机（IP / 主机名 / IP:端口）。"""
    if not text or " " in text:
        return False
    host, port = _split_host_port(text)
    if port is not None:
        return bool(host) and port > 0
    if _IPV4_RE.match(host):
        return all(0 <= int(o) <= 255 for o in host.split("."))
    if ":" in host:  # IPv6
        return all(c in "0123456789abcdefABCDEF:." for c in host) and host.count(":") >= 2
    return bool(re.match(r"^[a-zA-Z0-9_](?:[a-zA-Z0-9_.-]*[a-zA-Z0-9_])?$", host))
