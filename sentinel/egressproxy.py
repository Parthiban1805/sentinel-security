"""Egress proxy for the Docker sandbox (v0.7f item 4, ADR-0026).

Runs INSIDE a container made from the pinned sandbox image, as `python3 -I egressproxy.py <config>`.
That container is the only thing on the sandbox's internal Docker network that also has a route
out, so every connection the sandboxed code makes goes through these checks:

- HTTPS: `CONNECT host:port` only to hosts on the allow-list (exact names, or `*.suffix`), and only
  on the listed ports (443 by default). The tunnel is NOT decrypted (no TLS interception).
- Plain HTTP: only GET and HEAD, without a request body, to a host and path prefix named by an
  HTTP rule; one request per connection; the Host header is rewritten to the checked host.
- DNS: the proxy resolves allowed names itself and refuses a name if ANY answer is a private,
  loopback, link-local, shared, reserved or cloud-metadata address. It then connects to the vetted
  address, so a second lookup cannot swap it (DNS rebinding). A name that is not allowed is never
  looked up: a lookup alone can carry data out.
- IP addresses as targets are always refused.

Every decision is one JSON line on stdout (capped). Hosts in the log are the sandbox's own requests
and can carry data; the host side stores only a suffix and a hash (sentinel/sandbox.py).
Standard library only, no Sentinel imports: this file is copied into the container on its own.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import socketserver
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

PROXY_PORT = 3128
MAX_RULES = 100
MAX_HEAD = 16 * 1024
MAX_CONNECTIONS = 64
HEAD_TIMEOUT_S = 30
CONNECT_TIMEOUT_S = 10
IDLE_TIMEOUT_S = 120
LOG_LIMIT = 5000
# Refusals that point at the machine, the network or a metadata service: logged past LOG_LIMIT,
# so a flood of harmless refusals cannot hide them (security review 2026-11-10).
PRIORITY_REASONS = ("metadata_address", "internal_address", "ip_literal")
PRIORITY_LIMIT = 5000
HTTP_METHODS = ("GET", "HEAD")

# Names that point at the machine, the Docker host or a cloud metadata service.
_RESERVED_SUFFIXES = (".internal", ".local", ".localhost", ".localdomain", ".home.arpa", ".arpa")
_RESERVED_NAMES = ("metadata", "localhost", "metadata.google.internal", "instance-data")
_METADATA = {
    ipaddress.ip_address("169.254.169.254"),  # AWS, GCP, Azure, others
    ipaddress.ip_address("169.254.170.2"),  # AWS ECS task metadata
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
    ipaddress.ip_address("fd00:ec2::254"),  # AWS IPv6
}
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_HOP = {"host", "connection", "proxy-connection", "proxy-authorization", "proxy-authenticate",
        "keep-alive", "te", "trailer", "transfer-encoding", "upgrade"}  # fmt: skip


class Refused(Exception):
    """A request the proxy refuses; `reason` is a fixed word, never request text."""

    def __init__(self, reason: str, host: str = "", port: int = 0, method: str = "") -> None:
        super().__init__(reason)
        self.reason, self.host, self.port, self.method = reason, host, port, method


# --- rules ---------------------------------------------------------------------------------------
def _norm(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _check_name(host: str) -> str:
    """A DNS name with at least two labels, not an IP address and not a reserved local name."""
    name = _norm(host)
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(_LABEL.fullmatch(lb) for lb in labels):
        raise ValueError("not a valid host name (letters, digits, hyphens; two labels or more)")
    if labels[-1].isdigit():
        raise ValueError("IP addresses are not allowed, only host names")
    if name in _RESERVED_NAMES or any(name.endswith(s) for s in _RESERVED_SUFFIXES):
        raise ValueError("local and cloud-metadata names are never allowed")
    return name


@dataclass(frozen=True)
class AllowRule:
    pattern: str  # "pypi.org" or "*.githubusercontent.com"
    ports: tuple[int, ...] = (443,)

    def matches(self, host: str, port: int) -> bool:
        if port not in self.ports:
            return False
        if self.pattern.startswith("*."):
            suffix = self.pattern[1:]
            return host.endswith(suffix) and len(host) > len(suffix)
        return host == self.pattern


@dataclass(frozen=True)
class HttpRule:
    methods: tuple[str, ...]
    host: str
    prefix: str


def parse_allow(entry: str) -> AllowRule:
    """`host`, `host:port` or `*.suffix[:port]` (HTTPS through CONNECT)."""
    text = str(entry).strip()
    if text.count(":") > 1 or "/" in text:
        raise ValueError(f"allow entry must be host or host:port: {text[:80]!r}")
    host, _, port_text = text.partition(":")
    ports: tuple[int, ...] = (443,)
    if port_text:
        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            raise ValueError("allow entry port must be a number from 1 to 65535")
        ports = (int(port_text),)
    wildcard = _norm(host).startswith("*.")
    name = _check_name(_norm(host)[2:] if wildcard else host)
    return AllowRule(("*." + name) if wildcard else name, ports)


def _path_ok(path: str) -> bool:
    if any(ord(c) < 33 or ord(c) > 126 for c in path) or "\\" in path:
        return False
    low = path.lower()
    if "%2e" in low or "%2f" in low or "%5c" in low:
        return False
    segments = path.split("?", 1)[0].split("/")
    return not any(s in (".", "..") for s in segments)


def parse_http(entry: str) -> HttpRule:
    """`METHOD[,METHOD] host /path-prefix`, plain HTTP on port 80, GET and HEAD only."""
    parts = str(entry).split()
    if len(parts) != 3:
        raise ValueError("http rule must be: METHOD host /path-prefix")
    methods: list[str] = []
    for m in parts[0].upper().split(","):
        if m not in HTTP_METHODS:
            raise ValueError("http rule methods must be GET and/or HEAD")
        if m not in methods:
            methods.append(m)
    if ":" in parts[1] or "*" in parts[1]:
        raise ValueError("http rule host must be a plain host name (port 80, no wildcard)")
    prefix = parts[2]
    if not prefix.startswith("/") or not prefix.endswith("/") or not _path_ok(prefix):
        raise ValueError("http rule path must start and end with / and hold no . or .. segments")
    return HttpRule(tuple(methods), _check_name(parts[1]), prefix)


@dataclass(frozen=True)
class Rules:
    allow: tuple[AllowRule, ...] = ()
    http: tuple[HttpRule, ...] = ()

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> Rules:
        if not isinstance(cfg, dict) or set(cfg) - {"allow", "http"}:
            raise ValueError("egress config holds only 'allow' and 'http' lists")
        allow, http = cfg.get("allow", []), cfg.get("http", [])
        if not isinstance(allow, list) or not isinstance(http, list):
            raise ValueError("egress 'allow' and 'http' must be lists of strings")
        if len(allow) + len(http) > MAX_RULES:
            raise ValueError(f"at most {MAX_RULES} egress rules")
        return cls(tuple(parse_allow(a) for a in allow), tuple(parse_http(h) for h in http))

    def connect_allowed(self, host: str, port: int) -> bool:
        name = _norm(host)
        return any(r.matches(name, port) for r in self.allow)

    def http_reason(self, method: str, host: str, path: str, port: int = 80) -> str:
        """ "" when allowed, else the refusal reason. HTTP rules cover port 80 only."""
        rules = [r for r in self.http if r.host == _norm(host)]
        if not rules:
            return "host_not_allowed"
        if port != 80:
            return "port_not_allowed"
        rules = [r for r in rules if method in r.methods]
        if not rules:
            return "method_not_allowed"
        if not _path_ok(path) or not any(path.startswith(r.prefix) for r in rules):
            return "path_not_allowed"
        return ""

    def http_allowed(self, method: str, host: str, path: str, port: int = 80) -> bool:
        return self.http_reason(method, host, path, port) == ""


# --- addresses -----------------------------------------------------------------------------------
def blocked_address(text: str) -> str | None:
    """None for a public address, else "metadata_address" or "internal_address"."""
    try:
        ip: Any = ipaddress.ip_address(text)
    except ValueError:
        return "internal_address"  # includes zone ids such as fe80::1%eth0
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif ip.sixtofour is not None:
            ip = ip.sixtofour
        elif ip.teredo is not None:
            ip = ip.teredo[1]
    if ip in _METADATA:
        return "metadata_address"
    if (ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local
            or ip.is_private or ip.is_reserved or not ip.is_global):  # fmt: skip
        return "internal_address"
    return None


def vet(addresses: Sequence[str]) -> tuple[list[str] | None, str]:
    """All answers must be public; one bad answer refuses the name (metadata wins)."""
    if not addresses:
        return None, "dns_failed"
    reasons = [blocked_address(a) for a in addresses]
    if "metadata_address" in reasons:
        return None, "metadata_address"
    if any(reasons):
        return None, "internal_address"
    return list(addresses), ""


def _resolve(host: str, port: int) -> list[str]:
    out: list[str] = []
    for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        addr = str(info[4][0])
        if addr not in out:
            out.append(addr)
    return out


# --- requests ------------------------------------------------------------------------------------
@dataclass
class Request:
    method: str
    host: str
    port: int
    path: str
    headers: list[tuple[str, str]] = field(default_factory=list)  # (lower-case name, value)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)  # names as sent


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _target_host(host: str, port: int, method: str) -> str:
    """A request's target host. An IP address is refused as `ip_literal` (only a real address is
    ever recorded); anything that is not a well-formed DNS name is a bad request, recorded without
    the host (it is the sandbox's own text and can carry data)."""
    if _is_ip(host):
        raise Refused("ip_literal", host, port, method)
    name = _norm(host)
    labels = name.split(".")
    if len(name) > 253 or not all(_LABEL.fullmatch(lb) for lb in labels):
        raise Refused("bad_request", method=method)
    if labels[-1].isdigit() or labels[-1].startswith("0x"):  # 2130706433, 127.1, 0x7f.1
        raise Refused("bad_request", method=method)
    return name


def parse_head(data: bytes) -> Request:
    """Parse a proxy request head (up to the blank line). Raises Refused."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise Refused("bad_request") from None
    lines = text.split("\r\n")
    # A bare CR or LF (or another control character) could start a second request upstream.
    if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for line in lines for c in line):
        raise Refused("bad_request")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not _TOKEN.fullmatch(parts[0]) or not parts[2].startswith("HTTP/1."):
        raise Refused("bad_request")
    method, target = parts[0].upper(), parts[1]
    headers: list[tuple[str, str]] = []
    raw: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep or not _TOKEN.fullmatch(name):
            raise Refused("bad_request", method=method)
        headers.append((name.lower(), value.strip()))
        raw.append((name, value.strip()))
    if method == "CONNECT":
        host, sep, port_text = target.rpartition(":")
        if not sep or not host or not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            raise Refused("bad_request", method=method)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
            if not _is_ip(host):
                raise Refused("bad_request", method=method)
        host = _target_host(host, int(port_text), method)
        return Request(method, host, int(port_text), "", headers, raw)
    if method not in HTTP_METHODS:
        raise Refused("method_not_allowed", method=method)
    if not target.lower().startswith("http://"):
        raise Refused("bad_request", method=method)
    try:
        sp = urlsplit(target)
        port = sp.port or 80
    except ValueError:
        raise Refused("bad_request", method=method) from None
    if "@" in sp.netloc or not sp.hostname:
        raise Refused("bad_request", method=method)
    if sp.netloc.startswith("[") and not _is_ip(sp.hostname):
        raise Refused("bad_request", method=method)
    host = _target_host(sp.hostname, port, method)
    lengths = [v.strip() for n, v in headers if n == "content-length"]  # every copy, not the last
    has_body = any(v not in ("", "0") for v in lengths)
    if has_body or any(n == "transfer-encoding" for n, _ in headers):
        raise Refused("request_body", host, port, method)
    path = (sp.path or "/") + ("?" + sp.query if sp.query else "")
    return Request(method, host, port, path, headers, raw)


def forward_head(req: Request) -> bytes:
    """The request as sent upstream: origin-form, checked Host, no proxy or hop-by-hop headers."""
    named = {t.strip().lower() for n, v in req.headers if n == "connection" for t in v.split(",")}
    host = req.host if req.port == 80 else f"{req.host}:{req.port}"
    lines = [f"{req.method} {req.path} HTTP/1.1", f"Host: {host}"]
    for name, value in req.raw_headers:
        low = name.lower()
        if low in _HOP or low in named or low.startswith("proxy-"):
            continue
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def log_host(host: str) -> str:
    return "".join(c if 33 <= ord(c) <= 126 else "?" for c in host.lower())[:255]


def capped_printer(
    write: Callable[[str], None], limit: int = LOG_LIMIT, priority_limit: int = PRIORITY_LIMIT
) -> Callable[[dict[str, Any]], None]:
    """At most `limit` ordinary lines, then one `log_cut`. Refusals in PRIORITY_REASONS have
    their own budget, so they are still written after the ordinary lines run out."""
    lock, count, urgent = threading.Lock(), [0], [0]

    def log(obj: dict[str, Any]) -> None:
        with lock:
            if obj.get("reason") in PRIORITY_REASONS and urgent[0] < priority_limit:
                urgent[0] += 1
                write(json.dumps(obj, sort_keys=True))
                return
            if count[0] < limit:
                write(json.dumps(obj, sort_keys=True))
            elif count[0] == limit:
                write(json.dumps({"ev": "log_cut"}))
            count[0] += 1

    return log


# --- server --------------------------------------------------------------------------------------
_REPLY = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}


def _reply(sock: socket.socket, code: int, reason: str) -> None:
    body = f"sentinel egress proxy: {reason}\n".encode("ascii")
    head = (f"HTTP/1.1 {code} {_REPLY[code]}\r\nContent-Type: text/plain\r\nContent-Length: "
            f"{len(body)}\r\nConnection: close\r\n\r\n").encode("ascii")  # fmt: skip
    try:
        sock.sendall(head + body)
    except OSError:
        pass


def _read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    """The whole head must arrive within HEAD_TIMEOUT_S (one slow byte at a time does not keep
    a connection slot)."""
    buf = b""
    deadline = time.monotonic() + HEAD_TIMEOUT_S
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEAD:
            raise Refused("bad_request")
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("head deadline")
        sock.settimeout(left)
        chunk = sock.recv(4096)
        if not chunk:
            raise Refused("bad_request")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    if len(head) > MAX_HEAD:
        raise Refused("bad_request")
    return head, rest


def _copy(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, addr: tuple[str, int], rules: Rules, log: Callable[[dict[str, Any]], None],
                 resolve: Callable[[str, int], list[str]], allow_loopback: bool,
                 port_map: dict[int, int]) -> None:  # fmt: skip
        self.rules, self.log, self.resolve = rules, log, resolve
        self.allow_loopback, self.port_map = allow_loopback, port_map
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(addr, _Handler)


class _Handler(socketserver.BaseRequestHandler):
    server: _Server

    def handle(self) -> None:
        if not self.server.slots.acquire(blocking=False):
            return  # too many connections: close without reading
        try:
            self._handle()
        finally:
            self.server.slots.release()

    def _refuse(self, reason: str, host: str, port: int, method: str, code: int = 403) -> None:
        self.server.log({"ev": "refuse", "reason": reason, "host": log_host(host), "port": port,
                         "method": method})  # fmt: skip
        _reply(self.request, 400 if reason == "bad_request" else code, reason)

    def _handle(self) -> None:
        sock: socket.socket = self.request
        sock.settimeout(HEAD_TIMEOUT_S)
        try:
            head, rest = _read_head(sock)
            req = parse_head(head)
        except Refused as r:
            self._refuse(r.reason, r.host, r.port, r.method)
            return
        except OSError:
            return
        rules = self.server.rules
        if req.method == "CONNECT":
            reason = "" if rules.connect_allowed(req.host, req.port) else "host_not_allowed"
        else:
            reason = rules.http_reason(req.method, req.host, req.path, req.port)
        if reason:
            self._refuse(reason, req.host, req.port, req.method)
            return
        try:  # only allowed names reach DNS
            addresses = self.server.resolve(req.host, req.port)
        except (OSError, UnicodeError, ValueError):
            addresses = []
        if self.server.allow_loopback and addresses == ["127.0.0.1"]:
            vetted: list[str] | None = addresses  # tests only: an upstream on loopback
        else:
            vetted, reason = vet(addresses)
        if vetted is None:
            if reason == "dns_failed":
                self.server.log({"ev": "error", "reason": reason, "port": req.port,
                                 "method": req.method})  # fmt: skip
                _reply(sock, 502, reason)
            else:
                self._refuse(reason, req.host, req.port, req.method)
            return
        kind = "connect" if req.method == "CONNECT" else "http"
        entry: dict[str, Any] = {"ev": "allow", "kind": kind, "port": req.port}
        if kind == "http":
            entry["method"] = req.method
        upstream = None
        for address in vetted:
            try:
                upstream = socket.create_connection(
                    (address, self.server.port_map.get(req.port, req.port)),
                    timeout=CONNECT_TIMEOUT_S,
                )
                break
            except OSError:
                continue
        if upstream is None:
            self.server.log({"ev": "error", "reason": "upstream_unreachable", "port": req.port,
                             "method": req.method})  # fmt: skip
            _reply(sock, 502, "upstream_unreachable")
            return
        self.server.log(entry)
        with upstream:
            sock.settimeout(IDLE_TIMEOUT_S)
            upstream.settimeout(IDLE_TIMEOUT_S)
            try:
                if kind == "connect":
                    sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    if rest:
                        upstream.sendall(rest)
                    t = threading.Thread(target=_copy, args=(sock, upstream), daemon=True)
                    t.start()
                    _copy(upstream, sock)
                    t.join(IDLE_TIMEOUT_S)
                else:
                    # One request per connection: later bytes from the client are never sent on.
                    upstream.sendall(forward_head(req))
                    _copy(upstream, sock)
            except OSError:
                pass


def make_server(
    addr: tuple[str, int],
    rules: Rules,
    *,
    log: Callable[[dict[str, Any]], None],
    resolve: Callable[[str, int], list[str]] | None = None,
    _test_allow_loopback: bool = False,
    _test_port_map: dict[int, int] | None = None,
) -> socketserver.ThreadingTCPServer:
    return _Server(
        addr, rules, log, resolve or _resolve, _test_allow_loopback, _test_port_map or {}
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(json.dumps({"ev": "fatal", "reason": "usage"}), flush=True)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as fh:
            rules = Rules.from_config(json.load(fh))
    except (OSError, ValueError):
        print(json.dumps({"ev": "fatal", "reason": "bad_config"}), flush=True)
        return 2
    log = capped_printer(lambda s: print(s, flush=True))
    server = make_server(("0.0.0.0", PROXY_PORT), rules, log=log)  # noqa: S104 - container only
    print(json.dumps({"ev": "ready", "rules": len(rules.allow) + len(rules.http)}), flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
