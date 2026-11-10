"""v0.7f item 4 egress proxy (ADR-0026): rule parsing, host matching, address vetting, request
parsing and the proxy's decisions. Network-free: resolution is injected, and the end-to-end test
uses an upstream server on 127.0.0.1 with a test-only flag that permits loopback."""

import json
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sentinel import egressproxy as ep

# --- rules -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "pattern", "ports"),
    [
        ("pypi.org", "pypi.org", (443,)),
        ("PyPI.org.", "pypi.org", (443,)),
        ("files.pythonhosted.org:443", "files.pythonhosted.org", (443,)),
        ("*.githubusercontent.com", "*.githubusercontent.com", (443,)),
        ("registry.example.test:8443", "registry.example.test", (8443,)),
    ],
)
def test_allow_entry_parses(entry: str, pattern: str, ports: tuple[int, ...]) -> None:
    assert ep.parse_allow(entry) == ep.AllowRule(pattern, ports)


@pytest.mark.parametrize(
    "entry",
    [
        "",
        "*",
        "*.com",  # a wildcard must keep at least two labels
        "a.*.example.com",
        "10.0.0.1",
        "169.254.169.254",
        "[::1]",
        "::1",
        "localhost",  # single label
        "pypi.org:0",
        "pypi.org:70000",
        "pypi.org:http",
        "under_score.example.com",
        "http://pypi.org",
        "pypi.org/simple",
        "-bad.example.com",
        "a" * 64 + ".example.com",
        "x.example.com" + ".a" * 130,
        "pypi.org:443:443",
        "metadata.google.internal",  # cloud metadata name
    ],
)
def test_allow_entry_refused(entry: str) -> None:
    with pytest.raises(ValueError):
        ep.parse_allow(entry)


def test_http_rule_parses_and_defaults() -> None:
    rule = ep.parse_http("GET deb.debian.org /debian/")
    assert rule == ep.HttpRule(("GET",), "deb.debian.org", "/debian/")
    assert ep.parse_http("GET,HEAD deb.debian.org /") == ep.HttpRule(
        ("GET", "HEAD"), "deb.debian.org", "/"
    )


@pytest.mark.parametrize(
    "entry",
    [
        "POST deb.debian.org /",
        "GET deb.debian.org debian/",  # path must start with /
        "GET deb.debian.org /a/../b",
        "GET deb.debian.org /%2e%2e/",
        "GET *.debian.org /",  # no wildcards for plain HTTP
        "GET 10.0.0.1 /",
        "GET deb.debian.org",
        "GET deb.debian.org / extra",
        "GET deb.debian.org:80 /",  # port 80 only, never written
    ],
)
def test_http_rule_refused(entry: str) -> None:
    with pytest.raises(ValueError):
        ep.parse_http(entry)


def test_rules_from_config_rejects_too_many() -> None:
    with pytest.raises(ValueError):
        ep.Rules.from_config({"allow": [f"h{i}.example.com" for i in range(ep.MAX_RULES + 1)]})
    with pytest.raises(ValueError):
        ep.Rules.from_config({"allow": "pypi.org"})  # must be a list
    with pytest.raises(ValueError):
        ep.Rules.from_config({"allow": [], "http": [], "extra": 1})


# --- host matching -----------------------------------------------------------------------------
RULES = ep.Rules.from_config(
    {
        "allow": ["pypi.org", "*.githubusercontent.com", "registry.example.test:8443"],
        "http": ["GET,HEAD deb.debian.org /debian/"],
    }
)


@pytest.mark.parametrize(
    ("host", "port", "ok"),
    [
        ("pypi.org", 443, True),
        ("PYPI.ORG.", 443, True),
        ("pypi.org", 80, False),
        ("evil-pypi.org", 443, False),
        ("pypi.org.evil.test", 443, False),
        ("raw.githubusercontent.com", 443, True),
        ("a.b.githubusercontent.com", 443, True),
        ("githubusercontent.com", 443, False),  # the wildcard does not cover the bare name
        ("registry.example.test", 8443, True),
        ("registry.example.test", 443, False),
        ("deb.debian.org", 443, False),  # an HTTP rule does not allow CONNECT
    ],
)
def test_connect_allowed(host: str, port: int, ok: bool) -> None:
    assert RULES.connect_allowed(host, port) is ok


@pytest.mark.parametrize(
    ("method", "host", "path", "ok"),
    [
        ("GET", "deb.debian.org", "/debian/dists/stable/Release", True),
        ("HEAD", "deb.debian.org", "/debian/", True),
        ("GET", "deb.debian.org", "/debian", False),
        ("GET", "deb.debian.org", "/other/", False),
        ("GET", "deb.debian.org", "/debian/../etc/passwd", False),
        ("GET", "deb.debian.org", "/debian/%2E%2E/x", False),
        ("GET", "deb.debian.org", "/debian/a\\..\\b", False),
        ("POST", "deb.debian.org", "/debian/", False),
        ("GET", "pypi.org", "/simple/", False),  # CONNECT-only host
    ],
)
def test_http_allowed(method: str, host: str, path: str, ok: bool) -> None:
    assert RULES.http_allowed(method, host, path) is ok


# --- address vetting ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("ip", "reason"),
    [
        ("169.254.169.254", "metadata_address"),
        ("fd00:ec2::254", "metadata_address"),
        ("100.100.100.200", "metadata_address"),
        ("127.0.0.1", "internal_address"),
        ("10.1.2.3", "internal_address"),
        ("172.17.0.1", "internal_address"),
        ("192.168.1.1", "internal_address"),
        ("100.64.0.1", "internal_address"),
        ("169.254.1.1", "internal_address"),
        ("0.0.0.0", "internal_address"),  # noqa: S104 - an address under test, not a bind
        ("224.0.0.1", "internal_address"),
        ("255.255.255.255", "internal_address"),
        ("::1", "internal_address"),
        ("fe80::1", "internal_address"),
        ("fc00::1", "internal_address"),
        ("::ffff:169.254.169.254", "metadata_address"),
        ("::ffff:10.0.0.1", "internal_address"),
        ("64:ff9b::a9fe:a9fe", "metadata_address"),  # NAT64 of 169.254.169.254
        ("2002:a9fe:a9fe::", "metadata_address"),  # 6to4 of 169.254.169.254
        ("192.0.2.1", "internal_address"),  # documentation range
        ("not-an-ip", "internal_address"),
    ],
)
def test_blocked_addresses(ip: str, reason: str) -> None:
    assert ep.blocked_address(ip) == reason


@pytest.mark.parametrize("ip", ["151.101.0.223", "140.82.112.3", "2a04:4e42::223"])
def test_public_addresses_pass(ip: str) -> None:
    assert ep.blocked_address(ip) is None


def test_vet_refuses_mixed_answers() -> None:
    # One internal address among public ones refuses the whole name (DNS answer games).
    assert ep.vet(["151.101.0.223", "10.0.0.5"]) == (None, "internal_address")
    assert ep.vet(["151.101.0.223", "169.254.169.254"]) == (None, "metadata_address")
    assert ep.vet([]) == (None, "dns_failed")
    assert ep.vet(["151.101.0.223", "151.101.64.223"]) == (["151.101.0.223", "151.101.64.223"], "")


# --- request parsing ---------------------------------------------------------------------------
def test_parse_connect() -> None:
    req = ep.parse_head(b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n")
    assert (req.method, req.host, req.port, req.path) == ("CONNECT", "pypi.org", 443, "")


def test_parse_absolute_get() -> None:
    req = ep.parse_head(
        b"GET http://deb.debian.org/debian/x?y=1 HTTP/1.1\r\nHost: deb.debian.org\r\n"
        b"Proxy-Authorization: x\r\n\r\n"
    )
    assert (req.method, req.host, req.port, req.path) == (
        "GET",
        "deb.debian.org",
        80,
        "/debian/x?y=1",
    )
    assert ("proxy-authorization", "x") in req.headers


@pytest.mark.parametrize(
    ("head", "reason"),
    [
        (b"GET /relative HTTP/1.1\r\n\r\n", "bad_request"),
        (b"GET https://pypi.org/ HTTP/1.1\r\n\r\n", "bad_request"),
        (b"CONNECT pypi.org HTTP/1.1\r\n\r\n", "bad_request"),
        (b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n", "ip_literal"),
        (b"CONNECT 10.0.0.1:443 HTTP/1.1\r\n\r\n", "ip_literal"),
        (b"GET http://169.254.169.254/latest/ HTTP/1.1\r\n\r\n", "ip_literal"),
        (b"GET http://user:pw@deb.debian.org/ HTTP/1.1\r\n\r\n", "bad_request"),
        (b"BREW http://deb.debian.org/ HTTP/1.1\r\n\r\n", "method_not_allowed"),
        (
            b"POST http://deb.debian.org/ HTTP/1.1\r\nContent-Length: 3\r\n\r\n",
            "method_not_allowed",
        ),
        (b"GET http://deb.debian.org/ HTTP/1.1\r\nContent-Length: 3\r\n\r\n", "request_body"),
        (
            b"GET http://deb.debian.org/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "request_body",
        ),
        (b"\xff\xfe\r\n\r\n", "bad_request"),
        (b"GET http://deb.debian.org/ HTTP/1.1\r\nbad header line\r\n\r\n", "bad_request"),
    ],
)
def test_parse_refusals(head: bytes, reason: str) -> None:
    with pytest.raises(ep.Refused) as exc:
        ep.parse_head(head)
    assert exc.value.reason == reason


def test_forward_head_strips_proxy_and_hop_headers() -> None:
    req = ep.parse_head(
        b"GET http://deb.debian.org/debian/ HTTP/1.1\r\nHost: evil.test\r\nProxy-Authorization: x\r\n"
        b"Proxy-Connection: keep-alive\r\nConnection: keep-alive, X-Foo\r\nX-Foo: 1\r\nAccept: */*\r\n\r\n"
    )
    out = ep.forward_head(req).decode()
    assert out.startswith("GET /debian/ HTTP/1.1\r\n")
    assert "Host: deb.debian.org\r\n" in out
    assert "Connection: close\r\n" in out
    assert "evil.test" not in out and "Proxy-" not in out and "X-Foo" not in out
    assert "Accept: */*\r\n" in out and out.endswith("\r\n\r\n")


def test_safe_host_for_log() -> None:
    assert ep.log_host("PyPI.org") == "pypi.org"
    assert len(ep.log_host("a" * 1000)) <= 255
    assert ep.log_host("bad\x00host\nx") == "bad?host?x"


# --- end to end over loopback ------------------------------------------------------------------
class _Upstream(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = json.dumps({"path": self.path, "host": self.headers.get("Host")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def upstream() -> Iterator[int]:
    server = HTTPServer(("127.0.0.1", 0), _Upstream)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def proxy(upstream: int) -> Iterator[tuple[int, list[dict[str, object]]]]:
    logged: list[dict[str, object]] = []
    rules = ep.Rules.from_config(
        {"allow": ["up.example.test"], "http": ["GET up.example.test /ok/"]}
    )

    def resolve(host: str, port: int) -> list[str]:
        return ["127.0.0.1"] if host == "up.example.test" else ["10.0.0.9"]

    server = ep.make_server(
        ("127.0.0.1", 0), rules, log=logged.append, resolve=resolve, _test_allow_loopback=True,
        _test_port_map={80: upstream, 443: upstream},
    )  # fmt: skip
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server.server_address[1], logged
    server.shutdown()
    server.server_close()


def _ask(port: int, raw: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(raw)
        chunks = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def test_proxy_forwards_allowed_http(proxy: tuple[int, list[dict[str, object]]]) -> None:
    port, logged = proxy
    out = _ask(port, b"GET http://up.example.test/ok/x HTTP/1.1\r\nHost: other\r\n\r\n")
    assert out.startswith(b"HTTP/1.0 200") or out.startswith(b"HTTP/1.1 200")
    body = json.loads(out.split(b"\r\n\r\n", 1)[1])
    assert body == {"path": "/ok/x", "host": "up.example.test"}
    assert logged[-1]["ev"] == "allow"


def test_proxy_refuses_and_logs(proxy: tuple[int, list[dict[str, object]]]) -> None:
    port, logged = proxy
    out = _ask(port, b"GET http://up.example.test/secret HTTP/1.1\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 403")
    assert logged[-1] == {"ev": "refuse", "reason": "path_not_allowed", "host": "up.example.test",
                          "port": 80, "method": "GET"}  # fmt: skip
    out = _ask(port, b"CONNECT other.example.test:443 HTTP/1.1\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 403")
    assert logged[-1]["reason"] == "host_not_allowed"


def test_proxy_refuses_internal_resolution(upstream: int) -> None:
    logged: list[dict[str, object]] = []
    rules = ep.Rules.from_config({"allow": ["up.example.test"]})
    server = ep.make_server(
        ("127.0.0.1", 0), rules, log=logged.append, resolve=lambda h, p: ["169.254.169.254"]
    )
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        out = _ask(server.server_address[1], b"CONNECT up.example.test:443 HTTP/1.1\r\n\r\n")
    finally:
        server.shutdown()
        server.server_close()
    assert out.startswith(b"HTTP/1.1 403")
    assert logged[-1]["reason"] == "metadata_address"


def test_proxy_does_not_resolve_refused_names(upstream: int) -> None:
    """A name that is not allowed must never reach DNS (a lookup alone can carry data out)."""
    looked_up: list[str] = []
    rules = ep.Rules.from_config({"allow": ["up.example.test"]})

    def resolve(host: str, port: int) -> list[str]:
        looked_up.append(host)
        return ["151.101.0.223"]

    server = ep.make_server(("127.0.0.1", 0), rules, log=lambda e: None, resolve=resolve)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        _ask(
            server.server_address[1], b"CONNECT data-in-a-label.attacker.test:443 HTTP/1.1\r\n\r\n"
        )
    finally:
        server.shutdown()
        server.server_close()
    assert looked_up == []


def test_proxy_connect_tunnels(proxy: tuple[int, list[dict[str, object]]]) -> None:
    port, logged = proxy
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(b"CONNECT up.example.test:443 HTTP/1.1\r\n\r\n")
        head = b""
        while b"\r\n\r\n" not in head:
            head += s.recv(1)
        assert head.startswith(b"HTTP/1.1 200")
        s.sendall(b"GET /tunnel HTTP/1.1\r\nHost: up.example.test\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    assert b'"/tunnel"' in data
    assert logged[-1] == {"ev": "allow", "kind": "connect", "port": 443}  # no host: m5


def test_log_is_capped(proxy: tuple[int, list[dict[str, object]]]) -> None:
    lines: list[str] = []
    log = ep.capped_printer(lambda s: lines.append(s), limit=3)
    for i in range(10):
        log({"ev": "refuse", "n": i})
    assert len(lines) == 4
    assert json.loads(lines[-1]) == {"ev": "log_cut"}


def test_module_is_standalone() -> None:
    """The proxy file runs inside the container on its own: stdlib imports only."""
    src = Path(ep.__file__).read_text(encoding="utf-8")
    assert "from sentinel" not in src and "import sentinel" not in src
