"""Regression tests for the 2026-11-10 security review of the sandbox egress allow-list
(ADR-0026). Canary values are generated at runtime and are obviously fake."""

import json
import secrets
import time
from pathlib import Path

import pytest
from test_gateway import decide

from sentinel import egressproxy as ep
from sentinel import sandbox
from sentinel.cli import build_parser


def _canary() -> str:
    return "canary" + secrets.token_hex(10)


# --- C1: a secret must not be stored through an ip_literal refusal --------------------------------
@pytest.mark.parametrize("form", ["[{c}]:443", "{c}.0:443", "{c}.0x1:443", "[{c}.example]:443"])
def test_fake_ip_forms_are_bad_requests_without_the_host(form: str) -> None:
    c = _canary()
    with pytest.raises(ep.Refused) as exc:
        ep.parse_head(f"CONNECT {form.format(c=c)} HTTP/1.1\r\n\r\n".encode())
    assert exc.value.reason == "bad_request" and exc.value.host == ""


def test_safe_refusal_never_keeps_a_non_address_host() -> None:
    c = _canary()
    for host in (c, f"{c}.0", f"{c}.attacker.test"):
        safe = sandbox._safe_refusal({"reason": "ip_literal", "host": host, "port": 443})
        assert c not in json.dumps(safe), host
    kept = sandbox._safe_refusal({"reason": "ip_literal", "host": "10.0.0.1", "port": 443})
    assert kept["host"] == "10.0.0.1" and kept["target"] == "internal"


def test_refused_names_keep_only_allowed_domains(tmp_path: Path) -> None:
    known = sandbox.Egress(
        allow=("*.pythonhosted.org",), http=("GET deb.debian.org /d/",)
    ).known_domains()
    assert known == {"pythonhosted.org", "debian.org"}
    c = _canary()
    assert sandbox._host_suffix(f"{c}.pythonhosted.org", known) == "pythonhosted.org"
    hashed = sandbox._host_suffix(f"x.{c}.com", known)
    assert c not in hashed and hashed.startswith("h-") and hashed.endswith(".com")
    assert sandbox._host_suffix(f"a.b.{c}", known).endswith(".?")  # odd last label: not kept


# --- C2: BG-30 cannot be dodged by abbreviation or quoting ----------------------------------------
@pytest.mark.parametrize(
    "command",
    [
        "sentinel sandbox run --allow -- pytest -q",
        "sentinel sandbox run --allow-n -- pytest -q",
        'sentinel sandbox run --allow-ne"t" -- pytest -q',
        "sentinel sandbox run --allow-ne`t -- pytest -q",
        "sentinel sandbox run '--allow-net' -- pytest -q",
        "sentinel sandbox run --allow-net=1 -- pytest -q",
        "uv run sentinel sandbox run --timeout 30 --al -- pytest -q",
    ],
)
def test_bg30_catches_every_form(tmp_path: Path, command: str) -> None:
    d = decide(tmp_path, "Bash", command=command)
    assert (d.decision, d.rule) == ("ask", "BG-30"), command


def test_cli_refuses_abbreviated_options(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["sandbox", "run", "--allow", "--", "true"])
    with pytest.raises(SystemExit):
        build_parser().parse_args(["sandbox", "run", "--time", "5", "--", "true"])
    assert build_parser().parse_args(["sandbox", "run", "--allow-net", "--", "true"]).allow_net


# --- M1: plain-HTTP rules are port 80 only ----------------------------------------------------------
def test_http_rule_ignores_other_ports() -> None:
    rules = ep.Rules.from_config({"http": ["GET deb.debian.org /debian/"]})
    assert rules.http_reason("GET", "deb.debian.org", "/debian/x", 80) == ""
    assert rules.http_reason("GET", "deb.debian.org", "/debian/x", 22) == "port_not_allowed"
    req = ep.parse_head(b"GET http://deb.debian.org:22/debian/ HTTP/1.1\r\n\r\n")
    assert rules.http_reason(req.method, req.host, req.path, req.port) == "port_not_allowed"


# --- M2: no request smuggling through bare LF/CR or duplicate lengths -----------------------------
@pytest.mark.parametrize(
    "head",
    [
        b"GET http://deb.debian.org/debian/ HTTP/1.1\r\nX: a\n\nGET /other HTTP/1.1\nHost: other",
        b"GET http://deb.debian.org/debian/ HTTP/1.1\r\nX: a\rb",
        b"GET http://deb.debian.org/debian/ HTTP/1.1\r\nX: a\x00b",
        b"GET http://deb.debian.org/debian/\n HTTP/1.1",
    ],
)
def test_control_characters_are_refused(head: bytes) -> None:
    with pytest.raises(ep.Refused) as exc:
        ep.parse_head(head)
    assert exc.value.reason == "bad_request"


def test_tab_in_a_header_value_is_fine() -> None:
    req = ep.parse_head(b"GET http://deb.debian.org/debian/ HTTP/1.1\r\nUser-Agent: a\tb\r\n")
    assert ("user-agent", "a\tb") in req.headers


def test_every_content_length_copy_is_checked() -> None:
    with pytest.raises(ep.Refused) as exc:
        ep.parse_head(
            b"GET http://deb.debian.org/debian/ HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 0\r\n"
        )
    assert exc.value.reason == "request_body"


# --- M3: a flood of harmless refusals cannot hide a metadata probe --------------------------------
def test_priority_refusals_are_logged_after_the_cap() -> None:
    lines: list[str] = []
    log = ep.capped_printer(lines.append, limit=3)
    for i in range(10):
        log({"ev": "refuse", "reason": "host_not_allowed", "n": i})
    log({"ev": "refuse", "reason": "metadata_address", "host": "169.254.169.254"})
    assert json.loads(lines[-1])["reason"] == "metadata_address"
    assert {"ev": "log_cut"} in [json.loads(x) for x in lines]


def test_cut_log_summary_is_at_least_medium(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    report = sandbox.EgressReport(refused=[], log_cut=True)
    result = sandbox.Result(0, "", "", False, None, 0, egress=report, run_name="r1")
    events = sandbox.egress_events(result, tmp_path, datetime(2026, 11, 10, tzinfo=UTC))
    assert len(events) == 1 and events[0]["severity"] == "medium"


# --- m2: malformed names are refused, never resolved ----------------------------------------------
@pytest.mark.parametrize(
    "host", ["x\x01.example.test", "a..example.test", "-a.example.test", "a_b.test"]
)
def test_malformed_names_are_bad_requests(host: str) -> None:
    with pytest.raises(ep.Refused) as exc:
        ep.parse_head(f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode("latin-1"))
    assert exc.value.reason == "bad_request"


# --- m4: one deadline for the whole head ----------------------------------------------------------
class _SlowSock:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, t: float) -> None:
        self.timeouts.append(t)

    def recv(self, n: int) -> bytes:
        time.sleep(0.05)
        return b"G"


def test_head_deadline_covers_the_whole_head(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ep, "HEAD_TIMEOUT_S", 0.3)
    sock = _SlowSock()
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        ep._read_head(sock)  # type: ignore[arg-type]
    assert time.monotonic() - start < 2
    assert sock.timeouts == sorted(sock.timeouts, reverse=True)  # shrinking budget


# --- m3, m5, m6 --------------------------------------------------------------------------------------
def test_proxy_limits_fit_its_connection_cap(tmp_path: Path) -> None:
    session = sandbox._ProxySession("n-in", "n-out", "n-proxy", tmp_path)
    args = sandbox.proxy_args("python@sha256:" + "a" * 64, session)
    pids = int(args[args.index("--pids-limit") + 1])
    assert pids > 2 * ep.MAX_CONNECTIONS + 1
    assert "nofile=1024:1024" in args


def test_http_prefix_must_end_with_a_slash() -> None:
    with pytest.raises(ValueError):
        ep.parse_http("GET deb.debian.org /debian")
    assert ep.parse_http("GET deb.debian.org /debian/").prefix == "/debian/"
