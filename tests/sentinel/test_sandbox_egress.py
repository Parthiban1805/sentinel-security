"""v0.7f item 4 sandbox egress (ADR-0026): per-run internal network, the proxy container and its
teardown, refusals as safe `egress_anomaly` events, settings and the CLI flag. Unit tests use fake
docker calls; the live test runs only with SENTINEL_SANDBOX_IMAGE set and Docker running."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from test_sandbox import IMAGE, LIVE_IMAGE, FakeDocker, _live_ready, repo  # noqa: F401

from sentinel import config, sandbox
from sentinel.cli import build_parser
from sentinel.events.schema import validate_event

EGRESS = sandbox.Egress(allow=("pypi.org",), http=("GET deb.debian.org /debian/",))
NOW = datetime(2026, 11, 10, tzinfo=UTC)


class FakeDockerCli:
    """Fake for the short docker calls (networks, proxy, logs, cleanup)."""

    def __init__(
        self, log_lines: list[dict[str, Any]] | None = None, fail: str = "", ready: bool = True
    ) -> None:
        self.calls: list[list[str]] = []
        self.fail = fail
        lines = ([{"ev": "ready", "rules": 2}] if ready else []) + (log_lines or [])
        self.logs = "\n".join(json.dumps(x) for x in lines) + "\nnot json\n"
        self.proxy_folder_files: list[str] = []

    def __call__(self, args: list[str]) -> tuple[int, str, str]:
        self.calls.append(args)
        if self.fail and self.fail in " ".join(args):
            return 1, "", "failed"
        if args[:3] == ["docker", "run", "-d"]:
            mount = next(a for a in args if a.startswith("type=bind"))
            folder = Path(mount.split("source=")[1].split(",target=")[0])
            self.proxy_folder_files = sorted(p.name for p in folder.iterdir())
            cfg = json.loads((folder / "config.json").read_text(encoding="utf-8"))
            assert cfg == {"allow": ["pypi.org"], "http": ["GET deb.debian.org /debian/"]}
        if args[:2] == ["docker", "logs"]:
            return 0, self.logs, ""
        return 0, "", ""


def _verbs(cli: FakeDockerCli) -> list[str]:
    return [" ".join(c[:3]) for c in cli.calls if c[:2] != ["docker", "logs"]]


def test_networked_run_uses_internal_network_and_proxy(repo: Path) -> None:  # noqa: F811
    fake, cli = FakeDocker(), FakeDockerCli()
    result = sandbox.run(
        repo, IMAGE, ["pip", "download", "x"], runner=fake, egress=EGRESS, docker=cli
    )
    name = result.run_name
    creates = [c for c in cli.calls if c[:3] == ["docker", "network", "create"]]
    assert "--internal" in creates[0] and creates[0][-1] == f"{name}-in"
    assert "--internal" not in creates[1] and creates[1][-1] == f"{name}-out"
    proxy_run = next(c for c in cli.calls if c[:3] == ["docker", "run", "-d"])
    joined = " ".join(proxy_run)
    for flag in ("--pull never", f"--network {name}-out", "--read-only", "--cap-drop ALL",
                 "--security-opt no-new-privileges", "--user 65534:65534", ",readonly"):  # fmt: skip
        assert flag in joined, flag
    assert "docker.sock" not in joined and "--privileged" not in joined
    assert proxy_run[-4:] == ["python3", "-I", "/proxy/egressproxy.py", "/proxy/config.json"]
    assert cli.proxy_folder_files == ["config.json", "egressproxy.py"]
    connect = [
        "docker",
        "network",
        "connect",
        "--alias",
        "egress-proxy",
        f"{name}-in",
        f"{name}-proxy",
    ]
    assert connect in cli.calls
    args = " ".join(fake.calls[0]["args"])
    assert f"--network {name}-in" in args and "--network none" not in args
    assert f"--dns {sandbox.SANDBOX_DNS}" in args
    assert f"HTTPS_PROXY={sandbox.PROXY_URL}" in args and "NO_PROXY=" in args
    # Torn down afterwards: the proxy, then both networks.
    assert _verbs(cli)[-3:] == ["docker rm -f", "docker network rm", "docker network rm"]
    assert result.egress is not None and result.egress.cleanup_ok


def test_offline_run_is_unchanged(repo: Path) -> None:  # noqa: F811
    fake, cli = FakeDocker(), FakeDockerCli()
    result = sandbox.run(repo, IMAGE, ["true"], runner=fake, docker=cli)
    assert cli.calls == [] and result.egress is None
    assert "--network none" in " ".join(fake.calls[0]["args"])
    assert "--dns" not in fake.calls[0]["args"]


def test_allow_net_needs_rules_and_valid_rules(repo: Path) -> None:  # noqa: F811
    fake, cli = FakeDocker(), FakeDockerCli()
    with pytest.raises(sandbox.SandboxError, match="needs"):
        sandbox.run(repo, IMAGE, ["true"], runner=fake, egress=sandbox.Egress(), docker=cli)
    with pytest.raises(sandbox.SandboxError, match="sandbox.egress"):
        sandbox.run(repo, IMAGE, ["true"], runner=fake,
                    egress=sandbox.Egress(allow=("169.254.169.254",)), docker=cli)  # fmt: skip
    assert fake.calls == [] and cli.calls == []


@pytest.mark.parametrize("step", ["--internal", "docker run -d", "network connect"])
def test_proxy_start_failure_cleans_up_and_runs_nothing(repo: Path, step: str) -> None:  # noqa: F811
    fake, cli = FakeDocker(), FakeDockerCli(fail=step)
    with pytest.raises(sandbox.SandboxError, match="cannot"):
        sandbox.run(repo, IMAGE, ["true"], runner=fake, egress=EGRESS, docker=cli)
    assert fake.calls == []
    assert any(c[:3] == ["docker", "rm", "-f"] for c in cli.calls)


def test_proxy_that_never_gets_ready_fails_closed(
    repo: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox, "READY_WAIT_S", 0)
    fake = FakeDocker()
    with pytest.raises(sandbox.SandboxError, match="python3"):
        sandbox.run(
            repo, IMAGE, ["true"], runner=fake, egress=EGRESS, docker=FakeDockerCli(ready=False)
        )
    fatal = FakeDockerCli(log_lines=[{"ev": "fatal", "reason": "bad_config"}], ready=False)
    with pytest.raises(sandbox.SandboxError, match="configuration"):
        sandbox.run(repo, IMAGE, ["true"], runner=fake, egress=EGRESS, docker=fatal)
    assert fake.calls == []


def test_refusals_become_safe_events(repo: Path) -> None:  # noqa: F811
    hidden = "q" + "7" * 30  # stands in for data hidden in a host name
    lines = [
        {"ev": "allow", "kind": "connect", "host": "pypi.org", "port": 443},
        {"ev": "refuse", "reason": "host_not_allowed", "host": f"{hidden}.attacker.test",
         "port": 443, "method": "CONNECT"},
        {"ev": "refuse", "reason": "ip_literal", "host": "169.254.169.254", "port": 80,
         "method": "GET"},
        {"ev": "refuse", "reason": "ip_literal", "host": "151.101.0.223", "port": 443,
         "method": "CONNECT"},
        {"ev": "refuse", "reason": "internal_address", "host": "pypi.org", "port": 443,
         "method": "CONNECT"},
        {"ev": "error", "reason": "dns_failed", "host": "pypi.org", "port": 443},
    ]  # fmt: skip
    result = sandbox.run(repo, IMAGE, ["true"], runner=FakeDocker(), egress=EGRESS,
                         docker=FakeDockerCli(log_lines=lines))  # fmt: skip
    assert result.egress is not None
    assert (result.egress.allowed, len(result.egress.refused), result.egress.errors) == (1, 4, 1)
    events = sandbox.egress_events(result, repo, NOW)
    assert len(events) == 4
    for e in events:
        validate_event(e)
        assert e["event_type"] == "egress_anomaly" and e["source"] == "sandbox_proxy"
    assert hidden not in json.dumps(events)  # only the suffix and a hash of the name are kept
    # Most severe first: metadata (high), internal (medium), then the rest in log order.
    assert events[0]["attributes"]["target"] == "metadata" and events[0]["severity"] == "high"
    assert events[0]["attributes"]["host"] == "169.254.169.254"
    assert events[1]["severity"] == "medium"
    assert events[1]["attributes"]["host"] == "pypi.org"  # under an allowed domain: shown
    # Not under an allowed domain: only a hash of the second label and the last label.
    assert events[2]["attributes"]["host"].startswith("h-") and events[2]["attributes"][
        "host"
    ].endswith(".test")
    assert "attacker" not in json.dumps(events)
    assert events[3]["attributes"]["host"] == "[public address]"


def test_many_refusals_are_summarised(repo: Path) -> None:  # noqa: F811
    n = sandbox.MAX_EGRESS_EVENTS + 7
    lines = [{"ev": "refuse", "reason": "host_not_allowed", "host": f"h{i}.example.test",
              "port": 443, "method": "CONNECT"} for i in range(n)] + [{"ev": "log_cut"}]  # fmt: skip
    result = sandbox.run(repo, IMAGE, ["true"], runner=FakeDocker(), egress=EGRESS,
                         docker=FakeDockerCli(log_lines=lines))  # fmt: skip
    events = sandbox.egress_events(result, repo, NOW)
    assert len(events) == sandbox.MAX_EGRESS_EVENTS + 1
    assert events[-1]["attributes"]["more_refusals"] == 7 and events[-1]["attributes"]["log_cut"]
    assert (
        sandbox.egress_events(sandbox.run(repo, IMAGE, ["true"], runner=FakeDocker()), repo, NOW)
        == []
    )


def test_cleanup_failure_is_reported(repo: Path) -> None:  # noqa: F811
    result = sandbox.run(repo, IMAGE, ["true"], runner=FakeDocker(), egress=EGRESS,
                         docker=FakeDockerCli(fail="network rm"))  # fmt: skip
    assert result.egress is not None and not result.egress.cleanup_ok
    assert "could not remove" in result.stderr


def test_egress_settings_are_validated(tmp_path: Path) -> None:
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text(
        f'[sandbox]\nimage = "{IMAGE}"\n[sandbox.egress]\n'
        'allow = ["pypi.org", "*.pythonhosted.org"]\nhttp = ["GET deb.debian.org /debian/"]\n',
        encoding="utf-8",
    )
    s = config.load(cfg).sandbox
    assert s.egress_allow == ("pypi.org", "*.pythonhosted.org")
    assert s.egress_http == ("GET deb.debian.org /debian/",)
    for bad in ('allow = ["10.0.0.1"]', 'allow = ["metadata.google.internal"]', 'allow = "pypi.org"',
                'http = ["POST deb.debian.org /"]', "other = 1"):  # fmt: skip
        cfg.write_text(f"[sandbox]\n[sandbox.egress]\n{bad}\n", encoding="utf-8")
        with pytest.raises(ValueError, match="sandbox.egress"):
            config.load(cfg)


def test_cli_allow_net_flag() -> None:
    args = build_parser().parse_args(["sandbox", "run", "--allow-net", "--", "true"])
    assert args.allow_net is True
    assert build_parser().parse_args(["sandbox", "run", "--", "true"]).allow_net is False


@pytest.mark.parametrize(
    ("command", "expected", "rule"),
    [
        ("sentinel sandbox run --allow-net -- pytest -q", "ask", "BG-30"),
        ("uv run sentinel sandbox run --timeout 60 --allow-net -- pip download x", "ask", "BG-30"),
        ("sentinel sandbox run -- pytest -q", "allow", None),
        ("sentinel sandbox check", "allow", None),
    ],
)
def test_gateway_asks_for_a_networked_sandbox(
    tmp_path: Path, command: str, expected: str, rule: str | None
) -> None:
    from test_gateway import decide

    d = decide(tmp_path, "Bash", command=command)
    assert d.decision == expected, command
    if rule:
        assert d.rule == rule


@pytest.mark.skipif(not _live_ready(), reason="set SENTINEL_SANDBOX_IMAGE and start Docker")
def test_live_egress_proxy_allows_only_listed_hosts(repo: Path) -> None:  # noqa: F811
    """Live (the allowed host needs internet): an allowed HTTPS host is reached through the proxy;
    another host, the metadata address and direct connections are refused; external names do not
    resolve inside the sandbox."""
    probe = (
        "import socket, urllib.request\n"
        "def get(url):\n"
        "    try:\n"
        "        return urllib.request.urlopen(url, timeout=20).status\n"
        "    except Exception as e:\n"
        "        return type(e).__name__ + ':' + str(getattr(e, 'code', ''))\n"
        "print('allowed', get('https://pypi.org/simple/pip/'))\n"
        "print('other', get('https://example.com/'))\n"
        "print('metadata', get('http://169.254.169.254/latest/meta-data/'))\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 443), 5); print('direct', 'open')\n"
        "except OSError:\n"
        "    print('direct', 'blocked')\n"
        "try:\n"
        "    socket.getaddrinfo('example.com', 443); print('dns', 'resolves')\n"
        "except OSError:\n"
        "    print('dns', 'blocked')\n"
        # The Docker host: its name, and the internal network's gateway address if one is routed.
        "def reach(host, port):\n"
        "    try:\n"
        "        socket.create_connection((host, port), 3); return 'open'\n"
        "    except OSError:\n"
        "        return 'blocked'\n"
        "print('dockerhost', reach('host.docker.internal', 80))\n"
        "gw = None\n"
        "for line in open('/proc/net/route').read().splitlines()[1:]:\n"
        "    f = line.split()\n"
        "    if f[1] == '00000000' and f[2] != '00000000':\n"
        "        gw = socket.inet_ntoa(bytes.fromhex(f[2])[::-1])\n"
        "print('gateway', 'none' if gw is None else reach(gw, 80))\n"
    )
    result = sandbox.run(repo, LIVE_IMAGE, ["python", "-c", probe], sandbox.Limits(timeout_s=180),
                         egress=sandbox.Egress(allow=("pypi.org",)))  # fmt: skip
    assert result.exit_code == 0, result.stderr
    assert "allowed 200" in result.stdout
    assert "other 200" not in result.stdout and "metadata 200" not in result.stdout
    assert "direct blocked" in result.stdout
    assert "dns blocked" in result.stdout
    assert "dockerhost blocked" in result.stdout
    assert "gateway none" in result.stdout or "gateway blocked" in result.stdout
    assert result.egress is not None and len(result.egress.refused) >= 2
