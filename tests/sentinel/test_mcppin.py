"""MCP pinning and rug-pull detection (v0.7e F2, ADR-0028; S12). Fake values at runtime."""

import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from sentinel import mcppin

ROOT = Path(__file__).resolve().parents[2]
KEY = secrets.token_bytes(32)


def test_the_hook_copy_is_identical() -> None:
    copy = ROOT / "docs" / "patches" / "agent-gateway" / "_mcppin.py"
    assert copy.read_bytes() == (ROOT / "sentinel" / "mcppin.py").read_bytes()


def server(**extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"command": "npx", "args": ["-y", "@acme/mcp-docs@1.4.2"]}
    base.update(extra)
    return base


# the hash ----------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "change",
    [
        {"args": ["-y", "@acme/mcp-docs@1.4.3"]},  # a new version
        {"args": ["-y", "@acme/mcp-docs@1.4.2", "--allow-write"]},  # new argument
        {"command": "bunx"},
        {"url": "https://mcp.example.org/v2"},
        {"env": {"NEW_VAR": "x"}},  # a new env NAME counts
        {"headers": {"X-Extra": "x"}},
        {"cwd": "servers/docs"},
    ],
)
def test_any_launch_change_changes_the_hash(change: dict[str, Any]) -> None:
    assert mcppin.config_hash(server(**change), KEY) != mcppin.config_hash(server(), KEY)


@pytest.mark.parametrize(
    "change",
    [
        {"env": {"NODE_OPTIONS": "--require ./evil.js"}},  # env-based rug pulls (review #5)
        {"env": {"NPM_CONFIG_REGISTRY": "https://registry.example.org"}},
        {"headers": {"Authorization": "Bearer ${OTHER}"}},
        {"timeout": 5},  # any other launch key
    ],
)
def test_env_and_header_values_and_other_keys_change_the_hash(change: dict[str, Any]) -> None:
    assert mcppin.config_hash(server(**change), KEY) != mcppin.config_hash(server(), KEY)


def test_the_hash_is_domain_separated_from_credential_fingerprints() -> None:
    import hashlib
    import hmac

    plain = hmac.new(KEY, mcppin.canonical(server()).encode(), hashlib.sha256).hexdigest()[:32]
    assert mcppin.config_hash(server(), KEY) != plain


def test_the_hash_is_keyed() -> None:
    other = secrets.token_bytes(32)
    assert mcppin.config_hash(server(), KEY) != mcppin.config_hash(server(), other)
    assert len(mcppin.config_hash(server(), KEY)) == 32


# drift ---------------------------------------------------------------------------------------------
def setup(tmp_path: Path, servers: dict[str, Any], pins: dict[str, Any] | None) -> tuple[str, str]:
    workspace, home = tmp_path, tmp_path / ".sentinel"
    home.mkdir()
    (home / "fingerprint.key").write_bytes(KEY)
    (workspace / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    if pins is not None:
        (home / "mcp-allowlist.json").write_text(json.dumps({"servers": pins}), encoding="utf-8")
    return str(home), str(workspace)


def test_an_unchanged_server_has_no_drift(tmp_path: Path) -> None:
    pins = {"docs": {"owner": "x", "config_hash": mcppin.config_hash(server(), KEY)}}
    home, ws = setup(tmp_path, {"docs": server()}, pins)
    assert mcppin.drift(home, ws) == {}


def test_changed_missing_and_unpinned_servers(tmp_path: Path) -> None:
    pins = {
        "docs": {"config_hash": mcppin.config_hash(server(), KEY)},
        "gone": {"config_hash": mcppin.config_hash(server(), KEY)},
        "legacy": {"owner": "x"},  # approved before pinning: no hash, not checked here
    }
    current = {"docs": server(args=["-y", "@acme/mcp-docs@9.9.9"]), "legacy": server()}
    home, ws = setup(tmp_path, current, pins)
    assert mcppin.drift(home, ws) == {"docs": "changed", "gone": "missing"}


def test_no_key_or_unreadable_config_makes_every_pin_unverifiable(tmp_path: Path) -> None:
    pins = {"docs": {"config_hash": mcppin.config_hash(server(), KEY)}}
    home, ws = setup(tmp_path, {"docs": server()}, pins)
    (Path(home) / "fingerprint.key").unlink()
    assert mcppin.drift(home, ws) == {"docs": "unverifiable"}
    (Path(home) / "fingerprint.key").write_bytes(KEY)
    (Path(ws) / ".mcp.json").write_text("{not json", encoding="utf-8")
    assert mcppin.drift(home, ws) == {"docs": "unverifiable"}


def test_an_unreadable_allowlist_is_unverifiable_for_all(tmp_path: Path) -> None:
    home, ws = setup(tmp_path, {}, None)
    (Path(home) / "mcp-allowlist.json").write_text("[broken", encoding="utf-8")
    assert mcppin.drift(home, ws) == {mcppin.ALL: "unverifiable"}


def test_allowlist_off_means_no_drift(tmp_path: Path) -> None:
    home, ws = setup(tmp_path, {"docs": server()}, None)
    assert mcppin.drift(home, ws) == {}


def test_write_drift_binds_the_file_to_the_session_and_workspace(tmp_path: Path) -> None:
    pins = {"docs": {"config_hash": "0" * 32}}
    home, ws = setup(tmp_path, {"docs": server()}, pins)
    assert mcppin.write_drift(home, ws, "s-1") == {"docs": "changed"}
    data = json.loads((Path(home) / mcppin.DRIFT_NAME).read_text(encoding="utf-8"))
    assert data["servers"] == {"docs": "changed"}
    assert data["session"] == mcppin.session_key("s-1") and Path(data["workspace"]) == Path(ws)
    assert not list(Path(home).glob("*.tmp"))  # the temp file was swapped in


def test_a_malformed_pin_is_unverifiable(tmp_path: Path) -> None:
    pins = {"docs": {"config_hash": "ZZ" + "é" * 30}, "b": {"config_hash": ["x"]}}
    home, ws = setup(tmp_path, {"docs": server(), "b": server()}, pins)
    assert mcppin.drift(home, ws) == {"docs": "unverifiable", "b": "unverifiable"}


def _pins(ok: bool) -> dict[str, Any]:
    return {"docs": {"config_hash": mcppin.config_hash(server(), KEY) if ok else "0" * 32}}


def test_check_needs_a_file_for_this_session_and_workspace(tmp_path: Path) -> None:
    home, ws = setup(tmp_path, {"docs": server()}, _pins(True))
    assert mcppin.check(home, "docs", "s-1", ws) == mcppin.NOT_CHECKED  # no file yet
    mcppin.write_drift(home, ws, "s-1")
    assert mcppin.check(home, "docs", "s-1", ws) == ""
    assert mcppin.check(home, "docs", "s-2", ws) == mcppin.NOT_CHECKED  # another session
    assert mcppin.check(home, "docs", "", ws) == mcppin.NOT_CHECKED
    other = tmp_path / "other-project"
    other.mkdir()
    assert mcppin.check(home, "docs", "s-1", str(other)) == mcppin.NOT_CHECKED
    assert mcppin.check(home, "docs", "s-1", "") == ""  # the hook did not name a workspace


def test_within_a_session_drift_only_grows(tmp_path: Path) -> None:
    """Re-running the check after quietly restoring .mcp.json must not clear a server that is
    already running in this session (review #3)."""
    home, ws = setup(tmp_path, {"docs": server()}, _pins(False))
    assert mcppin.write_drift(home, ws, "s-1") == {"docs": "changed"}
    (Path(home) / "mcp-allowlist.json").write_text(json.dumps({"servers": _pins(True)}))
    assert mcppin.write_drift(home, ws, "s-1") == {"docs": "changed"}  # kept
    assert mcppin.write_drift(home, ws, "s-2") == {}  # a new session starts clean
    assert mcppin.check(home, "docs", "s-2", ws) == ""


def test_a_person_clears_drift_and_keeps_the_binding(tmp_path: Path) -> None:
    home, ws = setup(tmp_path, {"docs": server()}, _pins(False))
    mcppin.write_drift(home, ws, "s-1")
    (Path(home) / "mcp-allowlist.json").write_text(json.dumps({"servers": _pins(True)}))
    assert mcppin.write_drift(home, ws) == {}  # session None: a person after an approval
    assert mcppin.check(home, "docs", "s-1", ws) == ""


def test_an_unbound_file_written_by_a_person_is_not_trusted_by_a_session(tmp_path: Path) -> None:
    home, ws = setup(tmp_path, {"docs": server()}, _pins(True))
    mcppin.write_drift(home, ws)  # no earlier binding
    assert mcppin.check(home, "docs", "s-1", ws) == mcppin.NOT_CHECKED


def test_write_drift_retries_a_busy_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, ws = setup(tmp_path, {"docs": server()}, _pins(True))
    real, calls = mcppin.os.replace, []

    def busy(src: str, dst: str) -> None:
        calls.append(dst)
        if len(calls) < 3:
            raise PermissionError("in use")
        real(src, dst)

    monkeypatch.setattr(mcppin.os, "replace", busy)
    mcppin.write_drift(home, ws, "s-1")
    assert len(calls) == 3 and mcppin.check(home, "docs", "s-1", ws) == ""


# hygiene M1 / M2 ---------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("config", "unpinned"),
    [
        ({"command": "npx", "args": ["-y", "@acme/mcp-docs"]}, True),
        ({"command": "npx", "args": ["-y", "@acme/mcp-docs@latest"]}, True),
        ({"command": "npx", "args": ["-y", "@acme/mcp-docs@1.4.2"]}, False),
        ({"command": "npx -y mcp-server-git"}, True),
        ({"command": "npx -y mcp-server-git@0.6.2"}, False),
        ({"command": "C:\\tools\\npx.cmd", "args": ["mcp-x"]}, True),
        ({"command": "uvx", "args": ["mcp-server-fetch"]}, True),
        ({"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]}, False),
        ({"command": "pnpm", "args": ["dlx", "mcp-x@1.0.0"]}, False),
        ({"command": "docker", "args": ["run", "-i", "--rm", "ghcr.io/acme/mcp:latest"]}, True),
        (
            {"command": "docker", "args": ["run", "-i", "ghcr.io/acme/mcp@sha256:" + "a" * 64]},
            False,
        ),
        ({"command": "node", "args": ["server.js"]}, False),
        ({"url": "https://mcp.example.org"}, False),
    ],
)
def test_m1_unpinned_launch(config: dict[str, Any], unpinned: bool) -> None:
    assert mcppin.unpinned_launch(config) is unpinned


@pytest.mark.parametrize(
    ("url", "plain"),
    [
        ("http://mcp.example.org/sse", True),
        ("http://user@mcp.example.org:8080/x", True),
        ("https://mcp.example.org", False),
        ("http://localhost:3000/mcp", False),
        ("http://127.0.0.1:3000", False),
        ("http://[::1]:3000", False),
    ],
)
def test_m2_plain_http(url: str, plain: bool) -> None:
    assert mcppin.plain_http({"url": url}) is plain


def test_launch_findings_name_servers_only(tmp_path: Path) -> None:
    servers = {
        "docs": {"command": "npx", "args": ["-y", "mcp-docs", "--token", "placeholder-value"]},
        "remote": {"url": "http://mcp.example.org"},
        "bad name!": {"command": "uvx", "args": ["mcp-server-fetch"]},
        "fine": {"command": "npx", "args": ["mcp-fine@1.0.0"]},
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    found = mcppin.launch_findings(str(tmp_path))
    assert found == [("M1", "(unnamed-1)"), ("M1", "docs"), ("M2", "remote")]
    assert "placeholder-value" not in repr(found)


# security review 2026-11-10: M1/M2 parsing, M3, labels -------------------------------------------
@pytest.mark.parametrize(
    ("config", "unpinned"),
    [
        ({"command": "cmd", "args": ["/c", "npx", "-y", "mcp-x"]}, True),  # the Windows form
        ({"command": "cmd", "args": ["/c", "npx", "-y", "mcp-x@1.2.3"]}, False),
        ({"command": "sh", "args": ["-c", "npx -y mcp-x"]}, True),
        ({"command": "env", "args": ["A=1", "npx", "mcp-x"]}, True),
        ({"command": "npm", "args": ["exec", "mcp-x"]}, True),
        ({"command": "npm", "args": ["run", "start"]}, False),  # the project's own script
        ({"command": "bun", "args": ["x", "mcp-x"]}, True),
        ({"command": "npx", "args": ["mcp-x@1"]}, True),  # a range, not a version
        ({"command": "npx", "args": ["mcp-x@1.x"]}, True),
        ({"command": "npx", "args": ["--package", "other", "mcp-x@1.0.0"]}, False),
        ({"command": "uv", "args": ["run", "server.py"]}, False),  # a local file
        ({"command": "uv", "args": ["tool", "run", "mcp-x"]}, True),
        ({"command": "uvx", "args": ["--with", "dep==1", "mcp-x"]}, True),  # --with takes a value
        ({"command": "docker",
          "args": ["run", "-e", "KEY", "ghcr.io/acme/mcp@sha256:" + "a" * 64]}, False),
        ({"command": "docker", "args": ["run", "-e", "KEY", "ghcr.io/acme/mcp:1"]}, True),
        ({"command": "nerdctl", "args": ["run", "img:latest"]}, True),
    ],
)  # fmt: skip
def test_m1_wrappers_and_value_flags(config: dict[str, Any], unpinned: bool) -> None:
    assert mcppin.unpinned_launch(config) is unpinned


@pytest.mark.parametrize(
    ("url", "plain"),
    [
        ("http://evil.example?@localhost/", True),  # looks local to a naive parser
        ("http://evil.example#@localhost/", True),
        ("http://localhost?x=1", False),
        ("HTTP://MCP.EXAMPLE.ORG", True),
    ],
)
def test_m2_uses_the_real_host(url: str, plain: bool) -> None:
    assert mcppin.plain_http({"url": url}) is plain


def test_m3_variable_expansion_in_the_launch() -> None:
    assert mcppin.expands_variables({"command": "npx", "args": ["${PKG:-mcp-x}"]})
    assert mcppin.expands_variables({"url": "${API_BASE_URL}/mcp"})
    assert not mcppin.expands_variables({"command": "npx", "args": ["mcp-x@1.0.0"],
                                         "env": {"TOKEN": "${TOKEN}"}})  # fmt: skip


def test_unnamed_servers_get_their_own_labels(tmp_path: Path) -> None:
    servers = {"a b": {"url": "http://x.example"}, "c d": {"url": "http://y.example"}}
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    assert mcppin.launch_findings(str(tmp_path)) == [("M2", "(unnamed-1)"), ("M2", "(unnamed-2)")]
