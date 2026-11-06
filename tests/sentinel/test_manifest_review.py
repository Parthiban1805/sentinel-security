"""Agent permission manifest: fixes from the 2026-11-06 security review of ADR-0024."""

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from sentinel import agentmanifest
from sentinel.cli import main
from sentinel.store.db import Store

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "docs" / "patches" / "agent-gateway"
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)

TOML = """
version = 1
[agent]
id = "claude-code"
owner = "Parthiban"
expires = "2026-11-06"
[filesystem]
read = ["src/**"]
write = ["src/**"]
deny = ["src/{a,b}/**", "src/deploy/**"]
outside_workspace = "allow"
[network]
fetch_domains = ["good.com", "*.good.com"]
[execution]
shell = false
[mcp]
unlisted = "deny"
[mcp.servers.github]
tools = ["get_file"]
"""


def compiled(tmp_path: Path, text: str = TOML) -> dict[str, Any]:
    return agentmanifest.compile_manifest(text.encode(), str(tmp_path / "ws"), "Parthiban", NOW)


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    path = tmp_path / "ws"
    (path / "src" / "lib").mkdir(parents=True)
    (path / "config").mkdir()
    return path


def decide(m: dict[str, Any], tool: str, tool_input: dict[str, Any], ws: Path) -> Any:
    return agentmanifest.check(m, tool, tool_input, str(ws), NOW)


# device and UNC paths ------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform != "win32", reason="Windows path forms")
def test_device_prefixes_are_placed_in_the_workspace(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    inside = str(ws / "README.md")
    assert decide(m, "Read", {"file_path": "\\\\?\\" + inside}, ws)[1] == "MF-01"  # not "outside"
    assert decide(m, "Read", {"file_path": "\\\\.\\" + inside}, ws)[1] == "MF-01"


def test_unc_paths_cannot_slip_past_as_outside(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    assert decide(m, "Write", {"file_path": "//localhost/c$/ws/src/x.py"}, ws)[1] == "MF-13"
    assert decide(m, "Read", {"file_path": "\\\\server\\share\\x"}, ws)[1] == "MF-13"


# Glob and Grep -----------------------------------------------------------------------------
def test_patterns_resolve_under_the_tool_path(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    assert decide(m, "Glob", {"path": str(ws / "src" / "lib"), "pattern": "*.py"}, ws) is None
    assert (
        decide(m, "Grep", {"path": str(ws / "src" / "lib"), "glob": "*.py", "pattern": "x"}, ws)
        is None
    )
    escape = decide(m, "Glob", {"path": str(ws / "src"), "pattern": "../config/*"}, ws)
    assert escape is not None and escape[0] == "deny"  # refused (MF-03 or MF-01), never allowed


def test_brace_globs_are_wildcards_not_folders(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    assert decide(m, "Grep", {"path": str(ws / "src"), "pattern": "x"}, ws)[1] == "MF-03"


def test_a_grep_path_that_is_a_file_uses_the_file_glob(tmp_path: Path, ws: Path) -> None:
    (ws / "src" / "lib" / "a.py").write_text("x")
    m = compiled(tmp_path)
    assert decide(m, "Grep", {"path": str(ws / "src" / "lib" / "a.py"), "pattern": "x"}, ws) is None


def test_trailing_dot_spelling_of_a_denied_folder(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    assert (
        decide(m, "Write", {"file_path": str(ws / "src" / "deploy.") + "/x.txt"}, ws)[1] == "MF-03"
    )


# WebFetch ----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://good.com/x", True),
        ("https://api.good.com:8443/x", True),
        ("https://good.com./x", True),
        ("https://GOOD.com/x", True),
        ("https://evil.com\\@good.com/", False),
        ("https://evil.com\\.good.com/", False),
        ("https://good.com@evil.com/", False),
        ("https://user:pw@good.com/", False),
        ("https://g%6Fod.com/", False),
        ("https://gööd.com/", False),
        ("https://1.2.3.4/", False),
        ("ftp://good.com/", False),
        ("https://good.com.evil.com/", False),
    ],
)
def test_fetch_urls(tmp_path: Path, ws: Path, url: str, allowed: bool) -> None:
    result = decide(compiled(tmp_path), "WebFetch", {"url": url}, ws)
    assert (result is None) is allowed


# MCP, shell, expiry ----------------------------------------------------------------------------
def test_unlisted_mcp_servers_can_be_denied(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    assert decide(m, "mcp__other__x", {}, ws)[1] == "MF-09"
    assert decide(m, "mcp__github__get_file", {}, ws) is None
    assert decide(m, "mcp__git__hub__get_file", {}, ws)[1] == "MF-09"  # server is 'git__hub'


def test_server_names_with_dots_are_refused(tmp_path: Path) -> None:
    with pytest.raises(agentmanifest.ManifestError):
        compiled(tmp_path, TOML.replace("[mcp.servers.github]", '[mcp.servers."a.b"]'))


def test_a_non_string_command_is_still_a_shell_call(tmp_path: Path, ws: Path) -> None:
    assert decide(compiled(tmp_path), "PowerShell", {"command": ["dir"]}, ws)[1] == "MF-06"


def test_the_expiry_day_itself_is_still_valid(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path, TOML.replace("shell = false", "shell = true"))
    assert decide(m, "Bash", {"command": "ls"}, ws) is None  # expires 2026-11-06, now 2026-11-06


def test_globs_are_bounded(tmp_path: Path) -> None:
    reads = ", ".join(f'"src/r{i}"' for i in range(200))
    writes = ", ".join(f'"src/w{i}"' for i in range(200))
    text = TOML.replace('read = ["src/**"]', f"read = [{reads}]").replace(
        'write = ["src/**"]', f"write = [{writes}]"
    )
    with pytest.raises(agentmanifest.ManifestError, match="more than 400 globs"):
        compiled(tmp_path, text)
    nested = compiled(tmp_path, TOML.replace('read = ["src/**"]', 'read = ["**/**/**/**/x"]'))
    assert nested["filesystem"]["read"] == ["**/x"]


def test_error_messages_never_echo_odd_key_text(tmp_path: Path) -> None:
    with pytest.raises(agentmanifest.ManifestError) as err:
        compiled(tmp_path, 'version = 1\n"x\\u001b[2J" = 1\n[agent]\nid="a"\nowner="b"\n')
    assert "\x1b" not in str(err.value)


def test_compiled_manifest_records_its_source(tmp_path: Path) -> None:
    m = agentmanifest.compile_manifest(
        TOML.encode(), str(tmp_path), "P", NOW, source_path="/x.toml"
    )
    assert m["source_path"] == "/x.toml" and m["workspace_real"]


# the gateway: built-in rules first, then the manifest ------------------------------------------
@pytest.fixture
def policy(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(GATEWAY))
    sys.modules.pop("_manifest", None)
    spec = importlib.util.spec_from_file_location("gw_policy_review", GATEWAY / "_policy.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install(home: Path, m: dict[str, Any]) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / agentmanifest.COMPILED_NAME).write_text(json.dumps(m), encoding="utf-8")


def payload(tool: str, tool_input: dict[str, Any], cwd: Path) -> dict[str, Any]:
    return {"tool_name": tool, "tool_input": tool_input, "cwd": str(cwd)}


@pytest.mark.parametrize(
    "command",
    [
        "cd .sentinel && del agent-manifest.json",
        "Set-Location .sentinel; Remove-Item agent-manifest.json",
        "pushd .sentinel",
    ],
)
def test_changing_into_the_state_folder_is_denied(
    policy: ModuleType, tmp_path: Path, command: str
) -> None:
    d = policy.decide(payload("Bash", {"command": command}, tmp_path), str(tmp_path / ".sentinel"))
    assert d.decision == "deny" and d.rule in ("BG-14", "BG-26")


def test_commands_inside_the_state_folder_are_denied(policy: ModuleType, tmp_path: Path) -> None:
    home = tmp_path / ".sentinel"
    home.mkdir()
    d = policy.decide(payload("Bash", {"command": "del agent-manifest.json"}, home), str(home))
    assert (d.decision, d.rule) == ("deny", "BG-27")


@pytest.mark.parametrize(
    "command",
    [
        'start "" cmd /c "uv run sentinel agent manifest off"',
        "Start-Process uv -ArgumentList 'run sentinel agent manifest apply --actor x'",
        "uv run sentinel agent mcp-allowlist off",
        "uv run sentinel sandbox strict off",
        "uv run sentinel agentlog pin-hooks --actor x",
        "uv run sentinel creds set gcp-key-1 --actor x --rotated-at 2026-11-01",
        "uv run sentinel inventory set mcp-x --approve --actor x",
        "uv run sentinel agentlog archive --actor x",
    ],
)
def test_human_only_sentinel_actions_are_denied_to_the_agent(
    policy: ModuleType, tmp_path: Path, command: str
) -> None:
    d = policy.decide(payload("Bash", {"command": command}, tmp_path), str(tmp_path / ".sentinel"))
    assert (d.decision, d.rule) == ("deny", "BG-17")


def test_kill_switch_wins_over_a_manifest(policy: ModuleType, tmp_path: Path, ws: Path) -> None:
    home = tmp_path / "home"
    install(home, compiled(tmp_path, TOML.replace("shell = false", "shell = true")))
    (home / "agent-kill-switch").write_text("{}")
    d = policy.decide(payload("Bash", {"command": "ls"}, ws), str(home))
    assert d.rule == "KS-01"


def test_allow_mcp_can_be_tightened_and_mcp_deny_stays(
    policy: ModuleType, tmp_path: Path, ws: Path
) -> None:
    home = tmp_path / "home"
    install(home, compiled(tmp_path))
    d = policy.decide(payload("mcp__github__delete_repo", {}, ws), str(home))
    assert (d.decision, d.rule) == ("deny", "MF-09")
    (home / "mcp-allowlist.json").write_text(json.dumps({"servers": {}}))
    d = policy.decide(payload("mcp__github__get_file", {}, ws), str(home))
    assert d.rule == "MCP-02"  # the built-in allow-list deny stays ahead of the manifest


def test_import_failure_of_the_manifest_module_fails_closed(
    policy: ModuleType, tmp_path: Path, ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    install(home, compiled(tmp_path))
    monkeypatch.setitem(sys.modules, "_manifest", None)  # `import _manifest` raises ImportError
    d = policy.decide(payload("Write", {"file_path": str(ws / "src" / "a.py")}, ws), str(home))
    assert (d.decision, d.rule) == ("deny", "MF-05")
    d = policy.decide(payload("Read", {"file_path": str(ws / "src" / "a.py")}, ws), str(home))
    assert d.decision == "allow"


# the hook runs on the first `python` on PATH, which may be 3.10 ---------------------------------
def _python310() -> list[str] | None:
    import shutil
    import subprocess

    if shutil.which("py") is None:
        return None
    probe = subprocess.run(["py", "-3.10", "-c", "print(1)"], capture_output=True, check=False)  # noqa: S603, S607
    return ["py", "-3.10"] if probe.returncode == 0 else None


def test_the_gateway_with_a_manifest_runs_on_python_310(tmp_path: Path, ws: Path) -> None:
    """Regression (2026-11-06): `from datetime import UTC` broke the patch on the owner's 3.10."""
    import os
    import subprocess

    python = _python310()
    if python is None:
        pytest.skip("Python 3.10 is not installed here")
    home = tmp_path / "home"
    install(home, compiled(tmp_path, TOML.replace("shell = false", "shell = true")))
    env = {
        "SENTINEL_HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": "C:\\Windows",
    }

    def run(tool: str, tool_input: dict[str, Any]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [*python, "-I", str(GATEWAY / "gateway.py")],
            input=json.dumps(payload(tool, tool_input, ws)),
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    allowed = run("Read", {"file_path": str(ws / "src" / "lib" / "a.py")})
    assert allowed.returncode == 0 and "Traceback" not in allowed.stderr
    denied = run("Write", {"file_path": str(ws / "README.md")})
    assert denied.returncode == 2 and "MF-02" in denied.stderr
    (home / agentmanifest.COMPILED_NAME).write_text("{broken", encoding="utf-8")
    broken = run("Write", {"file_path": str(ws / "src" / "a.py")})
    assert broken.returncode == 2 and "MF-05" in broken.stderr


# CLI: apply only into a project's state folder ------------------------------------------------
def test_apply_outside_a_project_state_folder_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "not-a-project-home"
    home.mkdir()
    Store(home / "sentinel.db")
    toml = tmp_path / "m.toml"
    toml.write_text(TOML, encoding="utf-8")
    monkeypatch.setattr("sentinel.cli._require_human", lambda action: None)
    argv = ["--home", str(home), "agent", "manifest", "apply", "--file", str(toml), "--actor", "P"]
    assert main(argv) == 1
    assert "not the .sentinel folder" in capsys.readouterr().err
    assert not (home / agentmanifest.COMPILED_NAME).exists()
