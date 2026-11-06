"""Agent permission manifest (v0.7d item 1, ADR-0024): schema, decisions, gateway overlay, CLI."""

import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from sentinel import agentgate, agentmanifest
from sentinel.cli import main
from sentinel.doctor import check_agent_manifest
from sentinel.store.db import Store

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "docs" / "patches" / "agent-gateway"
EXAMPLE = ROOT / "policies" / "agent-manifest.example.toml"
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)

BASE_TOML = """
version = 1
[agent]
id = "claude-code"
owner = "Parthiban"
[filesystem]
read = ["src/**", "README.md"]
write = ["src/**"]
deny = ["src/private/**"]
ask_write = ["src/release/**"]
outside_workspace = "deny"
[network]
fetch_domains = ["docs.python.org", "*.github.com"]
web_search = false
[execution]
shell = false
deny_tools = ["NotebookEdit"]
[mcp.servers.github]
tools = ["get_file"]
"""


def compiled(tmp_path: Path, text: str = BASE_TOML) -> dict[str, Any]:
    return agentmanifest.compile_manifest(text.encode(), str(tmp_path / "ws"), "Parthiban", NOW)


def decide(m: dict[str, Any], tool: str, tool_input: dict[str, Any], ws: Path) -> Any:
    return agentmanifest.check(m, tool, tool_input, str(ws), NOW)


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    path = tmp_path / "ws"
    (path / "src" / "private").mkdir(parents=True)
    return path


# one implementation ------------------------------------------------------------------------
def test_the_hook_copy_is_identical_to_the_sentinel_module() -> None:
    assert (GATEWAY / "_manifest.py").read_bytes() == (
        ROOT / "sentinel" / "agentmanifest.py"
    ).read_bytes()


def test_the_patch_installs_the_manifest_module() -> None:
    assert "_manifest.py" in (GATEWAY / "apply-patch.bat").read_text(encoding="utf-8")


# schema ------------------------------------------------------------------------------------
def test_the_example_manifest_is_valid(tmp_path: Path) -> None:
    m = agentmanifest.compile_manifest(EXAMPLE.read_bytes(), str(tmp_path), "Parthiban", NOW)
    assert m["agent"]["id"] == "claude-code" and len(m["source_sha256"]) == 64


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('version = 1\nsurprise = 1\n[agent]\nid="a"\nowner="b"\n', "unknown key: surprise"),
        ('version = 1\n[agent]\nid="a"\nowner="b"\nrole="x"\n', "unknown key: agent.role"),
        ('version = 1\n[agent]\nid="a"\nowner="b"\n[network]\nallowed_domains=["x.com"]\n',
         "unknown key: network.allowed_domains"),
        ('version = 2\n[agent]\nid="a"\nowner="b"\n', "version must be 1"),
        ('version = 1\n[agent]\nid="a"\n', "missing key: agent.owner"),
        ('version = 1\n[agent]\nid="a"\nowner="b"\n[execution]\nshell="no"\n', "wrong type"),
        ('version = 1\n[agent]\nid="a"\nowner="b"\nexpires="soon"\n', "agent.expires"),
        ('version = 1\n[agent]\nid="a"\nowner="b"\n[filesystem]\nwrite=["../x"]\n', "without '..'"),
        ('version = 1\n[agent]\nid="a"\nowner="b"\n[filesystem]\nread=["C:/x"]\n', "workspace-relative"),
        ('version = 1\n[agent]\nid="a"\nowner="b"\n[network]\nfetch_domains=["http://x"]\n', "invalid domain"),
        ('version = 1\n[agent]\nid="a"\nowner="b"\n[filesystem]\noutside_workspace="maybe"\n', "outside"),
        ('version = 1\n[agent]\nid="a"\nowner="b"\n[mcp.servers.x]\ntools=["a"]\nextra=1\n', "only 'tools'"),
        ("not toml [", "not valid TOML"),
    ],
)  # fmt: skip
def test_invalid_manifests_are_refused(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(agentmanifest.ManifestError, match=message):
        compiled(tmp_path, text)


# decisions -----------------------------------------------------------------------------------
def test_file_rules(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    assert decide(m, "Read", {"file_path": str(ws / "src" / "a.py")}, ws) is None
    assert decide(m, "Read", {"file_path": str(ws / "notes.txt")}, ws)[1] == "MF-01"
    assert decide(m, "Read", {"file_path": str(ws / "README.md")}, ws) is None
    assert decide(m, "Edit", {"file_path": str(ws / "README.md")}, ws)[1] == "MF-02"
    assert (
        decide(m, "Write", {"file_path": str(ws / "src" / "private" / "k.txt")}, ws)[1] == "MF-03"
    )
    assert decide(m, "Read", {"file_path": str(ws / "src" / "private" / "k.txt")}, ws)[1] == "MF-03"
    assert decide(m, "Write", {"file_path": str(ws / "src" / "release" / "n.md")}, ws)[:2] == (
        "ask",
        "MF-11",
    )
    assert decide(m, "Write", {"file_path": str(tmp_path / "elsewhere.txt")}, ws)[:2] == (
        "deny",
        "MF-12",
    )


def test_relative_paths_use_the_working_folder(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    assert decide(m, "Read", {"file_path": "src/a.py"}, ws) is None
    assert decide(m, "Read", {"file_path": "other.py"}, ws)[1] == "MF-01"


def test_folder_searches_need_a_covering_read_glob(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    (ws / "src" / "public").mkdir()
    assert decide(m, "Grep", {"pattern": "x", "path": str(ws / "src" / "public")}, ws) is None
    # src holds src/private/**, which is denied: a search of src would return its content.
    assert decide(m, "Grep", {"pattern": "x", "path": str(ws / "src")}, ws)[1] == "MF-03"
    assert decide(m, "Grep", {"pattern": "x", "path": str(ws)}, ws)[1] in ("MF-01", "MF-03")
    assert decide(m, "Grep", {"pattern": "x"}, ws)[1] in ("MF-01", "MF-03")  # the whole workspace
    assert decide(m, "Glob", {"pattern": "src/public/**/*.py"}, ws) is None
    assert decide(m, "Glob", {"pattern": "**/*.py"}, ws)[1] in ("MF-01", "MF-03")


def test_outside_workspace_modes(tmp_path: Path, ws: Path) -> None:
    text = BASE_TOML.replace('outside_workspace = "deny"', 'outside_workspace = "ask"')
    m = compiled(tmp_path, text)
    assert decide(m, "Read", {"file_path": str(tmp_path / "x.md")}, ws)[:2] == ("ask", "MF-12")
    allow = compiled(
        tmp_path, BASE_TOML.replace('outside_workspace = "deny"', 'outside_workspace = "allow"')
    )
    assert decide(allow, "Read", {"file_path": str(tmp_path / "x.md")}, ws) is None


def test_symlink_out_of_an_allowed_folder_is_checked_at_its_target(
    tmp_path: Path, ws: Path
) -> None:
    secret_dir = tmp_path / "outside"
    secret_dir.mkdir()
    (secret_dir / "f.txt").write_text("x")
    link = ws / "src" / "link.txt"
    try:
        link.symlink_to(secret_dir / "f.txt")
    except OSError:
        pytest.skip("this account cannot create symlinks")
    assert decide(compiled(tmp_path), "Read", {"file_path": str(link)}, ws)[1] == "MF-12"


def test_shell_network_mcp_and_tools(tmp_path: Path, ws: Path) -> None:
    m = compiled(tmp_path)
    assert decide(m, "Bash", {"command": "ls"}, ws)[1] == "MF-06"
    assert decide(m, "PowerShell", {"command": "dir"}, ws)[1] == "MF-06"
    assert decide(m, "WebFetch", {"url": "https://docs.python.org/3/"}, ws) is None
    assert decide(m, "WebFetch", {"url": "https://api.github.com/x"}, ws) is None
    assert (
        decide(m, "WebFetch", {"url": "https://github.com/x"}, ws)[1] == "MF-07"
    )  # *. needs a label
    assert decide(m, "WebFetch", {"url": "https://evil.example/x"}, ws)[1] == "MF-07"
    assert decide(m, "WebFetch", {"url": "https://docs.python.org.evil.example/"}, ws)[1] == "MF-07"
    assert decide(m, "WebFetch", {"url": "not a url"}, ws)[1] == "MF-07"
    assert decide(m, "WebSearch", {"query": "x"}, ws)[1] == "MF-08"
    assert decide(m, "mcp__github__get_file", {}, ws) is None
    assert decide(m, "mcp__github__delete_repo", {}, ws)[1] == "MF-09"
    assert decide(m, "mcp__other__anything", {}, ws) is None  # the MCP allow-list governs it
    assert (
        decide(m, "NotebookEdit", {"notebook_path": str(ws / "src" / "n.ipynb")}, ws)[1] == "MF-10"
    )


def test_expiry_makes_non_read_calls_ask(tmp_path: Path, ws: Path) -> None:
    text = BASE_TOML.replace('owner = "Parthiban"', 'owner = "Parthiban"\nexpires = "2026-11-01"')
    m = compiled(tmp_path, text.replace("shell = false", "shell = true"))
    assert decide(m, "Bash", {"command": "ls"}, ws)[:2] == ("ask", "MF-04")
    assert decide(m, "Read", {"file_path": str(ws / "src" / "a.py")}, ws) is None


def test_deny_beats_ask(tmp_path: Path, ws: Path) -> None:
    text = BASE_TOML.replace('owner = "Parthiban"', 'owner = "Parthiban"\nexpires = "2026-11-01"')
    m = compiled(tmp_path, text)
    assert decide(m, "Bash", {"command": "ls"}, ws)[:2] == ("deny", "MF-06")


# the gateway overlay ---------------------------------------------------------------------------
@pytest.fixture
def policy(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(GATEWAY))
    sys.modules.pop("_manifest", None)
    spec = importlib.util.spec_from_file_location("gw_policy_manifest", GATEWAY / "_policy.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install(home: Path, m: dict[str, Any]) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / agentmanifest.COMPILED_NAME).write_text(json.dumps(m), encoding="utf-8")


def payload(tool: str, tool_input: dict[str, Any], cwd: Path) -> dict[str, Any]:
    return {"tool_name": tool, "tool_input": tool_input, "cwd": str(cwd)}


def test_no_manifest_changes_nothing(policy: ModuleType, tmp_path: Path, ws: Path) -> None:
    home = tmp_path / "home"
    d = policy.decide(payload("Bash", {"command": "ls"}, ws), str(home))
    assert d.decision == "allow"


def test_manifest_tightens_an_allow(policy: ModuleType, tmp_path: Path, ws: Path) -> None:
    home = tmp_path / "home"
    install(home, compiled(tmp_path))
    d = policy.decide(payload("Bash", {"command": "ls"}, ws), str(home))
    assert (d.decision, d.rule) == ("deny", "MF-06")
    d = policy.decide(payload("Read", {"file_path": str(ws / "src" / "a.py")}, ws), str(home))
    assert d.decision == "allow"


def test_manifest_never_loosens_a_builtin_deny(
    policy: ModuleType, tmp_path: Path, ws: Path
) -> None:
    home = tmp_path / "home"
    text = BASE_TOML.replace('read = ["src/**", "README.md"]', 'read = ["**"]')
    install(home, compiled(tmp_path, text))
    d = policy.decide(payload("Read", {"file_path": str(ws / ".env")}, ws), str(home))
    assert d.decision == "deny" and d.rule.startswith("PF-")  # the protected-path rule, not MF


def test_a_builtin_ask_stays_ask_or_becomes_deny(
    policy: ModuleType, tmp_path: Path, ws: Path
) -> None:
    home = tmp_path / "home"
    install(home, compiled(tmp_path, BASE_TOML.replace("shell = false", "shell = true")))
    d = policy.decide(payload("Bash", {"command": "python -c 'print(1)'"}, ws), str(home))
    assert d.decision == "ask"  # BG-15 inline code, untouched
    install(home, compiled(tmp_path))
    d = policy.decide(payload("Bash", {"command": "python -c 'print(1)'"}, ws), str(home))
    assert (d.decision, d.rule) == ("deny", "MF-06")


def test_unreadable_manifest_allows_only_reading(
    policy: ModuleType, tmp_path: Path, ws: Path
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / agentmanifest.COMPILED_NAME).write_text("{broken", encoding="utf-8")
    d = policy.decide(payload("Write", {"file_path": str(ws / "src" / "a.py")}, ws), str(home))
    assert (d.decision, d.rule) == ("deny", "MF-05")
    d = policy.decide(payload("Read", {"file_path": str(ws / "src" / "a.py")}, ws), str(home))
    assert d.decision == "allow"


def test_a_tampered_compiled_manifest_is_refused(
    policy: ModuleType, tmp_path: Path, ws: Path
) -> None:
    home = tmp_path / "home"
    m = compiled(tmp_path)
    m["filesystem"]["sneaky"] = ["**"]
    install(home, m)
    d = policy.decide(payload("Write", {"file_path": str(ws / "src" / "a.py")}, ws), str(home))
    assert (d.decision, d.rule) == ("deny", "MF-05")


def test_the_real_gateway_hook_enforces_the_manifest(tmp_path: Path, ws: Path) -> None:
    home = tmp_path / "home"
    install(home, compiled(tmp_path))
    env = {
        "SENTINEL_HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": "C:\\Windows",
    }
    r = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(GATEWAY / "gateway.py")],
        input=json.dumps(payload("Edit", {"file_path": str(ws / "README.md")}, ws)),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert r.returncode == 2 and "MF-02" in r.stderr
    log = (home / "agent-decisions.jsonl").read_text(encoding="utf-8")
    assert "MF-02" in log and "README" not in log  # rule recorded, never the path


# CLI and doctor --------------------------------------------------------------------------------
@pytest.fixture
def project(tmp_path: Path) -> Path:
    workspace = tmp_path / "proj"
    (workspace / "policies").mkdir(parents=True)
    (workspace / ".claude").mkdir()  # a Claude Code project: where the gateway reads its state
    (workspace / "policies" / "agent-manifest.toml").write_text(BASE_TOML, encoding="utf-8")
    home = workspace / ".sentinel"
    home.mkdir()
    Store(home / "sentinel.db")
    return home


def test_cli_check_apply_status_off(
    project: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    base = ["--home", str(project), "agent", "manifest"]
    assert main([*base, "check"]) == 0
    assert "valid" in capsys.readouterr().out
    assert main([*base, "apply", "--actor", "Parthiban"]) == 1  # no terminal in tests
    assert "interactive terminal" in capsys.readouterr().err
    monkeypatch.setattr("sentinel.cli._require_human", lambda action: None)
    assert main([*base, "apply", "--actor", "Parthiban"]) == 0
    capsys.readouterr()
    assert (project / agentmanifest.COMPILED_NAME).exists()
    assert any(
        e.get("action") == "agent_manifest_applied" for e in Store(project / "sentinel.db").audit()
    )
    assert main([*base, "status"]) == 0
    assert "applied for claude-code" in capsys.readouterr().out
    toml = project.parent / "policies" / "agent-manifest.toml"
    toml.write_text(BASE_TOML + "\n# edited\n", encoding="utf-8")
    assert main([*base, "status"]) == 1
    assert "DRIFT" in capsys.readouterr().out
    assert check_agent_manifest(project).status == "warn"
    assert main([*base, "off"]) == 0
    assert not (project / agentmanifest.COMPILED_NAME).exists()


def test_cli_check_refuses_invalid_and_missing(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = project.parent / "policies" / "agent-manifest.toml"
    toml.write_text('version = 1\n[agent]\nid="a"\nowner="b"\nrole="x"\n', encoding="utf-8")
    assert main(["--home", str(project), "agent", "manifest", "check"]) == 1
    assert "unknown key: agent.role" in capsys.readouterr().err
    toml.unlink()
    assert main(["--home", str(project), "agent", "manifest", "check"]) == 1
    assert "no manifest" in capsys.readouterr().err


def test_doctor_states(project: Path) -> None:
    assert check_agent_manifest(project).status == "warn"  # TOML present, not applied
    agentgate.apply_manifest(project, project.parent / "policies" / "agent-manifest.toml",
                             project.parent, "Parthiban", NOW)  # fmt: skip
    assert check_agent_manifest(project).status == "ok"
    (project / agentmanifest.COMPILED_NAME).write_text("{bad", encoding="utf-8")
    assert check_agent_manifest(project).status == "fail"
