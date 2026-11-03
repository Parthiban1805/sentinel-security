"""v0.7a agent gateway (ADR-0016): policy engine, a decision for every call, kill-switch drill,
MCP allow-list, path fingerprints shared with the decoys, and rule R9.

Runs the real patch files (docs/patches/agent-gateway) in a throwaway state directory.
"""

import importlib.util
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from sentinel import agentgate, canaries
from sentinel.cli import main
from sentinel.correlation.engine import correlate
from sentinel.correlation.model import Context
from sentinel.events.schema import make_event
from sentinel.security import fingerprint, load_key
from sentinel.simulation import scenarios
from sentinel.sources.agent import AgentLogSource
from sentinel.store.db import Store

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "docs" / "patches" / "agent-gateway"
T0 = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"gw_{name}", GATEWAY / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY = _load("_policy")


def decide(home: Path, tool: str, **tool_input: Any) -> Any:
    return POLICY.decide({"tool_name": tool, "tool_input": tool_input, "cwd": str(home)}, str(home))


def run_gateway(home: Path, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    env = {"SENTINEL_HOME": str(home), "PATH": "", "SystemRoot": "C:\\Windows"}
    return subprocess.run(  # noqa: S603
        [sys.executable, str(GATEWAY / "gateway.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def log_entries(home: Path) -> list[dict[str, Any]]:
    path = home / "agent-decisions.jsonl"
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]


# --- policy engine --------------------------------------------------------------------------------
def test_clean_calls_are_allowed_with_a_rule_and_class(tmp_path: Path) -> None:
    d = decide(tmp_path, "Read", file_path="src/app.py")
    assert (d.decision, d.rule, d.cls) == ("allow", "GW-00", "file_access")
    assert d.target == agentgate.normalize_path("src/app.py", str(tmp_path))
    assert decide(tmp_path, "WebSearch", query="x").cls == "tool_call"
    assert decide(tmp_path, "Bash", command="git status").cls == "command"


def test_file_rules_still_apply(tmp_path: Path) -> None:
    assert decide(tmp_path, "Read", file_path=".env").decision == "deny"
    assert decide(tmp_path, "Read", file_path=".env.example").decision == "allow"
    assert decide(tmp_path, "Edit", file_path=".claude/hooks/gateway.py").decision == "deny"
    assert decide(tmp_path, "Read", file_path=".claude/hooks/gateway.py").decision == "allow"
    assert decide(tmp_path, "Edit", file_path=".claude/settings.local.json").decision == "deny"


def test_kill_switch_refuses_all_but_reading(tmp_path: Path) -> None:
    agentgate.kill_switch_on(tmp_path, "drill", T0)
    for tool, kw in (
        ("Bash", {"command": "git status"}),
        ("Edit", {"file_path": "a.py"}),
        ("Write", {"file_path": "a.py"}),
        ("WebFetch", {"url": "https://example.invalid"}),
        ("mcp__notes__read_file", {}),
    ):
        d = decide(tmp_path, tool, **kw)
        assert (d.decision, d.rule) == ("deny", "KS-01"), tool
    assert decide(tmp_path, "Read", file_path="a.py").decision == "allow"
    assert decide(tmp_path, "Read", file_path=".env").decision == "deny"  # file rules still apply


def test_mcp_allowlist_modes(tmp_path: Path) -> None:
    assert decide(tmp_path, "mcp__notes__read").decision == "allow_mcp"  # no allow-list yet
    (tmp_path / "mcp-allowlist.json").write_text(
        json.dumps({"servers": {"notes": {"owner": "p", "pinned_version": "1.2.0"}}}),
        encoding="utf-8",
    )
    assert decide(tmp_path, "mcp__notes__read").decision == "allow_mcp"
    d = decide(tmp_path, "mcp__rogue__read")
    assert (d.decision, d.rule) == ("deny", "MCP-02") and "rogue" in d.reason
    (tmp_path / "mcp-allowlist.json").write_text("{not json", encoding="utf-8")
    assert decide(tmp_path, "mcp__notes__read").rule == "MCP-03"  # unreadable: fail closed


@pytest.mark.parametrize(
    "payload",
    [{}, {"tool_name": None}, {"tool_name": "Bash", "tool_input": None}, {"tool_name": 7}],
)
def test_decide_never_raises(tmp_path: Path, payload: dict[str, Any]) -> None:
    assert POLICY.decide(payload, str(tmp_path)).decision in ("allow", "deny", "ask", "allow_mcp")


@pytest.mark.parametrize(
    "path",
    ["src/app.py", "./a/../b.txt", "C:\\Work\\Repo\\x.env", "~/notes.md", "/abs/path/file"],
)
def test_hook_and_sentinel_normalise_paths_identically(tmp_path: Path, path: str) -> None:
    assert POLICY.normalize_path(path, str(tmp_path)) == agentgate.normalize_path(
        path, str(tmp_path)
    )


# --- the hook: a decision for every call, never the content -------------------------------------
def test_every_call_is_recorded_without_its_content(tmp_path: Path) -> None:
    calls = [
        ({"tool_name": "Bash", "tool_input": {"command": "git status"}}, 0, "allow"),
        ({"tool_name": "Bash", "tool_input": {"command": "python -c 'print(42)'"}}, 0, "ask"),
        ({"tool_name": "Bash", "tool_input": {"command": "curl https://x.invalid"}}, 2, "deny"),
        ({"tool_name": "Read", "tool_input": {"file_path": "notes-secret-name.md"}}, 0, "allow"),
        ({"tool_name": "mcp__notes__read", "tool_input": {}}, 0, "allow_mcp"),
        ({"tool_name": "WebSearch", "tool_input": {"query": "distinct-query-text"}}, 0, "allow"),
    ]
    for payload, code, _ in calls:
        assert run_gateway(tmp_path, {**payload, "session_id": "s1"}).returncode == code
    entries = log_entries(tmp_path)
    assert [e["decision"] for e in entries] == [c[2] for c in calls]  # one decision per call
    raw = (tmp_path / "agent-decisions.jsonl").read_text(encoding="utf-8")
    for secret_ish in ("git status", "print(42)", "x.invalid", "notes-secret-name", "distinct-q"):
        assert secret_ish not in raw


def test_allowed_calls_stay_silent_and_ask_is_a_prompt(tmp_path: Path) -> None:
    quiet = run_gateway(tmp_path, {"tool_name": "Bash", "tool_input": {"command": "ls"}})
    assert quiet.returncode == 0 and quiet.stdout == ""  # never "allow": prompts still apply
    ask = run_gateway(tmp_path, {"tool_name": "Bash", "tool_input": {"command": "node -e 1"}})
    out = json.loads(ask.stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse" and out["permissionDecision"] == "ask"
    assert "BG-15" in out["permissionDecisionReason"]


def test_malformed_input_never_breaks_a_session(tmp_path: Path) -> None:
    r = subprocess.run(  # noqa: S603
        [sys.executable, str(GATEWAY / "gateway.py")],
        input="not json",
        capture_output=True,
        text=True,
        check=False,
        env={"SENTINEL_HOME": str(tmp_path), "PATH": "", "SystemRoot": "C:\\Windows"},
    )
    assert r.returncode == 0


@pytest.mark.parametrize("wrapper", ["bash_guard.py", "protect_sensitive_files.py", "mcp_log.py"])
def test_old_hook_names_run_the_gateway(tmp_path: Path, wrapper: str) -> None:
    r = subprocess.run(  # noqa: S603
        [sys.executable, str(GATEWAY / wrapper)],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "curl https://x"}}),
        capture_output=True,
        text=True,
        check=False,
        env={"SENTINEL_HOME": str(tmp_path), "PATH": "", "SystemRoot": "C:\\Windows"},
    )
    assert r.returncode == 2 and "BG-01" in r.stderr


# --- kill-switch drill (exit gate) ----------------------------------------------------------------
def test_kill_switch_drill(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "state"
    bash = {"tool_name": "Bash", "tool_input": {"command": "git status"}, "session_id": "s"}
    assert run_gateway(home, bash).returncode == 0  # before: normal work passes
    assert main(["--home", str(home), "agent", "kill-switch", "on", "--actor", "drill"]) == 0
    assert main(["--home", str(home), "agent", "kill-switch", "status"]) == 0
    assert "ON since" in capsys.readouterr().out
    stopped = run_gateway(home, bash)
    assert stopped.returncode == 2 and "KS-01" in stopped.stderr  # during: refused
    read = {"tool_name": "Read", "tool_input": {"file_path": "README.md"}}
    assert run_gateway(home, read).returncode == 0  # reading still works
    # an agent (no terminal) cannot turn it off, by command or through the gateway
    assert main(["--home", str(home), "agent", "kill-switch", "off"]) == 1
    assert "interactive terminal" in capsys.readouterr().err
    off_cmd = {"tool_name": "Bash", "tool_input": {"command": "sentinel agent kill-switch off"}}
    assert run_gateway(home, off_cmd).returncode == 2
    assert agentgate.kill_switch_off(home) is True  # what a person at the terminal does
    assert run_gateway(home, bash).returncode == 0  # after: normal work passes again
    assert [e["rule"] for e in log_entries(home)].count("KS-01") >= 2  # the drill is on record


# --- MCP approval with owner, pinned version and review date ---------------------------------------
def _mcp_asset(store: Store, name: str) -> None:
    store.upsert_asset(
        {
            "asset_id": f"mcp-{name}",
            "asset_type": "mcp_server",
            "name": name,
            "owner": None,
            "importance": "medium",
            "monitoring": "partial",
            "last_seen": "2026-11-03T00:00:00Z",
        }
    )


def test_mcp_approval_needs_owner_and_version_and_writes_the_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sentinel.cli._require_human", lambda action: None)  # a person is present
    home = tmp_path / "state"
    _mcp_asset(Store(home / "sentinel.db"), "notes")
    base = ["--home", str(home), "inventory", "set", "mcp-notes", "--actor", "owner"]
    assert main([*base, "--approve"]) == 1
    assert "--owner" in capsys.readouterr().err
    assert main([*base, "--approve", "--owner", "team-a"]) == 1
    assert "--pinned-version" in capsys.readouterr().err
    assert main([*base, "--approve", "--owner", "team-a", "--pinned-version", "1.4.2"]) == 0
    allow = json.loads((home / "mcp-allowlist.json").read_text(encoding="utf-8"))["servers"]
    assert allow["notes"]["owner"] == "team-a" and allow["notes"]["pinned_version"] == "1.4.2"
    assert allow["notes"]["reviewed"]  # review date recorded
    assert decide(home, "mcp__notes__x").decision == "allow_mcp"
    assert decide(home, "mcp__other__x").decision == "deny"
    assert main([*base, "--unapprove"]) == 0
    # Allow-list mode stays on: an empty list blocks every server (it never silently opens).
    empty = json.loads((home / "mcp-allowlist.json").read_text(encoding="utf-8"))
    assert empty == {"servers": {}}
    assert decide(home, "mcp__notes__x").rule == "MCP-02"
    # Only a person returns to record-only mode.
    assert main(["--home", str(home), "agent", "mcp-allowlist", "off"]) == 0
    assert not (home / "mcp-allowlist.json").exists()
    assert decide(home, "mcp__notes__x").decision == "allow_mcp"


# --- agent-log source: which decisions become events ----------------------------------------------
def _record(decision: str, target_class: str, seq: int = 1) -> dict[str, Any]:
    return {
        "v": 1, "seq": seq, "time": "2026-11-03T12:00:00Z", "session": "a" * 16,
        "tool": "Read", "decision": decision, "rule": "GW-00", "target_class": target_class,
        "target_fp": "f" * 16,
    }  # fmt: skip


def test_file_allows_and_asks_become_events_other_allows_do_not() -> None:
    to_event = AgentLogSource._event
    assert to_event(_record("allow", "file_access"), "c", "agent-x") is not None
    assert to_event(_record("allow", "command"), "c", "agent-x") is None
    assert to_event(_record("allow", "tool_call"), "c", "agent-x") is None
    ask = to_event(_record("ask", "inline_code"), "c", "agent-x")
    assert ask is not None and ask["attributes"]["decision"] == "ask"


# --- the decoy path fingerprint joins with the gateway's ------------------------------------------
def test_decoy_events_carry_the_same_fingerprint_the_gateway_records(tmp_path: Path) -> None:
    home = tmp_path / "state"
    key = load_key(home)
    store = Store(home / "sentinel.db")
    decoys = tmp_path / "decoys"
    decoys.mkdir()
    doc = canaries.plant(store, key, decoys, T0, kind="google_key", name="creds.txt")
    Path(doc["path"]).write_text("changed", encoding="utf-8")  # trip it (modified)
    [event] = [e for e in canaries.check(store, T0, key) if e["attributes"]["reason"] == "modified"]
    gateway_fp = fingerprint(POLICY.normalize_path(doc["path"], str(tmp_path)), key)
    assert event["attributes"]["location_fp"] == gateway_fp


# --- R9 -------------------------------------------------------------------------------------------
def _agent_event(minutes_before: int, fp: str, seq: int) -> dict[str, Any]:
    return make_event(
        event_type="agent_tool_allowed",
        source="agent_hook",
        asset_id="agent-claude-code-x",
        time=T0 - timedelta(minutes=minutes_before),
        severity="info",
        confidence="high",
        evidence_ref=f"agentlog/c/{seq}",
        event_id=f"agentlog:c:{seq}",
        is_test=True,
        attributes={"tool": "Read", "decision": "allow", "target_class": "file_access",
                    "target_fp": fp, "rule": "GW-00", "session": "", "target_fp_kind": "path"},
    )  # fmt: skip


def _decoy(fp: str = "d" * 16) -> dict[str, Any]:
    [e] = scenarios.canary("canary-x", T0)
    e["attributes"] = {**(e.get("attributes") or {}), "reason": "read", "location_fp": fp}
    return e


def test_r9_fires_when_an_agent_session_was_active_and_no_decision_covers_the_decoy() -> None:
    events = [_agent_event(10, "a" * 16, 1), _agent_event(3, "b" * 16, 2), _decoy()]
    r9 = [m for m in correlate(events, Context()) if m.rule_id == "R9"]
    assert len(r9) == 1 and r9[0].severity_floor == "high" and r9[0].confidence == "medium"
    assert "none that allowed reading or writing the decoy" in r9[0].facts[1]
    assert any("backup job or scanner" in h for h in r9[0].hypotheses)  # innocent option named
    assert not any("unauthorized" in t.lower() for t in (*r9[0].facts, *r9[0].hypotheses))


def test_r9_is_quiet_when_the_gateway_saw_the_decoy_or_no_agent_was_active() -> None:
    covered = [_agent_event(5, "d" * 16, 1), _decoy("d" * 16)]
    assert not [m for m in correlate(covered, Context()) if m.rule_id == "R9"]
    no_agent = [_decoy()]
    assert not [m for m in correlate(no_agent, Context()) if m.rule_id == "R9"]
    too_old = [_agent_event(45, "a" * 16, 1), _decoy()]  # outside the 30-minute look-back
    assert not [m for m in correlate(too_old, Context()) if m.rule_id == "R9"]
    after = [_agent_event(-5, "a" * 16, 1), _decoy()]  # agent activity after the decoy event
    assert not [m for m in correlate(after, Context()) if m.rule_id == "R9"]
    no_fp = [_agent_event(5, "a" * 16, 1), _decoy("")]  # decoy event without the key: no join
    assert not [m for m in correlate(no_fp, Context()) if m.rule_id == "R9"]


# --- security review fixes (2026-11-03) ------------------------------------------------------------
def test_file_aliases_and_new_protected_files(tmp_path: Path) -> None:
    assert decide(tmp_path, "Read", file_path=".env ").decision == "deny"  # trailing space
    assert decide(tmp_path, "Read", file_path=".env.").decision == "deny"  # trailing dot
    assert decide(tmp_path, "Read", file_path="~/.claude.json").decision == "deny"
    assert decide(tmp_path, "Read", file_path=".mcp.json").decision == "allow"
    assert decide(tmp_path, "Write", file_path=".mcp.json").decision == "deny"
    assert decide(tmp_path, "Write", file_path="site-packages/evil.pth").decision == "deny"
    backup = decide(tmp_path, "Write", file_path=".claude/backup-before-gateway-1/x.py")
    assert backup.rule == "PF-15"
    grep = POLICY.decide(
        {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": ".", "glob": ".env"}},
        str(tmp_path),
    )
    assert grep.decision == "deny"  # the glob is checked, not only the path


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS alternate data streams")
def test_alternate_data_streams_are_refused(tmp_path: Path) -> None:
    d = decide(tmp_path, "Read", file_path="README.md::$DATA")
    assert (d.decision, d.rule) == ("deny", "PF-21")


def test_a_link_to_a_secret_is_judged_by_its_target(tmp_path: Path) -> None:
    secret = tmp_path / ".env"
    secret.write_text("FAKE=1", encoding="utf-8")
    link = tmp_path / "notes.txt"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("creating a symlink needs a privilege on this machine")
    assert decide(tmp_path, "Read", file_path=str(link)).decision == "deny"


def test_any_shell_tool_gets_the_command_rules(tmp_path: Path) -> None:
    assert decide(tmp_path, "PowerShell", command="Get-Content .env").decision == "deny"
    assert decide(tmp_path, "PowerShell", command="Get-ChildItem").decision == "allow"


def test_odd_tool_input_fails_closed(tmp_path: Path) -> None:
    d = POLICY.decide({"tool_name": "Bash", "tool_input": ["ls"]}, str(tmp_path))
    assert (d.decision, d.rule) == ("deny", "GW-99")


def test_mcp_spoofing_and_malformed_allowlists_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "mcp-allowlist.json"
    path.write_text(json.dumps({"servers": {"notes": {}}}), encoding="utf-8")
    assert decide(tmp_path, "mcp__notes__read").decision == "allow_mcp"
    assert decide(tmp_path, "mcp__notes__x__read").decision == "deny"  # server 'notes__x'
    assert decide(tmp_path, "mcp__notes").decision == "deny"  # no server/tool separator
    path.write_text(json.dumps({"servers": "notes-and-more"}), encoding="utf-8")
    assert decide(tmp_path, "mcp__notes__read").rule == "MCP-03"  # wrong type: fail closed


def _agent_call(minutes_before: int, fp: str, seq: int, tool: str, decision: str) -> dict[str, Any]:
    event = _agent_event(minutes_before, fp, seq)
    event["attributes"] = {**event["attributes"], "tool": tool, "decision": decision}
    if decision == "deny":
        event["event_type"] = "agent_tool_denied"
    return event


def test_r9_is_not_silenced_by_a_denied_call_or_a_listing() -> None:
    fp = "d" * 16
    denied = [_agent_call(8, fp, 1, "Read", "deny"), _decoy(fp)]
    [m] = [m for m in correlate(denied, Context()) if m.rule_id == "R9"]
    assert m.confidence == "high" and any("DENIED" in f for f in m.facts)
    listed = [_agent_call(8, fp, 1, "Glob", "allow"), _decoy(fp)]
    assert [m for m in correlate(listed, Context()) if m.rule_id == "R9"]
    read = [_agent_call(8, fp, 1, "Read", "allow"), _decoy(fp)]
    assert not [m for m in correlate(read, Context()) if m.rule_id == "R9"]


def test_changing_an_mcp_server_needs_a_person(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "state"
    _mcp_asset(Store(home / "sentinel.db"), "notes")
    args = ["--home", str(home), "inventory", "set", "mcp-notes", "--actor", "a"]
    assert main([*args, "--pinned-version", "99"]) == 1
    assert "interactive terminal" in capsys.readouterr().err


def test_kill_switch_warns_when_the_gateway_cannot_see_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stray = tmp_path / "elsewhere"
    assert main(["--home", str(stray), "agent", "kill-switch", "on"]) == 0
    assert "will NOT see it" in capsys.readouterr().err
    project = tmp_path / "project"
    (project / ".claude").mkdir(parents=True)
    assert main(["--home", str(project / ".sentinel"), "agent", "kill-switch", "on"]) == 0
    captured = capsys.readouterr()
    assert "will NOT see it" not in captured.err and "project" in captured.out
