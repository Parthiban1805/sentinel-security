"""Agent log source, agent/MCP inventory, runner wiring and the hooks verifier (v0.3b)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel import agentlog, runner
from sentinel.cli import main
from sentinel.config import Settings
from sentinel.incidents import lifecycle
from sentinel.inventory import agents
from sentinel.sources.agent import AgentLogSource, parse_mcp_tool
from sentinel.store.db import Store

T0 = datetime(2026, 10, 31, 9, 0, tzinfo=UTC)
SESSION = "a1b2c3d4e5f60718"
FAKE = "not-a-real-value-" + "x" * 12  # stands in for a credential in config files


def entry(seq: int, decision: str, tool: str = "Bash", minutes: int = 0, **kw: Any) -> dict:
    return {
        "v": 1,
        "seq": seq,
        "time": (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "session": kw.get("session", SESSION),
        "tool": tool,
        "decision": decision,
        "rule": kw.get("rule", "BG-03"),
        "target_class": kw.get("target_class", "network_tool"),
        "target_fp": kw.get("target_fp", "00ff00ff00ff00ff"),
    }


def write_log(home: Path, entries: list[dict[str, Any]]) -> Path:
    """A chained log exactly as the hooks write it (prev + hash per line)."""
    home.mkdir(parents=True, exist_ok=True)
    prev, lines = agentlog.GENESIS, []
    for e in entries:
        digest = agentlog.chain_hash(prev, e)
        lines.append(json.dumps({**e, "prev": prev, "hash": digest}))
        prev = digest
    path = home / agentlog.LOG_NAME
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def collect(store: Store, home: Path) -> list[dict[str, Any]]:
    source = AgentLogSource()
    events = source.collect(store, home, T0)
    for e in events:
        store.add_event(e)
    source.commit(store)
    return events


def mcp_config(folder: Path, servers: dict[str, Any]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")


# --- source -------------------------------------------------------------------------------------
def test_parse_mcp_tool_names() -> None:
    assert parse_mcp_tool("mcp__github__list_issues") == ("github", "list_issues")
    assert parse_mcp_tool("mcp__claude_ai_Claude_Docs__batch") == ("claude_ai_Claude_Docs", "batch")
    assert parse_mcp_tool("mcp__odd") == ("odd", "")


def test_denials_and_mcp_calls_become_events_heartbeats_do_not(tmp_path: Path) -> None:
    home = tmp_path / "proj" / ".sentinel"
    write_log(
        home,
        [
            entry(1, "session_start", "session", rule="SS-01", target_class="session"),
            entry(2, "deny", minutes=1),
            entry(3, "allow_mcp", "mcp__github__list_issues", minutes=2, rule="MCP-01"),
        ],
    )
    store = Store(tmp_path / "s.db")
    events = collect(store, home)
    assert [e["event_type"] for e in events] == ["agent_tool_denied", "agent_tool_allowed"]
    denied, allowed = events
    assert denied["severity"] == "low" and denied["asset_id"] == "agent-claude-code-proj"
    assert allowed["attributes"]["mcp_server"] == "github"
    assert not any(e["is_test"] for e in events)


def test_an_odd_session_value_is_dropped(tmp_path: Path) -> None:
    home = tmp_path / "proj" / ".sentinel"
    write_log(home, [entry(1, "deny", session="not hex, and much too long for a hash")])
    [event] = collect(Store(tmp_path / "s.db"), home)
    assert event["attributes"]["session"] == ""


def test_only_new_entries_are_emitted_and_reruns_add_nothing(tmp_path: Path) -> None:
    home = tmp_path / "proj" / ".sentinel"
    store = Store(tmp_path / "s.db")
    write_log(home, [entry(1, "deny"), entry(2, "deny", minutes=1)])
    assert len(collect(store, home)) == 2
    assert collect(store, home) == []
    write_log(home, [entry(1, "deny"), entry(2, "deny", minutes=1), entry(3, "deny", minutes=2)])
    [new] = collect(store, home)
    assert new["evidence_ref"].endswith("/3")


def test_a_tampered_log_emits_nothing(tmp_path: Path) -> None:
    home = tmp_path / "proj" / ".sentinel"
    path = write_log(home, [entry(1, "deny"), entry(2, "deny", minutes=1)])
    lines = path.read_text(encoding="utf-8").splitlines()
    edited = json.loads(lines[1])
    edited["rule"] = "XX-99"  # content changed, hash not
    path.write_text(lines[0] + "\n" + json.dumps(edited) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="failed verification"):
        AgentLogSource().collect(Store(tmp_path / "s.db"), home, T0)


def test_a_shortened_log_of_the_same_chain_is_refused(tmp_path: Path) -> None:
    home = tmp_path / "proj" / ".sentinel"
    store = Store(tmp_path / "s.db")
    write_log(home, [entry(1, "deny"), entry(2, "deny", minutes=1)])
    collect(store, home)
    write_log(home, [entry(1, "deny")])  # same first entry (same chain), tail removed
    with pytest.raises(ValueError, match="shorter"):
        AgentLogSource().collect(store, home, T0)


def test_a_rewritten_entry_of_the_same_chain_is_refused(tmp_path: Path) -> None:
    home = tmp_path / "proj" / ".sentinel"
    store = Store(tmp_path / "s.db")
    write_log(home, [entry(1, "deny"), entry(2, "deny", minutes=1)])
    collect(store, home)
    write_log(home, [entry(1, "deny"), entry(2, "deny", minutes=1, rule="XX-01")])  # re-chained
    with pytest.raises(ValueError, match="history changed"):
        AgentLogSource().collect(store, home, T0)


def test_an_archived_log_with_a_new_chain_is_read_from_the_start(tmp_path: Path) -> None:
    home = tmp_path / "proj" / ".sentinel"
    store = Store(tmp_path / "s.db")
    write_log(home, [entry(1, "deny"), entry(2, "deny", minutes=1)])
    collect(store, home)
    write_log(home, [entry(1, "deny", minutes=30, session="ffff000000000000")])
    [event] = collect(store, home)
    assert event["attributes"]["session"] == "ffff000000000000"


def test_the_cursor_waits_for_the_caller_to_commit(tmp_path: Path) -> None:
    """DeferredState: if storing fails, the same entries are read again next time."""
    home = tmp_path / "proj" / ".sentinel"
    store = Store(tmp_path / "s.db")
    write_log(home, [entry(1, "deny")])
    AgentLogSource().collect(store, home, T0)  # not committed
    assert len(AgentLogSource().collect(store, home, T0)) == 1


# --- inventory -----------------------------------------------------------------------------
def test_mcp_inventory_keeps_names_and_hosts_never_env_headers_or_args(tmp_path: Path) -> None:
    mcp_config(
        tmp_path,
        {
            "github": {
                "command": "C:/tools/npx.cmd",
                "args": ["-y", "server-github", "--token", FAKE],
                "env": {"GITHUB_TOKEN": FAKE},
            },
            "docs": {
                "type": "http",
                "url": f"https://user:{FAKE}@mcp.example.invalid/v1?key={FAKE}",
                "headers": {"Authorization": f"Bearer {FAKE}"},
            },
            "oneline": {"command": f"npx -y pkg --api-key {FAKE}"},
            "slashy": {"command": f"docker run -e TOKEN=ab/{FAKE} img"},
            "bad name; rm": {"command": "x"},
        },
    )
    store = Store(tmp_path / "s.db")
    ids, skipped = agents.discover_mcp(store, tmp_path, T0)
    assert sorted(ids) == ["mcp-docs", "mcp-github", "mcp-oneline", "mcp-slashy"]
    assert skipped == 1
    stored = json.dumps(store.assets())
    assert FAKE not in stored and "--token" not in stored and "user:" not in stored
    by_id = {a["asset_id"]: a["attributes"] for a in store.assets()}
    assert by_id["mcp-github"]["command"] == "npx.cmd"
    assert by_id["mcp-github"]["transport"] == "stdio"
    assert by_id["mcp-oneline"]["command"] == "npx"
    assert by_id["mcp-slashy"]["command"] == "docker"
    assert by_id["mcp-docs"]["host"] == "mcp.example.invalid"


def test_odd_transport_and_unparsable_url_are_stored_as_fixed_words(tmp_path: Path) -> None:
    mcp_config(tmp_path, {"odd": {"type": f"weird-{FAKE}", "url": f"https://[{FAKE}/x"}})
    store = Store(tmp_path / "s.db")
    agents.discover_mcp(store, tmp_path, T0)
    [attrs] = [a["attributes"] for a in store.assets()]
    assert attrs["transport"] == "unknown" and attrs["host"] == "unparsable"
    assert FAKE not in json.dumps(store.assets())


def test_look_alike_names_never_share_an_id(tmp_path: Path) -> None:
    mcp_config(tmp_path, {"github": {"command": "npx"}, "GitHub": {"command": "npx"},
                          "git_hub": {"command": "npx"}, "git-hub": {"command": "npx"}})  # fmt: skip
    ids, _ = agents.discover_mcp(Store(tmp_path / "s.db"), tmp_path, T0)
    assert len(set(ids)) == 4


def test_approval_survives_rediscovery_but_not_a_config_change(tmp_path: Path) -> None:
    mcp_config(tmp_path, {"docs": {"type": "http", "url": "https://good.example.invalid/mcp"}})
    store = Store(tmp_path / "s.db")
    agents.discover_mcp(store, tmp_path, T0)
    asset = next(a for a in store.assets() if a["asset_id"] == "mcp-docs")
    store.upsert_asset({**asset, "approved": True, "owner": "me"})
    agents.discover_mcp(store, tmp_path, T0 + timedelta(days=1))
    assert agents.approved_servers(store) == frozenset({"docs"})
    mcp_config(tmp_path, {"docs": {"type": "http", "url": "https://evil.example.invalid/mcp"}})
    agents.discover_mcp(store, tmp_path, T0 + timedelta(days=2))
    asset = next(a for a in store.assets() if a["asset_id"] == "mcp-docs")
    assert asset["approved"] is False and asset["owner"] == "me"
    assert any(r["action"] == "mcp_approval_cleared" for r in store.audit())


def test_a_broken_mcp_config_is_an_error_without_its_content(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"x": "secret-ish-text"', encoding="utf-8")
    with pytest.raises(ValueError, match="not readable JSON") as caught:
        agents.discover_mcp(Store(tmp_path / "s.db"), tmp_path, T0)
    assert "secret-ish" not in str(caught.value)


def test_no_mcp_config_means_no_servers(tmp_path: Path) -> None:
    assert agents.discover_mcp(Store(tmp_path / "s.db"), tmp_path, T0) == ([], 0)


# --- runner, end to end ---------------------------------------------------------------------
def run(tmp_path: Path, store: Store) -> dict[str, Any]:
    return runner.run_once(
        store, tmp_path / "proj" / ".sentinel", Settings(), T0 + timedelta(hours=1),
        toast=lambda *_: False, scan=False,
    )  # fmt: skip


def test_runner_turns_a_burst_of_denials_into_one_r5b_incident(tmp_path: Path) -> None:
    home = tmp_path / "proj" / ".sentinel"
    write_log(home, [entry(i + 1, "deny", minutes=i * 3) for i in range(6)])
    store = Store(tmp_path / "s.db")
    result = run(tmp_path, store)
    assert result["health"]["agentlog"] == "ok" and result["health"]["agentlog:events"] == "ok"
    [incident] = [store.get_doc("incidents", i) for i in result["incidents_created"]]
    assert incident is not None and incident["rule_id"] == "R5b"
    assert [s["step"] for s in incident["response_plan"]] == [
        "review_session_inputs",
        "end_session_revoke",
        "verify_agent_hooks",
    ]
    assert any(a["asset_type"] == "ai_agent" for a in store.assets())
    assert any("R5c" in n and "inactive" in n for n in result["notes"])
    assert run(tmp_path, store)["incidents_created"] == []  # no duplicate next run


def test_a_broken_mcp_config_never_stops_the_log_from_being_read(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".mcp.json").write_text("{ broken", encoding="utf-8")
    write_log(proj / ".sentinel", [entry(i + 1, "deny", minutes=i) for i in range(3)])
    store = Store(tmp_path / "s.db")
    result = run(tmp_path, store)
    assert result["health"]["agentlog:events"] == "ok"
    assert result["health"]["inventory:agents"].startswith("error:")
    assert len(result["incidents_created"]) == 1


def test_runner_r5c_once_a_server_is_approved(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    mcp_config(proj, {"github": {"command": "npx"}})
    write_log(proj / ".sentinel", [entry(1, "allow_mcp", "mcp__rogue__read_file", rule="MCP-01")])
    store = Store(tmp_path / "s.db")
    assert run(tmp_path, store)["incidents_created"] == []  # nothing approved yet: quiet
    asset = next(a for a in store.assets() if a["asset_id"] == "mcp-github")
    store.upsert_asset({**asset, "approved": True})
    [iid] = lifecycle.open_incidents(store, T0 + timedelta(hours=2))
    assert (store.get_doc("incidents", iid) or {})["rule_id"] == "R5c"


def test_a_closed_r5c_incident_does_not_silence_later_use(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    mcp_config(proj, {"github": {"command": "npx"}})
    home = proj / ".sentinel"
    write_log(home, [entry(1, "allow_mcp", "mcp__rogue__read_file", rule="MCP-01")])
    store = Store(tmp_path / "s.db")
    run(tmp_path, store)
    asset = next(a for a in store.assets() if a["asset_id"] == "mcp-github")
    store.upsert_asset({**asset, "approved": True})
    [first] = lifecycle.open_incidents(store, T0 + timedelta(hours=2))
    lifecycle.close(store, first, "me", T0 + timedelta(hours=3), unverified_note="removed it")
    write_log(home, [entry(1, "allow_mcp", "mcp__rogue__read_file", rule="MCP-01"),
                     entry(2, "allow_mcp", "mcp__rogue__read_file", minutes=300, rule="MCP-01")])  # fmt: skip
    collect(store, home)
    [second] = lifecycle.open_incidents(store, T0 + timedelta(hours=6))
    assert second != first


# --- CLI guards ------------------------------------------------------------------------------
def test_approving_an_mcp_server_needs_a_human(tmp_path: Path, capsys: Any) -> None:
    mcp_config(tmp_path / "proj", {"github": {"command": "npx"}})
    home = tmp_path / "proj" / ".sentinel"
    home.mkdir(parents=True)
    store = Store(home / "sentinel.db")
    agents.discover_mcp(store, tmp_path / "proj", T0)
    code = main(
        ["--home", str(home), "inventory", "set", "mcp-github", "--actor", "x", "--approve"]
    )
    assert code != 0 and "interactive terminal" in capsys.readouterr().err
    assert agents.approved_servers(store) == frozenset()


def test_pinning_hooks_needs_a_human(tmp_path: Path, capsys: Any) -> None:
    code = main(["--home", str(tmp_path / ".sentinel"), "agentlog", "pin-hooks", "--actor", "x"])
    assert code != 0 and "interactive terminal" in capsys.readouterr().err


# --- hooks verifier ---------------------------------------------------------------------------
def install_hooks(workspace: Path) -> None:
    hooks = workspace / ".claude" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    for name in runner.AGENT_HOOK_FILES:
        (hooks / name).write_text(f"# reviewed {name}\n")
    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "x"}]}]}}
    (workspace / ".claude" / "settings.json").write_text(json.dumps(settings))


def r5b_store(tmp_path: Path, *, pin: bool = True) -> tuple[Store, str, Path, Path]:
    workspace = tmp_path / "proj"
    home = workspace / ".sentinel"
    write_log(home, [entry(i + 1, "deny", minutes=i) for i in range(3)])
    store = Store(tmp_path / "s.db")
    [iid] = run(tmp_path, store)["incidents_created"]
    install_hooks(workspace)
    if pin:
        runner.pin_agent_hooks(store, workspace, "owner", T0)
    return store, iid, workspace, home


def test_verify_agent_hooks_passes_when_hooks_match_the_pin(tmp_path: Path) -> None:
    store, iid, _workspace, home = r5b_store(tmp_path)
    passed, evidence = runner.verify_agent_hooks(store, iid, "me", T0, home)
    assert passed and "chain intact" in evidence and evidence.count("matches pin") == 5


def test_editing_the_patch_folder_cannot_make_weakened_hooks_pass(tmp_path: Path) -> None:
    """The reference is the pin in the store, not any file the agent can edit."""
    store, iid, workspace, home = r5b_store(tmp_path)
    patch = workspace / "docs" / "patches" / "agent-decision-log"
    patch.mkdir(parents=True)
    for name in runner.AGENT_HOOK_FILES:
        (patch / name).write_text("# weakened\n")
        (workspace / ".claude" / "hooks" / name).write_text("# weakened\n")
    passed, evidence = runner.verify_agent_hooks(store, iid, "me", T0, home)
    assert not passed and "CHANGED" in evidence


def test_verify_agent_hooks_fails_on_a_changed_or_missing_hook(tmp_path: Path) -> None:
    store, iid, workspace, home = r5b_store(tmp_path)
    (workspace / ".claude" / "hooks" / "bash_guard.py").write_text("# weakened\n")
    (workspace / ".claude" / "hooks" / "mcp_log.py").unlink()
    passed, evidence = runner.verify_agent_hooks(store, iid, "me", T0, home)
    assert not passed and "bash_guard.py: CHANGED" in evidence and "mcp_log.py: MISSING" in evidence


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    [
        ("settings.local.json", {"disableAllHooks": True}, "DISABLES all hooks"),
        ("settings.local.json", {"hooks": {}}, "OVERRIDES hooks"),
        ("settings.json", {"hooks": {}}, "settings.json hooks: CHANGED"),
        ("settings.json", {"disableAllHooks": True, "hooks": None}, "DISABLES all hooks"),
    ],
)
def test_verify_agent_hooks_fails_when_settings_disable_or_override_hooks(
    tmp_path: Path, name: str, content: dict[str, Any], expected: str
) -> None:
    store, iid, workspace, home = r5b_store(tmp_path)
    (workspace / ".claude" / name).write_text(json.dumps(content))
    passed, evidence = runner.verify_agent_hooks(store, iid, "me", T0, home)
    assert not passed and expected in evidence


def test_verify_agent_hooks_fails_when_the_log_was_tampered(tmp_path: Path) -> None:
    store, iid, _workspace, home = r5b_store(tmp_path)
    path = home / agentlog.LOG_NAME
    path.write_text(path.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")
    passed, evidence = runner.verify_agent_hooks(store, iid, "me", T0, home)
    assert not passed and "chain NOT intact" in evidence  # truncated below the anchor


def test_verify_agent_hooks_needs_a_pin(tmp_path: Path) -> None:
    store, iid, _workspace, home = r5b_store(tmp_path, pin=False)
    with pytest.raises(ValueError, match="no reviewed hook pin"):
        runner.verify_agent_hooks(store, iid, "me", T0, home)


def test_an_overridden_hook_set_cannot_be_pinned(tmp_path: Path) -> None:
    workspace = tmp_path / "proj"
    install_hooks(workspace)
    (workspace / ".claude" / "settings.local.json").write_text(json.dumps({"hooks": {}}))
    with pytest.raises(ValueError, match="cannot pin"):
        runner.pin_agent_hooks(Store(tmp_path / "s.db"), workspace, "owner", T0)
