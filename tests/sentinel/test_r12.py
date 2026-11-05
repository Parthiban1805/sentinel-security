"""R12 and the session risk score (v0.7c item 3, S11). Spec: docs/spec/correlation-rules.md."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel.cli import main
from sentinel.correlation.engine import correlate
from sentinel.correlation.model import Config, Context
from sentinel.correlation.rules import r12_sensitive_then_outbound
from sentinel.correlation.session_risk import (
    OUTBOUND_CLASSES,
    SENSITIVE_CLASSES,
    session_risk,
)
from sentinel.events.schema import make_event
from sentinel.incidents import lifecycle
from sentinel.simulation import scenarios
from sentinel.store.db import Store

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
SESSION = "a1b2c3d4e5f60718"
APPROVED = Context(approved_mcp_servers=frozenset({"approved"}))


def attempt(
    minutes: float,
    cls: str,
    decision: str = "deny",
    *,
    session: str = SESSION,
    tool: str = "Bash",
    is_test: bool = False,
    server: str | None = None,
) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "session": session,
        "tool": tool,
        "rule": "BG-03",
        "target_class": cls,
        "target_fp": "00ff",
        "decision": decision,
    }
    if server:
        attrs.update(mcp_server=server, mcp_tool="send")
    return make_event(
        event_type="agent_tool_denied" if decision == "deny" else "agent_tool_allowed",
        source="agent_hook",
        asset_id="agent-claude-code-demo",
        time=T0 + timedelta(minutes=minutes),
        severity="low" if decision == "deny" else "info",
        confidence="high",
        evidence_ref=f"agentlog/x/{minutes}",
        event_id=f"agentlog:x:{session}:{cls}:{decision}:{minutes}:{is_test}",
        is_test=is_test,
        attributes=attrs,
    )


def sensitive(minutes: float, **kw: Any) -> dict[str, Any]:
    return attempt(minutes, "credential_read", **kw)


def outbound(minutes: float, **kw: Any) -> dict[str, Any]:
    return attempt(minutes, "network_tool", **kw)


# --- R12 ------------------------------------------------------------------------------------
def test_true_positive_sensitive_then_outbound() -> None:
    [m] = r12_sensitive_then_outbound([sensitive(0), outbound(5)], Context())
    assert m.rule_id == "R12" and m.key.startswith(f"R12:{SESSION}@")
    assert m.severity_floor == "high" and m.confidence == "low"
    assert any("credential_read" in f and "network_tool" in f for f in m.facts)
    assert "keyword" in " ".join(m.hypotheses)  # the innocent explanation is stated
    assert any("does not show" in h for h in m.hypotheses)  # no proof that data left


def test_near_miss_outbound_before_sensitive() -> None:
    assert r12_sensitive_then_outbound([outbound(0), sensitive(5)], Context()) == []


def test_near_miss_outside_the_window() -> None:
    assert r12_sensitive_then_outbound([sensitive(0), outbound(16)], Context()) == []


def test_window_edge_is_inclusive() -> None:
    assert len(r12_sensitive_then_outbound([sensitive(0), outbound(15)], Context())) == 1


def test_same_instant_has_no_known_order() -> None:
    assert r12_sensitive_then_outbound([sensitive(0), outbound(0)], Context()) == []


def test_true_negative_across_sessions() -> None:
    events = [sensitive(0, session="aaaa000000000000"), outbound(1, session="bbbb000000000000")]
    assert r12_sensitive_then_outbound(events, Context()) == []


def test_true_negative_sensitive_only_or_outbound_only() -> None:
    assert r12_sensitive_then_outbound([sensitive(0), sensitive(1)], Context()) == []
    assert r12_sensitive_then_outbound([outbound(0), outbound(1)], Context()) == []


def test_other_classes_do_not_count() -> None:
    events = [attempt(0, "force_push"), attempt(1, "container_cli", "ask")]
    assert r12_sensitive_then_outbound(events, Context()) == []


def test_an_ask_decision_counts_as_an_attempt() -> None:
    events = [attempt(0, "env_dump", "ask"), attempt(3, "cloud_cli", "ask")]
    assert len(r12_sensitive_then_outbound(events, Context())) == 1


def test_a_plain_allowed_outbound_call_is_not_an_attempt() -> None:
    assert (
        r12_sensitive_then_outbound([sensitive(0), outbound(2, decision="allow")], Context()) == []
    )


def test_unapproved_mcp_call_is_outbound_in_allowlist_mode() -> None:
    mcp = attempt(3, "mcp", "allow_mcp", tool="mcp__evil__send", server="evil")
    assert len(r12_sensitive_then_outbound([sensitive(0), mcp], APPROVED)) == 1
    assert (
        r12_sensitive_then_outbound([sensitive(0), mcp], Context()) == []
    )  # not in allowlist mode
    ok = attempt(3, "mcp", "allow_mcp", tool="mcp__approved__send", server="approved")
    assert r12_sensitive_then_outbound([sensitive(0), ok], APPROVED) == []


def test_look_alike_mcp_name_is_not_approved() -> None:
    mcp = attempt(3, "mcp", "allow_mcp", tool="mcp__approved__x__send", server="approved__x")
    assert len(r12_sensitive_then_outbound([sensitive(0), mcp], APPROVED)) == 1


def test_many_pairs_are_one_incident_per_session() -> None:
    events = [sensitive(0), outbound(2), sensitive(4), outbound(6), sensitive(8), outbound(10)]
    [m] = r12_sensitive_then_outbound(events, Context())
    assert len(m.event_ids) == 6


def test_finds_a_later_pair_after_an_unrelated_early_attempt() -> None:
    events = [sensitive(0), sensitive(60), outbound(65)]
    [m] = r12_sensitive_then_outbound(events, Context())
    assert m.first_time.endswith("10:00:00Z")


def test_closed_episode_does_not_silence_later_activity() -> None:
    old = [sensitive(0), outbound(2)]
    new = [sensitive(120), outbound(122)]
    closed = {f"R12:{SESSION}": (T0 + timedelta(minutes=60)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    ctx = Context(closed_episodes=closed)
    assert r12_sensitive_then_outbound(old, ctx) == []
    [m] = r12_sensitive_then_outbound([*old, *new], ctx)
    assert m.first_time.endswith("11:00:00Z")


def test_test_events_are_marked_and_grouped_apart() -> None:
    [m] = r12_sensitive_then_outbound(
        [sensitive(0, is_test=True), outbound(1, is_test=True)], Context()
    )
    assert m.is_test and m.key.startswith(f"R12:{SESSION}:test@")
    mixed = [sensitive(0, is_test=True), outbound(1)]  # a test event never pairs with a real one
    assert r12_sensitive_then_outbound(mixed, Context()) == []


def test_order_independent_and_deterministic() -> None:
    events = [outbound(5), sensitive(0), attempt(2, "force_push")]
    assert r12_sensitive_then_outbound(events, Context()) == r12_sensitive_then_outbound(
        list(reversed(events)), Context()
    )


def test_window_is_configurable() -> None:
    tight = Context(config=Config(r12_window=timedelta(minutes=2)))
    assert r12_sensitive_then_outbound([sensitive(0), outbound(3)], tight) == []
    assert len(r12_sensitive_then_outbound([sensitive(0), outbound(2)], tight)) == 1


def test_sessionless_events_share_a_bucket_per_agent() -> None:
    events = [sensitive(0, session=""), outbound(1, session="")]
    [m] = r12_sensitive_then_outbound(events, Context())
    assert m.key.startswith("R12:unknown-agent-claude-code-demo@")  # no "@" in the base


def test_engine_runs_r12_and_it_can_coexist_with_r5b() -> None:
    events = [sensitive(0), outbound(1), attempt(2, "remote_access")]
    rules = {m.rule_id for m in correlate(events, Context())}
    assert rules == {"R5b", "R12"}


def test_class_sets_are_disjoint() -> None:
    assert not SENSITIVE_CLASSES & OUTBOUND_CLASSES


# --- session risk score ---------------------------------------------------------------------
def test_empty_session_is_low_zero() -> None:
    assert session_risk([], Context()) == {"level": "low", "points": 0, "reasons": []}


def test_weights_and_levels() -> None:
    other = session_risk([attempt(0, "force_push")], Context())
    assert (other["points"], other["level"]) == (1, "low")
    ask = session_risk([attempt(0, "container_cli", "ask")], Context())
    assert ask["points"] == 1
    two = session_risk([sensitive(0)], Context())
    assert (two["points"], two["level"]) == (2, "low")
    three = session_risk([sensitive(0), attempt(1, "force_push")], Context())
    assert (three["points"], three["level"]) == (3, "elevated")
    six = session_risk([sensitive(0), sensitive(30), sensitive(60)], Context())
    assert (six["points"], six["level"]) == (6, "high")


def test_the_sequence_adds_three_points_with_a_reason() -> None:
    risk = session_risk([sensitive(0), outbound(5)], Context())
    assert risk["points"] == 2 + 2 + 3 and risk["level"] == "high"
    assert any("sequence" in r for r in risk["reasons"])


def test_unapproved_mcp_call_adds_two_points() -> None:
    mcp = attempt(0, "mcp", "allow_mcp", tool="mcp__evil__send", server="evil")
    assert session_risk([mcp], APPROVED)["points"] == 2
    assert session_risk([mcp], Context())["points"] == 0  # not in allowlist mode


def test_unknown_class_counts_as_other() -> None:
    assert session_risk([attempt(0, "something_new")], Context())["points"] == 1


def test_every_point_has_a_reason_and_none_carry_raw_values() -> None:
    risk = session_risk([sensitive(0), outbound(5), attempt(6, "force_push")], Context())
    assert len(risk["reasons"]) == 4
    text = json.dumps(risk)
    assert "00ff" not in text and SESSION not in text  # no fingerprints, no session id


def test_score_is_order_independent() -> None:
    events = [outbound(5), sensitive(0), attempt(6, "force_push")]
    assert session_risk(events, Context()) == session_risk(list(reversed(events)), Context())


# --- incident record, CLI, coverage ---------------------------------------------------------
def store_with(tmp_path: Path, events: list[dict[str, Any]]) -> Store:
    store = Store(tmp_path / "sentinel.db")
    for e in events:
        store.add_event(e)
    return store


def test_incident_opens_with_plan_and_session_risk(tmp_path: Path) -> None:
    store = store_with(tmp_path, [sensitive(0), outbound(5), attempt(7, "force_push")])
    created = lifecycle.open_incidents(store, T0 + timedelta(hours=1))
    incident = next(
        store.get_doc("incidents", i)
        for i in created
        if store.get_doc("incidents", i)["rule_id"] == "R12"
    )
    assert incident["session_risk"]["level"] == "high"
    steps = {s["step"] for s in incident["response_plan"]}
    assert {"review_session_inputs", "end_session_revoke", "verify_agent_hooks"} <= steps
    assert any("sent anywhere" in u or "data" in u for u in incident["unknowns"])
    assert incident["hypotheses"]


def test_session_risk_covers_the_whole_session_not_only_the_matched_events(tmp_path: Path) -> None:
    extra = [attempt(-200, "force_push"), attempt(-190, "force_push")]
    store = store_with(tmp_path, [sensitive(0), outbound(5), *extra])
    created = lifecycle.open_incidents(store, T0 + timedelta(hours=1))
    incident = next(
        store.get_doc("incidents", i)
        for i in created
        if store.get_doc("incidents", i)["rule_id"] == "R12"
    )
    assert incident["session_risk"]["points"] == 2 + 2 + 3 + 1 + 1


def test_cli_agent_sessions_lists_risk(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store_with(
        home, [sensitive(0), outbound(5), attempt(1, "force_push", session="bbbb000000000000")]
    )
    assert main(["--home", str(home), "agent", "sessions"]) == 0
    out = capsys.readouterr().out
    assert "high" in out and "low" in out and "advisory" in out.lower()
    assert main(["--home", str(home), "agent", "sessions", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [s["level"] for s in data["sessions"]] == ["high", "low"]  # highest first


def test_cli_agent_sessions_ignores_test_events_unless_asked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store_with(home, [sensitive(0, is_test=True), outbound(1, is_test=True)])
    assert main(["--home", str(home), "agent", "sessions"]) == 0
    assert "no agent sessions" in capsys.readouterr().out
    assert main(["--home", str(home), "agent", "sessions", "--include-test"]) == 0
    assert "high" in capsys.readouterr().out


def test_simulated_scenario_produces_exactly_one_r12_incident(tmp_path: Path) -> None:
    store = Store(tmp_path / "sentinel.db")
    for e in scenarios.sensitive_then_outbound("5e55105e55105e55", "agent-demo", T0):
        store.add_event(e)
    created = lifecycle.open_incidents(store, T0 + timedelta(hours=1))
    assert [store.get_doc("incidents", i)["rule_id"] for i in created] == ["R12"]


# --- review fixes (2026-11-05 security review of ADR-0020) ----------------------------------
def test_large_session_is_fast() -> None:
    import time

    # 25k sensitive then 25k outbound, the outbound ones far outside the window: no pair.
    events = [sensitive(i / 100) for i in range(25_000)]
    events += [outbound(10_000 + i / 100) for i in range(25_000)]
    started = time.monotonic()
    assert r12_sensitive_then_outbound(events, Context()) == []
    risk = session_risk(events, Context())
    assert time.monotonic() - started < 20
    assert risk["points"] == 25_000 * 2 + 25_000 * 2  # no sequence points
    assert len(risk["reasons"]) <= 21  # aggregated, not one line per attempt


def test_reasons_are_aggregated_with_counts() -> None:
    risk = session_risk([sensitive(i) for i in range(5)], Context())
    assert risk["reasons"] == [
        "+10 blocked: sensitive access attempt (BG-03, credential_read) (x5)"
    ]


def test_reason_lines_are_capped() -> None:
    events = [attempt(i, f"class{i}") for i in range(60)]
    risk = session_risk(events, Context())
    assert len(risk["reasons"]) == 21 and risk["reasons"][-1].startswith("and 40 more")


def test_text_from_attributes_is_sanitised_and_capped() -> None:
    evil = attempt(0, "x" * 500 + "\x1b[31m\nINJECTED")
    risk = session_risk([evil], Context())
    text = json.dumps(risk)
    assert "\x1b" not in text and "INJECTED" not in text and len(risk["reasons"][0]) < 120


def test_malformed_events_never_crash() -> None:
    good = [sensitive(0), outbound(2)]
    bad: list[dict[str, Any]] = [
        {**attempt(1, "network_tool"), "attributes": ["not", "a", "mapping"]},
        {k: v for k, v in attempt(1, "network_tool").items() if k != "attributes"},
        {**attempt(1, "network_tool"), "time": "not a time"},
        {**attempt(1, "network_tool"), "time": None},
    ]
    assert len(r12_sensitive_then_outbound([*good, *bad], Context())) == 1
    assert session_risk([*good, *bad], Context())["points"] >= 7


def test_decision_allow_with_a_sensitive_class_is_not_an_attempt() -> None:
    events = [attempt(0, "credential_read", "allow"), outbound(1)]
    assert r12_sensitive_then_outbound(events, Context()) == []
    assert session_risk([events[0]], Context())["points"] == 0


def test_closed_episode_cut_equal_to_an_event_time_excludes_that_event() -> None:
    closed = {f"R12:{SESSION}": (T0 + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    events = [sensitive(0), outbound(2)]  # the outbound event is AT the cut: not after it
    assert r12_sensitive_then_outbound(events, Context(closed_episodes=closed)) == []


def test_sessionless_key_has_no_at_sign_in_its_base_for_r5b_and_r12() -> None:
    from sentinel.correlation.rules import r5b_repeated_agent_denials

    events = [attempt(i, "network_tool", session="") for i in range(3)]
    [m] = r5b_repeated_agent_denials(events, Context())
    assert m.key.split("@", 1)[0] == "R5b:unknown-agent-claude-code-demo"
    closed = {
        "R5b:unknown-agent-claude-code-demo": (T0 + timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    }
    assert r5b_repeated_agent_denials(events, Context(closed_episodes=closed)) == []


def test_agent_sessions_keeps_test_and_real_events_apart(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store_with(home, [sensitive(0), sensitive(1, is_test=True), outbound(2, is_test=True)])
    assert main(["--home", str(home), "agent", "sessions", "--include-test", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)["sessions"]
    assert sorted((r["test"], r["points"]) for r in rows) == [(False, 2), (True, 2 + 2 + 3)]


def test_agent_sessions_output_states_its_limits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store_with(home, [attempt(0, "container_cli", "allow")])  # an event, but not an attempt
    assert main(["--home", str(home), "agent", "sessions"]) == 0
    out = capsys.readouterr().out
    assert "no time limit" in out and "no refused or questioned attempts logged" in out
    assert "not mean nothing happened" in out


def test_no_secret_in_incident_or_session_output(tmp_path: Path) -> None:
    from sentinel.simulation.fakes import fake_google_key

    fake = fake_google_key()
    events = [sensitive(0), outbound(4)]
    for e in events:
        e["attributes"]["target_fp"] = "00ff"  # keyed fingerprint only, never the value
    store = store_with(tmp_path, events)
    created = lifecycle.open_incidents(store, T0 + timedelta(hours=1))
    dump = json.dumps([store.get_doc("incidents", i) for i in created])
    assert fake not in dump and fake[:12] not in dump
