"""R5a/R5b/R5c (agent visibility, S11/S12): pure rule tests. Specs: docs/spec/correlation-rules.md."""

from datetime import UTC, datetime, timedelta
from typing import Any

from sentinel.correlation.engine import correlate
from sentinel.correlation.model import Config, Context
from sentinel.correlation.rules import r5b_repeated_agent_denials, r5c_unapproved_mcp_server
from sentinel.events.schema import make_event
from sentinel.simulation import scenarios

T0 = datetime(2026, 10, 31, 9, 0, tzinfo=UTC)
SESSION = "a1b2c3d4e5f60718"


def denial(minutes: float, session: str = SESSION, *, is_test: bool = False) -> dict[str, Any]:
    return make_event(
        event_type="agent_tool_denied",
        source="agent_hook",
        asset_id="agent-claude-code-demo",
        time=T0 + timedelta(minutes=minutes),
        severity="low",
        confidence="high",
        evidence_ref=f"agentlog/x/{minutes}",
        event_id=f"agentlog:x:{session}:{minutes}",
        is_test=is_test,
        attributes={
            "session": session,
            "tool": "Bash",
            "rule": "BG-03",
            "target_class": "network_tool",
            "target_fp": "00ff",
            "decision": "deny",
        },
    )


# --- R5a: a single denial is context only ------------------------------------------------
def test_r5a_a_single_denial_opens_nothing() -> None:
    assert r5b_repeated_agent_denials([denial(0)], Context()) == []
    assert correlate([denial(0)], Context()) == []


# --- R5b ------------------------------------------------------------------------------------
def test_r5b_true_positive_three_in_thirty_minutes() -> None:
    [m] = r5b_repeated_agent_denials([denial(0), denial(10), denial(29)], Context())
    assert m.rule_id == "R5b" and m.key.startswith(f"R5b:{SESSION}@")
    assert m.severity_floor == "medium" and m.confidence == "low"
    assert any("BG-03" in f and "network_tool" in f for f in m.facts)
    assert m.hypotheses and "keyword" in m.hypotheses[0]  # the innocent explanation is stated


def test_r5b_near_miss_outside_the_window() -> None:
    assert r5b_repeated_agent_denials([denial(0), denial(15), denial(31)], Context()) == []


def test_r5b_true_negative_across_sessions() -> None:
    events = [denial(0, "aaaa000000000000"), denial(1, "bbbb000000000000"), denial(2)]
    assert r5b_repeated_agent_denials(events, Context()) == []


def test_r5b_a_flood_is_one_incident_per_session() -> None:
    events = [denial(i) for i in range(20)]
    [m] = r5b_repeated_agent_denials(events, Context())
    assert len(m.event_ids) == 20 and "20 blocked" in m.title


def test_r5b_finds_a_later_burst_after_spread_out_denials() -> None:
    events = [denial(0), denial(60), denial(120), denial(121), denial(122)]
    [m] = r5b_repeated_agent_denials(events, Context())
    assert m.first_time.endswith("11:00:00Z") and len(m.event_ids) == 3


def test_r5b_thresholds_are_configurable() -> None:
    strict = Context(config=Config(r5b_count=5, r5b_window=timedelta(minutes=10)))
    events = [denial(0), denial(1), denial(2), denial(3)]
    assert r5b_repeated_agent_denials(events, strict) == []
    assert len(r5b_repeated_agent_denials([*events, denial(4)], strict)) == 1


def test_r5b_test_events_are_marked_test() -> None:
    [m] = r5b_repeated_agent_denials([denial(i, is_test=True) for i in range(3)], Context())
    assert m.is_test


def test_r5b_is_order_independent() -> None:
    events = [denial(29), denial(0), denial(10)]
    assert r5b_repeated_agent_denials(events, Context()) == r5b_repeated_agent_denials(
        list(reversed(events)), Context()
    )


def test_r5b_output_holds_no_raw_command_or_path() -> None:
    [m] = r5b_repeated_agent_denials([denial(0), denial(1), denial(2)], Context())
    text = " ".join([m.title, *m.facts, *m.hypotheses])
    assert "curl" not in text and "/" not in text.replace("BG-03", "")  # no paths, no commands


# --- R5c ------------------------------------------------------------------------------------
APPROVED = Context(approved_mcp_servers=frozenset({"trusted"}))


def test_r5c_is_silent_until_a_server_is_approved() -> None:
    assert (
        r5c_unapproved_mcp_server(scenarios.unapproved_mcp("rogue", "agent-x", T0), Context()) == []
    )


def test_r5c_flags_an_unapproved_server_once_allowlisting_is_on() -> None:
    events = scenarios.unapproved_mcp("rogue", "agent-x", T0) * 1 + scenarios.unapproved_mcp(
        "rogue", "agent-x", T0 + timedelta(minutes=5)
    )
    [m] = r5c_unapproved_mcp_server(events, APPROVED)
    assert m.rule_id == "R5c" and m.key.startswith("R5c:rogue:test@")  # simulated = test events
    assert m.severity_floor == "high"
    assert "rogue" in m.title and m.is_test


def test_r5c_approved_servers_are_quiet() -> None:
    assert (
        r5c_unapproved_mcp_server(scenarios.unapproved_mcp("trusted", "agent-x", T0), APPROVED)
        == []
    )


def test_r5c_one_incident_per_server() -> None:
    events = [
        *scenarios.unapproved_mcp("one", "agent-x", T0),
        *scenarios.unapproved_mcp("two", "agent-x", T0),
        *scenarios.unapproved_mcp("one", "agent-x", T0 + timedelta(hours=1)),
    ]
    keys = sorted(m.key.split("@")[0] for m in r5c_unapproved_mcp_server(events, APPROVED))
    assert keys == ["R5c:one:test", "R5c:two:test"]


def test_steered_agent_simulation_raises_one_incident_not_a_flood() -> None:
    """Product-plan exit criterion for v0.3b, on simulated input."""
    events = scenarios.steered_agent(SESSION, "agent-x", T0, count=12)
    matches = correlate(events, Context())
    assert [m.rule_id for m in matches] == ["R5b"]


# --- review fixes ---------------------------------------------------------------------------
def test_r5b_window_boundary_is_inclusive() -> None:
    assert len(r5b_repeated_agent_denials([denial(0), denial(15), denial(30)], Context())) == 1


def test_r5b_denials_without_a_session_are_not_dropped() -> None:
    [m] = r5b_repeated_agent_denials([denial(0, ""), denial(1, ""), denial(2, "")], Context())
    assert "unknown" in m.key


def test_a_test_event_never_masks_or_marks_real_events() -> None:
    events = [denial(0), denial(1), denial(2), denial(3, is_test=True)]
    [m] = r5b_repeated_agent_denials(events, Context())
    assert m.is_test is False and len(m.event_ids) == 3


def test_a_closed_episode_does_not_silence_a_later_burst() -> None:
    first = [denial(0), denial(1), denial(2)]
    [m1] = r5b_repeated_agent_denials(first, Context())
    closed = Context(closed_episodes={m1.key.split("@")[0]: "2026-10-31T10:00:00Z"})
    assert r5b_repeated_agent_denials(first, closed) == []  # the old burst stays closed
    later = [*first, denial(120), denial(121), denial(122)]
    [m2] = r5b_repeated_agent_denials(later, closed)
    assert m2.key != m1.key and m2.first_time.endswith("11:00:00Z")


def test_r5c_approval_needs_the_exact_name() -> None:
    ctx = Context(approved_mcp_servers=frozenset({"GitHub"}))
    assert len(r5c_unapproved_mcp_server(scenarios.unapproved_mcp("github", "a", T0), ctx)) == 1
    assert r5c_unapproved_mcp_server(scenarios.unapproved_mcp("GitHub", "a", T0), ctx) == []


def test_r5c_an_ambiguous_double_underscore_name_is_not_the_approved_server() -> None:
    """mcp__git__hub__x is ambiguous: tool 'hub__x' of 'git', or a server named 'git__hub'.
    Changed 2026-11-03 (ADR-0016, security review): the gateway and R5c both read the server as
    everything before the LAST '__', so a server named 'git__hub' cannot pass as the approved
    'git'. The cost is an alert for a legitimate tool whose own name contains '__'."""
    event = scenarios.unapproved_mcp("git", "a", T0)[0]
    event["attributes"]["tool"] = "mcp__git__hub__x"
    event["attributes"]["mcp_server"] = "git__hub"
    [match] = r5c_unapproved_mcp_server([event], Context(approved_mcp_servers=frozenset({"git"})))
    assert match.rule_id == "R5c"
    plain = scenarios.unapproved_mcp("git", "a", T0)  # mcp__git__read_file: the approved server
    assert r5c_unapproved_mcp_server(plain, Context(approved_mcp_servers=frozenset({"git"}))) == []
