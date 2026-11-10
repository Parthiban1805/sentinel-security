"""R13, the output-guard events and the trifecta score (v0.7e F1, ADR-0027, S11)."""

from datetime import UTC, datetime, timedelta
from typing import Any

from sentinel.correlation.engine import correlate
from sentinel.correlation.model import Context
from sentinel.correlation.rules import r13_trifecta_gate
from sentinel.correlation.session_risk import OUTBOUND_CLASSES, session_risk
from sentinel.events.schema import make_event
from sentinel.simulation import scenarios
from sentinel.sources.agent import AgentLogSource

T0 = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)
SESSION = "a1b2c3d4e5f60718"


def guard_event(
    minutes: float, rule: str, decision: str, cls: str, *, session: str = SESSION,
    tool: str = "Bash", is_test: bool = False, n: int = 0,
) -> dict[str, Any]:  # fmt: skip
    return make_event(
        event_type="agent_tool_allowed",
        source="agent_hook",
        asset_id="agent-x",
        time=T0 + timedelta(minutes=minutes),
        severity="info",
        confidence="high",
        evidence_ref=f"agentlog/c/{n}",
        event_id=f"agentlog:c:{session}:{n}:{rule}",
        is_test=is_test,
        attributes={
            "session": session,
            "tool": tool,
            "rule": rule,
            "target_class": cls,
            "target_fp": "",
            "decision": decision,
        },  # fmt: skip
    )


def tainted_session(session: str = SESSION, *, is_test: bool = False) -> list[dict[str, Any]]:
    return [
        guard_event(
            0,
            "OG-10",
            "taint",
            "untrusted_input",
            session=session,
            tool="WebFetch",
            is_test=is_test,
            n=1,
        ),  # fmt: skip
        guard_event(
            2, "OG-01", "output_redacted", "output_secret", session=session, is_test=is_test, n=2
        ),  # fmt: skip
        guard_event(
            5, "TF-01", "ask", "trifecta", session=session, tool="WebFetch", is_test=is_test, n=3
        ),  # fmt: skip
        guard_event(
            6,
            "TF-01",
            "ask",
            "trifecta",
            session=session,
            tool="mcp__x__send",
            is_test=is_test,
            n=4,
        ),  # fmt: skip
    ]


# --- the decision log -> events ---------------------------------------------------------------
def record(decision: str, rule: str, cls: str) -> dict[str, Any]:
    return {"decision": decision, "session": SESSION, "tool": "Bash", "rule": rule,
            "target_class": cls, "target_fp": "", "seq": 7,
            "time": "2026-11-06T12:00:00Z"}  # fmt: skip


def test_output_guard_records_become_allowed_tool_events() -> None:
    for decision, rule, cls, severity in (
        ("output_redacted", "OG-01", "output_secret", "low"),
        ("output_tainted", "OG-02", "output_secret_unredacted", "low"),
        ("taint", "OG-10", "untrusted_input", "info"),
        ("output_error", "OG-99", "output_guard_error", "low"),
    ):
        event = AgentLogSource._event(record(decision, rule, cls), "chain", "agent-x")
        assert event is not None
        assert event["event_type"] == "agent_tool_allowed" and event["severity"] == severity
        assert event["attributes"]["decision"] == decision
        assert event["attributes"]["rule"] == rule


def test_output_guard_events_add_no_points_by_themselves() -> None:
    events = tainted_session()[:2]
    assert session_risk(events, Context())["points"] == 0
    assert r13_trifecta_gate(events, Context()) == []


# --- R13 ----------------------------------------------------------------------------------------
def test_the_gate_firing_opens_one_incident_with_the_guard_evidence() -> None:
    events = tainted_session()
    matches = r13_trifecta_gate(events, Context())
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "R13" and m.severity_floor == "high"
    assert m.key == f"R13:{SESSION}@{events[2]['time']}"
    assert set(m.event_ids) == {e["event_id"] for e in events}
    assert m.first_time == events[0]["time"] and m.last_time == events[-1]["time"]
    assert any("OG-01" in f for f in m.facts) and any("2 data-leaving" in f for f in m.facts)
    assert any("not recorded" in f for f in m.facts)  # whether the person allowed it
    assert m.hypotheses and all("injection" in h or "legitimate" in h for h in m.hypotheses)


def test_r13_is_per_session_and_keeps_tests_apart() -> None:
    events = tainted_session("1111111111111111") + tainted_session("2222222222222222")
    events += tainted_session("1111111111111111", is_test=True)
    keys = sorted(m.key.split("@")[0] for m in r13_trifecta_gate(events, Context()))
    assert keys == ["R13:1111111111111111", "R13:1111111111111111:test", "R13:2222222222222222"]


def test_a_closed_incident_does_not_silence_a_later_episode() -> None:
    events = tainted_session()
    closed = Context(closed_episodes={f"R13:{SESSION}": events[-1]["time"]})
    assert r13_trifecta_gate(events, closed) == []
    later = guard_event(30, "TF-01", "ask", "trifecta", tool="WebSearch", n=9)
    assert len(r13_trifecta_gate([*events, later], closed)) == 1


def test_a_gate_error_is_not_the_trifecta() -> None:
    events = [guard_event(1, "TF-99", "ask", "trifecta_error", tool="WebFetch")]
    assert r13_trifecta_gate(events, Context()) == []


def test_r13_is_registered_and_the_scenario_fires_only_r13() -> None:
    events = scenarios.trifecta_exfil(SESSION, "agent-demo", T0)
    assert [m.rule_id for m in correlate(events, Context())] == ["R13"]
    assert all(e["is_test"] for e in events)


# --- the score ----------------------------------------------------------------------------------
def test_the_gate_is_an_outbound_attempt_with_a_bonus() -> None:
    assert "trifecta" in OUTBOUND_CLASSES
    risk = session_risk(tainted_session(), Context())
    # two asks (+1 each), plus the trifecta bonus once (+3)
    assert risk["points"] == 5 and risk["level"] == "elevated"
    assert any("R13" in r and r.startswith("+3") for r in risk["reasons"])


def test_a_leg_set_by_a_guard_error_is_not_called_a_seen_credential() -> None:
    """Rule 6: OG-99 sets leg S as a precaution; R13 must not state that a key was seen."""
    events = [
        guard_event(0, "OG-10", "taint", "untrusted_input", tool="WebFetch", n=1),
        guard_event(1, "OG-99", "output_error", "output_guard_error", n=2),
        guard_event(3, "TF-01", "ask", "trifecta", tool="WebFetch", n=3),
    ]
    (m,) = r13_trifecta_gate(events, Context())
    text = " ".join(m.facts)
    assert "no credential confirmed" in text and "OG-99" in text and "precaution" in text
