"""R11: provider usage AFTER a revocation was verified. True positive, negatives, near misses, end to end."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel import findings
from sentinel.correlation.engine import context_from_store, correlate
from sentinel.correlation.model import Context
from sentinel.events.refs import cred_ref
from sentinel.incidents import lifecycle
from sentinel.scanners.gitleaks import Finding
from sentinel.simulation import scenarios
from sentinel.store.db import Store

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
REF = cred_ref("ab" * 8)
OTHER = cred_ref("cd" * 8)
VERIFIED = "2026-10-27T12:00:00Z"


def ctx(**times: str) -> Context:
    mapping = {REF: VERIFIED, **times}
    return Context(revoked_verified=frozenset(mapping), revoked_verified_at=mapping)


def usage(ref: str = REF, minutes: int = 30) -> dict:  # type: ignore[type-arg]
    return scenarios.provider_usage(ref, "gcp-demo", T0 + timedelta(minutes=minutes))[0]


def test_true_positive_use_after_verified_revocation() -> None:
    [m] = [x for x in correlate([usage()], ctx()) if x.rule_id == "R11"]
    assert (m.severity_floor, m.cred_ref, m.confidence) == ("critical", REF, "medium")
    assert "revocation of" in m.facts[0] and VERIFIED in m.facts[0]
    assert any("did not take effect" in h for h in m.hypotheses)  # labelled as a hypothesis
    assert m.is_test is True  # simulated usage


def test_dead_key_reason_from_the_collector_raises_confidence() -> None:
    event = usage()
    event["attributes"] = {**event["attributes"], "reason": "use_of_dead_key"}
    [m] = [x for x in correlate([event], ctx()) if x.rule_id == "R11"]
    assert m.confidence == "high"


@pytest.mark.parametrize("minutes", [-120, -1, 0])
def test_usage_at_or_before_verification_is_the_original_abuse_not_r11(minutes: int) -> None:
    assert [m for m in correlate([usage(minutes=minutes)], ctx()) if m.rule_id == "R11"] == []


def test_other_credentials_and_unverified_ones_do_not_match() -> None:
    assert [m for m in correlate([usage(OTHER)], ctx()) if m.rule_id == "R11"] == []
    # revoked_verified without a recorded time (verified before v0.5): never guess
    legacy = Context(revoked_verified=frozenset({REF}), revoked_verified_at={})
    assert [m for m in correlate([usage()], legacy) if m.rule_id == "R11"] == []


def test_other_event_types_do_not_match() -> None:
    spend = scenarios.spend_spike("gcp-demo", T0 + timedelta(minutes=30))
    assert [m for m in correlate(spend, ctx()) if m.rule_id == "R11"] == []


def test_one_incident_per_credential_and_deterministic() -> None:
    events = [usage(minutes=30), usage(minutes=90), usage(minutes=60)]
    first = [m for m in correlate(events, ctx()) if m.rule_id == "R11"]
    assert len(first) == 1 and len(first[0].event_ids) == 3
    assert first == [m for m in correlate(list(reversed(events)), ctx()) if m.rule_id == "R11"]


# findings lifecycle and store wiring ----------------------------------------------------------------------
def test_verified_at_is_recorded_and_cleared(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    f = Finding(REF, "gcp-api-key", "a.txt", 1, "", "")
    findings.ingest(store, "repo-x", [f], T0)
    findings.set_status(
        store, REF, "revoked_verified", actor="me", now=T0, evidence="console shows deleted"
    )
    doc = store.get_doc("findings", REF)
    assert doc is not None and doc["verified_at"] == VERIFIED
    assert context_from_store(store).revoked_verified_at == {REF: VERIFIED}
    findings.set_status(store, REF, "revoke_pending", actor="me", now=T0 + timedelta(hours=1))
    doc = store.get_doc("findings", REF)
    assert doc is not None and "verified_at" not in doc
    assert context_from_store(store).revoked_verified_at == {}  # no longer verified: watch ends


def test_end_to_end_a_revocation_that_did_not_hold_reopens_the_story(tmp_path: Path) -> None:
    """Exposure, usage, incident, verified revocation, then MORE usage: a new critical R11 incident."""
    store = Store(tmp_path / "s.db")
    f = Finding(REF, "gcp-api-key", "a.txt", 1, "", "")
    findings.ingest(store, "repo-x", [f], T0 - timedelta(days=1))
    for e in scenarios.exposure(REF, "repo-x", T0 - timedelta(hours=5)):
        store.add_event(e)
    for e in scenarios.provider_usage(REF, "gcp-demo", T0 - timedelta(hours=1)):
        store.add_event(e)
    [r1] = lifecycle.open_incidents(store, T0 - timedelta(minutes=30))
    assert store.get_doc("incidents", r1)["rule_id"] == "R1"  # type: ignore[index]

    findings.set_status(
        store, REF, "revoked_verified", actor="me", now=T0, evidence="console shows deleted"
    )
    assert lifecycle.open_incidents(store, T0) == []  # quiet: revoked and verified, no later usage

    later = scenarios.provider_usage(REF, "gcp-demo", T0 + timedelta(hours=2))[0]
    store.add_event(later)
    [r11] = lifecycle.open_incidents(store, T0 + timedelta(hours=3))
    incident = store.get_doc("incidents", r11)
    assert (
        incident is not None and incident["rule_id"] == "R11" and incident["severity"] == "critical"
    )
    assert incident["urgency"] == "immediate"
    steps = {s["step"] for s in incident["response_plan"]}
    assert steps == {
        "confirm_revocation_state",
        "revoke_again",
        "review_usage",
        "find_other_copies",
    }
    assert any("late-arriving" in u for u in incident["unknowns"])
    assert lifecycle.open_incidents(store, T0 + timedelta(hours=4)) == []  # idempotent
