"""R1/R4/R6/R7: true positive, true negative, near miss, test routing, determinism."""

from datetime import UTC, datetime, timedelta

from sentinel.correlation.engine import correlate
from sentinel.correlation.model import Config, Context
from sentinel.events.refs import cred_ref, identity_ref
from sentinel.events.schema import make_event
from sentinel.simulation import scenarios

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
REF = cred_ref("ab" * 8)
OTHER = cred_ref("cd" * 8)


def exposure(ref: str = REF, at: datetime = T0, is_test: bool = False) -> dict:
    return make_event(
        event_type="secret_exposure",
        source="gitleaks",
        asset_id="repo-demo",
        time=at,
        severity="high",
        confidence="medium",
        evidence_ref="finding/x",
        credential_ref=ref,
        is_test=is_test,
    )


def usage(ref: str = REF, at: datetime = T0 + timedelta(hours=2)) -> dict:
    return scenarios.provider_usage(ref, "provider-demo", at)[0]


# R1 ---------------------------------------------------------------------
def test_r1_true_positive() -> None:
    [m] = correlate([exposure(), usage()], Context())
    assert (m.rule_id, m.severity_floor, m.cred_ref) == ("R1", "critical", REF)
    assert any("do not prove" in h for h in m.hypotheses)  # inference labelled as hypothesis
    assert m.is_test is True  # simulated usage event


def test_r1_true_negative_different_credential() -> None:
    assert correlate([exposure(), usage(OTHER)], Context()) == []


def test_r1_near_miss_usage_before_exposure() -> None:
    assert correlate([exposure(at=T0), usage(at=T0 - timedelta(minutes=1))], Context()) == []


def test_r1_suppressed_when_revoked_and_verified() -> None:
    assert correlate([exposure(), usage()], Context(revoked_verified=frozenset({REF}))) == []


def test_r1_real_events_are_not_test() -> None:
    real_usage = {**usage(), "is_test": False}
    [m] = correlate([exposure(), real_usage], Context())
    assert m.is_test is False


def test_r1_is_deterministic_and_order_independent() -> None:
    events = [exposure(), usage(), usage(at=T0 + timedelta(hours=3))]
    assert correlate(events, Context()) == correlate(list(reversed(events)), Context())
    assert len(correlate(events, Context())) == 1  # one incident per credential


# R4 ---------------------------------------------------------------------
def test_r4_threshold_boundaries() -> None:
    assert len(correlate(scenarios.spend_spike("p", T0, 3.0), Context())) == 1
    assert correlate(scenarios.spend_spike("p", T0, 2.9), Context()) == []
    ctx = Context(config=Config(spend_multiple=10.0))
    assert correlate(scenarios.spend_spike("p", T0, 5.0), ctx) == []


# R6 ---------------------------------------------------------------------
def test_r6_true_positive_and_near_miss() -> None:
    [m] = correlate(scenarios.login_then_token("ab12cd34", "gh", T0), Context())
    assert (m.rule_id, m.severity_floor) == ("R6", "critical")
    login, token = scenarios.login_then_token("ab12cd34", "gh", T0)
    late = {**token, "time": "2026-10-27T13:30:00Z"}  # 90 minutes: outside the 1h window
    assert correlate([login, late], Context()) == []


def test_r6_different_identity_is_negative() -> None:
    login, token = scenarios.login_then_token("ab12cd34", "gh", T0)
    other = {**token, "identity_ref": identity_ref("user", "ee11ff22")}
    assert correlate([login, other], Context()) == []


# R7 ---------------------------------------------------------------------
def test_r7_any_canary_is_critical() -> None:
    [m] = correlate(scenarios.canary("decoy-1", T0), Context())
    assert (m.rule_id, m.severity_floor, m.confidence) == ("R7", "critical", "high")


def test_no_events_no_matches() -> None:
    assert correlate([], Context()) == []
