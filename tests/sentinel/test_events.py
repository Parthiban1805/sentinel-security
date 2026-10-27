from datetime import UTC, datetime

import pytest

from sentinel.events.refs import cred_ref, identity_ref
from sentinel.events.schema import SchemaError, make_event, validate_asset, validate_event

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def good_event() -> dict:
    return make_event(
        event_type="secret_exposure",
        source="gitleaks",
        asset_id="repo-demo",
        time=NOW,
        severity="high",
        confidence="medium",
        evidence_ref="evidence/demo-1",
        credential_ref=cred_ref("ab" * 8),
        is_test=True,
    )


def test_make_event_is_valid_and_defaults_unverified():
    event = good_event()
    validate_event(event)
    assert event["verified"] is False
    assert event["time"] == "2026-10-27T12:00:00Z"
    assert event["event_id"]


def test_event_ids_are_unique():
    assert good_event()["event_id"] != good_event()["event_id"]


def test_unknown_event_type_rejected():
    with pytest.raises(SchemaError):
        make_event(
            event_type="not_a_type",
            source="gitleaks",
            asset_id="a",
            time=NOW,
            severity="low",
            confidence="low",
            evidence_ref="e",
        )


def test_extra_field_rejected():
    event = good_event()
    event["unexpected_field"] = "x"
    with pytest.raises(SchemaError):
        validate_event(event)


def test_naive_time_rejected():
    with pytest.raises(ValueError):
        make_event(
            event_type="secret_exposure",
            source="gitleaks",
            asset_id="a",
            time=datetime(2026, 10, 27, 12, 0),
            severity="low",
            confidence="low",
            evidence_ref="e",
        )


def test_ref_patterns_match_schema():
    event = good_event()
    event["identity_ref"] = identity_ref("user", "cd" * 4)
    validate_event(event)
    assert event["credential_ref"].startswith("cred-fp-")


@pytest.mark.parametrize("bad", ["", "xyz", "ABCD"])
def test_cred_ref_rejects_non_hex(bad):
    with pytest.raises(ValueError):
        cred_ref(bad)


def test_identity_ref_rejects_unknown_kind():
    with pytest.raises(ValueError):
        identity_ref("admin", "abcd")


def test_validate_asset_requires_owner_field():
    asset = {
        "asset_id": "repo-demo",
        "asset_type": "repository",
        "name": "demo",
        "owner": None,
        "importance": "low",
        "monitoring": "none",
        "last_seen": "2026-10-27T12:00:00Z",
    }
    validate_asset(asset)  # owner null is valid: it is a finding, not a schema error
    del asset["owner"]
    with pytest.raises(SchemaError):
        validate_asset(asset)
