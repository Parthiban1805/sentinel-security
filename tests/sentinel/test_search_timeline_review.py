"""Search and timeline: fixes from the 2026-11-05 security review of ADR-0022."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel.events.schema import make_event
from sentinel.incidents import lifecycle, timeline
from sentinel.inventory.blast import link
from sentinel.reporting import search
from sentinel.simulation import scenarios
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
CRED = "cred-fp-abcd1234"
SESSION = "a1b2c3d4e5f60718"


def asset(asset_id: str, asset_type: str = "cloud_account") -> dict[str, Any]:
    return {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "name": asset_id,
        "owner": "Parthiban",
        "importance": "high",
        "monitoring": "partial",
        "recovery_method": None,
        "approved": True,
        "last_seen": (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "sentinel.db")


def r1_incident(store: Store) -> str:
    store.upsert_asset(asset("provider-demo"))
    for e in scenarios.exposure(CRED, "provider-demo", NOW) + scenarios.provider_usage(
        CRED, "provider-demo", NOW
    ):
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, NOW + timedelta(minutes=5))
    return iid


def find(store: Store, **kw: Any) -> dict[str, Any]:
    return search.run(store, search.Query(**kw), NOW)


# S1: related assets respect AND semantics -------------------------------------------------
def test_credential_plus_type_returns_no_related_assets(store: Store) -> None:
    r1_incident(store)
    link(store, CRED, "provider-demo", "read", "Parthiban", NOW)
    result = find(store, credential=CRED, event_type="secret_exposure", include_test=True)
    assert {r["kind"] for r in result["results"]} == {"event"}


def test_credential_plus_session_returns_no_related_assets(store: Store) -> None:
    r1_incident(store)
    result = find(store, credential=CRED, session=SESSION, include_test=True)
    assert result["results"] == []


def test_credential_plus_asset_returns_only_that_asset(store: Store) -> None:
    r1_incident(store)
    store.upsert_asset(asset("other-asset"))
    link(store, CRED, "provider-demo", "read", "Parthiban", NOW)
    link(store, CRED, "other-asset", "read", "Parthiban", NOW)
    result = find(store, credential=CRED, asset="provider-demo", include_test=True)
    ids = {r["id"] for r in result["results"]}
    assert "other-asset" not in ids and f"{CRED}|other-asset" not in ids
    assert f"{CRED}|provider-demo" in ids


# S2: audit rows of simulated incidents are test data --------------------------------------
def test_time_only_search_hides_audit_rows_of_simulated_incidents(store: Store) -> None:
    iid = r1_incident(store)
    lifecycle.approve(store, iid, "review_usage", "Parthiban", NOW + timedelta(minutes=10))
    hidden = find(store, since=NOW - timedelta(days=1))
    assert not any(
        r["kind"] == "audit" and r["fields"].get("incident") == iid for r in hidden["results"]
    )
    shown = find(store, since=NOW - timedelta(days=1), include_test=True)
    assert any(
        r["kind"] == "audit" and r["fields"].get("incident") == iid for r in shown["results"]
    )


# S3: credential-shaped text in rule facts is withheld --------------------------------------
def test_secret_shaped_mcp_server_name_never_reaches_the_timeline(store: Store) -> None:
    fake = fake_google_key()
    store.upsert_asset({**asset("mcp-approved", "mcp_server"), "name": "approved"})
    event = make_event(
        event_type="agent_tool_allowed",
        source="agent_hook",
        asset_id="agent-demo",
        time=NOW,
        severity="info",
        confidence="high",
        evidence_ref="x",
        event_id="e-mcp",
        attributes={
            "session": SESSION,
            "tool": f"mcp__{fake}__send",
            "rule": "MCP",
            "target_class": "mcp",
            "target_fp": "00",
            "decision": "allow_mcp",
            "mcp_server": fake,
            "mcp_tool": "send",
        },
    )
    store.add_event(event)
    created = lifecycle.open_incidents(store, NOW + timedelta(minutes=1))
    assert created  # R5c fired on the unapproved server
    for iid in created:
        text = json.dumps(timeline.build(store, iid))
        assert fake not in text and fake[:12] not in text
        assert "withheld" in text


def test_secret_shaped_values_are_withheld_in_search_output(store: Store) -> None:
    fake = fake_google_key()
    store.add_audit("2026-11-05T11:00:00Z", {"action": "x", "actor": fake, "cred_ref": CRED})
    text = json.dumps(find(store, credential=CRED))
    assert fake not in text and "withheld" in text


# M1: a secret split by separators is refused -------------------------------------------------
@pytest.mark.parametrize("sep", [":", "-", "/", "."])
def test_split_secret_is_refused(store: Store, sep: str) -> None:
    fake = fake_google_key()
    split = fake[:20] + sep + fake[20:]
    with pytest.raises(ValueError) as err:
        find(store, asset=split)
    assert fake[:12] not in str(err.value)


def test_real_ids_are_not_mistaken_for_secrets(store: Store) -> None:
    for value in (
        "gcp-key-757cd8b4-7a3c-48cf-8256-be0373682fb1",
        "cred-fp-14900117354274a6",
        "74f15d20-161d-4744-891f-50795a7237fe",
        "wf-repo-sentinel-security-secret-scan-yml-0123456789",
    ):
        find(store, asset=value)  # must not raise


def test_spaces_are_no_longer_accepted(store: Store) -> None:
    with pytest.raises(ValueError):
        find(store, asset="two words")


# M2: an unknown incident id that looks like a key is not echoed ------------------------------
def test_unknown_incident_does_not_echo_a_pasted_key(store: Store) -> None:
    fake = fake_google_key()
    with pytest.raises(KeyError) as err:
        timeline.build(store, fake)
    assert fake not in str(err.value) and fake[:12] not in str(err.value)


# M3: mixed time formats sort as times ---------------------------------------------------------
def test_timeline_times_are_normalised_before_sorting(store: Store) -> None:
    iid = r1_incident(store)
    store.add_audit(
        "2026-11-05T13:30:00+05:30",
        {"incident": iid, "action": "approve", "step": "a", "actor": "early"},
    )  # 08:00 UTC
    store.add_audit(
        "garbage-time", {"incident": iid, "action": "approve", "step": "b", "actor": "x"}
    )
    items = timeline.build(store, iid)["sections"][0]["items"]
    timed = [i for i in items if "time" in i]
    assert [i["time"] for i in timed] == sorted(i["time"] for i in timed)
    assert timed[0]["text"].startswith("early") and timed[0]["time"] == "2026-11-05T08:00:00Z"
    assert any("step b" in i["text"] and "time" not in i for i in items)  # unreadable: untimed


# M5: wrong shapes never crash ----------------------------------------------------------------
def test_unhashable_and_wrong_shaped_fields_do_not_crash(store: Store) -> None:
    store.put_doc(
        "incidents",
        "INC-X",
        {
            "id": "INC-X",
            "timeline": [{"event_id": ["a"]}, "row"],
            "cred_ref": CRED,
            "blast_radius": "nope",
        },
    )
    store.put_doc("findings", CRED, {"cred_ref": CRED, "locations": "nope"})
    store.add_audit("2026-11-05T11:00:00Z", {"action": ["list"], "cred_ref": CRED})
    assert find(store, credential=CRED, include_test=True)["counts"]
    data = timeline.build(store, "INC-X")
    assert len(data["sections"]) == 6
    json.dumps(data)


def test_ansi_in_actor_is_sanitised(store: Store) -> None:
    iid = r1_incident(store)
    store.add_audit(
        "2026-11-05T12:10:00Z",
        {"incident": iid, "action": "approve", "step": "s", "actor": "evil\x1b[2Jname"},
    )
    text = json.dumps(timeline.build(store, iid))
    assert "\\u001b" not in text and "evil?[2Jname" in text
