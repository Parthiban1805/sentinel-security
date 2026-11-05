"""`sentinel search` and `incident timeline` (v0.7c item 5, ADR-0022)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel.cli import main
from sentinel.incidents import lifecycle, timeline
from sentinel.inventory.blast import link
from sentinel.reporting import search
from sentinel.simulation import scenarios
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
CRED = "cred-fp-abcd1234"
OTHER = "cred-fp-99998888"
SESSION = "a1b2c3d4e5f60718"


def asset(asset_id: str, **kw: Any) -> dict[str, Any]:
    return {
        "asset_id": asset_id,
        "asset_type": "cloud_account",
        "name": asset_id,
        "owner": "Parthiban",
        "importance": "high",
        "monitoring": "partial",
        "recovery_method": None,
        "approved": True,
        "last_seen": (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **kw,
    }


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "sentinel.db")


def r1_incident(store: Store, cred: str = CRED, asset_id: str = "provider-demo") -> str:
    store.upsert_asset(asset(asset_id))
    for e in scenarios.exposure(cred, asset_id, NOW) + scenarios.provider_usage(
        cred, asset_id, NOW
    ):
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, NOW + timedelta(minutes=5))
    return iid


def find(query: search.Query, store: Store) -> dict[str, Any]:
    return search.run(store, query, NOW)


def kinds(result: dict[str, Any]) -> set[str]:
    return {r["kind"] for r in result["results"]}


# search ---------------------------------------------------------------------------------
def test_a_filter_is_required(store: Store) -> None:
    with pytest.raises(ValueError, match="at least one filter"):
        find(search.Query(), store)


def test_credential_search_finds_events_incident_link_and_assets(store: Store) -> None:
    iid = r1_incident(store)
    link(store, CRED, "provider-demo", "read", "Parthiban", NOW)
    result = find(search.Query(credential=CRED, include_test=True), store)
    assert {"event", "incident", "link", "asset"} <= kinds(result)
    assert iid in {r["id"] for r in result["results"] if r["kind"] == "incident"}
    assert result["counts"]["event"] == 2 and result["truncated"] is False


def test_credential_search_does_not_return_another_credential(store: Store) -> None:
    r1_incident(store)
    assert find(search.Query(credential=OTHER, include_test=True), store)["results"] == []


def test_test_data_is_hidden_unless_asked(store: Store) -> None:
    r1_incident(store)
    assert find(search.Query(credential=CRED), store)["results"] == []
    assert find(search.Query(credential=CRED, include_test=True), store)["results"]


def test_asset_filter_matches_findings_by_location(store: Store) -> None:
    store.upsert_asset(asset("repo-a"))
    store.put_doc(
        "findings",
        CRED,
        {
            "cred_ref": CRED,
            "status": "open",
            "first_seen": "2026-11-01T00:00:00Z",
            "last_seen": "2026-11-04T00:00:00Z",
            "locations": [{"asset_id": "repo-a", "file": "x", "line": 1}],
        },
    )
    result = find(search.Query(asset="repo-a"), store)
    assert {"finding", "asset"} <= kinds(result)
    finding = next(r for r in result["results"] if r["kind"] == "finding")
    assert finding["fields"]["assets"] == ["repo-a"] and "file" not in json.dumps(finding)


def test_session_filter_returns_events_and_their_incidents_only(store: Store) -> None:
    for e in scenarios.steered_agent(SESSION, "agent-demo", NOW):
        store.add_event(e)
    store.upsert_asset(asset("agent-demo", asset_type="ai_agent"))
    [iid] = lifecycle.open_incidents(store, NOW + timedelta(minutes=30))
    result = find(search.Query(session=SESSION, include_test=True), store)
    assert kinds(result) == {"event", "incident"}
    assert [r["id"] for r in result["results"] if r["kind"] == "incident"] == [iid]


def test_type_and_source_filters_return_events_only(store: Store) -> None:
    r1_incident(store)
    result = find(search.Query(event_type="secret_exposure", include_test=True), store)
    assert kinds(result) == {"event"} and result["counts"]["event"] == 1
    by_source = find(search.Query(source="gitleaks", include_test=True), store)
    assert kinds(by_source) == {"event"}


def test_time_range_filters(store: Store) -> None:
    r1_incident(store)
    later = find(
        search.Query(credential=CRED, include_test=True, since=NOW + timedelta(days=1)), store
    )
    assert later["results"] == []
    window = find(
        search.Query(
            credential=CRED,
            include_test=True,
            since=NOW - timedelta(hours=1),
            until=NOW + timedelta(hours=1),
        ),
        store,
    )
    assert window["counts"]["event"] == 2


def test_results_are_newest_first_and_limited(store: Store) -> None:
    r1_incident(store)
    result = find(search.Query(credential=CRED, include_test=True, limit=2), store)
    times = [r["time"] for r in result["results"]]
    assert times == sorted(times, reverse=True) and len(result["results"]) == 2
    assert result["truncated"] is True and sum(result["counts"].values()) > 2


def test_search_is_deterministic(store: Store) -> None:
    r1_incident(store)
    q = search.Query(credential=CRED, include_test=True)
    assert find(q, store) == find(q, store)


def test_a_pasted_secret_is_refused_and_never_echoed(store: Store) -> None:
    fake = fake_google_key()
    with pytest.raises(ValueError) as err:
        find(search.Query(credential=fake), store)
    assert fake not in str(err.value) and "fingerprint" in str(err.value)


@pytest.mark.parametrize("bad", ["x" * 300, "a\nb", "a;b", ""])
def test_odd_filter_values_are_refused(store: Store, bad: str) -> None:
    with pytest.raises(ValueError):
        find(search.Query(asset=bad), store)


def test_notes_and_evidence_text_are_never_searched_or_shown(store: Store) -> None:
    store.put_doc(
        "findings",
        CRED,
        {
            "cred_ref": CRED,
            "status": "open",
            "first_seen": "2026-11-01T00:00:00Z",
            "last_seen": "2026-11-04T00:00:00Z",
            "locations": [],
            "notes": [{"time": "t", "actor": "x", "evidence": "SECRET-NOTE-TEXT", "note": "n"}],
        },
    )
    store.add_audit(
        "2026-11-04T00:00:00Z",
        {
            "action": "finding_status",
            "cred_ref": CRED,
            "actor": "Parthiban",
            "evidence": "SECRET-EVIDENCE-TEXT",
        },
    )
    text = json.dumps(find(search.Query(credential=CRED), store))
    assert "SECRET-NOTE-TEXT" not in text and "SECRET-EVIDENCE-TEXT" not in text
    assert "finding_status" in text  # the audit entry itself is found


def test_control_characters_are_removed_from_output(store: Store) -> None:
    store.upsert_asset(asset("repo-a", asset_type="repository"))
    store.add_audit(
        "2026-11-04T00:00:00Z", {"action": "x\x1b[31m\ny", "asset_id": "repo-a", "actor": "a"}
    )
    text = json.dumps(find(search.Query(asset="repo-a"), store))
    assert "\\u001b" not in text and "\\x1b" not in text and "\\n" not in text.replace("\\n  ", "")


def test_malformed_documents_do_not_crash(store: Store) -> None:
    store.put_doc("findings", "bad", {"cred_ref": CRED})  # no status, no times, no locations
    store.put_doc("incidents", "INC-BAD", {"id": "INC-BAD"})
    store.put_doc("links", "bad|link", {"cred_ref": CRED})
    store.add_audit("not a time", {"action": "x", "cred_ref": CRED})
    assert find(search.Query(credential=CRED, include_test=True), store)["counts"]


def test_search_writes_nothing(store: Store) -> None:
    r1_incident(store)
    before = (len(store.events()), len(store.assets()), len(store.audit()))
    find(search.Query(credential=CRED, include_test=True), store)
    assert (len(store.events()), len(store.assets()), len(store.audit())) == before


def test_relative_and_absolute_times() -> None:
    assert search.parse_time("7d", NOW) == NOW - timedelta(days=7)
    assert search.parse_time("12h", NOW) == NOW - timedelta(hours=12)
    assert search.parse_time("30m", NOW) == NOW - timedelta(minutes=30)
    assert search.parse_time("2026-11-01", NOW) == datetime(2026, 11, 1, tzinfo=UTC)
    for bad in ("soon", "0d", "-3d", "99999d", "2026-13-40"):
        with pytest.raises(ValueError):
            search.parse_time(bad, NOW)


# timeline -------------------------------------------------------------------------------
def test_timeline_sections_are_labelled_and_complete(store: Store) -> None:
    iid = r1_incident(store)
    link(store, CRED, "provider-demo", "read", "Parthiban", NOW)
    data = timeline.build(store, iid)
    assert data["incident"]["id"] == iid and data["incident"]["verified"] is False
    assert [s["label"] for s in data["sections"]] == [
        "confirmed",
        "stated by the rule",
        "inferred",
        "suspected",
        "alternative explanations",
        "missing evidence",
    ]
    confirmed = data["sections"][0]["items"]
    assert any("secret_exposure" in i["text"] for i in confirmed)
    assert any("incident_opened" in i["text"] or "opened" in i["text"] for i in confirmed)
    assert any("Parthiban" in i["text"] and "linked" in i["text"] for i in confirmed)
    times = [i["time"] for i in confirmed if i.get("time")]
    assert times == sorted(times)


def test_timeline_marks_suspected_and_alternatives(store: Store) -> None:
    data = timeline.build(store, r1_incident(store))
    sections = {s["label"]: s["items"] for s in data["sections"]}
    assert sections["suspected"] and all("not proven" in i["text"] for i in sections["suspected"])
    assert sections["alternative explanations"]
    assert any(
        "late" in i["text"] or "owner" in i["text"] for i in sections["alternative explanations"]
    )


def test_timeline_lists_missing_evidence(store: Store) -> None:
    sections = {
        s["label"]: s["items"] for s in timeline.build(store, r1_incident(store))["sections"]
    }
    missing = " ".join(i["text"] for i in sections["missing evidence"])
    assert "not linked to any asset" in missing  # no link recorded
    assert "not yet verified" in missing  # required steps are pending


def test_timeline_blast_radius_is_inferred_not_confirmed(store: Store) -> None:
    iid = r1_incident(store)
    store.upsert_asset(asset("db-prod", asset_type="database"))
    from sentinel.inventory import graph

    graph.add_documented_edge(store, "provider-demo", "db-prod", "reads", "Parthiban", NOW)
    link(store, CRED, "provider-demo", "read", "Parthiban", NOW)
    # The incident was opened before the link, so rebuild its blast radius view the same way open does.
    incident = store.get_doc("incidents", iid)
    from sentinel.inventory.blast import blast_radius

    incident["blast_radius"] = blast_radius(store, CRED)
    store.put_doc("incidents", iid, incident)
    sections = {s["label"]: s["items"] for s in timeline.build(store, iid)["sections"]}
    assert any("db-prod" in i["text"] and "hypothesis" in i["text"] for i in sections["inferred"])
    assert not any("db-prod" in i["text"] for i in sections["confirmed"])


def test_timeline_records_actions_with_their_actors(store: Store) -> None:
    iid = r1_incident(store)
    lifecycle.approve(store, iid, "review_usage", "Parthiban", NOW + timedelta(minutes=10))
    confirmed = timeline.build(store, iid)["sections"][0]["items"]
    assert any("Parthiban" in i["text"] and "approve" in i["text"] for i in confirmed)


def test_timeline_never_prints_audit_evidence_text(store: Store) -> None:
    iid = r1_incident(store)
    store.add_audit(
        "2026-11-05T12:30:00Z",
        {
            "incident": iid,
            "action": "verify",
            "step": "review_usage",
            "actor": "Parthiban",
            "passed": True,
            "evidence": "PRIVATE-EVIDENCE-TEXT",
        },
    )
    text = json.dumps(timeline.build(store, iid))
    assert "PRIVATE-EVIDENCE-TEXT" not in text and "Parthiban" in text


def test_timeline_for_an_agent_incident_has_no_credential_items(store: Store) -> None:
    for e in scenarios.steered_agent(SESSION, "agent-demo", NOW):
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, NOW + timedelta(minutes=30))
    sections = {s["label"]: s["items"] for s in timeline.build(store, iid)["sections"]}
    assert any("keyword" in i["text"] for i in sections["alternative explanations"])
    assert not any("first seen" in i["text"] for i in sections["confirmed"])


def test_every_rule_has_alternative_explanations() -> None:
    from sentinel.incidents.response import _PLANS

    assert set(_PLANS) <= set(timeline.ALTERNATIVES)


def test_timeline_unknown_incident(store: Store) -> None:
    with pytest.raises(KeyError):
        timeline.build(store, "INC-NOPE")


def test_timeline_is_deterministic_and_read_only(store: Store) -> None:
    iid = r1_incident(store)
    before = (len(store.audit()), len(store.docs("incidents")))
    assert timeline.build(store, iid) == timeline.build(store, iid)
    assert (len(store.audit()), len(store.docs("incidents"))) == before


def test_timeline_tolerates_a_sparse_incident(store: Store) -> None:
    store.put_doc("incidents", "INC-SPARSE", {"id": "INC-SPARSE", "rule_id": "R1"})
    data = timeline.build(store, "INC-SPARSE")
    assert len(data["sections"]) == 6


# CLI ------------------------------------------------------------------------------------
def test_cli_search_and_timeline(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    iid = r1_incident(store)
    base = ["--home", str(home)]
    assert main([*base, "search", "--credential", CRED, "--include-test"]) == 0
    out = capsys.readouterr().out
    assert "secret_exposure" in out and iid in out and "sensitive" in out.lower()
    assert (
        main([*base, "search", "--credential", CRED, "--include-test", "--json", "--since", "7d"])
        == 0
    )
    assert json.loads(capsys.readouterr().out)["counts"]["event"] == 2
    assert main([*base, "search"]) == 1  # no filter
    assert "at least one filter" in capsys.readouterr().err
    assert main([*base, "incident", "timeline", iid]) == 0
    text = capsys.readouterr().out
    assert "CONFIRMED" in text and "SUSPECTED" in text and "MISSING EVIDENCE" in text
    assert main([*base, "incident", "timeline", iid, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["incident"]["id"] == iid
    assert main([*base, "incident", "timeline", "INC-NOPE"]) == 1


def test_cli_search_refuses_a_pasted_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    Store(home / "sentinel.db")
    fake = fake_google_key()
    assert main(["--home", str(home), "search", "--credential", fake]) == 1
    err = capsys.readouterr().err
    assert fake not in err and fake[:12] not in err
