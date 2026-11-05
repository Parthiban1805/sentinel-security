"""`sentinel posture`: three separate indicators with evidence (v0.7c item 4, ADR-0021)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel import audit
from sentinel.cli import main
from sentinel.config import CredentialPolicy
from sentinel.doctor import Check
from sentinel.hygiene import Finding
from sentinel.reporting import posture
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
POLICY = CredentialPolicy()


def stamp(hours_ago: float = 0) -> str:
    return (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def asset(asset_id: str, asset_type: str = "repository", **kw: Any) -> dict[str, Any]:
    return {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "name": asset_id,
        "owner": "Parthiban",
        "importance": "medium",
        "monitoring": "partial",
        "recovery_method": None,
        "approved": True,
        "last_seen": stamp(),
        **kw,
    }


def incident(
    iid: str = "INC-1",
    severity: str = "high",
    *,
    status: str = "open",
    hours_ago: float = 1,
    verified: bool = False,
    is_test: bool = False,
    steps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": iid,
        "rule_id": "R1",
        "severity": severity,
        "status": status,
        "verified": verified,
        "is_test": is_test,
        "created": stamp(hours_ago),
        "close_note": "closed by hand" if status == "closed" else None,
        "response_plan": steps or [],
    }


def run_snapshot(
    store: Store, health: dict[str, str] | None = None, hours_ago: float = 0.2
) -> None:
    store.put_doc(
        "snapshots",
        "health:last_run",
        {"time": stamp(hours_ago), "health": health or {"github": "ok"}, "notes": []},
    )


def build(store: Store, **kw: Any) -> dict[str, Any]:
    return posture.build(store, NOW, policy=POLICY, **kw)


def indicator(report: dict[str, Any], name: str) -> dict[str, Any]:
    return next(i for i in report["indicators"] if i["name"] == name)


def area(ind: dict[str, Any], area_id: str) -> dict[str, Any]:
    return next(e for e in ind["evidence"] if e["id"] == area_id)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "sentinel.db")


# structure -----------------------------------------------------------------------
def test_three_separate_indicators_and_no_overall_score(store: Store) -> None:
    report = build(store)
    assert [i["name"] for i in report["indicators"]] == [
        "security posture",
        "threat exposure",
        "operational health",
    ]
    keys: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            keys.update(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(report)
    assert not keys & {"score", "overall", "total", "grade", "rating"}  # no combined number
    assert "No overall score" in report["note"]
    for ind in report["indicators"]:
        assert ind["status"] in {"good", "review", "attention", "unknown"}
        assert {"question", "reasons", "evidence", "not_measured", "measured"} <= set(ind)


def test_empty_store_is_unknown_not_good(store: Store) -> None:
    report = build(store)
    sec, threat, ops = (
        indicator(report, n) for n in ("security posture", "threat exposure", "operational health")
    )
    assert sec["status"] == "unknown" and sec["not_measured"]
    assert threat["status"] == "unknown"  # nothing has ever run: exposure is not known
    assert ops["status"] == "attention" and any("no run" in r for r in ops["reasons"])


def test_report_is_deterministic(store: Store) -> None:
    store.upsert_asset(asset("repo-a", owner=None))
    run_snapshot(store)
    assert build(store) == build(store)


# security posture ----------------------------------------------------------------
def test_clean_measured_posture_is_good_with_coverage_stated(store: Store) -> None:
    store.upsert_asset(asset("repo-a"))
    sec = indicator(build(store, hygiene={"repo-a": []}), "security posture")
    assert sec["status"] == "good" and sec["measured"] < sec["total_areas"]
    assert area(sec, "hygiene")["count"] == 0
    assert any(n["area"] == "github audit" for n in sec["not_measured"])


def test_asset_gaps_are_low_and_derived_assets_are_not_counted(store: Store) -> None:
    store.upsert_asset(asset("repo-a", owner=None))
    store.upsert_asset(asset("wf-x", "ci_workflow", owner=None, approved=False, monitoring="none"))
    store.upsert_asset(asset("loc-y", "scan_location", owner=None, approved=False))
    sec = indicator(build(store), "security posture")
    unowned = area(sec, "unowned assets")
    assert unowned["count"] == 1 and unowned["refs"] == ["repo-a"] and unowned["severity"] == "low"
    assert sec["status"] == "review"


def test_hygiene_high_finding_needs_attention(store: Store) -> None:
    store.upsert_asset(asset("repo-a"))
    found = {"repo-a": [Finding("H1", "high", ".env", "tracked"), Finding("H4", "low", "", "x")]}
    sec = indicator(build(store, hygiene=found), "security posture")
    assert sec["status"] == "attention"
    assert (
        area(sec, "hygiene findings (high)")["count"] == 1
        and area(sec, "hygiene findings (low)")["count"] == 1
    )
    assert area(sec, "hygiene findings (high)")["refs"] == ["repo-a:H1"]


def test_github_audit_uses_the_latest_snapshot_not_stored_events(store: Store) -> None:
    store.upsert_asset(asset("repo-a"))
    store.put_doc(
        "snapshots", audit.snapshot_key("o/r"), {"checks": ["BP1", "SS0"], "time": stamp()}
    )
    sec = indicator(build(store, repos=("o/r",)), "security posture")
    assert sec["status"] == "attention"  # BP1 is high
    assert area(sec, "github audit findings (high)")["refs"] == ["o/r:BP1"]
    assert any("cannot verify" in n["why"] for n in sec["not_measured"])  # SS0 is not a finding
    store.put_doc("snapshots", audit.snapshot_key("o/r"), {"checks": [], "time": stamp()})
    fixed = indicator(build(store, repos=("o/r",)), "security posture")
    assert not any(e["id"].startswith("github audit") and e["count"] for e in fixed["evidence"])


def test_repo_without_audit_snapshot_is_not_measured(store: Store) -> None:
    store.upsert_asset(asset("repo-a"))
    sec = indicator(build(store, repos=("o/r",)), "security posture")
    assert any(n["area"] == "github audit" and "o/r" in n["why"] for n in sec["not_measured"])


def test_credential_problems_split_by_severity(store: Store) -> None:
    store.upsert_asset(
        asset("gcp-key-a", "api_key", attributes={"created": stamp(24 * 400), "expires": stamp(24)})
    )
    store.upsert_asset(asset("gcp-key-b", "api_key", owner=None, attributes={"created": stamp(24)}))
    sec = indicator(build(store), "security posture")
    assert sec["status"] == "attention"  # C1 expired is high
    assert area(sec, "credential problems (high)")["refs"] == ["gcp-key-a"]
    assert area(sec, "credential problems (low)")["count"] >= 1  # C4 no owner on key b
    assert area(sec, "credentials with unknown facts")["severity"] == "info"


def test_agent_config_unpinned_hooks_and_unapproved_mcp(store: Store) -> None:
    store.upsert_asset(asset("mcp-x", "mcp_server", approved=False))
    sec = indicator(build(store), "security posture")
    assert area(sec, "agent hooks pin recorded")["count"] == 1  # not pinned
    assert area(sec, "unapproved MCP servers")["refs"] == ["mcp-x"]
    store.put_doc("snapshots", "agent_hooks:pin", {"time": stamp()})
    sec = indicator(build(store), "security posture")
    assert area(sec, "agent hooks pin recorded")["count"] == 0


# threat exposure -----------------------------------------------------------------
def test_open_high_incident_needs_attention(store: Store) -> None:
    store.put_doc("incidents", "INC-1", incident())
    threat = indicator(build(store), "threat exposure")
    assert threat["status"] == "attention"
    assert area(threat, "open incidents (high or critical)")["refs"] == ["INC-1"]


def test_open_medium_incident_is_review_and_stale_is_flagged(store: Store) -> None:
    store.put_doc("incidents", "INC-2", incident("INC-2", "medium", hours_ago=30))
    threat = indicator(build(store), "threat exposure")
    assert threat["status"] == "review"
    assert area(threat, "stale open incidents")["refs"] == ["INC-2"]


def test_test_incidents_are_ignored(store: Store) -> None:
    store.put_doc("incidents", "INC-T", incident("INC-T", "critical", is_test=True))
    run_snapshot(store)
    assert indicator(build(store), "threat exposure")["status"] == "good"


def test_closed_unverified_and_failed_verification(store: Store) -> None:
    store.put_doc("incidents", "INC-3", incident("INC-3", status="closed"))
    step = {"step": "revoke_credential", "required_for_close": True, "state": "verification_failed"}
    store.put_doc("incidents", "INC-4", incident("INC-4", "low", steps=[step]))
    threat = indicator(build(store), "threat exposure")
    assert area(threat, "closed without verification")["refs"] == ["INC-3"]
    assert area(threat, "verification failed")["severity"] == "high"
    assert threat["status"] == "attention"


def test_live_leaked_credentials_count_and_revoked_verified_do_not(store: Store) -> None:
    store.put_doc(
        "findings",
        "cred-fp-aaaa1111",
        {"cred_ref": "cred-fp-aaaa1111", "status": "open", "locations": [], "accepted_until": None},
    )
    store.put_doc(
        "findings",
        "cred-fp-bbbb2222",
        {
            "cred_ref": "cred-fp-bbbb2222",
            "status": "revoked_verified",
            "locations": [],
            "accepted_until": None,
        },
    )
    threat = indicator(build(store), "threat exposure")
    assert area(threat, "live leaked credentials")["refs"] == ["cred-fp-aaaa1111"]
    assert threat["status"] == "attention"


def test_expired_risk_acceptance_is_review(store: Store) -> None:
    store.put_doc(
        "findings",
        "cred-fp-aaaa1111",
        {
            "cred_ref": "cred-fp-aaaa1111",
            "status": "risk_accepted",
            "locations": [],
            "accepted_until": stamp(48),
        },
    )
    threat = indicator(build(store), "threat exposure")
    assert area(threat, "expired risk acceptances")["count"] == 1


def test_agent_session_score_is_advisory_and_never_drives_status(store: Store) -> None:
    from sentinel.events.schema import make_event

    run_snapshot(store)
    for i, cls in enumerate(["credential_read", "network_tool"]):
        store.add_event(
            make_event(
                event_type="agent_tool_denied",
                source="agent_hook",
                asset_id="agent-x",
                time=NOW - timedelta(minutes=10 - i),
                severity="low",
                confidence="high",
                evidence_ref="x",
                event_id=f"e{i}",
                attributes={
                    "session": "a1b2c3d4e5f60718",
                    "tool": "Bash",
                    "rule": "BG-01",
                    "target_class": cls,
                    "target_fp": "00",
                    "decision": "deny",
                },
            )
        )
    threat = indicator(build(store), "threat exposure")
    adv = area(threat, "agent sessions scored high (advisory)")
    assert adv["count"] == 1 and adv["severity"] == "info"
    assert threat["status"] == "good"


# operational health --------------------------------------------------------------
def test_recent_clean_run_is_good(store: Store) -> None:
    run_snapshot(store)
    ops = indicator(build(store, checks=[Check("gitleaks", "ok", "found")]), "operational health")
    assert ops["status"] == "good"


def test_stale_run_needs_attention(store: Store) -> None:
    run_snapshot(store, hours_ago=30)
    ops = indicator(build(store), "operational health")
    assert ops["status"] == "attention" and any("hours ago" in r for r in ops["reasons"])


def test_collector_error_warn_and_skipped_levels(store: Store) -> None:
    run_snapshot(
        store,
        {
            "github": "error: HTTP 401",
            "scan:x": "warn: 1 unreadable",
            "gcp": "skipped: no token",
            "agentlog": "ok",
        },
    )
    ops = indicator(build(store), "operational health")
    assert area(ops, "collector errors")["refs"] == ["github"]
    assert area(ops, "collector warnings")["refs"] == ["scan:x"]
    assert area(ops, "collectors skipped")["refs"] == ["gcp"]
    assert ops["status"] == "attention"


def test_health_text_is_not_copied_into_the_report(store: Store) -> None:
    run_snapshot(store, {"github": "error: token ghp_" + "x" * 40})
    assert "ghp_" not in json.dumps(build(store))


def test_doctor_failures_and_warnings(store: Store) -> None:
    run_snapshot(store)
    ok = Check("a", "ok", "fine")
    warn = build(store, checks=[ok, Check("b", "warn", "meh")])
    assert indicator(warn, "operational health")["status"] == "review"
    fail = build(store, checks=[ok, Check("c", "fail", "broken")])
    ops = indicator(fail, "operational health")
    assert ops["status"] == "attention" and area(ops, "doctor failures")["refs"] == ["c"]


# evidence hygiene ----------------------------------------------------------------
def test_refs_are_capped_but_counts_are_exact(store: Store) -> None:
    for i in range(15):
        store.upsert_asset(asset(f"repo-{i:02d}", owner=None))
    unowned = area(indicator(build(store), "security posture"), "unowned assets")
    assert unowned["count"] == 15 and len(unowned["refs"]) == 10 and unowned["more"] == 5


def test_no_names_or_secret_shaped_text_in_output(store: Store) -> None:
    fake = fake_google_key()
    store.upsert_asset({**asset("repo-a", owner=None), "name": fake})
    report = build(store, hygiene={"repo-a": [Finding("H1", "high", ".env", fake)]})
    text = json.dumps(report)
    assert fake not in text and fake[:12] not in text


# executive summary ---------------------------------------------------------------
def test_executive_summary_has_one_line_per_indicator(store: Store) -> None:
    store.put_doc("incidents", "INC-1", incident())
    lines = build(store)["executive"]
    assert len(lines) == 3
    assert lines[1].startswith("Threat exposure: attention") and "high" in lines[1]


# CLI -----------------------------------------------------------------------------
def test_cli_posture_text_json_and_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    Store(home / "sentinel.db").put_doc("incidents", "INC-1", incident())
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text("", encoding="utf-8")
    base = ["--home", str(home), "posture", "--config", str(cfg), "--no-hygiene"]
    assert main(base) == 0
    out = capsys.readouterr().out
    assert "Security posture" in out and "Threat exposure" in out and "Operational health" in out
    assert "no overall score" in out.lower()
    assert main([*base, "--check"]) == 2  # threat exposure is attention
    capsys.readouterr()
    assert main([*base, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["indicators"]) == 3 and "executive" in data
