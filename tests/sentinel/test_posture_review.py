"""Posture report: fixes from the 2026-11-05 security review of ADR-0021."""

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel import audit, hygiene
from sentinel.cli import main
from sentinel.config import CredentialPolicy
from sentinel.doctor import Check
from sentinel.events.schema import make_event
from sentinel.reporting import posture
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


def incident(iid: str = "INC-1", severity: str = "high", hours_ago: float = 1) -> dict[str, Any]:
    return {
        "id": iid,
        "rule_id": "R1",
        "severity": severity,
        "status": "open",
        "verified": False,
        "is_test": False,
        "created": stamp(hours_ago),
        "close_note": None,
        "response_plan": [],
    }


def run_snapshot(
    store: Store, health: dict[str, str] | None = None, hours_ago: float = 0.2
) -> None:
    store.put_doc(
        "snapshots",
        "health:last_run",
        {"time": stamp(hours_ago), "health": health or {"github": "ok"}, "notes": []},
    )


def snap(store: Store, repo: str, checks: Any, taken: str | None = None) -> None:
    store.put_doc(
        "snapshots",
        audit.snapshot_key(repo),
        {"checks": checks, "time": taken if taken is not None else stamp()},
    )


def build(store: Store, **kw: Any) -> dict[str, Any]:
    return posture.build(store, NOW, policy=POLICY, **kw)


def indicator(report: dict[str, Any], name: str) -> dict[str, Any]:
    return next(i for i in report["indicators"] if i["name"] == name)


def area(ind: dict[str, Any], area_id: str) -> dict[str, Any]:
    return next(e for e in ind["evidence"] if e["id"] == area_id)


def not_measured(ind: dict[str, Any], area_name: str) -> list[str]:
    return [n["why"] for n in ind["not_measured"] if n["area"] == area_name]


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "sentinel.db")


# S1 / S2: hygiene -----------------------------------------------------------------------
def test_hygiene_that_scanned_nothing_is_not_measured(store: Store) -> None:
    store.upsert_asset(asset("repo-a"))
    sec = indicator(build(store, hygiene={}, hygiene_skipped=["repo-gone"]), "security posture")
    assert any("repo-gone" in why for why in not_measured(sec, "hygiene"))
    assert not any(e["id"].startswith("hygiene findings") for e in sec["evidence"])


def test_partial_hygiene_scan_lists_the_skipped_repository(store: Store) -> None:
    store.upsert_asset(asset("repo-a"))
    report = build(store, hygiene={"repo-a": []}, hygiene_skipped=["repo-b"])
    sec = indicator(report, "security posture")
    assert area(sec, "hygiene")["count"] == 0
    assert any("repo-b" in why for why in not_measured(sec, "hygiene"))


def test_git_failure_is_an_error_not_a_clean_repo(tmp_path: Path) -> None:
    broken = tmp_path / "corrupt-repo"
    (broken / ".git").mkdir(parents=True)  # a .git folder that is not a valid repository
    with pytest.raises(ValueError, match="hygiene was not checked"):
        hygiene.scan_repo(broken)


# S3: GitHub audit -----------------------------------------------------------------------
def test_audit_gp0_only_is_not_measured(store: Store) -> None:
    snap(store, "o/r", ["GP0"])
    sec = indicator(build(store, repos=("o/r",)), "security posture")
    assert any("GP0" in why for why in not_measured(sec, "github audit"))
    assert not any(e["id"].startswith("github audit") for e in sec["evidence"])


def test_stale_audit_snapshot_is_not_current(store: Store) -> None:
    snap(store, "o/r", [], taken=stamp(24 * 10))
    sec = indicator(build(store, repos=("o/r",)), "security posture")
    assert any("hours old" in why for why in not_measured(sec, "github audit"))
    longer = build(store, repos=("o/r",), audit_max_age_hours=24 * 30)
    assert area(indicator(longer, "security posture"), "github audit findings (high)")["count"] == 0


@pytest.mark.parametrize("checks", [None, "BP1", [{"x": 1}], 5])
def test_malformed_audit_result_is_not_measured(store: Store, checks: Any) -> None:
    snap(store, "o/r", checks)
    sec = indicator(build(store, repos=("o/r",)), "security posture")
    assert any("unreadable" in why for why in not_measured(sec, "github audit"))


def test_unreadable_audit_time(store: Store) -> None:
    snap(store, "o/r", [], taken="yesterday")
    sec = indicator(build(store, repos=("o/r",)), "security posture")
    assert any("time is unreadable" in why for why in not_measured(sec, "github audit"))


def test_one_good_repo_does_not_hide_an_unaudited_one(store: Store) -> None:
    snap(store, "o/good", [])
    sec = indicator(build(store, repos=("o/good", "o/missing")), "security posture")
    assert area(sec, "github audit findings (high)")["count"] == 0
    assert any("o/missing" in why for why in not_measured(sec, "github audit"))


# S4: credentials ------------------------------------------------------------------------
def test_only_deleted_credentials_are_not_measured(store: Store) -> None:
    store.upsert_asset(asset("gcp-key-d", "api_key", attributes={"deleted": stamp(24 * 90)}))
    sec = indicator(build(store), "security posture")
    assert not_measured(sec, "credentials")


def test_stale_ssh_key_list_is_not_measured(store: Store) -> None:
    keys = {"ids": {"1": stamp(24)}, "time": stamp(24 * 30)}
    store.put_doc("snapshots", "github:user_keys", keys)
    assert not_measured(indicator(build(store), "security posture"), "credentials")


# S5: freshness of threat exposure ------------------------------------------------------
def test_findings_without_a_run_do_not_measure_incidents(store: Store) -> None:
    ref = "cred-fp-aaaa1111"
    store.put_doc("findings", ref, {"cred_ref": ref, "status": "revoked_verified", "locations": []})
    threat = indicator(build(store), "threat exposure")
    assert not_measured(threat, "incidents")
    assert threat["measured"] < threat["total_areas"]


def test_stale_run_stops_threat_exposure_from_saying_good(store: Store) -> None:
    run_snapshot(store, hours_ago=30)
    threat = indicator(build(store), "threat exposure")
    assert threat["status"] == "unknown"
    assert any("out of date" in r for r in threat["reasons"])


def test_stale_run_does_not_hide_a_real_finding(store: Store) -> None:
    run_snapshot(store, hours_ago=30)
    store.put_doc("incidents", "INC-1", incident())
    assert indicator(build(store), "threat exposure")["status"] == "attention"


def test_all_collectors_failed_is_not_good(store: Store) -> None:
    run_snapshot(store, {"github": "error: x", "gcp": "error: y"})
    threat = indicator(build(store), "threat exposure")
    assert threat["status"] == "unknown"
    assert any("every collector failed" in r for r in threat["reasons"])


# S6: malformed stored documents ---------------------------------------------------------
def test_malformed_incident_makes_only_that_indicator_unknown(store: Store) -> None:
    run_snapshot(store)
    store.put_doc("incidents", "INC-BAD", {"id": "INC-BAD"})  # missing every other field
    report = build(store)
    threat = indicator(report, "threat exposure")
    assert threat["status"] == "unknown"
    assert any("KeyError" in why for why in not_measured(threat, "report"))
    assert indicator(report, "operational health")["status"] in {"good", "review"}


@pytest.mark.parametrize(
    "run",
    [
        {"time": "2026-11-05T11:00:00Z", "health": ["not", "a", "dict"]},
        {"health": {"github": "ok"}},
        {"time": "2026-11-05T11:00:00", "health": {"github": "ok"}},
        {"time": 12345, "health": {"github": "ok"}},
        {"time": "2099-01-01T00:00:00Z", "health": {"github": "ok"}},
        "not a dict",
    ],
)
def test_malformed_run_snapshot_never_crashes(store: Store, run: Any) -> None:
    store.put_doc("snapshots", "health:last_run", run)
    report = build(store)
    assert len(report["indicators"]) == 3
    json.dumps(report)


def test_future_and_unreadable_run_times_are_findings(store: Store) -> None:
    store.put_doc("snapshots", "health:last_run", {"time": "2099-01-01T00:00:00Z", "health": {}})
    ops = indicator(build(store), "operational health")
    assert ops["status"] == "attention" and any("future" in r for r in ops["reasons"])
    store.put_doc("snapshots", "health:last_run", {"health": {}})
    ops = indicator(build(store), "operational health")
    assert any("unreadable" in r for r in ops["reasons"])


def test_unknown_health_kind_counts_as_a_warning(store: Store) -> None:
    run_snapshot(store, {"github": "partial: something", "gcp": "ok"})
    ops = indicator(build(store), "operational health")
    assert area(ops, "collector warnings")["refs"] == ["github"] and ops["status"] == "review"


# M6 / M7 --------------------------------------------------------------------------------
def test_risk_acceptance_dates(store: Store) -> None:
    def put(ref: str, until: Any) -> None:
        doc: dict[str, Any] = {"cred_ref": ref, "status": "risk_accepted", "locations": []}
        if until is not None:
            doc["accepted_until"] = until
        store.put_doc("findings", ref, doc)

    put("cred-fp-active001", "2026-11-10")
    put("cred-fp-expired01", "2026-11-04")
    put("cred-fp-offset001", "2026-11-05T11:00:00+05:30")  # 05:30 UTC: already past
    put("cred-fp-missing01", None)
    put("cred-fp-garbage01", "someday")
    threat = indicator(build(store), "threat exposure")
    assert area(threat, "risk-accepted credentials (active)")["refs"] == ["cred-fp-active001"]
    assert area(threat, "expired risk acceptances")["refs"] == [
        "cred-fp-expired01",
        "cred-fp-garbage01",
        "cred-fp-missing01",
        "cred-fp-offset001",
    ]


def test_thresholds_at_the_boundary(store: Store) -> None:
    run_snapshot(store, hours_ago=6)  # exactly 6 hours: late means MORE than 6
    assert area(indicator(build(store), "operational health"), "last run")["count"] == 0
    run_snapshot(store, hours_ago=6.01)
    assert area(indicator(build(store), "operational health"), "last run")["count"] == 1
    custom = build(store, stale_run_hours=12)
    assert area(indicator(custom, "operational health"), "last run")["count"] == 0
    store.put_doc("incidents", "INC-24", incident("INC-24", "medium", hours_ago=24))
    assert area(indicator(build(store), "threat exposure"), "stale open incidents")["count"] == 1


# S8 / M9 / misc -------------------------------------------------------------------------
def test_pin_area_does_not_claim_the_hooks_match(store: Store) -> None:
    store.put_doc("snapshots", "agent_hooks:pin", {"time": stamp()})
    sec = indicator(build(store), "security posture")
    assert not_measured(sec, "agent hooks drift")
    assert area(sec, "agent hooks pin recorded")["detail"] == "a pin of the agent hooks is recorded"


def test_executive_line_states_partial_coverage(store: Store) -> None:
    store.upsert_asset(asset("repo-a"))
    line = build(store, hygiene={"repo-a": []})["executive"][0]
    assert line.startswith("Security posture: good (partial: 2 of 5 areas measured)")


def test_test_events_are_not_agent_sessions(store: Store) -> None:
    attrs = {
        "session": "a1b2c3d4e5f60718",
        "tool": "Bash",
        "rule": "BG-01",
        "target_class": "network_tool",
        "target_fp": "00",
        "decision": "deny",
    }
    event = make_event(
        event_type="agent_tool_denied",
        source="agent_hook",
        asset_id="agent-x",
        time=NOW,
        severity="low",
        confidence="high",
        evidence_ref="x",
        event_id="t1",
        is_test=True,
        attributes=attrs,
    )
    store.add_event(event)
    assert not_measured(indicator(build(store), "threat exposure"), "agent sessions")


def test_doctor_check_names_keep_their_spaces(store: Store) -> None:
    run_snapshot(store)
    ops = indicator(build(store, checks=[Check("agent log", "warn", "x")]), "operational health")
    assert area(ops, "doctor warnings")["refs"] == ["agent log"]


def test_exit_code_function() -> None:
    def rep(*statuses: str) -> dict[str, Any]:
        return {"indicators": [{"status": s} for s in statuses]}

    assert posture.exit_code(rep("good", "review", "attention")) == 2
    assert posture.exit_code(rep("unknown", "unknown", "unknown")) == 3
    assert posture.exit_code(rep("good", "unknown", "review")) == 0


# CLI ------------------------------------------------------------------------------------
def test_cli_missing_state_creates_nothing_and_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "typo-home"
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text("", encoding="utf-8")
    assert main(["--home", str(home), "posture", "--config", str(cfg)]) == 1
    assert "no Sentinel state" in capsys.readouterr().err
    assert not home.exists()


def test_cli_posture_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    store.upsert_asset(asset("repo-a", owner=None))
    run_snapshot(store)
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text("", encoding="utf-8")

    def counts() -> tuple[int, int, int, int]:
        return (
            len(store.assets()),
            len(store.events()),
            len(store.audit()),
            len(store.docs("snapshots")),
        )

    before = counts()
    assert main(["--home", str(home), "posture", "--config", str(cfg), "--no-hygiene"]) == 0
    capsys.readouterr()
    assert counts() == before


def test_cli_scans_configured_repos_and_reports_unreadable_ones(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "demo-repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    (repo / ".env").write_text("NOT_A_REAL_VALUE=1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", ".env"], check=True)
    plain = tmp_path / "plain-folder"
    plain.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    Store(home / "sentinel.db")
    cfg = tmp_path / "sentinel.toml"
    paths = f'["{repo.as_posix()}", "{plain.as_posix()}"]'
    cfg.write_text(f"[scan]\npaths = {paths}\n", encoding="utf-8")
    assert main(["--home", str(home), "posture", "--config", str(cfg), "--json"]) == 0
    sec = indicator(json.loads(capsys.readouterr().out), "security posture")
    assert sec["status"] == "attention"
    assert area(sec, "hygiene findings (high)")["refs"] == ["repo-demo-repo:H1"]
    assert any("repo-plain-folder" in why for why in not_measured(sec, "hygiene"))
