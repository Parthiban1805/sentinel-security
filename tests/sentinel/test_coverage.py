"""coverage: honest matrix, regression detection, producer registry consistent with the schema."""

import json
from pathlib import Path

import pytest

from sentinel import coverage
from sentinel.cli import main


def test_every_scenario_logic_verified_through_the_real_pipeline() -> None:
    report = coverage.build_report(None, set())
    by_rule = {r["rule"]: r for r in report["scenarios"]}
    assert set(by_rule) == {
        "R1",
        "R2",
        "R4",
        "R5b",
        "R5c",
        "R6",
        "R7",
        "R8",
        "R10",
        "R11",
        "R12",
        "R13",
    }
    assert all(r["logic_verified_simulated"] and r["plan_generated"] for r in by_rule.values())


def test_live_source_is_not_claimed_without_a_healthy_collector() -> None:
    report = coverage.build_report(None, set())
    assert all(
        r["live_source"] in ("none", "unknown (no `sentinel run` recorded)")
        for r in report["scenarios"]
    )
    healthy = {"github:o/r": "ok", "github:user_keys": "ok", "scan:x": "ok"}
    by_rule = {r["rule"]: r for r in coverage.build_report(healthy, set())["scenarios"]}
    assert by_rule["R2"]["live_source"] == "live"
    assert by_rule["R1"]["live_source"] == "partial"  # scan ok but no Google usage source
    assert by_rule["R6"]["live_source"] == "none" and by_rule["R7"]["live_source"] == "none"
    broken = {"github:o/r": "error: HTTP 403", "scan:x": "ok"}
    assert {r["rule"]: r for r in coverage.build_report(broken, set())["scenarios"]}["R2"][
        "live_source"
    ] == "none"


def test_only_revoke_credential_is_auto_verified() -> None:
    by_rule = {r["rule"]: r for r in coverage.build_report(None, set())["scenarios"]}
    assert by_rule["R1"]["auto_verifiable_steps"] == 1
    assert by_rule["R2"]["auto_verifiable_steps"] == 0  # human attestation only


def test_producer_registry_matches_schema_event_types() -> None:
    schema_types = set(coverage.schema_event_types())
    registry = set(coverage.REAL_PRODUCERS) | set(coverage.SIMULATION_ONLY)
    assert registry <= schema_types  # registry never names a type the schema lacks
    report = coverage.build_report(None, set())
    assert set(report["event_types_with_no_producer"]) == schema_types - registry
    assert "egress_anomaly" not in report["event_types_with_no_producer"]  # sandbox proxy, v0.7f
    assert "agent_tool_denied" not in report["event_types_with_no_producer"]  # v0.3b source


def test_regression_detection() -> None:
    report = coverage.build_report(None, set())
    baseline = coverage.baseline_from(report)
    assert coverage.regressions(report, baseline) == []
    broken = json.loads(json.dumps(report))
    broken["scenarios"][0]["logic_verified_simulated"] = False
    assert any("R1" in line for line in coverage.regressions(broken, baseline))
    baseline["rules"]["R9"] = {"logic_verified_simulated": True, "plan_generated": True}
    assert any("R9: scenario removed" in line for line in coverage.regressions(report, baseline))


def test_cli_update_then_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = tmp_path / "base.json"
    home = str(tmp_path / "home")
    assert main(["--home", home, "coverage", "--baseline", str(base), "--update-baseline"]) == 0
    assert main(["--home", home, "coverage", "--baseline", str(base), "--check"]) == 0
    data = json.loads(base.read_text())
    data["rules"]["R1"]["logic_verified_simulated"] = True
    data["rules"]["R99"] = {"logic_verified_simulated": True, "plan_generated": True}
    base.write_text(json.dumps(data))
    assert main(["--home", home, "coverage", "--baseline", str(base), "--check"]) == 1
    out = capsys.readouterr()
    assert "REGRESSION R99" in out.err and "LOGIC" in out.out
