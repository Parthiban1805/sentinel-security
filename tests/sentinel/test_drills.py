"""Detection drills (v0.7c item 6, ADR-0023)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel import drills, runner
from sentinel.cli import main
from sentinel.config import CredentialPolicy, Settings, load
from sentinel.reporting import posture
from sentinel.scanners import gitleaks
from sentinel.simulation import fakes
from sentinel.store.db import Store

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)

try:
    gitleaks.find_gitleaks()
    HAVE_GITLEAKS = True
except gitleaks.ScanError:
    HAVE_GITLEAKS = False
needs_gitleaks = pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not installed")


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "sentinel.db")


def fixed_fake(monkeypatch: pytest.MonkeyPatch) -> str:
    value = fakes.fake_google_key()  # still generated at runtime, but known to the test
    monkeypatch.setattr(drills, "fake_google_key", lambda: value)
    return value


# the drills themselves ------------------------------------------------------------------
def test_agent_sequence_drill_passes_and_is_timed() -> None:
    result = drills.run_drill("agent-sequence")
    assert result.passed and result.incident_rule == "R12" and not result.checks
    assert result.time_to_incident_s is not None and result.time_to_incident_s >= 0
    assert set(result.stages) == {"events", "correlate"}


@needs_gitleaks
def test_leaked_key_drill_passes_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fixed_fake(monkeypatch)
    result = drills.run_drill("leaked-key")
    assert result.passed, result.checks or result.error
    assert result.incident_rule == "R1"
    assert set(result.stages) == {"commit", "scan", "ingest", "correlate"}
    assert result.time_to_detect_s is not None and result.time_to_incident_s is not None
    assert result.time_to_incident_s >= result.time_to_detect_s
    text = json.dumps(result.as_dict())
    assert fake not in text and fake[:12] not in text and "cred-fp" not in text


@needs_gitleaks
def test_the_drill_detects_its_own_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fixed_fake(monkeypatch)
    real_ingest = drills.findings.ingest

    def leaky(store: Store, *args: Any, **kw: Any) -> list[str]:
        store.add_audit("2026-11-06T00:00:00Z", {"action": "oops", "note": fake})  # a bug
        return real_ingest(store, *args, **kw)

    monkeypatch.setattr(drills.findings, "ingest", leaky)
    result = drills.run_drill("leaked-key")
    assert not result.passed and any(c.startswith("leak") for c in result.checks)
    assert fake not in json.dumps(result.as_dict())


def test_a_scanner_failure_is_a_failed_drill_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_a: Any, **_k: Any) -> list[Any]:
        raise gitleaks.ScanError("gitleaks failed in C:/some/secret/path")

    monkeypatch.setattr(drills.gitleaks, "run", broken)
    result = drills.run_drill("leaked-key")
    assert not result.passed and result.error in ("ScanError", "CalledProcessError", "OSError")
    assert "secret/path" not in json.dumps(result.as_dict())  # the text is never kept


def test_no_finding_fails_the_right_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drills.gitleaks, "run", lambda *_a, **_k: [])
    result = drills.run_drill("leaked-key")
    if result.error:  # no git on this machine
        pytest.skip("git is not available")
    assert not result.passed
    assert "expected exactly one new credential" in result.checks
    assert "no R1 incident" in result.checks


def test_unknown_scenario_is_refused() -> None:
    with pytest.raises(ValueError):
        drills.run_drill("nope")


def test_the_workspace_is_removed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(drills.tempfile, "tempdir", str(tmp_path))
    drills.run_drill("agent-sequence")
    assert not any(p.name.startswith("sentinel-drill-") for p in tmp_path.iterdir())


# results in the live store ---------------------------------------------------------------
def test_record_keeps_the_last_twenty(store: Store) -> None:
    for i in range(25):
        drills.record(
            store, drills.DrillResult("agent-sequence", f"2026-11-06T00:{i:02d}:00Z", True)
        )
    runs = drills.history(store)
    assert len(runs) == 20 and runs[-1]["time"] == "2026-11-06T00:24:00Z"
    assert drills.last(store) == runs[-1]


def test_due_logic(store: Store) -> None:
    assert drills.due(store, NOW, 0) is False  # off
    assert drills.due(store, NOW, 24) is True  # never run
    drills.record(store, drills.DrillResult("agent-sequence", "2026-11-06T06:00:00Z", True))
    assert drills.due(store, NOW, 24) is False
    assert drills.due(store, NOW, 6) is True
    store.put_doc("snapshots", drills.HISTORY_KEY, {"runs": "garbage"})
    assert drills.history(store) == [] and drills.due(store, NOW, 6) is True


def test_settings(tmp_path: Path) -> None:
    toml = tmp_path / "sentinel.toml"
    toml.write_text(
        '[drills]\ninterval_hours = 24\nscenario = "agent-sequence"\n', encoding="utf-8"
    )
    settings = load(toml)
    assert (settings.drill_interval_hours, settings.drill_scenario) == (24, "agent-sequence")
    toml.write_text("[drills]\ninterval_hours = -1\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load(toml)
    toml.write_text('[drills]\nscenario = "real-attack"\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load(toml)
    assert Settings().drill_interval_hours == 0  # off unless the owner turns it on


def test_scheduled_drill_runs_from_sentinel_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    settings = Settings(drill_interval_hours=24, drill_scenario="agent-sequence")
    result = runner.run_once(store, home, settings, NOW, scan=False)
    assert result["health"]["drill"] == "ok"
    assert drills.last(store)["scenario"] == "agent-sequence"
    again = runner.run_once(store, home, settings, NOW + timedelta(hours=1), scan=False)
    assert "drill" not in again["health"]  # not due yet
    assert not store.docs("incidents")  # the drill's incident stayed in its own store


def test_failed_scheduled_drill_is_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    failed = drills.DrillResult("agent-sequence", "2026-11-06T12:00:00Z", False, checks=["x"])
    monkeypatch.setattr(drills, "run_drill", lambda *_a, **_k: failed)
    settings = Settings(drill_interval_hours=1, drill_scenario="agent-sequence")
    result = runner.run_once(store, home, settings, NOW, scan=False)
    assert result["health"]["drill"].startswith("warn:")


# posture --------------------------------------------------------------------------------
def ops(store: Store) -> dict[str, Any]:
    report = posture.build(store, NOW, policy=CredentialPolicy())
    return next(i for i in report["indicators"] if i["name"] == "operational health")


def test_posture_without_a_drill_is_not_measured(store: Store) -> None:
    assert any(n["area"] == "detection drill" for n in ops(store)["not_measured"])
    assert ops(store)["total_areas"] == 4


def test_posture_failed_and_old_drills(store: Store) -> None:
    drills.record(store, drills.DrillResult("leaked-key", "2026-11-06T11:00:00Z", False))
    assert any("failed" in r for r in ops(store)["reasons"]) and ops(store)["status"] == "attention"
    drills.record(store, drills.DrillResult("leaked-key", "2026-10-20T11:00:00Z", True))
    assert any("days old" in r for r in ops(store)["reasons"])


# CLI ------------------------------------------------------------------------------------
def test_cli_drill_run_and_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    Store(home / "sentinel.db")
    base = ["--home", str(home), "drill"]
    assert main([*base, "status"]) == 0
    assert "no drill recorded" in capsys.readouterr().out
    assert main([*base, "run", "--scenario", "agent-sequence"]) == 0
    assert "PASSED" in capsys.readouterr().out
    assert main([*base, "status", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["runs"]) == 1
    assert main([*base, "run", "--scenario", "agent-sequence", "--no-record", "--json"]) == 0
    capsys.readouterr()
    assert len(drills.history(Store(home / "sentinel.db"))) == 1


def test_cli_failed_drill_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    Store(home / "sentinel.db")
    failed = drills.DrillResult("agent-sequence", "2026-11-06T12:00:00Z", False, checks=["x"])
    monkeypatch.setattr(drills, "run_drill", lambda *_a, **_k: failed)
    assert main(["--home", str(home), "drill", "run", "--scenario", "agent-sequence"]) == 2
    assert "FAILED" in capsys.readouterr().out


def test_cli_drill_needs_existing_state(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "missing"
    assert main(["--home", str(home), "drill", "run", "--scenario", "agent-sequence"]) == 1
    assert not home.exists()
