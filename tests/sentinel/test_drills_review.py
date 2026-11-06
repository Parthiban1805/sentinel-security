"""Detection drills: fixes from the 2026-11-06 security review of ADR-0023."""

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sentinel import drills, runner
from sentinel.config import CredentialPolicy, Settings
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


def hostile_global_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A user git config whose hooks would record that they ran (and could send the key away)."""
    hooks = tmp_path / "user-hooks"
    hooks.mkdir()
    marker = tmp_path / "hook-ran.txt"
    for name in ("pre-commit", "commit-msg", "post-commit"):
        hook = hooks / name
        hook.write_text(f"#!/bin/sh\necho ran >> '{marker.as_posix()}'\n", encoding="utf-8")
        hook.chmod(0o755)
    config = tmp_path / "user.gitconfig"
    config.write_text(
        f"[core]\n\thooksPath = {hooks.as_posix()}\n[commit]\n\tgpgsign = true\n", "utf-8"
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    return marker


@needs_gitleaks
def test_user_hooks_and_signing_never_run_on_the_drill_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = hostile_global_config(tmp_path, monkeypatch)
    result = drills.run_drill("leaked-key")
    assert result.passed, result.checks or result.error  # gpgsign=true would have failed it
    assert not marker.exists()


@needs_gitleaks
def test_inherited_git_dir_cannot_redirect_the_drill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = tmp_path / "real-repo"
    real.mkdir()
    subprocess.run(["git", "-C", str(real), "init", "-q"], check=True)
    monkeypatch.setenv("GIT_DIR", str(real / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(real))
    result = drills.run_drill("leaked-key")
    assert result.passed, result.checks or result.error
    log = subprocess.run(
        ["git", "-C", str(real), "log", "--all", "--oneline"],
        capture_output=True,
        text=True,
        env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
    )
    assert "drill" not in log.stdout  # nothing was committed to the real repository


def test_scanner_child_env_drops_git_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    monkeypatch.setenv("SENTINEL_GITHUB_TOKEN", "x")
    env = gitleaks._child_env()
    assert "GIT_DIR" not in env and "SENTINEL_GITHUB_TOKEN" not in env


def test_a_workspace_that_survives_fails_the_drill(monkeypatch: pytest.MonkeyPatch) -> None:
    class StuckDir:
        def __init__(self, *_a: Any, **_k: Any) -> None:
            import tempfile

            self.path = tempfile.mkdtemp(prefix="sentinel-drill-test-")

        def __enter__(self) -> str:
            return self.path

        def __exit__(self, *_a: Any) -> None:
            return None  # cleanup "failed": the folder stays

    monkeypatch.setattr(drills.tempfile, "TemporaryDirectory", StuckDir)
    result = drills.run_drill("agent-sequence")
    assert not result.passed and any("workspace not removed" in c for c in result.checks)


@needs_gitleaks
def test_leaked_key_workspace_is_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drills.tempfile, "tempdir", str(tmp_path))
    result = drills.run_drill("leaked-key")
    assert result.passed
    assert not any(p.name.startswith("sentinel-drill-") for p in tmp_path.iterdir())


def test_failed_detection_reports_no_time_to_detect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drills.gitleaks, "run", lambda *_a, **_k: [])
    result = drills.run_drill("leaked-key")
    if result.error:
        pytest.skip("git is not available")
    assert result.time_to_detect_s is None and result.time_to_incident_s is None


def test_unexpected_exceptions_are_kept_as_a_type(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        raise TypeError("something private")

    monkeypatch.setattr(drills, "_agent_sequence", boom)
    result = drills.run_drill("agent-sequence")
    assert result.error == "TypeError" and "private" not in json.dumps(result.as_dict())


def test_leak_check_catches_partial_values() -> None:
    fake = fakes.fake_google_key()
    assert drills._leaked(fake, f"x{fake[4:]}y")  # the random part alone
    assert drills._leaked(fake, f"..{fake[10:22]}..")  # a 12-character slice
    assert not drills._leaked(fake, "cred-fp-0123456789abcdef")


def test_run_uses_the_given_time() -> None:
    assert drills.run_drill("agent-sequence", now=NOW).time == "2026-11-06T12:00:00Z"


# snapshots that were tampered with ------------------------------------------------------------
def put_runs(store: Store, *runs: Any) -> None:
    store.put_doc("snapshots", drills.HISTORY_KEY, {"runs": list(runs)})


def test_future_drill_time_does_not_silence_the_schedule(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    put_runs(store, {"scenario": "leaked-key", "time": "2099-01-01T00:00:00Z", "passed": True})
    assert drills.due(store, NOW, 24) is True


def ops(store: Store) -> dict[str, Any]:
    report = posture.build(store, NOW, policy=CredentialPolicy())
    return next(i for i in report["indicators"] if i["name"] == "operational health")


def test_posture_strictness_for_tampered_or_partial_drills(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    put_runs(store, {"scenario": "leaked-key", "time": "2026-11-06T11:00:00Z", "passed": "no"})
    assert any("failed" in r for r in ops(store)["reasons"])  # only True counts as a pass
    put_runs(store, {"scenario": "leaked-key", "time": "2099-01-01T00:00:00Z", "passed": True})
    assert any("in the future" in n["why"] for n in ops(store)["not_measured"])
    put_runs(store, {"scenario": "agent-sequence", "time": "2026-11-06T11:00:00Z", "passed": True})
    assert any("secret-leak path was not drilled" in n["why"] for n in ops(store)["not_measured"])


def test_format_result_survives_bad_types() -> None:
    text = drills.format_result(
        {"scenario": "x\x1b[2J", "stages": {"scan": "slow", 3: None}, "checks": "nope", "passed": 1}
    )
    assert "FAILED" in text and "\x1b" not in text and "scan" in text


def test_scheduled_leaked_key_drill_leaves_nothing_in_the_live_store(tmp_path: Path) -> None:
    if not HAVE_GITLEAKS:
        pytest.skip("gitleaks not installed")
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    settings = Settings(drill_interval_hours=24, drill_scenario="leaked-key")
    result = runner.run_once(store, home, settings, NOW, scan=False)
    assert result["health"]["drill"] == "ok"
    dump = json.dumps([store.events(), store.docs("findings"), store.docs("incidents")])
    assert "cred-fp" not in dump and "secret_exposure" not in dump
    assert drills.last(store)["passed"] is True
