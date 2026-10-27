"""Canary decoys (R7): planting, tripwires, copy detection through the real secret scan, incidents.

Real gitleaks and real files in temp dirs. Decoy values are fake and random; the tests read them from
the decoy file ONLY to prove that they never appear in anything Sentinel stores or prints.
"""

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel import canaries, runner
from sentinel.cli import main
from sentinel.config import Settings
from sentinel.incidents import lifecycle
from sentinel.scanners import gitleaks
from sentinel.security import load_key
from sentinel.store.db import Store

try:
    gitleaks.find_gitleaks()
    HAVE_GITLEAKS = True
except gitleaks.ScanError:
    HAVE_GITLEAKS = False

needs_gitleaks = pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not installed")
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S603, S607


def decoy_value(path: Path) -> str:
    """Test-only: pull the fake value out of the decoy file (Sentinel itself never keeps it)."""
    return path.read_text(encoding="utf-8").splitlines()[1].split("=", 1)[1]


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.home = tmp_path / "home"
        self.store = Store(self.home / "sentinel.db")
        self.key = load_key(self.home)
        self.vault = tmp_path / "vault"
        self.vault.mkdir()
        self.elsewhere = tmp_path / "elsewhere"
        self.elsewhere.mkdir()

    def plant(self, **kw: str) -> dict:  # type: ignore[type-arg]
        return canaries.plant(self.store, self.key, self.vault, NOW, **kw)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


# planting -------------------------------------------------------------------------------------------
def test_plant_creates_a_fake_credential_file_and_stores_only_a_fingerprint(env: Env) -> None:
    doc = env.plant()
    path = Path(doc["path"])
    assert path.name == ".env.backup" and path.exists()
    value = decoy_value(path)
    assert value.startswith("AIza") and len(value) == 39  # provider-shaped fake
    assert doc["cred_ref"].startswith("cred-fp-") and doc["status"] == "armed"
    assert doc["atime_check"] in ("immediate", "unverified")
    stored = json.dumps(doc) + json.dumps(env.store.assets()) + json.dumps(env.store.audit())
    assert value not in stored
    assert any(a["asset_id"].startswith("canary-") and a["approved"] for a in env.store.assets())


def test_both_kinds_and_unique_values(env: Env) -> None:
    a = env.plant(name="a.bak")
    b = env.plant(kind="github_pat", name="b.bak")
    assert decoy_value(Path(a["path"])) != decoy_value(Path(b["path"]))
    assert decoy_value(Path(b["path"])).startswith("github_pat_")
    assert a["canary_id"] != b["canary_id"]


@pytest.mark.parametrize("name", ["../evil", "a/b", "", ".", "..", "x" * 70, "bad name"])
def test_unsafe_decoy_names_are_refused(env: Env, name: str) -> None:
    with pytest.raises(canaries.CanaryError):
        env.plant(name=name)


def test_plant_refuses_to_overwrite_and_bad_directories(env: Env, tmp_path: Path) -> None:
    env.plant()
    with pytest.raises(canaries.CanaryError, match="already exists"):
        env.plant()
    with pytest.raises(canaries.CanaryError, match="not a directory"):
        canaries.plant(env.store, env.key, tmp_path / "missing", NOW)
    with pytest.raises(canaries.CanaryError, match="kind"):
        env.plant(kind="aws")


def test_decoy_inside_a_git_repo_is_excluded_locally_so_it_cannot_be_committed(
    tmp_path: Path,
) -> None:
    env = Env(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    doc = canaries.plant(env.store, env.key, repo, NOW)
    assert "info/exclude" in (doc["git_note"] or "")
    status = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "status", "--porcelain"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert ".env.backup" not in status  # untracked-but-excluded: `git add .` cannot pick it up


# tripwires: tamper / remove / read --------------------------------------------------------------------
def test_untouched_decoy_produces_no_signals_and_check_never_reads_it(env: Env) -> None:
    env.plant()
    for _ in range(3):
        assert canaries.check(env.store, NOW) == []  # stat() only: our own checks never fake a read


def test_modification_is_detected_once(env: Env) -> None:
    doc = env.plant()
    path = Path(doc["path"])
    path.write_text(path.read_text() + "# edited\n", encoding="utf-8")  # editing also READS it
    events = canaries.check(env.store, NOW)
    by_reason = {e["attributes"]["reason"]: e for e in events}
    assert "modified" in by_reason  # a 'read' signal may accompany it: realistic, and harmless
    event = by_reason["modified"]
    assert event["severity"] == "high" and event["confidence"] == "medium"
    assert event["credential_ref"] == doc["cred_ref"]
    assert canaries.check(env.store, NOW) == []  # reported once
    assert env.store.get_doc("canaries", doc["canary_id"])["status"] == "triggered"  # type: ignore[index]


def test_removal_is_detected_once(env: Env) -> None:
    doc = env.plant()
    Path(doc["path"]).unlink()
    [event] = canaries.check(env.store, NOW)
    assert event["attributes"]["reason"] == "removed"
    assert canaries.check(env.store, NOW) == []


def test_read_is_a_low_confidence_event_that_never_opens_an_incident(env: Env) -> None:
    doc = env.plant()
    path = Path(doc["path"])
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns + 5_000_000_000, st.st_mtime_ns))  # simulate a later read
    [event] = canaries.check(env.store, NOW)
    assert (event["attributes"]["reason"], event["severity"], event["confidence"]) == (
        "read",
        "low",
        "low",
    )
    env.store.add_event(event)
    assert lifecycle.open_incidents(env.store, NOW) == []  # antivirus/indexers must not page anyone
    assert canaries.check(env.store, NOW) == []  # the same access is reported once


def test_disarmed_canaries_are_ignored(env: Env) -> None:
    doc = env.plant()
    canaries.disarm(env.store, doc["canary_id"], NOW, delete_file=True)
    assert canaries.check(env.store, NOW) == [] and not Path(doc["path"]).exists()
    with pytest.raises(KeyError):
        canaries.disarm(env.store, "CAN-NOPE", NOW)


# copy detection through the real scan -----------------------------------------------------------------
@needs_gitleaks
def test_decoy_at_its_own_location_is_not_a_finding(env: Env) -> None:
    env.plant()
    found = gitleaks.run(env.vault, "dir", env.key, env.home)
    assert len(found) >= 1  # gitleaks does see the decoy...
    events, kept = canaries.filter_findings(env.store, env.vault, found, NOW)
    assert events == [] and kept == []  # ...but it is expected there, so no event and no finding


@needs_gitleaks
def test_a_copied_decoy_is_a_canary_event_and_never_a_live_credential_finding(env: Env) -> None:
    doc = env.plant()
    value_line = Path(doc["path"]).read_text(encoding="utf-8")
    (env.elsewhere / "notes.txt").write_text(value_line, encoding="utf-8")  # an attacker stages it
    found = gitleaks.run(env.elsewhere, "dir", env.key, env.home)
    events, kept = canaries.filter_findings(env.store, env.elsewhere, found, NOW)
    assert kept == []  # the decoy never becomes a "live exposed key"
    [event] = events
    assert event["attributes"]["reason"] == "copied" and event["severity"] == "critical"
    assert event["confidence"] == "high" and "notes.txt" in event["attributes"]["location"]
    assert env.store.get_doc("canaries", doc["canary_id"])["status"] == "triggered"  # type: ignore[index]


@needs_gitleaks
def test_a_decoy_committed_to_git_history_counts_as_copied(env: Env, tmp_path: Path) -> None:
    doc = env.plant()
    repo = tmp_path / "otherrepo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "sentinel-test")
    (repo / "config.txt").write_text(Path(doc["path"]).read_text(encoding="utf-8"))
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "oops")
    (repo / "config.txt").unlink()  # deleted, but still in history (the origin incident pattern)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "remove")
    found = gitleaks.run(repo, "git", env.key, env.home)
    events, kept = canaries.filter_findings(env.store, repo, found, NOW)
    assert kept == [] and events and all(e["attributes"]["reason"] == "copied" for e in events)
    assert "@" in events[0]["attributes"]["location"]  # location names the commit


@needs_gitleaks
def test_unrelated_secrets_still_become_findings(env: Env) -> None:
    from sentinel.simulation.fakes import fake_google_key

    env.plant()
    (env.elsewhere / "real.txt").write_text(f'gemini_api_key = "{fake_google_key()}"\n')
    found = gitleaks.run(env.elsewhere, "dir", env.key, env.home)
    events, kept = canaries.filter_findings(env.store, env.elsewhere, found, NOW)
    assert events == [] and len(kept) == 1


# end to end: run -> incident -> response -------------------------------------------------------------------
@needs_gitleaks
def test_run_detects_a_copied_decoy_and_opens_a_critical_incident_without_leaking(
    env: Env, tmp_path: Path
) -> None:
    doc = env.plant()
    value = decoy_value(Path(doc["path"]))
    (env.elsewhere / "stolen.txt").write_text(Path(doc["path"]).read_text(encoding="utf-8"))
    settings = Settings(scan_paths=(str(env.elsewhere),))
    result = runner.run_once(env.store, env.home, settings, NOW, scan=True, probe_pause=0)
    assert result["health"]["canary:check"] == "ok"
    [iid] = result["incidents_created"]
    incident = env.store.get_doc("incidents", iid)
    assert (
        incident is not None and incident["rule_id"] == "R7" and incident["severity"] == "critical"
    )
    assert incident["is_test"] is False and "another location" in incident["facts"][0]
    assert not env.store.docs("findings")  # no live-credential finding was registered
    assert any("alerts" in a or iid in a for a in result["alerts"])
    for path in env.home.rglob("*"):
        if path.is_file():
            assert value.encode() not in path.read_bytes(), path.name


# CLI ----------------------------------------------------------------------------------------------------
def test_cli_plant_list_check_disarm(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    home = str(env.home)
    assert main(["--home", home, "canary", "plant", str(env.vault), "--name", "x.bak"]) == 0
    out = capsys.readouterr().out
    assert "planted CAN-" in out and "fingerprint is kept" in out
    value = decoy_value(env.vault / "x.bak")
    assert value not in out  # the decoy value is never printed
    assert main(["--home", home, "canary", "list"]) == 0
    listing = capsys.readouterr().out
    assert "armed" in listing and "x.bak" in listing
    assert main(["--home", home, "canary", "check"]) == 0
    (env.vault / "x.bak").unlink()
    assert main(["--home", home, "canary", "check"]) == 1  # removal is an alert-worthy signal
    cid = listing.split()[0]
    assert main(["--home", home, "canary", "disarm", cid]) == 0
    assert main(["--home", home, "canary", "disarm", "CAN-NOPE"]) == 1


def test_r7_still_fires_for_the_simulated_chain_and_for_use() -> None:
    from sentinel.correlation.engine import correlate
    from sentinel.correlation.model import Context
    from sentinel.simulation import scenarios

    [match] = correlate(scenarios.canary("decoy", NOW), Context())
    assert (
        match.rule_id == "R7" and match.severity_floor == "critical" and match.confidence == "high"
    )


def test_coverage_registry_knows_the_canary_producer() -> None:
    from sentinel import coverage

    assert "canary_triggered" in coverage.REAL_PRODUCERS
    assert "canary_triggered" not in coverage.SIMULATION_ONLY
