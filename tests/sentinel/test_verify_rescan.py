"""verify-rescan: rescan_clean passes only when a successful re-scan no longer finds the credential."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel import findings, runner
from sentinel.events.refs import cred_ref as make_cred_ref
from sentinel.incidents import lifecycle, response
from sentinel.scanners import gitleaks
from sentinel.scanners.gitleaks import Finding, ScanError
from sentinel.simulation import scenarios
from sentinel.store.db import Store

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
STEP = "rescan_clean"
CRED = make_cred_ref("ab" * 8)
OTHER = make_cred_ref("cd" * 8)


def hit(cred_ref: str, file: str = "app.txt", commit: str = "") -> Finding:
    return Finding(cred_ref, "gcp-api-key", file, 3, commit, "")


class FakeScan:
    """Stands in for gitleaks: answers per (path, mode), records every call."""

    def __init__(self, answers: dict[str, list[Finding]] | None = None) -> None:
        self.answers = answers or {}
        self.calls: list[tuple[Path, str]] = []

    def __call__(self, path: Path, mode: str) -> list[Finding]:
        self.calls.append((path, mode))
        return self.answers.get(mode, [])


def r1_incident(tmp_path: Path, *, commit: str = "") -> tuple[Store, str, Path]:
    repo = tmp_path / "victim"
    repo.mkdir()
    store = Store(tmp_path / "s.db")
    store.upsert_asset(
        {
            "asset_id": "repo-victim",
            "asset_type": "repository",
            "name": "victim",
            "owner": "me",
            "importance": "high",
            "monitoring": "partial",
            "recovery_method": None,
            "approved": True,
            "last_seen": "2026-10-27T12:00:00Z",
            "attributes": {"path": str(repo)},
        }
    )
    findings.ingest(store, "repo-victim", [hit(CRED, commit=commit)], T0, is_test=True)
    for e in scenarios.provider_usage(CRED, "repo-victim", T0 + timedelta(minutes=30)):
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, T0 + timedelta(hours=1))
    assert (store.get_doc("incidents", iid) or {})["rule_id"] == "R1"
    return store, iid, repo


def step_state(store: Store, iid: str) -> str:
    incident = store.get_doc("incidents", iid)
    assert incident is not None
    return next(s["state"] for s in incident["response_plan"] if s["step"] == STEP)


def test_r1_plan_has_an_optional_rescan_step() -> None:
    step = next(s for s in response.plan_for("R1") if s["step"] == STEP)
    assert step["response_class"] == "investigate_first"  # a read-only check: no approval needed
    assert step["required_for_close"] is False  # existing close criteria do not change


def test_passes_when_the_credential_is_gone(tmp_path: Path) -> None:
    store, iid, repo = r1_incident(tmp_path)
    scan = FakeScan({"dir": [hit(OTHER, "other.txt")]})  # another credential does not matter
    passed, evidence = runner.verify_rescan(store, iid, "me", T0, scan)
    assert passed and step_state(store, iid) == "verified"
    assert scan.calls == [(repo, "dir")]
    assert "repo-victim" in evidence and "absent" in evidence


def test_fails_while_the_credential_is_still_found(tmp_path: Path) -> None:
    store, iid, _ = r1_incident(tmp_path)
    passed, evidence = runner.verify_rescan(
        store, iid, "me", T0, FakeScan({"dir": [hit(CRED, "moved.txt")]})
    )
    assert not passed and step_state(store, iid) == "verification_failed"
    assert "STILL FOUND" in evidence


def test_a_history_location_is_checked_in_git_mode(tmp_path: Path) -> None:
    store, iid, repo = r1_incident(tmp_path, commit="5910c92")
    (repo / ".git").mkdir()
    scan = FakeScan({"git": [hit(CRED, commit="5910c92")]})
    passed, _ = runner.verify_rescan(store, iid, "me", T0, scan)
    assert not passed  # still in history until it is rewritten (revocation is the real fix)
    assert scan.calls == [(repo, "git")]


def test_a_scan_error_is_never_proof(tmp_path: Path) -> None:
    store, iid, _ = r1_incident(tmp_path)

    def broken(_path: Path, _mode: str) -> list[Finding]:
        raise ScanError("gitleaks exited with code 2")

    with pytest.raises(ScanError):
        runner.verify_rescan(store, iid, "me", T0, broken)
    assert step_state(store, iid) == "pending"  # nothing recorded either way


def test_a_missing_folder_is_never_proof(tmp_path: Path) -> None:
    store, iid, repo = r1_incident(tmp_path)
    repo.rmdir()
    with pytest.raises(ValueError, match="no longer exists"):
        runner.verify_rescan(store, iid, "me", T0, FakeScan())
    assert step_state(store, iid) == "pending"


def test_refuses_what_it_cannot_verify(tmp_path: Path) -> None:
    other = Store(tmp_path / "o.db")
    for e in scenarios.exposed_path("host-demo", T0):
        other.add_event(e)
    [rid] = lifecycle.open_incidents(other, T0)
    with pytest.raises(ValueError, match="rescan_clean"):  # an R10 plan has no such step
        runner.verify_rescan(other, rid, "me", T0, FakeScan())
    with pytest.raises(KeyError):
        runner.verify_rescan(other, "INC-00000000", "me", T0, FakeScan())


def test_asset_without_a_local_path_is_refused(tmp_path: Path) -> None:
    store, iid, _ = r1_incident(tmp_path)
    store.upsert_asset({**next(a for a in store.assets()), "attributes": {}})
    with pytest.raises(ValueError, match="local path"):
        runner.verify_rescan(store, iid, "me", T0, FakeScan())


try:
    gitleaks.find_gitleaks()
    HAVE_GITLEAKS = True
except gitleaks.ScanError:
    HAVE_GITLEAKS = False


@pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not installed")
def test_real_gitleaks_fails_then_passes_once_the_file_is_gone(tmp_path: Path) -> None:
    """End to end with the real scanner and a runtime-generated fake key."""
    from sentinel.security import load_key
    from sentinel.simulation.fakes import fake_google_key

    home = tmp_path / "home"
    key = load_key(home)
    store, iid, repo = r1_incident(tmp_path)
    secret_file = repo / "app.txt"
    fake = fake_google_key()
    secret_file.write_text(f'gemini_api_key = "{fake}"\n')
    real = gitleaks.run(repo, "dir", key, home)
    assert len(real) == 1
    # re-point the incident at the credential the real scanner fingerprinted
    cred = real[0].cred_ref
    incident = store.get_doc("incidents", iid) or {}
    incident["cred_ref"] = cred
    store.put_doc("incidents", iid, incident)
    findings.ingest(store, "repo-victim", real, T0, is_test=True)

    def scan(folder: Path, mode: str) -> list[Finding]:
        return gitleaks.run(folder, mode, key, home)

    passed, evidence = runner.verify_rescan(store, iid, "me", T0, scan)
    assert not passed and "STILL FOUND" in evidence
    secret_file.unlink()
    passed, evidence = runner.verify_rescan(store, iid, "me", T0, scan)
    assert passed and fake not in evidence and cred not in evidence
    assert step_state(store, iid) == "verified"


def test_no_recorded_location_is_never_a_vacuous_pass(tmp_path: Path) -> None:
    store, iid, _ = r1_incident(tmp_path)
    doc = store.get_doc("findings", CRED) or {}
    doc["locations"] = []
    store.put_doc("findings", CRED, doc)
    scan = FakeScan()
    with pytest.raises(ValueError, match="no recorded location"):
        runner.verify_rescan(store, iid, "me", T0, scan)
    assert scan.calls == [] and step_state(store, iid) == "pending"


def test_a_relative_path_is_refused(tmp_path: Path) -> None:
    store, iid, _ = r1_incident(tmp_path)
    store.upsert_asset({**next(a for a in store.assets()), "attributes": {"path": "victim"}})
    with pytest.raises(ValueError, match="absolute"):
        runner.verify_rescan(store, iid, "me", T0, FakeScan())


def test_history_scan_needs_a_git_repository(tmp_path: Path) -> None:
    store, iid, _ = r1_incident(tmp_path, commit="5910c92")  # the folder exists but has no .git
    scan = FakeScan()
    with pytest.raises(ValueError, match="not a Git repository"):
        runner.verify_rescan(store, iid, "me", T0, scan)
    assert scan.calls == [] and step_state(store, iid) == "pending"


def test_a_non_repository_asset_is_refused(tmp_path: Path) -> None:
    store, iid, _ = r1_incident(tmp_path)
    store.upsert_asset({**next(a for a in store.assets()), "asset_type": "api_key"})
    with pytest.raises(ValueError, match="not a known repository"):
        runner.verify_rescan(store, iid, "me", T0, FakeScan())


def test_a_later_scan_failing_records_nothing(tmp_path: Path) -> None:
    """Two locations; the first still finds the credential, the second scan errors: fail closed."""
    store, iid, repo = r1_incident(tmp_path)
    second = tmp_path / "second"
    (second / ".git").mkdir(parents=True)
    store.upsert_asset({**next(a for a in store.assets()), "asset_id": "repo-second",
                        "attributes": {"path": str(second)}})  # fmt: skip
    doc = store.get_doc("findings", CRED) or {}
    doc["locations"].append({"asset_id": "repo-second", "file": "a", "line": 1, "commit": "abc"})
    store.put_doc("findings", CRED, doc)

    def flaky(path: Path, mode: str) -> list[Finding]:
        if path == second:
            raise ScanError("gitleaks timed out after 300s")
        return [hit(CRED)]

    with pytest.raises(ScanError):
        runner.verify_rescan(store, iid, "me", T0, flaky)
    assert step_state(store, iid) == "pending"


def test_the_fingerprint_key_is_never_created_by_a_check(tmp_path: Path) -> None:
    from sentinel.security import load_existing_key, load_key

    home = tmp_path / "home"
    with pytest.raises(ValueError, match="refusing to verify with a new key"):
        load_existing_key(home)
    assert not (home / "fingerprint.key").exists()  # nothing was created
    key = load_key(home)
    assert load_existing_key(home) == key


def test_unscanned_files_make_the_result_inconclusive_not_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Files the scan could not read might hold the credential: 'absent' would prove nothing."""
    monkeypatch.setattr(gitleaks, "_MAX_JSON_BYTES", 10)
    store, iid, repo = r1_incident(tmp_path)
    (repo / "transcript.jsonl").write_text('{"c": "' + "x" * 200 + '"}\n')
    passed, evidence = runner.verify_rescan(store, iid, "me", T0, FakeScan())
    assert not passed and "INCONCLUSIVE" in evidence and "absent" not in evidence
    assert step_state(store, iid) == "verification_failed"  # recorded, never a pass


def test_evidence_states_the_limited_scope(tmp_path: Path) -> None:
    store, iid, _ = r1_incident(tmp_path)
    _passed, evidence = runner.verify_rescan(store, iid, "me", T0, FakeScan())
    assert "scanned scope only" in evidence and "build folders skipped" in evidence


def test_evidence_carries_no_fingerprint_or_value(tmp_path: Path) -> None:
    store, iid, _ = r1_incident(tmp_path)
    _passed, evidence = runner.verify_rescan(store, iid, "me", T0, FakeScan())
    assert evidence.startswith("re-scan at ") and CRED not in evidence and "cred-fp" not in evidence
