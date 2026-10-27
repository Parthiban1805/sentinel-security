"""M2: gitleaks wrapper + findings registry. Fake keys only, generated at runtime."""

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel import findings
from sentinel.cli import main
from sentinel.scanners import gitleaks
from sentinel.security import fingerprint, load_key
from sentinel.simulation.fakes import fake_google_key
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


def make_repo(tmp_path: Path, key: str, *, delete: bool) -> Path:
    repo = tmp_path / "demo repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "sentinel-test")
    (repo / "config.txt").write_text(f'gemini_api_key = "{key}"\n')
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "add config")
    if delete:
        (repo / "config.txt").unlink()
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "remove config")
    return repo


def test_fingerprint_is_keyed_and_stable(tmp_path: Path) -> None:
    key_a, key_b = load_key(tmp_path / "a"), load_key(tmp_path / "b")
    assert fingerprint("v", key_a) == fingerprint("v", key_a)
    assert fingerprint("v", key_a) != fingerprint("v", key_b)
    assert load_key(tmp_path / "a") == key_a  # persisted


def test_parse_drops_secret_and_hashes() -> None:
    raw = '[{"RuleID":"r","File":"a\\\\b.txt","StartLine":3,"Commit":"c1","Date":"d","Secret":"TOPSECRETVALUE","Match":"TOPSECRETVALUE"}]'
    key = b"k" * 32
    [f] = gitleaks.parse(raw, key)
    assert f.cred_ref == f"cred-fp-{fingerprint('TOPSECRETVALUE', key)}"
    assert f.file == "a/b.txt"
    assert "TOPSECRET" not in repr(f)


def test_parse_empty_output() -> None:
    assert gitleaks.parse("", b"k" * 32) == []
    assert gitleaks.parse("null", b"k" * 32) == []


@needs_gitleaks
def test_same_key_in_history_and_tree_is_one_credential(tmp_path: Path) -> None:
    key = fake_google_key()
    repo = make_repo(tmp_path, key, delete=False)
    home = tmp_path / "home"
    k = load_key(home)
    hits = gitleaks.run(repo, "dir", k, home) + gitleaks.run(repo, "git", k, home)
    assert len(hits) >= 2
    assert len({h.cred_ref for h in hits}) == 1  # one key = one ID
    assert hits[0].cred_ref == f"cred-fp-{fingerprint(key, k)}"


@needs_gitleaks
def test_cli_scan_registers_finding_without_leaking_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = fake_google_key()
    repo = make_repo(tmp_path, key, delete=True)
    home = tmp_path / "home"
    assert main(["--home", str(home), "scan", str(repo), "--history"]) == 0
    assert main(["--home", str(home), "findings", "list"]) == 0
    out = capsys.readouterr()
    assert "NEW cred-fp-" in out.out
    assert key not in out.out + out.err
    for path in home.rglob("*"):
        if path.is_file():
            assert key.encode() not in path.read_bytes(), f"secret value found in {path.name}"
    store = Store(home / "sentinel.db")
    [event] = store.events(event_type="secret_exposure")
    assert event["credential_ref"].startswith("cred-fp-")
    assert event["is_test"] is False


@needs_gitleaks
def test_rescan_reports_nothing_new(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = make_repo(tmp_path, fake_google_key(), delete=True)
    home = tmp_path / "home"
    main(["--home", str(home), "scan", str(repo), "--history"])
    capsys.readouterr()
    main(["--home", str(home), "scan", str(repo), "--history"])
    assert "0 new credential(s)" in capsys.readouterr().out
    assert len(Store(home / "sentinel.db").events()) == 1


def test_lifecycle_rules(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    f = gitleaks.Finding("cred-fp-abcd1234", "gcp-api-key", "a.txt", 1, "", "")
    findings.ingest(store, "repo-x", [f], NOW)
    with pytest.raises(ValueError):
        findings.set_status(store, f.cred_ref, "revoked_verified", actor="me", now=NOW)
    with pytest.raises(ValueError):
        findings.set_status(store, f.cred_ref, "risk_accepted", actor="me", now=NOW)
    with pytest.raises(ValueError):
        findings.set_status(store, f.cred_ref, "bogus", actor="me", now=NOW)
    findings.set_status(store, f.cred_ref, "risk_accepted", actor="me", now=NOW, accept_days=30)
    assert findings.expired_acceptances(store, NOW + timedelta(days=29)) == []
    assert len(findings.expired_acceptances(store, NOW + timedelta(days=31))) == 1
    doc = findings.set_status(
        store, f.cred_ref, "revoked_verified", actor="me", now=NOW, evidence="console shows deleted"
    )
    assert doc["status"] == "revoked_verified"
    assert [a["to"] for a in store.audit()] == ["risk_accepted", "revoked_verified"]
