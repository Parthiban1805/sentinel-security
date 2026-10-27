"""End-to-end: fake leaked credential -> scan -> R1 incident -> impact -> approved dry-run response
-> verification -> closure. Also proves failed verification cannot close, and no raw value leaks."""

import json
import subprocess
from pathlib import Path

import pytest

from sentinel.cli import main
from sentinel.scanners import gitleaks
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

try:
    gitleaks.find_gitleaks()
    HAVE_GITLEAKS = True
except gitleaks.ScanError:
    HAVE_GITLEAKS = False

pytestmark = pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not installed")

ACTOR = "tester"


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S603, S607


class Env:
    def __init__(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        self.home = tmp_path / "home"
        self.capsys = capsys
        self.key = fake_google_key()
        self.transcript = ""
        self.repo = tmp_path / "victim-repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "t@example.invalid")
        git(self.repo, "config", "user.name", "sentinel-test")
        (self.repo / "app.txt").write_text(f'gemini_api_key = "{self.key}"\n')
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "add")
        (self.repo / "app.txt").unlink()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "remove")
        cloud = tmp_path / "assets.json"
        cloud.write_text(
            json.dumps(
                [
                    {
                        "asset_id": "provider-demo",
                        "asset_type": "cloud_account",
                        "name": "demo cloud project",
                        "owner": "tester",
                        "importance": "high",
                        "monitoring": "partial",
                        "approved": True,
                        "last_seen": "2026-10-27T12:00:00Z",
                    }
                ]
            )
        )
        self.cloud = cloud

    def run(self, *argv: str) -> int:
        code = main(["--home", str(self.home), *argv])
        out = self.capsys.readouterr()
        self.transcript += out.out + out.err
        self.last = out.out + out.err
        return code

    @property
    def store(self) -> Store:
        return Store(self.home / "sentinel.db")


@pytest.fixture
def env(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Env:
    return Env(tmp_path, capsys)


def open_r1_incident(env: Env) -> tuple[str, str]:
    assert env.run("scan", str(env.repo), "--history") == 0
    [finding] = env.store.docs("findings")
    ref = finding["cred_ref"]
    assert env.run("inventory", "import", str(env.cloud)) == 0
    assert (
        env.run(
            "inventory", "link", ref, "provider-demo", "--permission", "write", "--actor", ACTOR
        )
        == 0
    )
    assert env.run("simulate", "usage", "--cred", ref, "--asset", "provider-demo") == 0
    assert env.run("correlate") == 0
    [incident] = env.store.docs("incidents")
    return incident["id"], ref


def test_full_incident_loop(env: Env) -> None:
    iid, ref = open_r1_incident(env)
    incident = env.store.get_doc("incidents", iid)
    assert incident is not None
    assert (incident["rule_id"], incident["severity"], incident["urgency"]) == (
        "R1",
        "critical",
        "immediate",
    )
    assert incident["is_test"] is True and incident["verified"] is False
    assert incident["blast_radius"]["confirmed_access"][0]["asset_id"] == "provider-demo"
    assert any("do not prove" in h for h in incident["hypotheses"])
    assert [t["event_type"] for t in incident["timeline"]] == [
        "secret_exposure",
        "credential_usage_anomaly",
    ]

    # nothing can be closed or executed without the gates
    assert env.run("incident", "close", iid, "--actor", ACTOR) == 1
    assert "required steps not verified" in env.last
    assert env.run("incident", "execute", iid, "revoke_credential", "--actor", ACTOR) == 1
    assert "needs human approval" in env.last

    # approve + dry-run execute; a FAILED verification keeps the incident open and the finding pending
    assert env.run("incident", "approve", iid, "revoke_credential", "--actor", ACTOR) == 0
    assert env.run("incident", "execute", iid, "revoke_credential", "--actor", ACTOR) == 0
    assert "DRY-RUN" in env.last
    assert (
        env.run(
            "incident",
            "verify",
            iid,
            "revoke_credential",
            "--actor",
            ACTOR,
            "--evidence",
            "old key still authenticates",
            "--fail",
        )
        == 0
    )
    assert env.run("incident", "close", iid, "--actor", ACTOR) == 1
    assert env.store.get_doc("findings", ref)["status"] == "revoke_pending"  # type: ignore[index]

    # real verification passes -> finding becomes revoked_verified
    assert (
        env.run(
            "incident",
            "verify",
            iid,
            "revoke_credential",
            "--actor",
            ACTOR,
            "--evidence",
            "provider console shows key deleted",
        )
        == 0
    )
    assert env.store.get_doc("findings", ref)["status"] == "revoked_verified"  # type: ignore[index]
    for step in ("review_usage", "review_related_identities"):
        assert (
            env.run(
                "incident",
                "verify",
                iid,
                step,
                "--actor",
                ACTOR,
                "--evidence",
                "reviewed, nothing else",
            )
            == 0
        )
    assert env.run("incident", "close", iid, "--actor", ACTOR) == 1  # replacement still missing
    assert env.run("incident", "approve", iid, "issue_replacement", "--actor", ACTOR) == 0
    assert (
        env.run(
            "incident",
            "verify",
            iid,
            "issue_replacement",
            "--actor",
            ACTOR,
            "--evidence",
            "new scoped key in secret store",
        )
        == 0
    )
    assert env.run("incident", "close", iid, "--actor", ACTOR) == 0
    closed = env.store.get_doc("incidents", iid)
    assert closed is not None and closed["status"] == "closed" and closed["verified"] is True

    # re-correlating must not reopen it; revoked+verified suppresses R1
    assert env.run("correlate") == 0
    assert "0 new incident" in env.last
    assert len(env.store.docs("incidents")) == 1

    # reports
    report = env.home / "report.md"
    assert env.run("report", "--out", str(report)) == 0
    assert env.run("report", "--incident", iid) == 0
    assert "Gate A" in report.read_text() and "CONFIRMED access" in env.last

    # no raw credential anywhere: output, state files, report
    assert env.key not in env.transcript
    for path in env.home.rglob("*"):
        if path.is_file():
            assert env.key.encode() not in path.read_bytes(), path.name


def test_unverified_close_is_explicit_and_recorded(env: Env) -> None:
    iid, _ = open_r1_incident(env)
    assert (
        env.run(
            "incident", "close", iid, "--actor", ACTOR, "--unverified-note", "provider unreachable"
        )
        == 0
    )
    closed = env.store.get_doc("incidents", iid)
    assert closed is not None
    assert closed["verified"] is False and "UNVERIFIED" in closed["close_note"]


def test_verify_requires_evidence_and_known_step(env: Env) -> None:
    iid, _ = open_r1_incident(env)
    assert (
        env.run("incident", "verify", iid, "review_usage", "--actor", ACTOR, "--evidence", "  ")
        == 1
    )
    assert (
        env.run("incident", "verify", iid, "no_such_step", "--actor", ACTOR, "--evidence", "x") == 1
    )
    assert (
        env.run("incident", "verify", iid, "issue_replacement", "--actor", ACTOR, "--evidence", "x")
        == 1
    )  # unapproved
