"""GitHub protection audit: evaluation of realistic API answers, error classification, run gating."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel import audit, runner
from sentinel.cli import main
from sentinel.config import Settings
from sentinel.sources.github import GitHubCollector
from sentinel.sources.http import HttpClient, HttpError, Response, error_hint
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
TOKEN = "github_pat_" + "Z9y8X7w6V5" * 8  # fake, built at runtime

PLAN_LIMIT = b'{"message":"Upgrade to GitHub Pro or make this repository public to enable this feature.","status":"403"}'
NO_PERMISSION = b'{"message":"Resource not accessible by personal access token","status":"403"}'
NOT_PROTECTED = b'{"message":"Branch not protected","status":"404"}'


def checks(findings: list[audit.AuditFinding]) -> set[str]:
    return {f.check for f in findings}


REPO_FULL = {
    "default_branch": "main",
    "private": True,
    "security_and_analysis": {
        "secret_scanning": {"status": "enabled"},
        "secret_scanning_push_protection": {"status": "enabled"},
    },
}
GOOD_PROTECTION = {
    "required_pull_request_reviews": {"required_approving_review_count": 1},
    "enforce_admins": {"enabled": True},
    "allow_force_pushes": {"enabled": False},
    "allow_deletions": {"enabled": False},
}


# error classification -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "body,expected",
    [
        (PLAN_LIMIT, "plan_limit"),
        (NO_PERMISSION, "no_permission"),
        (NOT_PROTECTED, "not_protected"),
        (b'{"message":"Something else"}', None),
        (b"", None),
    ],
)
def test_error_hint_uses_a_fixed_vocabulary(body: bytes, expected: str | None) -> None:
    assert error_hint(body) == expected


def test_http_error_carries_the_hint_but_never_the_body() -> None:
    class T:
        def send(self, *a: Any, **k: Any) -> Response:
            return Response(403, {}, PLAN_LIMIT)

    with pytest.raises(HttpError) as exc:
        HttpClient(T()).get("https://api.github.com/repos/o/r/branches/main/protection")
    assert exc.value.status == 403 and exc.value.hint == "plan_limit"
    assert "Upgrade" not in str(exc.value) and "message" not in str(exc.value)


# evaluation -----------------------------------------------------------------------------------------
def test_well_configured_repo_has_no_findings() -> None:
    assert audit.evaluate((200, REPO_FULL, None), (200, GOOD_PROTECTION, None)) == []


def test_free_plan_private_repo_is_reported_as_a_plan_limit_not_a_permission_problem() -> None:
    meta = {"default_branch": "main", "private": True}  # no security_and_analysis visible
    found = audit.evaluate((200, meta, None), (403, None, "plan_limit"))
    bp1 = next(f for f in found if f.check == "BP1")
    assert (
        bp1.severity == "high" and "this plan" in bp1.detail and "Administration" not in bp1.detail
    )
    assert "SS0" in checks(found)  # scanning settings invisible: "cannot see", not "off"


def test_scanning_settings_missing_after_a_plan_limit_is_explained_as_a_hypothesis() -> None:
    """Found live: with Administration read granted, SS0 still appeared. The message must not blame the token."""
    meta = {"default_branch": "main", "private": True}
    ss0 = next(
        f for f in audit.evaluate((200, meta, None), (403, None, "plan_limit")) if f.check == "SS0"
    )
    assert "private repositories on this plan" in ss0.detail and "hypothesis" in ss0.detail
    assert "lacks" not in ss0.detail  # the token is not the suspect here
    permission = audit.evaluate((200, meta, None), (403, None, "no_permission"))
    assert "lacks the Administration" in next(f for f in permission if f.check == "SS0").detail


def test_missing_permission_is_distinct_from_the_plan_limit() -> None:
    found = audit.evaluate((200, {"default_branch": "main"}, None), (403, None, "no_permission"))
    gp9 = next(f for f in found if f.check == "GP9")
    assert "Administration" in gp9.detail and "BP1" not in checks(found)


def test_unprotected_branch() -> None:
    found = audit.evaluate((200, REPO_FULL, None), (404, None, "not_protected"))
    assert checks(found) == {"BP1"}


def test_weak_protection_details() -> None:
    weak = {
        "required_pull_request_reviews": None,
        "enforce_admins": {"enabled": False},
        "allow_force_pushes": {"enabled": True},
        "allow_deletions": {"enabled": True},
    }
    found = audit.evaluate((200, REPO_FULL, None), (200, weak, None))
    assert checks(found) == {"BP2", "BP3", "BP4", "BP5"}
    assert next(f for f in found if f.check == "BP2").severity == "high"


def test_secret_scanning_disabled_is_reported_when_visible() -> None:
    meta = dict(
        REPO_FULL,
        security_and_analysis={
            "secret_scanning": {"status": "disabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
        },
    )
    assert checks(audit.evaluate((200, meta, None), (200, GOOD_PROTECTION, None))) == {"SS1", "SS2"}


def test_unreadable_repository_and_unknown_errors_are_low_confidence_gaps() -> None:
    assert checks(audit.evaluate((404, None, None), (0, None, None))) == {"GP0"}
    found = audit.evaluate((200, REPO_FULL, None), (500, None, None))
    assert checks(found) == {"GP9"}
    events = audit.to_events("o/r", found, NOW)
    assert events[0]["confidence"] == "low"  # a gap in what we could see is not a verified problem


# events, gating ---------------------------------------------------------------------------------------
def test_events_are_valid_idempotent_config_drift(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    found = audit.evaluate((200, {"default_branch": "main"}, None), (403, None, "plan_limit"))
    events = audit.to_events("Parthiban1805/sentinel-security", found, NOW)
    assert all(e["event_type"] == "config_drift" and e["source"] == "github_audit" for e in events)
    assert sum(store.add_event(e) for e in events) == len(events)
    assert (
        sum(
            store.add_event(e)
            for e in audit.to_events("Parthiban1805/sentinel-security", found, NOW)
        )
        == 0
    )


def test_an_audit_that_could_not_read_the_repo_never_suppresses_the_next_attempt(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "s.db")
    incomplete = audit.new_snapshot([audit.AuditFinding("GP0", "low", "unreadable")], NOW)
    store.put_doc("snapshots", audit.snapshot_key("o/r"), incomplete)
    assert audit.due(store, "o/r", NOW + timedelta(minutes=5), 24)  # retried immediately
    complete = audit.new_snapshot([audit.AuditFinding("BP1", "high", "unprotected")], NOW)
    store.put_doc("snapshots", audit.snapshot_key("o/r"), complete)
    assert not audit.due(store, "o/r", NOW + timedelta(minutes=5), 24)  # a real result is respected


def test_due_gates_by_interval(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    assert audit.due(store, "o/r", NOW, 24)
    store.put_doc("snapshots", audit.snapshot_key("o/r"), audit.new_snapshot([], NOW))
    assert not audit.due(store, "o/r", NOW + timedelta(hours=23), 24)
    assert audit.due(store, "o/r", NOW + timedelta(hours=25), 24)


# collector + run integration with a fake transport ---------------------------------------------------------
class Routes:
    def __init__(self, answers: dict[str, tuple[int, bytes]]) -> None:
        self.answers = answers
        self.urls: list[str] = []

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
    ) -> Response:
        self.urls.append(url)
        for suffix, (status, payload) in self.answers.items():
            if url.endswith(suffix):
                return Response(status, {}, payload)
        return Response(404, {}, b"")


def free_plan_routes() -> Routes:
    return Routes(
        {
            "/branches/main/protection": (403, PLAN_LIMIT),
            "/repos/o/r": (200, json.dumps({"default_branch": "main", "private": True}).encode()),
        }
    )


def test_audit_inputs_uses_the_default_branch_and_classifies_errors() -> None:
    routes = free_plan_routes()
    gh = GitHubCollector(HttpClient(routes), TOKEN, b"k" * 32)
    repo_probe, protection = gh.audit_inputs("o/r")
    assert repo_probe[0] == 200 and protection == (403, None, "plan_limit")
    assert any(u.endswith("/repos/o/r/branches/main/protection") for u in routes.urls)
    assert all(
        u.startswith("https://api.github.com/") for u in routes.urls
    )  # allowlisted host only


def test_run_audits_once_per_interval_and_tolerates_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(runner.GITHUB_TOKEN_ENV, TOKEN)
    home = tmp_path / "home"
    store = Store(home / "sentinel.db")
    routes = free_plan_routes()
    settings = Settings(github_repos=("o/r",))
    first = runner.run_once(store, home, settings, NOW, client=HttpClient(routes), scan=False)
    assert first["health"]["audit:o/r"] == "ok"
    drift = [e for e in store.events(event_type="config_drift") if e["source"] == "github_audit"]
    assert {e["attributes"]["check"] for e in drift} == {"BP1", "SS0"}
    calls = len(routes.urls)
    runner.run_once(
        store, home, settings, NOW + timedelta(hours=1), client=HttpClient(routes), scan=False
    )
    protection_calls = [u for u in routes.urls[calls:] if "protection" in u]
    assert protection_calls == []  # inside the interval: not audited again
    off = runner.run_once(
        store, home, Settings(github_repos=("o/r",), github_audit=False), NOW + timedelta(days=3),
        client=HttpClient(routes), scan=False,
    )  # fmt: skip
    assert "audit:o/r" not in off["health"]


def test_cli_audit_requires_a_repo_and_a_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(runner.GITHUB_TOKEN_ENV, raising=False)
    cfg = str(tmp_path / "none.toml")
    home = str(tmp_path / "home")
    assert main(["--home", home, "audit", "--config", cfg]) == 1
    assert "no repositories" in capsys.readouterr().err
    assert main(["--home", home, "audit", "--repo", "o/r", "--config", cfg]) == 1
    assert "no GitHub token" in capsys.readouterr().err
    assert main(["--home", home, "audit", "--repo", "a/b/../../user", "--config", cfg]) == 1


def test_a_rejected_token_is_a_health_failure_and_records_no_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found live: an expired token made the audit report 'ok' plus a misleading 'could not read' event."""
    monkeypatch.setenv(runner.GITHUB_TOKEN_ENV, TOKEN)
    home = tmp_path / "home"
    store = Store(home / "sentinel.db")

    class Rejected:  # GitHub answers 401 to everything when the token is bad
        def send(self, *args: Any, **kwargs: Any) -> Response:
            return Response(401, {}, b'{"message":"Bad credentials"}')

    rejected = Rejected()
    result = runner.run_once(
        store, home, Settings(github_repos=("o/r",)), NOW, client=HttpClient(rejected), scan=False
    )
    assert result["health"]["audit:o/r"].startswith("error: GitHub rejected the token")
    assert (
        "expired, revoked or wrong" in result["health"]["github:o/r"]
    )  # the collectors say it too
    assert [
        e for e in store.events(event_type="config_drift") if e["source"] == "github_audit"
    ] == []
    assert TOKEN not in json.dumps(result)
    assert (
        main(
            ["--home", str(home), "audit", "--repo", "o/r", "--config", str(tmp_path / "none.toml")]
        )
        == 1
    )
    assert TOKEN not in capsys.readouterr().err


def test_coverage_still_lists_config_drift_producers() -> None:
    from sentinel import coverage

    assert "config_drift" in coverage.REAL_PRODUCERS
