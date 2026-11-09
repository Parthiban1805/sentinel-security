"""Google Cloud collector: baseline detection, dead-key use, aliases, key status. Fake transport."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinel.events.schema import format_time
from sentinel.sources.gcp import GcpCollector, alias_key, detect, normalize_credential_id
from sentinel.sources.http import HttpClient, Response
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


class FakeTokens:
    def token(self) -> str:
        return "fake-access-token"


class Routes:
    def __init__(
        self, keys: list[dict[str, Any]], per_key: dict[str, list[int]], project: list[int]
    ) -> None:
        self.keys, self.per_key, self.project = keys, per_key, project
        self.urls: list[str] = []
        self.headers: list[dict[str, str]] = []

    @staticmethod
    def _points(counts: list[int]) -> list[dict[str, Any]]:
        start = NOW - timedelta(hours=len(counts) + 1)
        return [
            {
                "interval": {"endTime": format_time(start + timedelta(hours=i))},
                "value": {"int64Value": str(c)},
            }
            for i, c in enumerate(counts)
        ]

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
    ) -> Response:
        self.urls.append(url)
        self.headers.append(headers)
        if "apikeys.googleapis.com" in url:
            payload: Any = {"keys": self.keys}
        elif "groupByFields" in url:
            payload = {
                "timeSeries": [
                    {"resource": {"labels": {"credential_id": cid}}, "points": self._points(c)}
                    for cid, c in self.per_key.items()
                ]
            }
        else:
            payload = {"timeSeries": [{"points": self._points(self.project)}]}
        return Response(200, {}, json.dumps(payload).encode())


def not_first_run(store: Store) -> Store:
    """Pretend an earlier run already learned the baseline window (alerts are then live)."""
    store.put_doc("cursors", "gcp:demo", {"since": format_time(NOW - timedelta(days=8))})
    return store


def run(store: Store, routes: Routes) -> list[dict[str, Any]]:
    collector = GcpCollector(HttpClient(routes), FakeTokens())
    events = collector.collect_usage(
        store, "demo", NOW, lookback=timedelta(days=7), multiple=3.0, floor=50, spend_multiple=3.0
    )
    collector.commit(store)  # what the runner does after the events were stored
    return events


def test_detect_needs_history_and_threshold() -> None:
    points = [(f"t{i:03d}", 10) for i in range(30)] + [("t999", 200)]
    anomalies, history = detect(points, [], 3.0, 50)
    assert [(a[0], a[3]) for a in anomalies] == [("t999", "volume_above_baseline")]
    assert len(history) == 30  # the spike is NOT learned into the baseline
    assert detect([("x", 40)], [10] * 30, 3.0, 50)[0] == []  # above 3x mean but under floor


def test_slow_ramp_cannot_inflate_the_baseline() -> None:
    history = [10] * 30
    for step in range(5):  # attacker ramps up: every hour is flagged, none is learned
        anomalies, history = detect([(f"r{step}", 400)], history, 3.0, 50)
        assert len(anomalies) == 1
    assert sum(history) / len(history) == 10


def test_new_key_warmup_flags_only_large_volume() -> None:
    assert detect([("a", 100)], [], 3.0, 50)[0] == []  # modest use of a new key: quiet
    [(when, count, _mean, reason)] = detect([("b", 400)], [], 3.0, 50)[0]
    assert (when, count, reason) == ("b", 400, "warmup_volume_above_floor")  # stolen-key burst


def test_adc_refuses_non_authorized_user_credentials() -> None:
    import pytest

    from sentinel.sources.gcp import AdcTokenProvider

    class ServiceAccountLike:
        pass

    with pytest.raises(ValueError, match="authorized_user"):
        AdcTokenProvider(ServiceAccountLike())


def test_only_read_only_scopes_are_requested() -> None:
    from sentinel.sources.gcp import READ_ONLY_SCOPES

    assert READ_ONLY_SCOPES  # narrowing happens only if scopes are passed to google-auth
    for scope in READ_ONLY_SCOPES:
        assert scope.startswith("https://www.googleapis.com/auth/")
        assert scope.endswith((".read-only", ".read")), scope


def test_normalize_credential_id() -> None:
    assert normalize_credential_id("apikey:abc") == normalize_credential_id("abc") == "abc"


def test_volume_spike_on_unmapped_key_has_no_cred_ref(tmp_path: Path) -> None:
    store = not_first_run(Store(tmp_path / "s.db"))
    routes = Routes([], {"apikey:k1": [5] * 30 + [500]}, [5] * 31)
    [event] = [e for e in run(store, routes) if e["event_type"] == "credential_usage_anomaly"]
    assert event["attributes"]["reason"] == "volume_above_baseline"
    assert event["attributes"]["mapped"] is False and "credential_ref" not in event


def test_mapped_spike_carries_cred_ref_and_is_idempotent(tmp_path: Path) -> None:
    store = not_first_run(Store(tmp_path / "s.db"))
    store.put_doc("aliases", alias_key("demo", "k1"), {"cred_ref": "cred-fp-abcd1234"})
    routes = Routes([], {"apikey:k1": [5] * 30 + [500]}, [5] * 31)
    events = run(store, routes)
    [usage] = [e for e in events if e["event_type"] == "credential_usage_anomaly"]
    assert usage["credential_ref"] == "cred-fp-abcd1234"
    assert run(store, routes) == []  # same points again: nothing new


def test_any_use_of_dead_key_is_flagged(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    store.put_doc("aliases", alias_key("demo", "k1"), {"cred_ref": "cred-fp-dead0001"})
    store.put_doc(
        "findings",
        "cred-fp-dead0001",
        {"cred_ref": "cred-fp-dead0001", "status": "revoked_verified", "locations": []},
    )
    events = run(store, Routes([], {"apikey:k1": [0, 0, 3]}, [3]))
    assert [e["attributes"]["reason"] for e in events] == ["use_of_dead_key"]


def test_project_spike_becomes_spend_proxy(tmp_path: Path) -> None:
    store = not_first_run(Store(tmp_path / "s.db"))
    [spend] = [
        e
        for e in run(store, Routes([], {}, [10] * 30 + [400]))
        if e["event_type"] == "spend_anomaly"
    ]
    assert spend["attributes"]["proxy"].startswith("request volume")
    assert spend["attributes"]["multiple_of_baseline"] > 3


def test_key_status_and_asset_sync(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    keys = [
        {"uid": "live", "displayName": "app key", "createTime": "2026-01-01T00:00:00Z"},
        {"uid": "gone", "displayName": "old", "deleteTime": "2026-10-26T00:00:00Z"},
    ]
    collector = GcpCollector(HttpClient(Routes(keys, {}, [])), FakeTokens())
    assert collector.sync_key_assets(store, "demo", NOW) == 2
    assert collector.key_status("demo", "live")["deleted"] is False
    assert collector.key_status("demo", "gone")["deleted"] is True
    assert collector.key_status("demo", "never")["found"] is False
    asset = {a["asset_id"]: a for a in store.assets()}["gcp-key-live"]
    assert asset["asset_type"] == "api_key" and asset["owner"] is None


# --- pre-live review fixes ---------------------------------------------------------------
def test_first_run_learns_a_busy_baseline_and_raises_nothing(tmp_path: Path) -> None:
    """A normally busy key and project must not open incidents on first contact."""
    store = Store(tmp_path / "s.db")
    store.put_doc("aliases", alias_key("demo", "k1"), {"cred_ref": "cred-fp-busy0001"})
    routes = Routes([], {"apikey:k1": [900] * 48}, [5000] * 48)
    collector = GcpCollector(HttpClient(routes), FakeTokens())
    events = collector.collect_usage(
        store, "demo", NOW, lookback=timedelta(days=7), multiple=3.0, floor=50, spend_multiple=3.0
    )
    collector.commit(store)
    assert events == []
    assert any("first run" in n and "48 hour" in n for n in collector.notes)
    assert len((store.get_doc("baselines", "gcp:demo:cred:k1") or {})["history"]) == 48
    assert run(store, Routes([], {"apikey:k1": [900] * 49}, [5000] * 49)) == []  # still normal


def test_warm_up_flags_are_bounded_for_a_busy_new_key() -> None:
    """Warm-up hours are learned, so a busy new key stops being flagged after 24 hours."""
    anomalies, history = detect([(f"h{i:03d}", 400) for i in range(40)], [], 3.0, 50)
    assert len(anomalies) == 24 and {a[3] for a in anomalies} == {"warmup_volume_above_floor"}
    assert len(history) == 40


def test_warm_up_events_have_low_confidence(tmp_path: Path) -> None:
    store = not_first_run(Store(tmp_path / "s.db"))
    [event] = run(store, Routes([], {"apikey:new": [400]}, []))
    assert event["attributes"]["reason"] == "warmup_volume_above_floor"
    assert event["confidence"] == "low"


def test_dead_key_use_still_alerts_on_the_first_run(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")  # no cursor: first contact
    store.put_doc("aliases", alias_key("demo", "k1"), {"cred_ref": "cred-fp-dead0002"})
    store.put_doc(
        "findings",
        "cred-fp-dead0002",
        {"cred_ref": "cred-fp-dead0002", "status": "revoked_verified", "locations": []},
    )
    assert [e["attributes"]["reason"] for e in run(store, Routes([], {"apikey:k1": [2]}, []))] == [
        "use_of_dead_key"
    ]


def test_series_without_a_key_id_are_reported(tmp_path: Path) -> None:
    store = not_first_run(Store(tmp_path / "s.db"))
    routes = Routes([], {"": [5]}, [5])
    collector = GcpCollector(HttpClient(routes), FakeTokens())
    collector.collect_usage(
        store, "demo", NOW, lookback=timedelta(days=7), multiple=3.0, floor=50, spend_multiple=3.0
    )
    assert any("no API key id" in n for n in collector.notes)


def test_quota_project_header_is_sent(tmp_path: Path) -> None:
    routes = Routes([{"uid": "k"}], {}, [])
    GcpCollector(HttpClient(routes), FakeTokens()).list_keys("demo")
    assert routes.headers[-1]["x-goog-user-project"] == "demo"

    class WithQuota(FakeTokens):
        quota_project = "billing-proj-1"

    GcpCollector(HttpClient(routes), WithQuota()).list_keys("demo")
    assert routes.headers[-1]["x-goog-user-project"] == "billing-proj-1"


class Fixed:
    """Transport that always answers with one status and body."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status, self.body = status, body

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
    ) -> Response:
        return Response(self.status, {}, self.body)


def test_google_errors_give_a_next_step_without_echoing_the_body() -> None:
    import pytest

    from sentinel.sources.http import HttpError

    body = json.dumps(
        {"error": {"status": "PERMISSION_DENIED", "message": "secret-ish detail xyz",
                   "details": [{"reason": "SERVICE_DISABLED"}]}}
    ).encode()  # fmt: skip
    collector = GcpCollector(HttpClient(Fixed(403, body), retries=0), FakeTokens())
    with pytest.raises(HttpError) as caught:
        collector.list_keys("demo")
    assert caught.value.hint == "api_disabled" and "not enabled" in str(caught.value)
    assert "secret-ish" not in str(caught.value)


def test_google_messages_without_reason_codes_are_still_classified() -> None:
    from sentinel.sources.http import error_hint

    scopes = b'{"error":{"code":403,"message":"Request had insufficient authentication scopes.",'
    scopes += b'"status":"PERMISSION_DENIED"}}'
    missing = b'{"error":{"code":403,"message":"Permission monitoring.timeSeries.list denied '
    missing += b'(or the resource may not exist).","status":"PERMISSION_DENIED"}}'
    assert error_hint(scopes) == "scope_insufficient"
    assert error_hint(missing) == "denied_or_missing"
    assert error_hint(b'{"error":{"status":"PERMISSION_DENIED"}}') == "no_permission"


def test_an_empty_body_is_an_error_not_an_empty_list() -> None:
    import pytest

    from sentinel.sources.http import HttpError

    collector = GcpCollector(HttpClient(Fixed(200, b""), retries=0), FakeTokens())
    with pytest.raises(HttpError, match="unexpected response"):
        collector.list_keys("demo")


def test_a_repeated_page_token_stops() -> None:
    import pytest

    from sentinel.sources.http import HttpError

    looping = Fixed(200, json.dumps({"keys": [], "nextPageToken": "same"}).encode())
    with pytest.raises(HttpError, match="repeated page token"):
        GcpCollector(HttpClient(looping, retries=0), FakeTokens()).list_keys("demo")


def test_a_malformed_point_never_echoes_its_value() -> None:
    import pytest

    bad = {"points": [{"interval": {"endTime": "not-a-time-ZZZ"}, "value": {"int64Value": "1"}}]}
    with pytest.raises(ValueError, match="malformed Monitoring data point") as caught:
        GcpCollector._points(bad)
    assert "ZZZ" not in str(caught.value)


def test_a_key_not_found_is_never_reported_as_deleted() -> None:
    status = GcpCollector(HttpClient(Routes([], {}, [])), FakeTokens()).key_status("demo", "x")
    assert status == {"found": False, "deleted": None, "deleteTime": None}


def test_a_project_failing_part_way_does_not_commit_its_baselines(tmp_path: Path) -> None:
    """Shared collector: project A's half-done state must not be committed by project B."""
    from sentinel import runner
    from sentinel.config import Settings

    class FailProjectSeriesForA(Routes):
        def send(
            self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
        ) -> Response:
            if "/projects/proj-aaa/timeSeries" in url and "groupByFields" not in url:
                return Response(403, {}, b"")
            return super().send(method, url, headers, body, timeout)

    store = Store(tmp_path / "s.db")
    routes = FailProjectSeriesForA([], {"apikey:k1": [5] * 30}, [5] * 30)
    result = runner.run_once(
        store,
        tmp_path / "home",
        Settings(gcp_projects=("proj-aaa", "proj-bbb")),
        NOW,
        client=HttpClient(routes, retries=0),
        gcp_tokens=FakeTokens,
        toast=lambda *_: False,
        scan=False,
    )
    assert result["health"]["gcp:proj-aaa:usage"].startswith("error:")
    assert result["health"]["gcp:proj-bbb:usage"] == "ok"
    assert store.get_doc("baselines", "gcp:proj-aaa:cred:k1") is None
    assert store.get_doc("cursors", "gcp:proj-aaa") is None  # will retry the window next run
    assert store.get_doc("baselines", "gcp:proj-bbb:cred:k1") is not None


def test_verify_key_needs_the_key_seen_in_the_same_project(tmp_path: Path) -> None:
    """A key seen in ANOTHER project is no proof that this alias was deleted (rule 7)."""
    from sentinel import runner
    from sentinel.incidents import lifecycle
    from sentinel.simulation import scenarios

    store = Store(tmp_path / "s.db")
    cred = "cred-fp-" + "ab" * 8
    for e in scenarios.exposure(cred, "repo-x", NOW) + scenarios.provider_usage(
        cred, "repo-x", NOW
    ):
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, NOW)
    lifecycle.approve(store, iid, "revoke_credential", "me", NOW)  # a human approved revocation
    store.put_doc(
        "aliases", alias_key("right-proj", "uid1"),
        {"cred_ref": cred, "project": "right-proj", "uid": "uid1"},
    )  # fmt: skip
    store.upsert_asset(
        {"asset_id": "gcp-key-uid1", "asset_type": "api_key", "name": "k", "owner": None,
         "importance": "high", "monitoring": "partial", "last_seen": format_time(NOW),
         "attributes": {"project": "other-proj", "uid": "uid1"}}
    )  # fmt: skip
    collector = GcpCollector(HttpClient(Routes([], {}, [])), FakeTokens())  # uid1 not listed
    passed, evidence = runner.verify_key(store, iid, "me", NOW, collector)
    assert not passed and "never seen before" in evidence


def test_requests_never_ask_for_key_strings(tmp_path: Path) -> None:
    routes = Routes([{"uid": "k"}], {"apikey:k": [1]}, [1])
    collector = GcpCollector(HttpClient(routes), FakeTokens())
    collector.sync_key_assets(Store(tmp_path / "s.db"), "demo", NOW)
    run(Store(tmp_path / "t.db"), routes)
    assert routes.urls and not any("keystring" in u.lower() for u in routes.urls)
