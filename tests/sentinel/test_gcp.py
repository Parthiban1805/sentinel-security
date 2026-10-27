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


def run(store: Store, routes: Routes) -> list[dict[str, Any]]:
    collector = GcpCollector(HttpClient(routes), FakeTokens())
    return collector.collect_usage(
        store, "demo", NOW, lookback=timedelta(days=7), multiple=3.0, floor=50, spend_multiple=3.0
    )


def test_detect_needs_history_and_threshold() -> None:
    points = [(f"t{i:03d}", 10) for i in range(30)] + [("t999", 200)]
    anomalies, history = detect(points, [], 3.0, 50)
    assert [a[0] for a in anomalies] == ["t999"]
    assert len(history) == 31
    assert detect([("x", 40)], [10] * 30, 3.0, 50)[0] == []  # above 3x mean but under floor


def test_normalize_credential_id() -> None:
    assert normalize_credential_id("apikey:abc") == normalize_credential_id("abc") == "abc"


def test_volume_spike_on_unmapped_key_has_no_cred_ref(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    routes = Routes([], {"apikey:k1": [5] * 30 + [500]}, [5] * 31)
    [event] = [e for e in run(store, routes) if e["event_type"] == "credential_usage_anomaly"]
    assert event["attributes"]["reason"] == "volume_above_baseline"
    assert event["attributes"]["mapped"] is False and "credential_ref" not in event


def test_mapped_spike_carries_cred_ref_and_is_idempotent(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
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
    store = Store(tmp_path / "s.db")
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


def test_requests_never_ask_for_key_strings(tmp_path: Path) -> None:
    routes = Routes([{"uid": "k"}], {"apikey:k": [1]}, [1])
    collector = GcpCollector(HttpClient(routes), FakeTokens())
    collector.sync_key_assets(Store(tmp_path / "s.db"), "demo", NOW)
    run(Store(tmp_path / "t.db"), routes)
    assert routes.urls and not any("keystring" in u.lower() for u in routes.urls)
