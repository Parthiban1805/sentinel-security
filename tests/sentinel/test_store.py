from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.events.schema import SchemaError, make_event
from sentinel.store.db import Store

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def event(minutes: int = 0, event_type: str = "secret_exposure", is_test: bool = False) -> dict:
    return make_event(
        event_type=event_type,
        source="gitleaks",
        asset_id="repo-demo",
        time=T0 + timedelta(minutes=minutes),
        severity="high",
        confidence="medium",
        evidence_ref="evidence/1",
        is_test=is_test,
    )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / ".sentinel" / "sentinel.db")


def test_event_round_trip_ordered_by_time(store: Store) -> None:
    late, early = event(10), event(0)
    store.add_event(late)
    store.add_event(early)
    assert [e["event_id"] for e in store.events()] == [early["event_id"], late["event_id"]]
    assert store.events()[0] == early


def test_duplicate_event_id_is_ignored(store: Store) -> None:
    e = event()
    assert store.add_event(e) is True
    assert store.add_event(e) is False
    assert len(store.events()) == 1


def test_invalid_event_is_rejected_and_not_stored(store: Store) -> None:
    bad = event()
    bad["severity"] = "catastrophic"
    with pytest.raises(SchemaError):
        store.add_event(bad)
    assert store.events() == []


def test_filters(store: Store) -> None:
    store.add_event(event(0, "secret_exposure"))
    store.add_event(event(5, "canary_triggered", is_test=True))
    assert len(store.events(event_type="canary_triggered")) == 1
    assert len(store.events(include_test=False)) == 1
    assert len(store.events(since=T0 + timedelta(minutes=1))) == 1


def test_asset_upsert_replaces(store: Store) -> None:
    asset = {
        "asset_id": "repo-demo",
        "asset_type": "repository",
        "name": "demo",
        "owner": None,
        "importance": "low",
        "monitoring": "none",
        "last_seen": "2026-10-27T12:00:00Z",
    }
    store.upsert_asset(asset)
    store.upsert_asset({**asset, "owner": "someone"})
    assets = store.assets()
    assert len(assets) == 1
    assert assets[0]["owner"] == "someone"


def test_store_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "s" / "sentinel.db"
    Store(path).add_event(event())
    assert len(Store(path).events()) == 1
