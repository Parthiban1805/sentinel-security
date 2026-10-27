"""Verification watch and the automatic re-probe of open exposure incidents."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from sentinel import probes, runner
from sentinel.incidents import lifecycle, watch
from sentinel.simulation import scenarios
from sentinel.store.db import Store

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def real_r10(store: Store) -> str:
    event = scenarios.exposed_path("host-demo", T0)[0]
    event["is_test"] = False
    event["attributes"] = {**event["attributes"], "base_url": "http://x.invalid", "path": "/.env"}
    store.add_event(event)
    [iid] = lifecycle.open_incidents(store, T0)
    return iid


def test_report_flags_stale_and_ignores_test_incidents(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    for e in scenarios.exposed_path("host-test", T0):  # simulated: is_test
        store.add_event(e)
    lifecycle.open_incidents(store, T0)
    assert watch.report(store, T0)["open"] == []
    iid = real_r10(store)
    fresh = watch.report(store, T0 + timedelta(hours=1))["open"]
    assert [(r["id"], r["stale"]) for r in fresh] == [(iid, False)]
    stale = watch.report(store, T0 + timedelta(hours=30))["open"]
    assert stale[0]["stale"] and "verify_path_closed" in stale[0]["unverified_steps"]


def test_closed_unverified_is_listed(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    iid = real_r10(store)
    lifecycle.close(store, iid, "me", T0, unverified_note="accepted risk")
    data = watch.report(store, T0)
    assert data["open"] == [] and data["closed_unverified"][0]["id"] == iid
    assert "Closed WITHOUT verification: 1" in watch.format_report(data)


def test_auto_reprobe_fails_while_served_passes_after_fix_and_is_rate_limited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Store(tmp_path / "s.db")
    iid = real_r10(store)
    served = [True]
    calls: list[str] = []

    def fake(base_url: str, path: str, fetch: probes.FetchFn) -> tuple[str, int | None]:
        calls.append(path)
        return ("exposed", 200) if served[0] else ("clear", 404)

    monkeypatch.setattr(probes, "reprobe", fake)

    def run(hours: int) -> None:
        runner.reverify_open_paths(store, T0 + timedelta(hours=hours), cast(probes.FetchFn, None))

    run(1)
    run(2)  # checked within 6h: skipped
    assert len(calls) == 1
    served[0] = False
    run(8)
    assert len(calls) == 2
    incident = store.get_doc("incidents", iid)
    assert incident is not None
    step = next(s for s in incident["response_plan"] if s["step"] == "verify_path_closed")
    assert step["state"] == "verified" and step["events"][0]["verified"] is False
    run(20)
    assert len(calls) == 2  # verified steps are not re-probed
