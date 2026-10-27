"""inventory set: owners/approval are validated, audited and secret-screened."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.cli import main
from sentinel.inventory import assets
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def seeded(tmp_path: Path) -> Store:
    store = Store(tmp_path / "s.db")
    store.upsert_asset(
        {
            "asset_id": "repo-x",
            "asset_type": "repository",
            "name": "x",
            "owner": None,
            "importance": "medium",
            "monitoring": "none",
            "approved": False,
            "last_seen": "2026-10-01T00:00:00Z",
        }
    )
    return store


def test_owner_and_approval_leave_the_gap_list(tmp_path: Path) -> None:
    store = seeded(tmp_path)
    assert assets.gaps(store)["unowned"] == ["repo-x"]
    assets.update_asset(store, "repo-x", actor="me", now=NOW, owner="alice", approved=True)
    gaps = assets.gaps(store)
    assert gaps["unowned"] == [] and gaps["unapproved"] == []
    [entry] = store.audit()
    assert entry["action"] == "asset_update" and entry["changes"]["owner"] == {
        "from": None,
        "to": "alice",
    }


def test_no_change_writes_no_audit(tmp_path: Path) -> None:
    store = seeded(tmp_path)
    assets.update_asset(store, "repo-x", actor="me", now=NOW, importance="medium")
    assert store.audit() == []


def test_validation_and_unknown_asset(tmp_path: Path) -> None:
    store = seeded(tmp_path)
    with pytest.raises(ValueError):
        assets.update_asset(store, "repo-x", actor="me", now=NOW, importance="huge")
    with pytest.raises(KeyError):
        assets.update_asset(store, "missing", actor="me", now=NOW, owner="a")


def test_pasted_key_as_owner_is_refused(tmp_path: Path) -> None:
    store = seeded(tmp_path)
    with pytest.raises(ValueError):
        assets.update_asset(store, "repo-x", actor="me", now=NOW, owner=fake_google_key())
    assert store.assets()[0]["owner"] is None


def test_cli_set(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    Store(home / "sentinel.db").upsert_asset(
        seeded(tmp_path).assets()[0]
    )  # CLI reads <home>/sentinel.db
    code = main(
        [
            "--home",
            str(home),
            "inventory",
            "set",
            "repo-x",
            "--actor",
            "me",
            "--owner",
            "bob",
            "--approve",
        ]
    )
    assert code == 0 and "owner=bob approved=True" in capsys.readouterr().out
    assert main(["--home", str(home), "inventory", "set", "nope", "--actor", "me"]) == 1
