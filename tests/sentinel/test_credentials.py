"""Credential lifecycle checks C1-C9 (v0.7c item 2, ADR-0019)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel.cli import main
from sentinel.config import load
from sentinel.inventory import credentials as creds
from sentinel.simulation.fakes import fake_google_key
from sentinel.sources.gcp import alias_key
from sentinel.store.db import Store

NOW = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
POLICY = creds.Policy()


def key_asset(asset_id: str = "gcp-key-u1", owner: str | None = "Parthiban", **attrs: Any):
    return {
        "asset_id": asset_id,
        "asset_type": "api_key",
        "name": asset_id,
        "owner": owner,
        "importance": "high",
        "monitoring": "partial",
        "recovery_method": None,
        "approved": False,
        "last_seen": "2026-11-05T09:00:00Z",
        "attributes": attrs,
    }


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "sentinel.db")


def checks(view: creds.CredentialView) -> set[str]:
    return {p.check for p in view.problems}


def only(store: Store) -> creds.CredentialView:
    views = creds.review(store, NOW, POLICY)
    assert len(views) == 1
    return views[0]


def iso(days: int) -> str:
    return (NOW + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


# checks --------------------------------------------------------------------------
def test_healthy_key_has_no_problems(store: Store) -> None:
    store.upsert_asset(key_asset(created=iso(-10), expires=iso(200), last_used=iso(-1)))
    view = only(store)
    assert view.problems == [] and view.age_days == 10
    assert view.rotate_due == iso(80)[:10]


def test_c1_expired_and_c2_expiring_soon(store: Store) -> None:
    store.upsert_asset(key_asset("gcp-key-a", created=iso(-5), expires=iso(-1)))
    store.upsert_asset(key_asset("gcp-key-b", created=iso(-5), expires=iso(10)))
    by_ref = {v.ref: v for v in creds.review(store, NOW, POLICY)}
    assert checks(by_ref["gcp-key-a"]) == {"C1"}
    assert checks(by_ref["gcp-key-b"]) == {"C2"}
    assert by_ref["gcp-key-a"].problems[0].severity == "high"


def test_c3_rotation_overdue_from_created_or_rotated(store: Store) -> None:
    store.upsert_asset(key_asset("gcp-key-a", created=iso(-100)))
    store.upsert_asset(key_asset("gcp-key-b", created=iso(-100), rotated_at=iso(-20)))
    store.upsert_asset(key_asset("gcp-key-c", created=iso(-40), rotate_every_days="30"))
    by_ref = {v.ref: v for v in creds.review(store, NOW, POLICY)}
    assert "C3" in checks(by_ref["gcp-key-a"])
    assert "C3" not in checks(by_ref["gcp-key-b"])
    assert "C3" in checks(by_ref["gcp-key-c"])  # per-credential interval wins


def test_c4_unowned_and_c5_unused(store: Store) -> None:
    store.upsert_asset(key_asset(owner=None, created=iso(-5), last_used=iso(-120)))
    assert checks(only(store)) == {"C4", "C5"}


def test_unknown_fields_are_listed_not_treated_as_fine(store: Store) -> None:
    store.upsert_asset(key_asset())
    view = only(store)
    assert view.problems == []
    assert "rotation cannot be checked" in view.unknown
    assert "expiry" in view.unknown and "last use" in view.unknown


def test_unparsable_date_is_unknown_not_a_crash(store: Store) -> None:
    store.upsert_asset(key_asset(created="sometime", expires="2026-13-45"))
    view = only(store)
    assert view.problems == []
    assert "expiry not a valid date" in view.unknown
    assert "creation date not a valid date" in view.unknown


def test_deleted_key_is_listed_but_never_checked(store: Store) -> None:
    store.upsert_asset(key_asset(owner=None, created=iso(-400), deleted=iso(-3)))
    view = only(store)
    assert view.deleted is True and view.problems == []


def test_c6_key_aliased_to_live_leak(store: Store) -> None:
    store.upsert_asset(key_asset(project="demo-project", uid="u1", created=iso(-5)))
    store.put_doc(
        "findings",
        "cred-fp-abcd1234",
        {"cred_ref": "cred-fp-abcd1234", "status": "open", "locations": []},
    )
    store.put_doc(
        "aliases",
        alias_key("demo-project", "u1"),
        {"cred_ref": "cred-fp-abcd1234", "project": "demo-project", "uid": "u1"},
    )
    view = only(store)
    assert "C6" in checks(view) and view.exposed_as == "cred-fp-abcd1234"


def test_c6_not_raised_once_revocation_verified(store: Store) -> None:
    store.upsert_asset(key_asset(project="demo-project", uid="u1", created=iso(-5)))
    store.put_doc(
        "findings",
        "cred-fp-abcd1234",
        {"cred_ref": "cred-fp-abcd1234", "status": "revoked_verified", "locations": []},
    )
    store.put_doc(
        "aliases",
        alias_key("demo-project", "u1"),
        {"cred_ref": "cred-fp-abcd1234", "project": "demo-project", "uid": "u1"},
    )
    assert "C6" not in checks(only(store))


def test_ssh_keys_from_snapshot_get_age_checks_only(store: Store) -> None:
    store.put_doc(
        "snapshots", "github:user_keys", {"ids": {"101": iso(-400), "102": iso(-3)}, "time": iso(0)}
    )
    by_ref = {v.ref: v for v in creds.review(store, NOW, POLICY)}
    assert checks(by_ref["github-ssh-101"]) == {"C3"}
    assert by_ref["github-ssh-102"].problems == []
    assert by_ref["github-ssh-101"].kind == "ssh_key"


def test_c9_same_leak_in_several_assets(store: Store) -> None:
    store.put_doc(
        "findings",
        "cred-fp-abcd1234",
        {
            "cred_ref": "cred-fp-abcd1234",
            "status": "open",
            "locations": [
                {"asset_id": "repo-a", "file": "x", "line": 1},
                {"asset_id": "repo-b", "file": "y", "line": 2},
                {"asset_id": "repo-a", "file": "z", "line": 3},
            ],
        },
    )
    store.put_doc(
        "findings",
        "cred-fp-11112222",
        {
            "cred_ref": "cred-fp-11112222",
            "status": "open",
            "locations": [{"asset_id": "repo-a", "file": "x", "line": 1}],
        },
    )
    dups = creds.duplicates(store)
    assert [d.ref for d in dups] == ["cred-fp-abcd1234"]
    assert dups[0].assets == ["repo-a", "repo-b"]


def test_review_is_sorted_and_deterministic(store: Store) -> None:
    store.upsert_asset(key_asset("gcp-key-b", created=iso(-5)))
    store.upsert_asset(key_asset("gcp-key-a", created=iso(-5)))
    first = creds.review(store, NOW, POLICY)
    assert [v.ref for v in first] == ["gcp-key-a", "gcp-key-b"]
    assert first == creds.review(store, NOW, POLICY)


def test_non_credential_assets_are_ignored(store: Store) -> None:
    store.upsert_asset({**key_asset("repo-x"), "asset_type": "repository"})
    assert creds.review(store, NOW, POLICY) == []


# events --------------------------------------------------------------------------
def test_events_are_idempotent_config_drift(store: Store) -> None:
    store.upsert_asset(key_asset(owner=None, created=iso(-5), expires=iso(-1)))
    events = creds.to_events(creds.review(store, NOW, POLICY), creds.duplicates(store), NOW)
    assert {e["event_type"] for e in events} == {"config_drift"}
    assert {e["attributes"]["check"] for e in events} == {"C1", "C4"}
    assert sum(store.add_event(e) for e in events) == 2
    again = creds.to_events(creds.review(store, NOW, POLICY), creds.duplicates(store), NOW)
    assert sum(store.add_event(e) for e in again) == 0


# setting values ------------------------------------------------------------------
def test_set_lifecycle_validates_and_audits(store: Store) -> None:
    store.upsert_asset(key_asset())
    creds.set_lifecycle(
        store, "gcp-key-u1", actor="Parthiban", now=NOW, expires="2027-01-29", rotate_every_days=60
    )
    asset = store.assets()[0]
    assert asset["attributes"]["expires"] == "2027-01-29"
    assert asset["attributes"]["rotate_every_days"] == "60"
    assert store.audit()[-1]["action"] == "asset_update"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"expires": "next week"},
        {"rotated_at": "2026-02-30"},
        {"rotate_every_days": 0},
        {"rotate_every_days": 99999},
        {},
    ],
)
def test_set_lifecycle_refuses_bad_values(store: Store, kwargs: dict[str, Any]) -> None:
    store.upsert_asset(key_asset())
    with pytest.raises(ValueError):
        creds.set_lifecycle(store, "gcp-key-u1", actor="Parthiban", now=NOW, **kwargs)


def test_set_lifecycle_refuses_a_credential_shaped_value(store: Store) -> None:
    store.upsert_asset(key_asset())
    with pytest.raises(ValueError):
        creds.set_lifecycle(
            store, "gcp-key-u1", actor=fake_google_key(), now=NOW, expires="2027-01-01"
        )


def test_set_lifecycle_only_on_credential_assets(store: Store) -> None:
    store.upsert_asset({**key_asset("repo-x"), "asset_type": "repository"})
    with pytest.raises(ValueError):
        creds.set_lifecycle(store, "repo-x", actor="Parthiban", now=NOW, expires="2027-01-01")
    with pytest.raises(KeyError):
        creds.set_lifecycle(store, "nope", actor="Parthiban", now=NOW, expires="2027-01-01")


# settings and CLI ----------------------------------------------------------------
def test_policy_comes_from_settings(tmp_path: Path) -> None:
    toml = tmp_path / "sentinel.toml"
    toml.write_text("[credentials]\nrotate_days = 30\nexpiry_warn_days = 7\nunused_days = 60\n")
    assert load(toml).credentials == creds.Policy(30, 7, 60)
    toml.write_text("[credentials]\nrotate_days = 0\n")
    with pytest.raises(ValueError):
        load(toml)


def test_cli_creds_report_set_and_record(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sentinel.cli._require_human", lambda action: None)  # a person is present
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    store.upsert_asset(key_asset(owner=None, created="2020-01-01T00:00:00Z"))
    base = ["--home", str(home)]

    assert (
        main(
            [*base, "creds", "set", "gcp-key-u1", "--actor", "Parthiban", "--expires", "2020-06-01"]
        )
        == 0
    )
    capsys.readouterr()
    assert main([*base, "creds"]) == 1  # problems found
    out = capsys.readouterr().out
    assert "gcp-key-u1" in out and "C1" in out and "C4" in out and "C3" in out

    assert main([*base, "creds", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["credentials"][0]["ref"] == "gcp-key-u1"

    assert main([*base, "creds", "--record"]) == 1
    assert len(store.events()) == 3


def test_cli_creds_clean_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    assert main(["--home", str(home), "creds"]) == 0
    assert "no credential assets" in capsys.readouterr().out


# review fixes (2026-11-05 security review of ADR-0019) ------------------------------
def test_s1_gcp_resync_keeps_human_lifecycle_facts(store: Store) -> None:
    from sentinel.sources.gcp import GcpCollector

    collector = GcpCollector.__new__(GcpCollector)
    keys = [{"uid": "u1", "displayName": "demo", "createTime": iso(-100)}]
    collector.list_keys = lambda project: keys  # type: ignore[method-assign]
    collector.sync_key_assets(store, "demo-project", NOW)
    creds.set_lifecycle(store, "gcp-key-u1", actor="Parthiban", now=NOW, rotated_at=iso(-5)[:10])
    collector.sync_key_assets(store, "demo-project", NOW + timedelta(hours=1))
    attrs = store.assets()[0]["attributes"]
    assert attrs["rotated_at"] == iso(-5)[:10] and attrs["created"] == iso(-100)
    assert "C3" not in checks(only(store))


def test_s2_creds_set_needs_a_person(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    store.upsert_asset(key_asset())
    argv = ["--home", str(home), "creds", "set", "gcp-key-u1", "--actor", "agent"]
    assert main([*argv, "--rotated-at", "2026-11-01"]) == 1  # pytest stdin is not a terminal
    assert "interactive terminal" in capsys.readouterr().err
    assert "rotated_at" not in store.assets()[0]["attributes"]


@pytest.mark.parametrize("field", ["rotated_at", "last_used"])
def test_s3_future_past_dates_are_refused(store: Store, field: str) -> None:
    store.upsert_asset(key_asset())
    with pytest.raises(ValueError, match="future"):
        creds.set_lifecycle(
            store, "gcp-key-u1", actor="Parthiban", now=NOW, **{field: "2099-01-01"}
        )


def test_s3_stored_future_dates_are_unknown_not_fine(store: Store) -> None:
    store.upsert_asset(
        key_asset(created=iso(-400), rotated_at="2099-01-01", last_used="2099-01-01")
    )
    view = only(store)
    assert "rotation date is in the future" in view.unknown
    assert "last use is in the future" in view.unknown
    assert "C3" in checks(view)  # falls back to the creation date, which is overdue


def test_s4_extreme_years_never_crash(store: Store) -> None:
    store.upsert_asset(
        key_asset(created="9999-12-31", expires="9999-12-31", rotated_at="0001-01-01")
    )
    view = only(store)  # no OverflowError
    assert "rotation cannot be checked" in view.unknown
    with pytest.raises(ValueError):
        creds.set_lifecycle(store, "gcp-key-u1", actor="Parthiban", now=NOW, expires="9999-12-31")


def test_s5_unscreened_name_and_owner_are_withheld_in_output(store: Store) -> None:
    fake = fake_google_key()
    store.upsert_asset({**key_asset(owner=fake, created=iso(-5)), "name": fake})
    data = creds.report_json(creds.review(store, NOW, POLICY), [], NOW)
    text = json.dumps(data)
    assert fake not in text and fake[:12] not in text
    assert data["credentials"][0]["name"] == creds.WITHHELD


def test_s5_cli_text_and_json_carry_no_fake_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    fake = fake_google_key()
    Store(home / "sentinel.db").upsert_asset({**key_asset(owner=fake), "name": fake})
    main(["--home", str(home), "creds"])
    main(["--home", str(home), "creds", "--json"])
    out = capsys.readouterr().out
    assert fake not in out and fake[:12] not in out


def test_s6_nothing_known_is_unknown_not_ok(store: Store) -> None:
    store.upsert_asset(key_asset())
    view = only(store)
    assert view.state.startswith("unknown")
    assert creds.report_json([view], [], NOW)["counts"]["with_unknowns"] == 1


def test_s7_recurrence_is_recorded_again(store: Store) -> None:
    store.upsert_asset(key_asset(created=iso(-5), expires=iso(-1)))
    first = creds.to_events(creds.review(store, NOW, POLICY), [], NOW)
    assert sum(store.add_event(e) for e in first) == 1
    asset = store.assets()[0]
    asset["attributes"]["expires"] = iso(30)  # renewed ...
    store.upsert_asset(asset)
    later = NOW + timedelta(days=40)  # ... and expired again
    again = creds.to_events(creds.review(store, later, POLICY), [], later)
    assert sum(store.add_event(e) for e in again if e["attributes"]["check"] == "C1") == 1


def test_s7_c9_new_asset_is_recorded_again(store: Store) -> None:
    loc = [
        {"asset_id": "repo-a", "file": "x", "line": 1},
        {"asset_id": "repo-b", "file": "y", "line": 1},
    ]
    store.put_doc(
        "findings",
        "cred-fp-abcd1234",
        {"cred_ref": "cred-fp-abcd1234", "status": "open", "locations": loc},
    )
    assert sum(store.add_event(e) for e in creds.to_events([], creds.duplicates(store), NOW)) == 1
    loc.append({"asset_id": "repo-c", "file": "z", "line": 1})
    store.put_doc(
        "findings",
        "cred-fp-abcd1234",
        {"cred_ref": "cred-fp-abcd1234", "status": "open", "locations": loc},
    )
    events = creds.to_events([], creds.duplicates(store), NOW)
    assert sum(store.add_event(e) for e in events) == 1
    assert events[0]["credential_ref"] == "cred-fp-abcd1234"
    assert events[0]["attributes"]["assets"] == ["repo-a", "repo-b", "repo-c"]


def _alias_live(store: Store) -> None:
    store.put_doc(
        "findings",
        "cred-fp-abcd1234",
        {"cred_ref": "cred-fp-abcd1234", "status": "open", "locations": []},
    )
    store.put_doc("aliases", alias_key("demo-project", "u1"), {"cred_ref": "cred-fp-abcd1234"})


def test_s8_recently_deleted_key_keeps_exposure(store: Store) -> None:
    store.upsert_asset(key_asset(project="demo-project", uid="u1", deleted=iso(-3)))
    _alias_live(store)
    view = only(store)
    assert view.deleted and "C6" in checks(view)
    assert any("restorable until" in u for u in view.unknown)
    events = creds.to_events([view], [], NOW)
    assert events[0]["attributes"]["check"] == "C6" and events[0]["severity"] == "high"


def test_s8_long_deleted_key_is_quiet(store: Store) -> None:
    store.upsert_asset(key_asset(project="demo-project", uid="u1", deleted=iso(-60)))
    _alias_live(store)
    view = only(store)
    assert view.deleted and view.problems == [] and view.unknown == []


def test_m2_deleted_must_be_a_date(store: Store) -> None:
    store.upsert_asset(key_asset(owner=None, created=iso(-5), deleted="false"))
    view = only(store)
    assert not view.deleted and "C4" in checks(view)
    assert any("deleted flag" in u for u in view.unknown)


def test_m6_offsets_are_normalised_to_utc() -> None:
    assert creds.utc_date("2026-11-05T23:30:00-05:00") == "2026-11-06"
    assert creds.utc_date("2026-11-05T01:00:00+05:30") == "2026-11-04"


def test_m7_invalid_interval_is_reported(store: Store) -> None:
    store.upsert_asset(key_asset(created=iso(-5), rotate_every_days="lots"))
    assert any("rotate_every_days invalid" in u for u in only(store).unknown)


def test_boundaries_expiry_now_and_rotation_due_today(store: Store) -> None:
    store.upsert_asset(key_asset("gcp-key-a", created=iso(-90), expires=iso(0)))
    store.upsert_asset(
        key_asset("gcp-key-b", created=iso(-5), expires=iso(POLICY.expiry_warn_days))
    )
    store.upsert_asset(
        key_asset("gcp-key-c", created=iso(-5), expires=iso(POLICY.expiry_warn_days + 1))
    )
    by_ref = {v.ref: v for v in creds.review(store, NOW, POLICY)}
    assert {"C1", "C3"} <= checks(by_ref["gcp-key-a"])
    assert "C2" in checks(by_ref["gcp-key-b"])
    assert "C2" not in checks(by_ref["gcp-key-c"])


def test_ssh_unknowns_and_stale_snapshot(store: Store) -> None:
    store.put_doc("snapshots", "github:user_keys", {"ids": {"101": iso(-3)}, "time": iso(-10)})
    view = only(store)
    assert "last use" in view.unknown and any("stale" in u for u in view.unknown)


def test_recorded_events_open_no_incident(store: Store) -> None:
    from sentinel.incidents import lifecycle

    store.upsert_asset(key_asset(owner=None, created=iso(-400), expires=iso(-1)))
    _alias_live(store)
    for e in creds.to_events(creds.review(store, NOW, POLICY), creds.duplicates(store), NOW):
        store.add_event(e)
    assert lifecycle.open_incidents(store, NOW) == []
