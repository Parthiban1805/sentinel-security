"""S2 beyond Git: opt-in scan locations (folders and single files), fingerprints only."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sentinel import runner
from sentinel.config import Settings, load, validate_extra_path
from sentinel.inventory.assets import location_asset_id
from sentinel.scanners import gitleaks
from sentinel.scanners.gitleaks import Finding
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

try:
    gitleaks.find_gitleaks()
    HAVE_GITLEAKS = True
except gitleaks.ScanError:
    HAVE_GITLEAKS = False

needs_gitleaks = pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not installed")
NOW = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)


def run(tmp_path: Path, *paths: Path) -> tuple[Store, dict[str, Any]]:
    store = Store(tmp_path / "s.db")
    settings = Settings(extra_scan_paths=tuple(str(p) for p in paths))
    result = runner.run_once(
        store, tmp_path / "home", settings, NOW, toast=lambda *_: False, probe_pause=0
    )
    return store, result


def state_of(result: dict[str, Any]) -> str:
    """The single scan-extra health entry of a run with one location."""
    [state] = [v for k, v in result["health"].items() if k.startswith("scan-extra:")]
    return str(state)


def copied_events(store: Store) -> list[dict[str, Any]]:
    """R7 'copied' events only: scanning a decoy also touches it, which is a low-confidence 'read'."""
    return [
        e
        for e in store.events(event_type="canary_triggered")
        if e["attributes"]["reason"] == "copied"
    ]


def everything_stored(store: Store) -> str:
    """All stored data as text, to prove no raw value reached the store."""
    return json.dumps(
        [store.events(), store.docs("findings"), store.assets(), store.docs("incidents")],
        default=str,
    )


# --- configuration -------------------------------------------------------------------------
def test_nothing_is_scanned_by_default(tmp_path: Path) -> None:
    assert Settings().extra_scan_paths == ()
    store, result = run(tmp_path)
    assert not any(k.startswith("scan-extra") for k in result["health"])
    assert not [a for a in store.assets() if a["asset_type"] == "scan_location"]


def test_config_reads_extra_paths(tmp_path: Path) -> None:
    folder = tmp_path / "logs"
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text(f'[scan]\nextra_paths = ["{folder.as_posix()}"]\n', encoding="utf-8")
    assert load(cfg).extra_scan_paths == (folder.as_posix(),)


@pytest.mark.parametrize("bad", ["", "  ", "-rf", "relative/logs", "logs"])
def test_unsafe_extra_paths_are_refused(bad: str) -> None:
    with pytest.raises(ValueError, match="extra_paths"):
        validate_extra_path(bad)


def test_drive_roots_and_the_home_folder_are_too_broad(tmp_path: Path) -> None:
    for broad in (Path(tmp_path.anchor), Path.home()):
        with pytest.raises(ValueError, match="too broad"):
            validate_extra_path(str(broad))
    assert validate_extra_path(str(tmp_path / "logs")) == str(tmp_path / "logs")


def test_dotdot_ancestors_of_home_and_credential_stores_are_refused(tmp_path: Path) -> None:
    for bad in (
        str(tmp_path / "a" / ".." / "b"),  # '..' segments
        str(Path.home() / "x" / ".."),
        str(Path.home().parent),  # the folder that contains the home folder
        str(Path.home() / ".ssh"),
        str(Path.home() / ".aws" / "cli" / "cache"),
        str(Path.home() / "AppData" / "Roaming" / "gcloud"),
    ):
        with pytest.raises(ValueError, match="extra_paths"):
            validate_extra_path(bad)
    allowed = validate_extra_path(str(Path.home() / ".ssh"), allow_credential_stores=True)
    assert allowed == str(Path.home() / ".ssh")  # an explicit owner opt-in


def test_config_errors_do_not_echo_the_full_path(tmp_path: Path) -> None:
    secret_ish = tmp_path / "somebody-private-folder" / ".." / "x"
    with pytest.raises(ValueError) as caught:
        validate_extra_path(str(secret_ish))
    assert "somebody-private-folder" not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)


def test_allow_credential_stores_is_read_from_config(tmp_path: Path) -> None:
    cfg = tmp_path / "sentinel.toml"
    ssh = (Path.home() / ".ssh").as_posix()
    cfg.write_text(f'[scan]\nextra_paths = ["{ssh}"]\n', encoding="utf-8")
    with pytest.raises(ValueError, match="credential store"):
        load(cfg)
    cfg.write_text(
        f'[scan]\nallow_credential_stores = true\nextra_paths = ["{ssh}"]\n', encoding="utf-8"
    )
    assert load(cfg).allow_credential_stores is True


def test_code_built_settings_are_validated_again_at_scan_time(tmp_path: Path) -> None:
    """Settings(...) skips load(); a broad path must still never be scanned."""
    store, result = run(tmp_path, Path.home())
    [state] = [v for k, v in result["health"].items() if k.startswith("scan-extra:")]
    assert state.startswith("error:") and "too broad" in state
    assert not [a for a in store.assets() if a["asset_type"] == "scan_location"]


def test_location_ids_are_stable_and_keep_same_named_folders_apart(tmp_path: Path) -> None:
    a, b = tmp_path / "x" / "logs", tmp_path / "y" / "logs"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    assert location_asset_id(a) == location_asset_id(a)
    assert location_asset_id(a) != location_asset_id(b)
    assert location_asset_id(a).startswith("loc-logs-")


# --- real scanner --------------------------------------------------------------------------
@needs_gitleaks
def test_a_key_in_an_opt_in_folder_becomes_a_finding_by_fingerprint(tmp_path: Path) -> None:
    folder = tmp_path / "ci-logs"
    folder.mkdir()
    key = fake_google_key()
    (folder / "run-4821.log").write_text(f"Run tests\nGEMINI_API_KEY: {key}\n", encoding="utf-8")
    store, result = run(tmp_path, folder)
    assert state_of(result) == "ok"
    [asset] = [a for a in store.assets() if a["asset_type"] == "scan_location"]
    assert asset["owner"] is None and asset["approved"] is False  # unowned until assigned
    [doc] = store.docs("findings")
    assert doc["locations"][0]["asset_id"] == asset["asset_id"]
    assert doc["locations"][0]["file"] == "run-4821.log" and doc["locations"][0]["commit"] == ""
    assert key not in everything_stored(store)


@needs_gitleaks
def test_a_single_file_location_is_scanned_and_reported_by_name(tmp_path: Path) -> None:
    history = tmp_path / "ConsoleHost_history.txt"
    key = fake_google_key()
    history.write_text(f"ls\n$env:GEMINI_API_KEY='{key}'\n", encoding="utf-8")
    store, result = run(tmp_path, history)
    assert state_of(result) == "ok"
    [doc] = store.docs("findings")
    assert doc["locations"][0]["file"] == history.name
    assert key not in everything_stored(store)


@needs_gitleaks
def test_a_json_escaped_key_in_an_agent_transcript_file_is_found(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    key = fake_google_key()
    transcript.write_text('{"c":"gemini_api_key = \\"' + key + '\\""}\n', encoding="utf-8")
    store, _ = run(tmp_path, transcript)
    assert [d["locations"][0]["file"] for d in store.docs("findings")] == ["session.jsonl"]
    assert key not in everything_stored(store)


@needs_gitleaks
def test_a_clean_location_makes_no_finding_and_a_rerun_adds_no_duplicates(tmp_path: Path) -> None:
    folder = tmp_path / "notes"
    folder.mkdir()
    (folder / "a.txt").write_text("nothing secret\n", encoding="utf-8")
    store, result = run(tmp_path, folder)
    assert state_of(result) == "ok" and not store.docs("findings")
    runner.run_once(
        store,
        tmp_path / "home",
        Settings(extra_scan_paths=(str(folder),)),
        NOW,
        toast=lambda *_: False,
        probe_pause=0,
    )
    assert len([a for a in store.assets() if a["asset_type"] == "scan_location"]) == 1


def test_a_missing_location_is_a_health_error_never_clean(tmp_path: Path) -> None:
    store, result = run(tmp_path, tmp_path / "gone")
    assert state_of(result).startswith("error:")
    assert not store.docs("findings") and not [
        a for a in store.assets() if a["asset_type"] == "scan_location"
    ]


@needs_gitleaks
def test_same_named_folders_have_separate_health_entries(tmp_path: Path) -> None:
    """A broken location must not be hidden by a healthy one with the same final name."""
    good, bad = tmp_path / "a" / "logs", tmp_path / "b" / "logs"
    good.mkdir(parents=True)
    (good / "x.txt").write_text("clean\n", encoding="utf-8")
    _store, result = run(tmp_path, bad, good)  # the broken one first, the healthy one last
    states = {k: v for k, v in result["health"].items() if k.startswith("scan-extra:")}
    assert len(states) == 2
    assert sorted(v.split(":")[0] for v in states.values()) == ["error", "ok"]


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here (needs privilege on Windows)")


@needs_gitleaks
def test_a_symlink_inside_a_location_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    key = fake_google_key()
    (outside / "secret.json").write_text(json.dumps({"k": f"gemini_api_key = {key}"}))
    (outside / "secret.txt").write_text(f"GEMINI_API_KEY={key}\n")
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "ok.txt").write_text("clean\n")
    _symlink(folder / "link.json", outside / "secret.json")
    _symlink(folder / "link.txt", outside / "secret.txt")
    store, result = run(tmp_path, folder)
    [state] = [v for k, v in result["health"].items() if k.startswith("scan-extra:")]
    assert not store.docs("findings"), "content from outside the listed scope was scanned"
    assert state.startswith("warn:") and "symlink" in state
    assert str(tmp_path) not in state and key not in everything_stored(store) + state


def pretend_symlinks(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    """Make files with these names look like symlinks (real ones need a privilege on Windows)."""
    real = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name in names or real(self))


def test_symlinks_are_counted_and_never_decoded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Logic only: files that look like links are skipped by the JSON decoder and reported."""
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "link.json").write_text(json.dumps({"k": "value"}))
    (folder / "plain.txt").write_text("clean\n")
    pretend_symlinks(monkeypatch, "link.json")
    assert [p.name for p in gitleaks._iter_json_files(folder)] == []
    gaps = gitleaks.coverage(folder)
    assert gaps.symlinks == 1 and gaps.gaps == 1 and "1 symlink(s) not followed" in gaps.describe()


@needs_gitleaks
def test_a_listed_symlink_is_refused_logic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "history.txt"
    target.write_text("clean\n")
    pretend_symlinks(monkeypatch, "history.txt")
    _store, result = run(tmp_path, target)
    state = state_of(result)
    assert state.startswith("error:") and "symlink" in state and str(tmp_path) not in state


@needs_gitleaks
def test_the_scan_never_aborts_on_a_path_that_resolves_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A JSON file that resolves outside the folder is skipped; no path appears in any error."""
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "a.json").write_text(json.dumps({"k": "v"}))
    config = tmp_path / "c.toml"
    config.write_text(gitleaks._config_text("dir"), encoding="utf-8")
    real_resolve = Path.resolve
    elsewhere = real_resolve(tmp_path / "elsewhere" / "a.json")

    def resolve(self: Path, strict: bool = False) -> Path:  # a followed link resolves elsewhere
        return elsewhere if self.name == "a.json" else real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolve)
    assert gitleaks._scan_json_files(folder, b"k" * 32, config, 60, set()) == []


@needs_gitleaks
def test_a_listed_symlink_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real.log"
    real.write_text("clean\n")
    link = tmp_path / "link.log"
    _symlink(link, real)
    _store, result = run(tmp_path, link)
    [state] = [v for k, v in result["health"].items() if k.startswith("scan-extra:")]
    assert state.startswith("error:") and "symlink" in state and str(tmp_path) not in state


@needs_gitleaks
def test_unscanned_files_make_a_warning_not_a_plain_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gitleaks, "_MAX_JSON_BYTES", 10)
    folder = tmp_path / "transcripts"
    folder.mkdir()
    (folder / "big.jsonl").write_text('{"c": "' + "x" * 200 + '"}\n')
    _store, result = run(tmp_path, folder)
    [state] = [v for k, v in result["health"].items() if k.startswith("scan-extra:")]
    assert state.startswith("warn:") and "1 JSON file" in state and str(tmp_path) not in state


@needs_gitleaks
def test_a_decoy_in_a_single_file_location_is_not_reported_as_copied(tmp_path: Path) -> None:
    """The decoy sitting at its own planted path is expected; it must not raise a COPIED event."""
    from sentinel import canaries
    from sentinel.security import load_key

    home = tmp_path / "home"
    store = Store(tmp_path / "s.db")
    decoys = tmp_path / "decoys"
    decoys.mkdir()
    doc = canaries.plant(store, load_key(home), decoys, NOW)
    runner.run_once(
        store,
        home,
        Settings(extra_scan_paths=(doc["path"],)),
        NOW,
        toast=lambda *_: False,
        probe_pause=0,
    )
    assert not copied_events(store)  # at its own planted path: expected, not a copy
    assert not store.docs("findings")  # a decoy is never a live-credential finding


@needs_gitleaks
def test_a_decoy_copied_into_a_location_is_reported(tmp_path: Path) -> None:
    """Control for the test above: a copy elsewhere still raises the R7 event."""
    from sentinel import canaries
    from sentinel.security import load_key

    home = tmp_path / "home"
    store = Store(tmp_path / "s.db")
    decoys = tmp_path / "decoys"
    decoys.mkdir()
    doc = canaries.plant(store, load_key(home), decoys, NOW)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "pasted.txt").write_text(Path(doc["path"]).read_text(encoding="utf-8"))
    runner.run_once(
        store,
        home,
        Settings(extra_scan_paths=(str(logs),)),
        NOW,
        toast=lambda *_: False,
        probe_pause=0,
    )
    assert len(copied_events(store)) == 1
    assert not store.docs("findings")


@needs_gitleaks
def test_the_rescan_verifier_works_on_a_location(tmp_path: Path) -> None:
    """A location finding can be re-scanned and verified once the file is cleaned."""
    from sentinel.incidents import lifecycle
    from sentinel.security import load_existing_key
    from sentinel.simulation import scenarios

    folder = tmp_path / "ci-logs"
    folder.mkdir()
    log = folder / "run.log"
    log.write_text(f"GEMINI_API_KEY: {fake_google_key()}\n", encoding="utf-8")
    store, _ = run(tmp_path, folder)
    [doc] = store.docs("findings")
    for e in scenarios.provider_usage(doc["cred_ref"], doc["locations"][0]["asset_id"], NOW):
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, NOW)
    home = tmp_path / "home"
    key = load_existing_key(home)

    def scan(path: Path, mode: str) -> list[Finding]:
        return gitleaks.run(path, mode, key, home)

    passed, evidence = runner.verify_rescan(store, iid, "me", NOW, scan)
    assert not passed and "STILL FOUND" in evidence
    log.write_text("cleaned\n", encoding="utf-8")
    passed, evidence = runner.verify_rescan(store, iid, "me", NOW, scan)
    assert passed and evidence.startswith("re-scan at ")
