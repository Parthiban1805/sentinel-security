"""sentinel doctor: read-only checks; must never reveal token or key contents."""

from pathlib import Path

import pytest

from sentinel import doctor, runner
from sentinel.cli import main
from sentinel.config import Settings
from sentinel.security import load_key

TOKEN = "github_pat_" + "Z9y8X7w6V5" * 8  # fake, built at runtime


def by_name(checks: list[doctor.Check]) -> dict[str, doctor.Check]:
    return {c.name: c for c in checks}


def test_missing_token_fails_with_instructions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(runner.GITHUB_TOKEN_ENV, raising=False)
    c = doctor.check_github_token(tmp_path, Settings(github_repos=("o/r",)))
    assert c.status == "fail" and runner.GITHUB_TOKEN_ENV in c.detail


def test_token_found_in_file_never_echoed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(runner.GITHUB_TOKEN_ENV, raising=False)
    (tmp_path / runner.GITHUB_TOKEN_FILE).write_text(TOKEN, encoding="utf-8")
    c = doctor.check_github_token(tmp_path, Settings(github_repos=("o/r",)))
    assert c.status in ("ok", "warn") and "file" in c.detail
    assert TOKEN not in c.detail and TOKEN[:15] not in c.detail


def test_github_not_configured_is_fine(tmp_path: Path) -> None:
    assert doctor.check_github_token(tmp_path, Settings()).status == "ok"


def test_gitignore_check_flags_missing_entries(tmp_path: Path) -> None:
    assert doctor.check_gitignore(tmp_path).status == "fail"
    (tmp_path / ".gitignore").write_text(".sentinel/\nsentinel.toml\n", encoding="utf-8")
    assert doctor.check_gitignore(tmp_path).status == "ok"


def test_bad_key_file_fails(tmp_path: Path) -> None:
    load_key(tmp_path)
    (tmp_path / "fingerprint.key").write_bytes(b"short")
    assert doctor.check_fingerprint_key(tmp_path).status == "fail"


def test_config_checks(tmp_path: Path) -> None:
    assert doctor.check_config(tmp_path / "none.toml").status == "warn"
    bad = tmp_path / "bad.toml"
    bad.write_text("this is = = not toml", encoding="utf-8")
    assert doctor.check_config(bad).status == "fail"
    good = tmp_path / "good.toml"
    good.write_text(f'[scan]\npaths = ["{(tmp_path / "gone").as_posix()}"]\n', encoding="utf-8")
    assert doctor.check_config(good).status == "warn"  # path does not exist


def test_cli_doctor_exit_code_and_no_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(runner.GITHUB_TOKEN_ENV, raising=False)
    home = tmp_path / "home"
    home.mkdir()
    (home / runner.GITHUB_TOKEN_FILE).write_text(TOKEN, encoding="utf-8")
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text('[github]\nrepos = ["o/r"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)  # no .gitignore here -> that check fails -> exit code 1
    code = main(["--home", str(home), "doctor", "--config", str(cfg)])
    out = capsys.readouterr().out
    assert code == 1 and "[FAIL] gitignore" in out
    assert TOKEN not in out and "checks:" in out
