"""A stale SENTINEL_GITHUB_TOKEN in the environment must not silently override a freshly saved token file.

Found live on 2026-10-27: an old token set with `setx` kept winning over the new one saved by
`sentinel init`, so GitHub answered 401 even though the file held a valid token.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel import doctor, onboarding, runner
from sentinel.config import Settings
from sentinel.sources.http import HttpClient, Response
from sentinel.store.db import Store

OLD = "github_pat_" + "A1b2C3d4E5" * 8  # fake, built at runtime
NEW = "github_pat_" + "Z9y8X7w6V5" * 8
NOW = datetime(2026, 10, 27, tzinfo=UTC)


def save(home: Path, token: str) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / runner.GITHUB_TOKEN_FILE).write_text(token, encoding="utf-8")


def test_source_and_shadow_detection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(runner.GITHUB_TOKEN_ENV, raising=False)
    assert runner.github_token_source(tmp_path) == ("", "none", False)
    save(tmp_path, NEW)
    assert runner.github_token_source(tmp_path) == (NEW, "file", False)
    monkeypatch.setenv(runner.GITHUB_TOKEN_ENV, NEW)  # same value in both: no conflict
    assert runner.github_token_source(tmp_path) == (NEW, "environment", False)
    monkeypatch.setenv(runner.GITHUB_TOKEN_ENV, OLD)  # the trap: environment wins and differs
    assert runner.github_token_source(tmp_path) == (OLD, "environment", True)
    monkeypatch.delenv(runner.GITHUB_TOKEN_ENV)
    assert runner.github_token(tmp_path) == NEW  # backwards-compatible helper


def test_doctor_warns_without_revealing_either_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save(tmp_path, NEW)
    monkeypatch.setenv(runner.GITHUB_TOKEN_ENV, OLD)
    check = doctor.check_github_token(tmp_path, Settings(github_repos=("o/r",)))
    assert check.status == "warn" and "overrides the saved token file" in check.detail
    assert "reg delete" in check.detail  # tells the user how to fix it
    assert OLD not in check.detail and NEW not in check.detail


def test_run_surfaces_the_shadowing_in_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    save(home, NEW)
    monkeypatch.setenv(runner.GITHUB_TOKEN_ENV, OLD)

    class Reject:
        def send(self, *args: object, **kwargs: object) -> Response:
            return Response(401, {}, b'{"message":"Bad credentials"}')

    result = runner.run_once(
        Store(home / "sentinel.db"),
        home,
        Settings(github_repos=("o/r",)),
        NOW,
        client=HttpClient(Reject()),
        scan=False,
    )
    assert result["health"]["github:token-source"].startswith("warn: the environment variable")
    assert "rejected" in result["health"]["github:o/r"]  # the cause is visible next to the symptom
    assert OLD not in json.dumps(result) and NEW not in json.dumps(result)


def test_no_warning_when_only_one_source_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    save(home, NEW)
    monkeypatch.delenv(runner.GITHUB_TOKEN_ENV, raising=False)

    class Ok:
        def send(self, *args: object, **kwargs: object) -> Response:
            return Response(200, {}, b"[]")

    result = runner.run_once(
        Store(home / "sentinel.db"), home, Settings(github_repos=("o/r",)), NOW,
        client=HttpClient(Ok()), scan=False,
    )  # fmt: skip
    assert "github:token-source" not in result["health"]


def test_init_warns_right_after_saving_a_token_that_the_environment_would_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(runner.GITHUB_TOKEN_ENV, OLD)
    lines: list[str] = []
    opts = onboarding.InitOptions(
        config_path=tmp_path / "sentinel.toml",
        home=tmp_path / ".sentinel",
        root=tmp_path,
        scan_paths=[str(tmp_path)],
        github_repos=["o/r"],
        interactive=True,
        store_token=True,
    )
    onboarding.run_init(opts, lines.append, lambda q, d: d, lambda q: NEW)
    text = "\n".join(lines)
    assert "token saved to" in text and "WARNING: the environment variable" in text
    assert OLD not in text and NEW not in text
