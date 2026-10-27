"""sentinel run: isolation of failing sources, alerts for real incidents only, verify-key evidence."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sentinel import runner
from sentinel.config import Settings, load
from sentinel.events.schema import make_event
from sentinel.incidents import lifecycle
from sentinel.simulation import scenarios
from sentinel.sources.gcp import GcpCollector, alias_key
from sentinel.sources.http import HttpClient, Response
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


class FailingTransport:
    def send(self, *a: Any, **k: Any) -> Response:
        return Response(500, {}, b"")


class KeysTransport:
    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
    ) -> Response:
        return Response(200, {}, json.dumps({"keys": self.keys}).encode())


class FakeTokens:
    def token(self) -> str:
        return "fake"


def no_sleep_client(transport: Any) -> HttpClient:
    return HttpClient(transport, retries=1, sleep=lambda _s: None)


def test_failing_sources_are_isolated_and_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(runner.GITHUB_TOKEN_ENV, "fake-token-value")
    store = Store(tmp_path / "s.db")
    settings = Settings(
        github_repos=("o/r",), gcp_projects=("demo",), scan_paths=(str(tmp_path / "missing"),)
    )
    result = runner.run_once(
        store,
        tmp_path / "home",
        settings,
        NOW,
        client=no_sleep_client(FailingTransport()),
        gcp_tokens=FakeTokens,
        toast=lambda t, b: True,
    )
    assert result["health"]["github:o/r"].startswith("error: HTTP 500")
    assert result["health"]["gcp:demo:usage"].startswith("error")
    assert "fake-token-value" not in json.dumps(result)
    assert store.get_doc("snapshots", "health:last_run") is not None


def test_github_skipped_without_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(runner.GITHUB_TOKEN_ENV, raising=False)
    result = runner.run_once(
        Store(tmp_path / "s.db"),
        tmp_path / "h",
        Settings(github_user_keys=True),
        NOW,
        toast=lambda t, b: True,
    )
    assert result["health"]["github"].startswith("skipped")


def test_token_from_file_when_env_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(runner.GITHUB_TOKEN_ENV, raising=False)
    assert runner.github_token(tmp_path) == ""
    (tmp_path / runner.GITHUB_TOKEN_FILE).write_text("﻿file-token-value \r\n", encoding="utf-8")
    assert runner.github_token(tmp_path) == "file-token-value"
    monkeypatch.setenv(runner.GITHUB_TOKEN_ENV, "env-token-value")
    assert runner.github_token(tmp_path) == "env-token-value"  # env wins


def test_alerts_only_for_real_high_incidents(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    home = tmp_path / "home"
    store.add_event(scenarios.canary("decoy-test", NOW)[0])  # test event -> no alert
    real = make_event(
        event_type="canary_triggered",
        source="canary",
        asset_id="decoy-real",
        time=NOW,
        severity="high",
        confidence="high",
        evidence_ref="canary/1",
    )
    store.add_event(real)
    toasts: list[str] = []
    result = runner.run_once(
        store, home, Settings(), NOW, toast=lambda t, b: toasts.append(t) or True
    )
    assert len(result["incidents_created"]) == 2
    assert len(result["alerts"]) == 1 and len(toasts) == 1
    assert "decoy-real" in (home / "alerts.log").read_text()


def open_r1(store: Store) -> str:
    ref = "cred-fp-abcd1234"
    store.add_event(
        make_event(
            event_type="secret_exposure",
            source="gitleaks",
            asset_id="repo-x",
            time=NOW,
            severity="high",
            confidence="medium",
            evidence_ref="f",
            credential_ref=ref,
        )
    )
    store.add_event(scenarios.provider_usage(ref, "gcp-demo", NOW)[0])
    [iid] = lifecycle.open_incidents(store, NOW)
    store.put_doc(
        "aliases", alias_key("demo", "uid1"), {"cred_ref": ref, "project": "demo", "uid": "uid1"}
    )
    lifecycle.approve(store, iid, "revoke_credential", "me", NOW)
    return iid


def test_verify_key_fails_while_key_is_active(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    iid = open_r1(store)
    collector = GcpCollector(HttpClient(KeysTransport([{"uid": "uid1"}])), FakeTokens())
    passed, evidence = runner.verify_key(store, iid, "me", NOW, collector)
    assert passed is False and "ACTIVE" in evidence
    step = next(
        s
        for s in store.get_doc("incidents", iid)["response_plan"]
        if s["step"] == "revoke_credential"
    )  # type: ignore[index]
    assert step["state"] == "verification_failed"


def test_verify_key_not_found_and_never_seen_is_not_proof(tmp_path: Path) -> None:
    """A mistyped alias must not make a live key look revoked."""
    store = Store(tmp_path / "s.db")
    iid = open_r1(store)
    collector = GcpCollector(HttpClient(KeysTransport([])), FakeTokens())  # empty listing
    passed, evidence = runner.verify_key(store, iid, "me", NOW, collector)
    assert passed is False and "never seen" in evidence


def test_verify_key_absent_but_previously_seen_passes(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    iid = open_r1(store)
    GcpCollector(HttpClient(KeysTransport([{"uid": "uid1"}])), FakeTokens()).sync_key_assets(
        store, "demo", NOW
    )
    gone = GcpCollector(HttpClient(KeysTransport([])), FakeTokens())
    passed, evidence = runner.verify_key(store, iid, "me", NOW, gone)
    assert passed is True and "previously seen" in evidence


def test_verify_key_passes_when_deleted(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    iid = open_r1(store)
    keys = [{"uid": "uid1", "deleteTime": "2026-10-27T11:00:00Z"}]
    collector = GcpCollector(HttpClient(KeysTransport(keys)), FakeTokens())
    passed, evidence = runner.verify_key(store, iid, "me", NOW, collector)
    assert passed is True and "deleted at" in evidence


def test_config_loader(tmp_path: Path) -> None:
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text(
        '[github]\nrepos = ["o/r"]\nuser_keys = true\n[gcp]\nprojects = ["demo-project"]\nusage_floor = 10\n'
    )
    s = load(cfg)
    assert (
        s.github_repos == ("o/r",)
        and s.github_user_keys
        and s.gcp_projects == ("demo-project",)
        and s.usage_floor == 10
    )
    assert load(tmp_path / "absent.toml") == Settings()
