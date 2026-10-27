"""verify-ssh-key (R6): passes only when every flagged key id is absent from a successful listing."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel import runner
from sentinel.events.refs import identity_ref
from sentinel.events.schema import make_event
from sentinel.incidents import lifecycle
from sentinel.simulation import scenarios
from sentinel.sources.github import GitHubCollector
from sentinel.sources.http import HttpClient, HttpError, Response
from sentinel.store.db import Store

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
WHO = identity_ref("user", "ab12cd34")
STEP = "revoke_token_or_ssh_key"


class Listing:
    """Fake transport answering /user/keys with the given key ids, or with an HTTP status."""

    def __init__(self, ids: list[int] | None = None, status: int = 200) -> None:
        self.ids, self.status = ids or [], status

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
    ) -> Response:
        if self.status != 200:
            return Response(self.status, {}, b"")
        return Response(200, {}, json.dumps([{"id": i} for i in self.ids]).encode())


def gh(listing: Listing) -> GitHubCollector:
    return GitHubCollector(HttpClient(listing, retries=1), "fake", b"k" * 32)


def key_event(key_id: str, minutes: int = 20) -> dict[str, Any]:
    return make_event(
        event_type="ssh_key_added",
        source="github_api",
        asset_id="gh-account",
        time=T0 + timedelta(minutes=minutes),
        severity="medium",
        confidence="high",
        evidence_ref=f"github/user_keys/{key_id}",
        event_id=f"github:user_key:{key_id}",
        identity_ref=WHO,
        is_test=True,
        attributes={"key_id": key_id},
    )


def r6_incident(tmp_path: Path, *events: dict[str, Any]) -> tuple[Store, str]:
    store = Store(tmp_path / "s.db")
    login = scenarios.login_then_token("ab12cd34", "gh-account", T0)[0]
    for e in (login, *events):
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, T0 + timedelta(hours=1))
    assert (store.get_doc("incidents", iid) or {})["rule_id"] == "R6"
    lifecycle.approve(store, iid, STEP, "me", T0)  # a human approved the revocation first
    return store, iid


def step_state(store: Store, iid: str) -> str:
    incident = store.get_doc("incidents", iid)
    assert incident is not None
    return next(s["state"] for s in incident["response_plan"] if s["step"] == STEP)


def test_passes_when_every_flagged_key_is_gone(tmp_path: Path) -> None:
    store, iid = r6_incident(tmp_path, key_event("111"), key_event("222", 25))
    passed, evidence = runner.verify_ssh_key(store, iid, "me", T0, gh(Listing([999])))
    assert passed and step_state(store, iid) == "verified"
    assert "key 111: absent" in evidence and "key 222: absent" in evidence


def test_fails_while_any_flagged_key_remains(tmp_path: Path) -> None:
    store, iid = r6_incident(tmp_path, key_event("111"), key_event("222", 25))
    passed, evidence = runner.verify_ssh_key(store, iid, "me", T0, gh(Listing([222, 5])))
    assert not passed and step_state(store, iid) == "verification_failed"
    assert "key 222: STILL PRESENT" in evidence and "key 111: absent" in evidence


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_a_failed_listing_is_never_proof(tmp_path: Path, status: int) -> None:
    store, iid = r6_incident(tmp_path, key_event("111"))
    with pytest.raises(HttpError):
        runner.verify_ssh_key(store, iid, "me", T0, gh(Listing(status=status)))
    assert step_state(store, iid) == "approved"  # no verification recorded either way


def test_refuses_incidents_it_cannot_verify(tmp_path: Path) -> None:
    store, iid = r6_incident(tmp_path, scenarios.login_then_token("ab12cd34", "gh-account", T0)[1])
    with pytest.raises(ValueError, match="token"):
        runner.verify_ssh_key(store, iid, "me", T0, gh(Listing()))  # a token is not an SSH key

    other = Store(tmp_path / "o.db")
    for e in scenarios.exposed_path("host-demo", T0):
        other.add_event(e)
    [rid] = lifecycle.open_incidents(other, T0)
    with pytest.raises(ValueError, match="R6"):
        runner.verify_ssh_key(other, rid, "me", T0, gh(Listing()))
    with pytest.raises(KeyError):
        runner.verify_ssh_key(other, "INC-00000000", "me", T0, gh(Listing()))


def test_evidence_carries_ids_only(tmp_path: Path) -> None:
    store, iid = r6_incident(tmp_path, key_event("111"))
    _passed, evidence = runner.verify_ssh_key(store, iid, "me", T0, gh(Listing()))
    assert evidence.startswith("GET /user/keys at ") and "fake" not in evidence
