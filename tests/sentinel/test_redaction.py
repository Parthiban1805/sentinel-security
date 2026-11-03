"""Free-text fields must never store credential-shaped strings."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel import findings
from sentinel.redaction import check_free_text, looks_like_secret
from sentinel.scanners.gitleaks import Finding
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "text",
    [
        fake_google_key(),
        "token github_pat_" + "A1b2C3d4E5" * 4,
        "key AKIA" + "ABCDEFGHIJKLMNOP",
        "-----BEGIN " + "RSA PRIVATE KEY-----",  # built at runtime: no literal key header on disk
        ".".join(["eyJ" + "a" * 20, "b" * 20, "c" * 20]),  # JWT-shaped, built at runtime
    ],
)
def test_credential_shaped_text_is_detected(text: str) -> None:
    assert looks_like_secret(text)


@pytest.mark.parametrize(
    "text",
    [
        "provider console shows key deleted",
        "old key fails with API_KEY_INVALID at 2026-10-27T11:00:00Z",
        "see ticket INC-0A1B2C3D and commit 3f574b5",
    ],
)
def test_normal_evidence_is_allowed(text: str) -> None:
    assert not looks_like_secret(text)
    assert check_free_text("evidence", text) == text


def test_refusal_never_echoes_the_secret() -> None:
    secret = fake_google_key()
    with pytest.raises(ValueError) as exc:
        check_free_text("evidence", f"deleted key {secret}")
    assert secret not in str(exc.value)


def test_too_long_text_refused() -> None:
    with pytest.raises(ValueError, match="too long"):
        check_free_text("note", "x" * 5000)


def test_set_status_refuses_pasted_key_and_stores_nothing(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    f = Finding("cred-fp-abcd1234", "gcp-api-key", "a.txt", 1, "", "")
    findings.ingest(store, "repo-x", [f], NOW)
    secret = fake_google_key()
    with pytest.raises(ValueError):
        findings.set_status(
            store, f.cred_ref, "revoked_verified", actor="me", now=NOW, evidence=f"was {secret}"
        )
    doc = store.get_doc("findings", f.cred_ref)
    assert doc is not None and doc["status"] == "open" and doc["notes"] == []
    assert store.audit() == []


def test_a_long_hyphenated_name_without_digits_is_not_mistaken_for_a_key() -> None:
    from sentinel.redaction import looks_like_secret

    slug = ".github/workflows/this-is-a-plain-long-hyphenated-name-of-a-file-without-numbers.yml"
    assert not looks_like_secret(slug)


def test_a_random_token_with_digits_is_still_caught() -> None:
    import random
    import string

    from sentinel.redaction import looks_like_secret

    rng = random.Random(7)  # noqa: S311  runtime-built test value (CLAUDE.md rule 3)
    token = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(40)) + "7"
    assert looks_like_secret(token)
