"""Fake credentials, generated at runtime. Never hard-code credential-shaped strings."""

import secrets
import string

_ALPHABET = string.ascii_letters + string.digits + "_-"


def fake_google_key() -> str:
    """A Google-API-key-shaped random string (39 chars, 'AIza' prefix). Not a real credential."""
    return "AIza" + "".join(secrets.choice(_ALPHABET) for _ in range(35))
