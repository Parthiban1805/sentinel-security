"""Credential fingerprints: keyed hash (HMAC-SHA256) of a secret value, raw value discarded.

The key lives in <home>/fingerprint.key. Without it a fingerprint cannot be brute-forced from a
guessed value, and the same value always maps to the same ref (one key = one ID).
"""

import hashlib
import hmac
import os
import secrets
from pathlib import Path

_KEY_FILE = "fingerprint.key"
_KEY_BYTES = 32
_DIGEST_CHARS = 16


def load_key(home: Path) -> bytes:
    """Read the fingerprint key, creating it atomically on first use.

    Raises ValueError if an existing key file is not exactly 32 bytes (a truncated or empty key
    would make fingerprints guessable, so we refuse rather than continue).
    """
    path = home / _KEY_FILE
    home.mkdir(parents=True, exist_ok=True)
    try:
        # O_EXCL makes creation atomic: a concurrent run either wins or reads the winner's file.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        key = path.read_bytes()
    else:
        key = secrets.token_bytes(_KEY_BYTES)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
    if len(key) != _KEY_BYTES:
        raise ValueError(
            f"{path.name} must be exactly {_KEY_BYTES} bytes (found {len(key)}); "
            "delete it to regenerate (all credential refs will change)"
        )
    return key


def fingerprint(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:_DIGEST_CHARS]
