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
_DIGEST_CHARS = 16


def load_key(home: Path) -> bytes:
    path = home / _KEY_FILE
    if path.exists():
        return path.read_bytes()
    home.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    with path.open("xb") as handle:
        handle.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best effort (Windows ACLs differ)
    return key


def fingerprint(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:_DIGEST_CHARS]
