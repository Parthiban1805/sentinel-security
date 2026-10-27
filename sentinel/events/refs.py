"""Safe reference helpers: credentials and identities appear only as fingerprints."""

import re

_HEX = re.compile(r"^[0-9a-f]{4,}$")
_IDENTITY_KINDS = ("user", "bot", "svc")


def _check_hex(digest: str) -> str:
    if not _HEX.fullmatch(digest):
        raise ValueError("fingerprint must be at least 4 lowercase hex characters")
    return digest


def cred_ref(digest: str) -> str:
    """Build a credential ref from a keyed-hash hex digest (never from the raw value)."""
    return f"cred-fp-{_check_hex(digest)}"


def identity_ref(kind: str, digest: str) -> str:
    if kind not in _IDENTITY_KINDS:
        raise ValueError(f"identity kind must be one of {_IDENTITY_KINDS}")
    return f"{kind}-fp-{_check_hex(digest)}"
