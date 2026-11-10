"""Session taint markers (v0.7e F1, ADR-0027). Stdlib only.

This file is ALSO the gateway's `.claude/hooks/_taint.py` (a byte-identical copy shipped by the
gateway patch; a test keeps them identical). It must import nothing from `sentinel` and run on
the first `python` on PATH, which can be 3.10.

The "lethal trifecta" (Willison 2025; CaMeL, arXiv:2503.18813; Beurer-Kellner et al.,
arXiv:2506.08837): a session that has read untrusted content (leg U) AND seen private data (leg
S) must not send data out unchecked. The output guard (PostToolUse) sets the legs; the gateway
(PreToolUse) asks before a data-leaving call in a session with both (TF-01).

One marker file per leg, `<home>/agent-sessions/<sha256(session)[:16]>.<leg>`, created with
O_EXCL and never rewritten: two hooks running at once cannot undo each other's leg. Markers hold
the leg, the first rule that set it and the time. No content, no raw session id.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path

DIR_NAME = "agent-sessions"
LEGS = ("U", "S")  # U: untrusted content read; S: private data seen
KEEP_DAYS = 14


def session_key(session_id: str) -> str:
    """The decision log's session hash (sha256[:16]). An empty id is hashed as "no-session" here
    (the log writes ""), so calls without an id still share one set of legs."""
    return hashlib.sha256((session_id or "no-session").encode("utf-8")).hexdigest()[:16]


def marker_path(home: str, session_id: str, leg: str) -> Path:
    if leg not in LEGS:
        raise ValueError(f"unknown leg {leg!r}")
    return Path(home) / DIR_NAME / f"{session_key(session_id)}.{leg}"


def mark(home: str, session_id: str, leg: str, rule: str) -> bool:
    """Set a leg for a session. True if it was newly set; False if it was already set."""
    path = marker_path(home, session_id, leg)
    os.makedirs(path.parent, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    try:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        os.write(fd, json.dumps({"leg": leg, "rule": rule, "time": stamp}).encode("utf-8"))
    finally:
        os.close(fd)
    return True


def _present(path: Path) -> bool:
    """True if the marker exists. Anything other than 'not found' counts as set (fail closed)."""
    try:
        os.stat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return True


def legs(home: str, session_id: str) -> set[str]:
    """The legs set for a session. Raises OSError if the marker folder exists but is not a folder:
    on Windows a marker under a FILE reads as "not found", which would silently open the gate
    (security review 2026-11-06). The gateway turns the error into an ask (TF-99)."""
    folder = Path(home) / DIR_NAME
    try:
        info = os.stat(folder)
    except FileNotFoundError:
        info = None
    if info is not None and not stat.S_ISDIR(info.st_mode):
        raise OSError(f"{DIR_NAME} is not a folder")
    return {leg for leg in LEGS if _present(marker_path(home, session_id, leg))}


def tainted(home: str, session_id: str) -> bool:
    """Both legs set: untrusted content read and private data seen in this session."""
    return set(LEGS) <= legs(home, session_id)


def prune(home: str, days: int = KEEP_DAYS) -> int:
    """Remove markers older than `days`. Returns how many were removed. Never raises."""
    folder = Path(home) / DIR_NAME
    cutoff = time.time() - days * 86400
    removed = 0
    try:
        entries = list(folder.iterdir())
    except OSError:
        return 0
    for entry in entries:
        try:
            if entry.suffix.lstrip(".") in LEGS and entry.stat().st_mtime < cutoff:
                entry.unlink()
                removed += 1
        except OSError:
            continue
    return removed
