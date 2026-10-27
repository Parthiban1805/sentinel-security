"""Tamper-evident decision log for Claude Code hooks. Standard library only. NEVER raises.

Each line is one JSON object: the entry fields plus `prev` (hash of the previous line) and `hash`
(sha256 of prev + canonical entry). Editing, deleting or reordering a line breaks the chain, and
`sentinel agentlog verify` also compares against an anchor stored outside this file, so truncating
the tail is detected too.

Never stored: the raw command, path, prompt or tool arguments. A target is represented only by a
keyed fingerprint (HMAC with <home>/fingerprint.key; omitted when no key exists).

Logging must never change a hook's decision: every public function swallows its own errors.
"""

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone

GENESIS = "0" * 64
LOG_NAME = "agent-decisions.jsonl"
_LOCK_NAME = "agent-decisions.lock"
_TAIL_BYTES = 65536


def home():
    configured = os.environ.get("SENTINEL_HOME")
    if configured:
        return configured
    return os.path.join(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd(), ".sentinel")


def canonical(entry):
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def chain_hash(prev, entry):
    return hashlib.sha256((prev + canonical(entry)).encode("utf-8")).hexdigest()


def _last_state(path):
    """(seq, hash) of the last complete line, or (0, GENESIS) for a new/empty log."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            handle.seek(max(0, size - _TAIL_BYTES))
            tail = handle.read().decode("utf-8", errors="ignore")
    except OSError:
        return 0, GENESIS
    for line in reversed([x for x in tail.splitlines() if x.strip()]):
        try:
            obj = json.loads(line)
            return int(obj["seq"]), str(obj["hash"])
        except (ValueError, KeyError, TypeError):
            continue
    return 0, GENESIS


def target_fingerprint(base, text):
    if not text:
        return ""
    try:
        with open(os.path.join(base, "fingerprint.key"), "rb") as handle:
            key = handle.read()
    except OSError:
        return ""
    if len(key) != 32:
        return ""
    return hmac.new(key, text.encode("utf-8", errors="ignore"), hashlib.sha256).hexdigest()[:16]


def _acquire(lock_path, wait=2.0):
    deadline = time.time() + wait
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return True
        except FileExistsError:
            try:  # a lock older than 10 s is stale (a crashed hook)
                if time.time() - os.path.getmtime(lock_path) > 10:
                    os.remove(lock_path)
                    continue
            except OSError:
                pass
            if time.time() >= deadline:
                return False
            time.sleep(0.02)
        except OSError:
            return False


def record(decision, tool, rule, target_class, target_text="", session_id=""):
    """Append one chained entry. Returns True if written. Never raises."""
    try:
        base = home()
        os.makedirs(base, exist_ok=True)
        log_path = os.path.join(base, LOG_NAME)
        lock_path = os.path.join(base, _LOCK_NAME)
        if not _acquire(lock_path):
            return False
        try:
            seq, prev = _last_state(log_path)
            entry = {
                "v": 1,
                "seq": seq + 1,
                "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "session": hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
                if session_id
                else "",
                "tool": str(tool)[:120],
                "decision": decision,
                "rule": rule,
                "target_class": target_class,
                "target_fp": target_fingerprint(base, target_text),
            }
            line = dict(entry, prev=prev, hash=chain_hash(prev, entry))
            payload = (json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
            fd = os.open(log_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            return True
        finally:
            try:
                os.remove(lock_path)
            except OSError:
                pass
    except Exception:  # noqa: BLE001 - logging must never affect a decision
        return False
