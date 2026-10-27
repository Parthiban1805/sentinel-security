"""Verify the tamper-evident agent decision log written by the hooks.

Hook side: docs/patches/agent-decision-log. The chain proves lines were not edited, removed from
the middle or reordered. Truncating the END of the file is invisible to the chain alone, so
`verify` also checks an anchor (the last verified seq and hash) kept in Sentinel's store, outside
the file the agent could touch.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
LOG_NAME = "agent-decisions.jsonl"
_ENTRY_KEYS = (
    "v",
    "seq",
    "time",
    "session",
    "tool",
    "decision",
    "rule",
    "target_class",
    "target_fp",
)


def _canonical(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def chain_hash(prev: str, entry: dict[str, Any]) -> str:
    return hashlib.sha256((prev + _canonical(entry)).encode("utf-8")).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    entries: int = 0
    last_seq: int = 0
    last_hash: str = GENESIS
    problems: list[str] = field(default_factory=list)
    records: list[dict[str, Any]] = field(default_factory=list)


def verify_with_anchor(store: Any, path: Path, *, advance: bool = True) -> VerifyResult:
    """Verify against the stored anchor; on success move the anchor to the newest verified entry."""
    anchor = store.get_doc("snapshots", "agentlog:anchor")
    result = verify(path, anchor)
    if result.ok and advance and result.entries:
        store.put_doc(
            "snapshots", "agentlog:anchor", {"seq": result.last_seq, "hash": result.last_hash}
        )
    return result


def verify(path: Path, anchor: dict[str, Any] | None = None) -> VerifyResult:
    """Check the whole chain; `anchor` ({"seq", "hash"}) catches rewritten history or truncation."""
    result = VerifyResult(ok=True)
    if not path.exists():
        result.ok = anchor is None
        if anchor is not None:
            result.problems.append("log file missing but a previous verification exists (deleted?)")
        return result
    prev, expected_seq = GENESIS, 1
    by_seq: dict[int, str] = {}
    for number, raw in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        if not raw.strip():
            continue
        try:
            line = json.loads(raw)
            digest, line_prev = line.pop("hash"), line.pop("prev")
            entry = {k: line[k] for k in _ENTRY_KEYS}
        except (ValueError, KeyError, TypeError, AttributeError):
            result.problems.append(
                f"line {number}: unreadable or malformed (torn write or tampering)"
            )
            result.ok = False
            break
        if set(line) != set(_ENTRY_KEYS):
            result.problems.append(f"line {number}: unexpected fields")
        if entry["seq"] != expected_seq:
            result.problems.append(
                f"line {number}: sequence {entry['seq']}, expected {expected_seq}"
            )
        if line_prev != prev:
            result.problems.append(f"line {number}: does not follow the previous line")
        if chain_hash(line_prev, entry) != digest:
            result.problems.append(f"line {number}: content does not match its hash (edited)")
        by_seq[entry["seq"]] = digest
        result.records.append(entry)
        prev, expected_seq = digest, entry["seq"] + 1
        result.last_seq, result.last_hash = entry["seq"], digest
    result.entries = len(result.records)
    if anchor is not None:
        if result.last_seq < anchor["seq"]:
            result.problems.append(
                f"log ends at seq {result.last_seq} but seq {anchor['seq']} "
                "was verified before (truncated)"
            )
        elif by_seq.get(anchor["seq"]) != anchor["hash"]:
            result.problems.append(
                f"entry {anchor['seq']} no longer matches the verified history (rewritten)"
            )
    result.ok = not result.problems
    return result
