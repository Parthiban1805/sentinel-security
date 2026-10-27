"""Canary decoys (rule R7): fake credential files that no legitimate process has a reason to touch.

What a self-built decoy can and cannot tell you (ADR-0009):
- COPIED (strong): the decoy's value turns up somewhere else (another repo, a transcript, a
  commit). Found by Sentinel's normal secret scan: the decoy is a provider-shaped fake, so gitleaks
  reports it and its keyed fingerprint matches the canary registry.
- MODIFIED / REMOVED (medium): size or modification time changed, or the file is gone.
- READ (weak): the file's last-access time moved. Antivirus and desktop indexers also read files,
  and Windows may delay or disable access-time updates, so this is recorded at low confidence and
  never opens an incident by itself. Absence of a change proves nothing.
- USED AT A PROVIDER: NOT detectable here (needs a live provider key or a hosted canary service).

The decoy value is generated at runtime, written to the decoy file, and discarded. Only its keyed
fingerprint is stored. Decoys are never committed: inside a Git work tree the file is added to the
repository's local `.git/info/exclude`.
"""

import os
import re
import secrets
import string
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.events.schema import format_time, make_event
from sentinel.scanners.gitleaks import Finding
from sentinel.security import fingerprint
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

_ALNUM = string.ascii_letters + string.digits + "_"
DECOY_NAMES = (".env.backup", "credentials.bak", "secrets.old.env", "gemini-key-old.txt")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class CanaryError(ValueError):
    """Invalid canary operation (message never contains a decoy value)."""


def _fake_github_pat() -> str:
    return "github_pat_" + "".join(secrets.choice(_ALNUM) for _ in range(82))


KINDS: dict[str, tuple[Any, str]] = {
    "google_key": (fake_google_key, "GEMINI_API_KEY"),
    "github_pat": (_fake_github_pat, "GITHUB_TOKEN"),
}

# reason -> (severity, confidence). Only copied/modified/removed can open an incident (rule R7).
REASONS = {
    "copied": ("critical", "high"),
    "modified": ("high", "medium"),
    "removed": ("high", "medium"),
    "read": ("low", "low"),
}


def asset_id(canary_id: str) -> str:
    return f"canary-{canary_id.lower()}"


def _git(directory: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 (fixed argv, no shell)
        ["git", "-C", str(directory), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


def _exclude_from_git(directory: Path, filename: str) -> str | None:
    """Keep a decoy inside a Git work tree from ever being committed (local-only exclude)."""
    top = _git(directory, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return None
    if _git(directory, "check-ignore", "-q", "--", filename).returncode == 0:
        return "already ignored by Git"
    rel = Path(directory).resolve().relative_to(Path(top.stdout.strip()).resolve()) / filename
    exclude = Path(
        _git(
            directory, "rev-parse", "--path-format=absolute", "--git-path", "info/exclude"
        ).stdout.strip()
    )
    exclude.parent.mkdir(parents=True, exist_ok=True)
    existing = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
    line = "/" + rel.as_posix()
    if line not in existing.splitlines():
        exclude.write_text(
            existing + ("" if existing.endswith("\n") or not existing else "\n") + line + "\n",
            encoding="utf-8",
        )
    return f"added {line} to the repository's local .git/info/exclude"


def _atime_probe(directory: Path) -> str:
    """Does a read here move the access time right away? Returns 'immediate' or 'unverified'."""
    probe = directory / f".sentinel-atime-probe-{secrets.token_hex(4)}"
    try:
        probe.write_text("probe", encoding="utf-8")
        before = probe.stat().st_atime_ns
        time.sleep(1.1)
        probe.read_text(encoding="utf-8")
        return "immediate" if probe.stat().st_atime_ns > before else "unverified"
    except OSError:
        return "unverified"
    finally:
        try:
            probe.unlink()
        except OSError:
            pass


def plant(
    store: Store,
    key: bytes,
    directory: Path,
    now: datetime,
    *,
    kind: str = "google_key",
    name: str = DECOY_NAMES[0],
) -> dict[str, Any]:
    if kind not in KINDS:
        raise CanaryError(f"kind must be one of {sorted(KINDS)}")
    if not _SAFE_NAME.fullmatch(name) or name in (".", ".."):
        raise CanaryError("decoy name must be a plain file name")
    directory = directory.resolve()
    if not directory.is_dir():
        raise CanaryError(f"not a directory: {directory}")
    path = directory / name
    if path.exists():
        raise CanaryError(f"{path} already exists (refusing to overwrite)")
    generator, variable = KINDS[kind]
    value = generator()
    ref = f"cred-fp-{fingerprint(value, key)}"
    note = _exclude_from_git(directory, name)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(f"# old backup, do not use\n{variable}={value}\n")
    del value  # only the fingerprint survives
    atime_mode = _atime_probe(directory)
    st = path.stat()
    canary_id = "CAN-" + ref[-8:].upper()
    doc = {
        "canary_id": canary_id,
        "kind": kind,
        "path": path.as_posix(),
        "created": format_time(now),
        "cred_ref": ref,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "atime_ns": st.st_atime_ns,
        "atime_check": atime_mode,
        "status": "armed",
        "triggers": [],
        "git_note": note,
    }
    store.put_doc("canaries", canary_id, doc)
    store.upsert_asset(
        {
            "asset_id": asset_id(canary_id),
            "asset_type": "artifact",
            "name": f"decoy credential file ({kind})",
            "owner": None,
            "importance": "medium",
            "monitoring": "full",
            "approved": True,
            "last_seen": format_time(now),
            "attributes": {"canary": True, "location": path.as_posix()},
        }
    )
    store.add_audit(
        format_time(now),
        {"action": "canary_planted", "canary": canary_id, "kind": kind, "path": path.as_posix()},
    )
    return doc


def _event(
    doc: dict[str, Any], reason: str, now: datetime, detail: str, location: str = ""
) -> dict[str, Any]:
    severity, confidence = REASONS[reason]
    attrs: dict[str, Any] = {"canary_id": doc["canary_id"], "reason": reason, "kind": doc["kind"]}
    if location:
        attrs["location"] = location
    return make_event(
        event_type="canary_triggered",
        source="canary",
        asset_id=asset_id(doc["canary_id"]),
        time=now,
        severity=severity,
        confidence=confidence,
        evidence_ref=f"canary/{doc['canary_id']}/{reason}",
        event_id=f"canary:{doc['canary_id']}:{reason}:{detail}",
        credential_ref=doc["cred_ref"],
        attributes=attrs,
    )


def check(store: Store, now: datetime) -> list[dict[str, Any]]:
    """Tripwire pass over armed decoys. Uses stat() only: reading a decoy would move its access
    time and fake a 'read'."""
    events: list[dict[str, Any]] = []
    for doc in store.docs("canaries"):
        if doc["status"] == "disarmed":
            continue
        path = Path(doc["path"])
        if not path.exists():
            if "removed" not in doc["triggers"]:
                events.append(_event(doc, "removed", now, "gone"))
                doc["triggers"].append("removed")
                doc["status"] = "triggered"
            store.put_doc("canaries", doc["canary_id"], doc)
            continue
        st = path.stat()
        if (st.st_size, st.st_mtime_ns) != (doc["size"], doc["mtime_ns"]):
            events.append(_event(doc, "modified", now, str(st.st_mtime_ns)))
            doc["size"], doc["mtime_ns"] = st.st_size, st.st_mtime_ns
            if "modified" not in doc["triggers"]:
                doc["triggers"].append("modified")
            doc["status"] = "triggered"
        if st.st_atime_ns > doc["atime_ns"]:
            events.append(_event(doc, "read", now, str(st.st_atime_ns)))
            doc["atime_ns"] = st.st_atime_ns  # advance so the same access is reported once
        store.put_doc("canaries", doc["canary_id"], doc)
    return events


def filter_findings(
    store: Store, target: Path, findings: list[Finding], now: datetime
) -> tuple[list[dict[str, Any]], list[Finding]]:
    """Split scan findings: decoy values never become 'live credential' findings.

    A decoy value at its own planted path is expected (dropped). The same value anywhere else, or in
    Git history, means the decoy was COPIED: a `canary_triggered` event is produced."""
    by_ref = {d["cred_ref"]: d for d in store.docs("canaries") if d["status"] != "disarmed"}
    if not by_ref:
        return [], findings
    events: list[dict[str, Any]] = []
    kept: list[Finding] = []
    base = target.resolve()
    for f in findings:
        doc = by_ref.get(f.cred_ref)
        if doc is None:
            kept.append(f)
            continue
        here = (base / f.file).resolve().as_posix() if not f.commit else ""
        if here and here == Path(doc["path"]).resolve().as_posix():
            continue  # the decoy sitting where we put it
        location = f"{f.file}" + (f"@{f.commit[:7]}" if f.commit else "")
        events.append(
            _event(doc, "copied", now, f"{base.name}:{location}", f"{base.name}/{location}")
        )
        if "copied" not in doc["triggers"]:
            doc["triggers"].append("copied")
        doc["status"] = "triggered"
        store.put_doc("canaries", doc["canary_id"], doc)
    return events, kept


def disarm(
    store: Store, canary_id: str, now: datetime, *, delete_file: bool = False
) -> dict[str, Any]:
    doc = store.get_doc("canaries", canary_id)
    if doc is None:
        raise KeyError(f"unknown canary: {canary_id}")
    doc["status"] = "disarmed"
    if delete_file:
        try:
            Path(doc["path"]).unlink()
        except FileNotFoundError:
            pass
    store.put_doc("canaries", canary_id, doc)
    store.add_audit(
        format_time(now),
        {"action": "canary_disarmed", "canary": canary_id, "file_deleted": delete_file},
    )
    return replace_status(doc)


def replace_status(doc: dict[str, Any]) -> dict[str, Any]:
    return dict(doc)
