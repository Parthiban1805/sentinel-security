"""Findings registry: one record per credential (cred_ref), with a lifecycle and audit trail."""

from datetime import UTC, datetime, timedelta
from typing import Any

from sentinel.events.schema import format_time, make_event
from sentinel.redaction import check_free_text
from sentinel.scanners.gitleaks import Finding
from sentinel.store.db import Store

STATUSES = (
    "open",
    "revoke_pending",
    "risk_accepted",
    "revoked_unverified",
    "revoked_verified",
)
# Statuses where the credential may still work (R1 can fire).
LIVE_STATUSES = ("open", "revoke_pending", "risk_accepted", "revoked_unverified")


def _parse_time(value: str, fallback: datetime) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def ingest(
    store: Store, asset_id: str, findings: list[Finding], now: datetime, *, is_test: bool = False
) -> list[str]:
    """Record scan findings; returns refs seen for the first time (each gets an event)."""
    new_refs: list[str] = []
    for f in findings:
        doc = store.get_doc("findings", f.cred_ref)
        location = {"asset_id": asset_id, "file": f.file, "line": f.line, "commit": f.commit}
        if doc is None:
            doc = {
                "cred_ref": f.cred_ref,
                "rule_id": f.rule_id,
                "status": "open",
                "first_seen": format_time(now),
                "last_seen": format_time(now),
                "locations": [location],
                "accepted_until": None,
                "notes": [],
            }
            store.put_doc("findings", f.cred_ref, doc)
            exposed_at = _parse_time(f.date, now) if f.date else now
            store.add_event(
                make_event(
                    event_type="secret_exposure",
                    source="gitleaks",
                    asset_id=asset_id,
                    time=exposed_at,
                    severity="high",
                    confidence="medium",
                    evidence_ref=f"finding/{f.cred_ref}",
                    credential_ref=f.cred_ref,
                    is_test=is_test,
                    attributes={"rule_id": f.rule_id, "file": f.file, "line": f.line},
                )
            )
            new_refs.append(f.cred_ref)
        else:
            doc["last_seen"] = format_time(now)
            if location not in doc["locations"]:
                doc["locations"].append(location)
            store.put_doc("findings", f.cred_ref, doc)
    return new_refs


def set_status(
    store: Store,
    cred_ref: str,
    status: str,
    *,
    actor: str,
    now: datetime,
    evidence: str | None = None,
    accept_days: int | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    actor = check_free_text("actor", actor) or ""
    evidence = check_free_text("evidence", evidence)
    note = check_free_text("note", note)
    doc = store.get_doc("findings", cred_ref)
    if doc is None:
        raise KeyError(f"unknown finding: {cred_ref}")
    if status == "revoked_verified" and not (evidence and evidence.strip()):
        raise ValueError("revoked_verified requires verification evidence")
    if status == "risk_accepted":
        if accept_days is None or accept_days <= 0:
            raise ValueError("risk_accepted requires an expiry (accept_days > 0)")
        doc["accepted_until"] = format_time(now + timedelta(days=accept_days))
    else:
        doc["accepted_until"] = None
    previous = doc["status"]
    doc["status"] = status
    if evidence or note:
        doc["notes"].append(
            {"time": format_time(now), "actor": actor, "evidence": evidence, "note": note}
        )
    store.put_doc("findings", cred_ref, doc)
    store.add_audit(
        format_time(now),
        {
            "action": "finding_status",
            "cred_ref": cred_ref,
            "from": previous,
            "to": status,
            "actor": actor,
            "evidence": evidence,
        },
    )
    return doc


def expired_acceptances(store: Store, now: datetime) -> list[dict[str, Any]]:
    stamp = format_time(now)
    return [
        d
        for d in store.docs("findings")
        if d["status"] == "risk_accepted" and d["accepted_until"] and d["accepted_until"] <= stamp
    ]
