"""Incident lifecycle: open from matches, approve, execute (dry run), verify, close.

Closure rule (project rule 7): an incident closes as verified only when every required step has
passing verification evidence. Otherwise it stays open, or is closed explicitly as unverified.
"""

import hashlib
from datetime import datetime
from typing import Any

from sentinel import findings
from sentinel.correlation.engine import context_from_store, correlate
from sentinel.correlation.model import Match
from sentinel.events.schema import format_time
from sentinel.incidents import response, scoring
from sentinel.inventory.blast import blast_radius
from sentinel.redaction import check_free_text
from sentinel.store.db import Store

# What we do NOT know, per rule (credential rules fall back to the provider-activity unknown).
_UNKNOWNS: dict[str, tuple[str, ...]] = {
    "R10": (
        "Whether anyone fetched the exposed file during the exposure window (server access logs).",
        "Which credentials or data the file contains and whether any were already used.",
    ),
    "R2": (
        "What the workflow change actually does when it runs (the diff content is not stored).",
        "Whether the actor is a legitimate new contributor.",
    ),
    "R8": ("Whether the release was built by the modified pipeline or by an earlier run.",),
    "R11": (
        "Whether the revoked key is still active, or the usage is late-arriving provider data.",
        "Whether another copy of the key exists elsewhere.",
    ),
    "R4": ("Whether the volume comes from credential abuse or from legitimate load.",),
    "R6": ("Whether the session was stolen or the user changed device or location.",),
    "R7": ("Where the decoy was read and by whom.",),
}


class IncidentError(ValueError):
    """Invalid lifecycle transition (message names the rule that was violated)."""


def incident_id(key: str) -> str:
    return "INC-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper()


def _timeline(store: Store, event_ids: tuple[str, ...]) -> list[dict[str, str]]:
    wanted = set(event_ids)
    return [
        {
            "time": e["time"],
            "event_id": e["event_id"],
            "event_type": e["event_type"],
            "source": e["source"],
            "asset_id": e["asset_id"],
            "is_test": str(e["is_test"]),
        }
        for e in store.events()
        if e["event_id"] in wanted
    ]


def open_incidents(store: Store, now: datetime) -> list[str]:
    """Correlate all stored events; create an incident for each match not yet recorded."""
    created: list[str] = []
    for match in correlate(store.events(), context_from_store(store)):
        iid = incident_id(match.key)
        if store.get_doc("incidents", iid) is not None:
            continue
        blast = blast_radius(store, match.cred_ref) if match.cred_ref else None
        risk = scoring.score(match, blast)
        incident = _build(store, iid, match, blast, risk, now)
        store.put_doc("incidents", iid, incident)
        store.add_audit(
            format_time(now),
            {
                "action": "incident_opened",
                "incident": iid,
                "rule": match.rule_id,
                "severity": risk["severity"],
            },
        )
        created.append(iid)
    return created


def _build(
    store: Store,
    iid: str,
    match: Match,
    blast: dict[str, Any] | None,
    risk: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    unknowns = list(
        _UNKNOWNS.get(
            match.rule_id,
            ("Whether the provider shows other activity outside the correlated events.",),
        )
    )
    if blast is not None and blast["unlinked"]:
        unknowns.append("Credential is not linked to any asset: blast radius is unknown.")
    return {
        "id": iid,
        "key": match.key,  # dedup key; episode-based rules use it to see closed incidents
        "rule_id": match.rule_id,
        "title": match.title,
        "status": "open",
        "verified": False,
        "is_test": match.is_test,
        "created": format_time(now),
        "closed": None,
        "close_note": None,
        "cred_ref": match.cred_ref,
        "identity_ref": match.identity_ref,
        "asset_id": match.asset_id,
        "first_event_time": match.first_time,
        "severity": risk["severity"],
        "confidence": risk["confidence"],
        "urgency": risk["urgency"],
        "risk": risk,
        "facts": list(match.facts),
        "hypotheses": list(match.hypotheses),
        "unknowns": unknowns,
        "timeline": _timeline(store, match.event_ids),
        "blast_radius": blast,
        "response_plan": response.plan_for(match.rule_id),
    }


def _get(store: Store, iid: str) -> dict[str, Any]:
    incident = store.get_doc("incidents", iid)
    if incident is None:
        raise KeyError(f"unknown incident: {iid}")
    if incident["status"] == "closed":
        raise IncidentError("incident is closed")
    return incident


def _step(incident: dict[str, Any], name: str) -> dict[str, Any]:
    for step in incident["response_plan"]:
        if step["step"] == name:
            return step  # type: ignore[no-any-return]
    raise KeyError(f"unknown step: {name}")


def _save(store: Store, incident: dict[str, Any], now: datetime, entry: dict[str, Any]) -> None:
    store.put_doc("incidents", incident["id"], incident)
    store.add_audit(format_time(now), {"incident": incident["id"], **entry})


def approve(store: Store, iid: str, name: str, actor: str, now: datetime) -> None:
    incident = _get(store, iid)
    step = _step(incident, name)
    if step["state"] != "pending":
        raise IncidentError(f"step '{name}' is {step['state']}, not pending")
    step["state"] = "approved"
    step["approved_by"] = actor
    _save(store, incident, now, {"action": "approve", "step": name, "actor": actor})


def execute(
    store: Store,
    iid: str,
    name: str,
    actor: str,
    now: datetime,
    adapter: response.ResponseAdapter,
) -> response.AdapterResult:
    incident = _get(store, iid)
    step = _step(incident, name)
    if step["response_class"] not in response.NO_APPROVAL_NEEDED and step["state"] != "approved":
        raise IncidentError(
            f"step '{name}' needs human approval first (class: {step['response_class']})"
        )
    result = adapter.execute(
        name, incident["cred_ref"] or incident["identity_ref"] or incident["asset_id"]
    )
    step["state"] = "executed_dry_run" if result.ok else "execution_failed"
    step["events"].append({"time": format_time(now), "actor": actor, "detail": result.detail})
    _save(
        store,
        incident,
        now,
        {"action": "execute", "step": name, "actor": actor, "detail": result.detail},
    )
    return result


def verify(
    store: Store, iid: str, name: str, actor: str, now: datetime, *, passed: bool, evidence: str
) -> None:
    if not evidence.strip():
        raise IncidentError("verification needs evidence")
    evidence = check_free_text("evidence", evidence) or ""
    actor = check_free_text("actor", actor) or ""
    incident = _get(store, iid)
    step = _step(incident, name)
    if step["response_class"] not in response.NO_APPROVAL_NEEDED and step["state"] not in (
        "approved",
        "executed_dry_run",
        "verification_failed",
    ):
        raise IncidentError(f"step '{name}' must be approved before it can be verified")
    step["state"] = "verified" if passed else "verification_failed"
    step["events"].append(
        {"time": format_time(now), "actor": actor, "verified": passed, "evidence": evidence}
    )
    _save(
        store,
        incident,
        now,
        {"action": "verify", "step": name, "actor": actor, "passed": passed, "evidence": evidence},
    )
    cred = incident["cred_ref"]
    if name == "revoke_credential" and cred and store.get_doc("findings", cred):
        findings.set_status(
            store,
            cred,
            "revoked_verified" if passed else "revoke_pending",
            actor=actor,
            now=now,
            evidence=evidence if passed else None,
            note=None if passed else f"verification failed: {evidence}",
        )


def close(
    store: Store, iid: str, actor: str, now: datetime, *, unverified_note: str | None = None
) -> dict[str, Any]:
    unverified_note = check_free_text("unverified note", unverified_note)
    incident = _get(store, iid)
    missing = [
        s["step"]
        for s in incident["response_plan"]
        if s["required_for_close"] and s["state"] != "verified"
    ]
    if missing and not (unverified_note and unverified_note.strip()):
        raise IncidentError("cannot close: required steps not verified: " + ", ".join(missing))
    incident["status"] = "closed"
    incident["verified"] = not missing
    incident["closed"] = format_time(now)
    incident["close_note"] = None if not missing else f"closed UNVERIFIED: {unverified_note}"
    _save(
        store,
        incident,
        now,
        {"action": "close", "actor": actor, "verified": incident["verified"], "missing": missing},
    )
    return incident
