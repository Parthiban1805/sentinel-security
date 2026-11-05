"""Incident timeline (v0.7c item 5, ADR-0022): one incident rebuilt from recorded data only.

Every line belongs to exactly one labelled section, so a reader can tell what was recorded from what
was inferred or suspected, and what is still missing:

  confirmed (timed)        events, first and last sighting of the credential, links a person
                           confirmed, and every lifecycle action with its actor (audit trail)
  stated by the rule       the facts the rule printed from the matched events
  inferred                 relationships Sentinel derived (hypotheses of access, not observed use)
  suspected                the hypotheses recorded on the incident: not proven
  alternative explanations fixed text per rule, written from the rule specs
  missing evidence         unknowns, required steps not yet verified, failed verification

No AI model is involved and nothing is changed. Audit `evidence` and `detail` text and finding notes
are never printed: only ids, fingerprints, actions, actors and statuses.
"""

from typing import Any

from sentinel.events.schema import format_time
from sentinel.inventory.credentials import parse_when
from sentinel.redaction import has_secret_pattern, looks_like_secret
from sentinel.store.db import Store

WITHHELD = "[withheld: looks like a credential]"

# Written from docs/spec/correlation-rules.md. Generic per rule: they may not fit a given incident.
ALTERNATIVES: dict[str, tuple[str, ...]] = {
    "R1": (
        "The key's owner or an authorised service used it: usage shows volume, not intent.",
        "Late or misattributed provider data (usage can arrive about 30 minutes late).",
        "The key was exposed, but the usage is unrelated to the exposure.",
    ),
    "R2": (
        "A legitimate new contributor made a normal workflow change.",
        "The added network call or secret reference is intentional.",
    ),
    "R4": (
        "Legitimate load (a launch, a batch job, a new feature) raised the volume.",
        "The usage baseline for a new key is still warming up.",
    ),
    "R6": (
        "The user changed device or location.",
        "The user created the new key or token themselves.",
    ),
    "R7": (
        "An automated process (a scanner, a backup job, an indexer) touched the decoy.",
        "The owner opened or copied the decoy while testing.",
    ),
    "R8": (
        "The release was built by an earlier pipeline run, not by the modified workflow.",
        "Both changes are routine, planned work.",
    ),
    "R9": (
        "Another process, such as a backup job or scanner, touched the decoy in the same period.",
        "A script started during the agent session touched it outside the gateway.",
    ),
    "R10": (
        "The path is served on purpose and only resembles a sensitive file.",
        "The probe matched a placeholder or an empty file.",
    ),
    "R11": (
        "Late-arriving provider data from before the revocation.",
        "The revocation was verified for a different key than the one that was used.",
    ),
    "R5b": (
        "Harmless commands blocked by keyword matching (the guard matches words such as 'ssh' or "
        "'curl' inside ordinary text).",
        "A person repeatedly asked for something the guard blocks.",
    ),
    "R5c": (
        "A legitimate server that nobody has approved yet.",
        "A user-scope server or claude.ai connector that the inventory cannot see.",
    ),
    "R12": (
        "A person ran legitimate commands that the keyword guard matched (keyword false positive).",
        "The two attempts were unrelated tasks that happened close together.",
    ),
}
SECTIONS = (
    "confirmed",
    "stated by the rule",
    "inferred",
    "suspected",
    "alternative explanations",
    "missing evidence",
)


def _s(value: Any, limit: int = 200) -> str:
    """Printable text only (control and escape characters replaced), length capped. Text in a known
    credential format is withheld: rule facts quote event attributes (a workflow file name, an MCP
    server name) that an attacker can choose."""
    text = "".join(c if c.isprintable() and c != "\x1b" else "?" for c in str(value))[:limit]
    return WITHHELD if has_secret_pattern(text) else text


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _item(text: str, time: Any = None, ref: Any = None) -> dict[str, Any]:
    out: dict[str, Any] = {"text": _s(text)}
    parsed = parse_when(time) if isinstance(time, str) else None
    if parsed is not None:  # one UTC format, so the sort below is a real time order
        out["time"] = format_time(parsed)
    if ref:
        out["ref"] = _s(ref, 80)
    return out


def _action_text(entry: dict[str, Any]) -> str:
    action, actor = _s(entry.get("action", "?"), 40), _s(entry.get("actor", "someone"), 60)
    step = _s(entry.get("step", "?"), 60)
    if action == "incident_opened":
        rule, severity = _s(entry.get("rule", "?"), 10), _s(entry.get("severity", "?"), 10)
        return f"Sentinel opened this incident (rule {rule}, severity {severity})"
    if action == "approve":
        return f"{actor} approved step {step}"
    if action == "execute":
        return f"{actor} executed step {step}"
    if action == "verify":
        result = "passed" if entry.get("passed") else "failed"
        return f"{actor} recorded verification of step {step}: {result}"
    if action == "close":
        return f"{actor} closed the incident (verified: {bool(entry.get('verified'))})"
    return f"recorded action: {action}"


def _confirmed(store: Store, incident: dict[str, Any], iid: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in _list(incident.get("timeline")):
        if not isinstance(row, dict):
            continue
        simulated = " (simulated)" if row.get("is_test") == "True" else ""
        kind, source = _s(row.get("event_type", "?"), 40), _s(row.get("source", "?"), 40)
        text = f"{kind} from {source} on {_s(row.get('asset_id', '?'), 80)}{simulated}"
        items.append(_item(text, row.get("time"), row.get("event_id")))
    cred = incident.get("cred_ref")
    finding = store.get_doc("findings", cred) if isinstance(cred, str) else None
    if isinstance(finding, dict):
        count = len(_list(finding.get("locations")))
        items.append(
            _item(
                f"credential {_s(cred, 60)} first seen by the scanner ({count} location(s))",
                finding.get("first_seen"),
            )
        )
        if finding.get("last_seen") and finding.get("last_seen") != finding.get("first_seen"):
            items.append(
                _item(
                    f"credential {_s(cred, 60)} last seen "
                    f"(status: {_s(finding.get('status'), 30)})",
                    finding.get("last_seen"),
                )
            )
    for link in store.docs("links"):
        if isinstance(link, dict) and isinstance(cred, str) and link.get("cred_ref") == cred:
            who = _s(link.get("confirmed_by", "a person"), 60)
            items.append(
                _item(
                    f"{who} linked the credential to {_s(link.get('asset_id'), 80)} "
                    f"({_s(link.get('permission'), 30)})",
                    link.get("time"),
                )
            )
    for time, entry in store.audit_rows():
        if isinstance(entry, dict) and entry.get("incident") == iid:
            items.append(_item(_action_text(entry), time))
    # Timed items first in time order; untimed items keep their order after them.
    return sorted(items, key=lambda i: (0, i["time"]) if "time" in i else (1, ""))


def _inferred(incident: dict[str, Any]) -> list[dict[str, Any]]:
    items = [
        _item(
            f"Rule {_s(incident.get('rule_id', '?'), 10)} joined the events above; "
            "the join itself is the rule's inference"
        )
    ]
    blast = incident.get("blast_radius")
    for p in _list(blast.get("possible_access") if isinstance(blast, dict) else None):
        if isinstance(p, dict):
            items.append(
                _item(
                    f"may be able to reach {_s(p.get('asset_id'), 80)} via {_s(p.get('via'), 80)} "
                    f"({_s(p.get('permission'), 30)}, {_s(p.get('origin'), 20)}): "
                    "hypothesis of access, not observed use"
                )
            )
    return items


def _missing(incident: dict[str, Any]) -> list[dict[str, Any]]:
    items = [_item(str(u)) for u in _list(incident.get("unknowns"))]
    for step in _list(incident.get("response_plan")):
        if not isinstance(step, dict):
            continue
        name = _s(step.get("step", "?"), 60)
        if step.get("state") == "verification_failed":
            items.append(_item(f"verification of step {name} failed"))
        elif step.get("required_for_close") and step.get("state") != "verified":
            items.append(
                _item(
                    f"required step {name} is not yet verified (state: {_s(step.get('state'), 30)})"
                )
            )
    if incident.get("status") == "closed" and not incident.get("verified"):
        items.append(_item("the incident was closed without verification"))
    return items


def build(store: Store, iid: str) -> dict[str, Any]:
    """The labelled timeline of one incident. Raises KeyError for an unknown id. Read-only."""
    incident = store.get_doc("incidents", iid)
    if not isinstance(incident, dict):
        # A pasted key must never be echoed back as an "unknown incident".
        shown = "that id" if looks_like_secret(iid) else iid
        raise KeyError(f"unknown incident: {shown}")
    rule = str(incident.get("rule_id", ""))
    content = {
        "confirmed": _confirmed(store, incident, iid),
        "stated by the rule": [_item(str(f)) for f in _list(incident.get("facts"))],
        "inferred": _inferred(incident),
        "suspected": [
            _item(f"{h} (suspected, not proven)") for h in _list(incident.get("hypotheses"))
        ],
        "alternative explanations": [_item(a) for a in ALTERNATIVES.get(rule, ())],
        "missing evidence": _missing(incident),
    }
    return {
        "incident": {
            "id": _s(iid, 40),
            "rule_id": _s(rule, 10),
            "severity": _s(incident.get("severity", "?"), 10),
            "status": _s(incident.get("status", "?"), 10),
            "verified": bool(incident.get("verified")),
            "is_test": bool(incident.get("is_test")),
        },
        "sections": [{"label": label, "items": content[label]} for label in SECTIONS],
    }


def format_timeline(data: dict[str, Any]) -> str:
    inc = data["incident"]
    lines = [
        f"Timeline of {inc['id']} (rule {inc['rule_id']}, {inc['severity']}, {inc['status']}, "
        f"verified: {inc['verified']})" + (" [simulated]" if inc["is_test"] else ""),
        "Built only from recorded data. Nothing below is an AI summary.",
    ]
    for section in data["sections"]:
        lines += ["", section["label"].upper()]
        if not section["items"]:
            lines.append("  (none recorded)")
        for i in section["items"]:
            lines.append(f"  {i.get('time', '-'):<21} {i['text']}")
    return "\n".join(lines) + "\n"
