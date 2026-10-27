"""Local incident summary (v0.6, ADR-0010): plain template, no AI model, no network.

Only fields in ALLOWED are copied out of an incident; everything else (close notes, evidence text,
actor names, approver names) is dropped before rendering. The output is scanned once more for
credential-shaped text, and the function refuses to return anything that looks like a secret.
"""

from typing import Any

from sentinel.redaction import looks_like_secret

ALLOWED = (
    "id",
    "rule_id",
    "title",
    "status",
    "severity",
    "confidence",
    "urgency",
    "created",
    "first_event_time",
    "is_test",
    "cred_ref",
    "identity_ref",
    "asset_id",
    "facts",
    "hypotheses",
    "unknowns",
    "timeline",
    "response_plan",
)


def view(incident: dict[str, Any]) -> dict[str, Any]:
    """Copy only the allow-listed fields; plan events keep just time and verified flag."""
    out = {k: incident.get(k) for k in ALLOWED}
    out["timeline"] = [
        {k: t[k] for k in ("time", "event_id", "event_type", "source", "asset_id")}
        for t in incident.get("timeline", [])
    ]
    out["response_plan"] = [
        {
            "step": s["step"],
            "response_class": s["response_class"],
            "required_for_close": s["required_for_close"],
            "state": s["state"],
            "verifications": [
                {"time": e["time"], "verified": e["verified"]}
                for e in s.get("events", [])
                if "verified" in e
            ],
        }
        for s in incident.get("response_plan", [])
    ]
    return out


def render(incident: dict[str, Any]) -> str:
    v = view(incident)
    lines = [
        f"# Summary of {v['id']}: {v['title']}",
        "",
        "Built from recorded fields only (local template, no AI model, no network).",
        "",
        f"- Rule: {v['rule_id']}   Severity: {v['severity']}   Confidence: {v['confidence']}",
        f"- Status: {v['status']}   Created: {v['created']}   Test incident: {v['is_test']}",
        "",
        "## Known facts",
        *[f"- {f}" for f in v["facts"]],
        "",
        "## Hypotheses (not proven)",
        *[f"- {h}" for h in v["hypotheses"]],
        "",
        "## Unknowns",
        *[f"- {u}" for u in v["unknowns"]],
        "",
        f"## Timeline ({len(v['timeline'])} event(s))",
        *[f"- {t['time']} {t['event_type']} ({t['source']})" for t in v["timeline"]],
        "",
        "## Response steps",
    ]
    for s in v["response_plan"]:
        checks = ", ".join(f"verified={x['verified']} at {x['time']}" for x in s["verifications"])
        req = "required" if s["required_for_close"] else "optional"
        lines.append(
            f"- {s['step']}: {s['state']} ({req}, {s['response_class']}) {checks}".rstrip()
        )
    pending = [
        s["step"]
        for s in v["response_plan"]
        if s["required_for_close"] and not any(x["verified"] for x in s["verifications"])
    ]
    lines += [
        "",
        "## Needs a human decision",
        f"- Required steps without passing verification: {', '.join(pending) or 'none'}",
        "",
    ]
    text = "\n".join(lines)
    if looks_like_secret(text):
        raise ValueError("summary looks like it contains a credential; refusing to output it")
    return text
