"""Incident and baseline reports."""

from datetime import datetime
from typing import Any

from sentinel import findings
from sentinel.inventory.assets import gaps
from sentinel.store.db import Store


def _seconds(start: str, end: str) -> float:
    a = datetime.fromisoformat(start.replace("Z", "+00:00"))
    b = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return (b - a).total_seconds()


def incident_report(incident: dict[str, Any]) -> str:
    lines = [f"# Incident {incident['id']}: {incident['title']}", ""]
    if incident["is_test"]:
        lines += ["> TEST incident (simulated events): counted in metrics only.", ""]
    risk = incident["risk"]
    lines += [
        f"- Status: **{incident['status']}**, verified: **{incident['verified']}**",
        f"- Rule: {incident['rule_id']}",
        f"- Severity: **{incident['severity']}**, confidence: {incident['confidence']}, "
        f"urgency: {incident['urgency']} (risk score {risk['score']}, factors {risk['factors']})",
        f"- Credential: {incident['cred_ref'] or 'n/a'}",
        f"- Identity: {incident['identity_ref'] or 'n/a'}",
        "",
        "## Facts (supported by recorded events)",
        *[f"- {f}" for f in incident["facts"]],
        "",
        "## Hypotheses (not proven)",
        *[f"- {h}" for h in incident["hypotheses"]],
        "",
        "## Unknowns",
        *[f"- {u}" for u in incident["unknowns"]],
        "",
        "## Timeline",
        *[
            f"- {t['time']}  {t['event_type']} ({t['source']}) on {t['asset_id']}"
            for t in incident["timeline"]
        ],
        "",
    ]
    blast = incident["blast_radius"]
    if blast is not None:
        lines += [
            "## Impact (blast radius)",
            f"- Exposed in: {', '.join(blast['exposed_in']) or 'unknown'}",
        ]
        lines += [
            f"- CONFIRMED access (linked by {a['confirmed_by']}): {a['asset_id']} "
            f"[{a['permission']}, importance {a['importance']}]"
            for a in blast["confirmed_access"]
        ]
        lines += [
            f"- POSSIBLE access (hypothesis, via {a['via']}): {a['asset_id']} "
            f"[{a['permission']}, {a['origin']}]"
            for a in blast["possible_access"]
        ]
        if blast["unlinked"]:
            lines.append("- Credential not linked to any asset: impact unknown.")
        lines.append("")
    lines += ["## Response plan (Sentinel recommends; humans approve and act)"]
    for s in incident["response_plan"]:
        req = "required" if s["required_for_close"] else "optional"
        lines.append(
            f"- [{s['state']}] {s['step']} ({s['response_class']}, {req}): {s['description']}"
        )
    if incident["close_note"]:
        lines += ["", f"**{incident['close_note']}**"]
    return "\n".join(lines) + "\n"


def summary_report(store: Store, now: datetime) -> str:
    from sentinel.events.schema import format_time

    docs = store.docs("findings")
    incidents = store.docs("incidents")
    inv = gaps(store)
    live = [d for d in docs if d["status"] in ("open", "revoke_pending", "revoked_unverified")]
    accepted = [d for d in docs if d["status"] == "risk_accepted"]
    expired = findings.expired_acceptances(store, now)
    real = [i for i in incidents if not i["is_test"]]
    closed_verified = [i for i in real if i["status"] == "closed" and i["verified"]]
    mttc = [_seconds(i["created"], i["closed"]) for i in closed_verified]
    mttd = [_seconds(i["first_event_time"], i["created"]) for i in real]
    if live or expired:
        gate = "NOT PASSED"
    elif accepted:
        gate = "PASSED WITH ACCEPTED RISK (owner sign-off required)"
    else:
        gate = "PASSED"
    if inv["unowned"]:
        gate = "NOT PASSED"
    lines = [
        f"# Sentinel baseline report ({format_time(now)})",
        "",
        f"**Exposure status: {gate}**",
        "",
        "## Metrics",
        f"- Credentials tracked: {len(docs)}; live (open/pending/unverified): {len(live)}; "
        f"risk accepted: {len(accepted)} (expired: {len(expired)}); revoked and verified: "
        f"{sum(d['status'] == 'revoked_verified' for d in docs)}",
        f"- Unowned assets: {len(inv['unowned'])} of {len(store.assets())}",
        f"- Incidents: {len(real)} real, {len(incidents) - len(real)} test; "
        f"open real: {sum(i['status'] == 'open' for i in real)}",
        f"- Mean time to detect (event to incident): "
        f"{(sum(mttd) / len(mttd)) if mttd else 0:.0f}s over {len(mttd)} incident(s)",
        f"- Mean time to contain (incident to verified close): "
        f"{(sum(mttc) / len(mttc)) if mttc else 0:.0f}s over {len(mttc)} incident(s)",
        "",
        "## Findings (fingerprints and locations only)",
        "| Credential | Rule | Status | Locations | First seen |",
        "|---|---|---|---|---|",
        *[
            f"| {d['cred_ref']} | {d['rule_id']} | {d['status']} | {len(d['locations'])} | "
            f"{d['first_seen']} |"
            for d in docs
        ],
        "",
        "## Inventory gaps",
        f"- Unowned: {', '.join(inv['unowned']) or 'none'}",
        f"- Unapproved: {', '.join(inv['unapproved']) or 'none'}",
        f"- Unmonitored: {', '.join(inv['unmonitored']) or 'none'}",
        "",
        "## Incidents",
        *[
            f"- {i['id']} [{i['status']}, {i['severity']}{', test' if i['is_test'] else ''}] "
            f"{i['title']}"
            for i in incidents
        ],
    ]
    last_run = store.get_doc("snapshots", "health:last_run")
    lines += ["", "## Collector health (last `sentinel run`)"]
    if last_run is None:
        lines.append("- No continuous run recorded yet.")
    else:
        lines.append(f"- Run at {last_run['time']}")
        lines += [f"- {name}: {state}" for name, state in sorted(last_run["health"].items())]
    return "\n".join(lines) + "\n"
