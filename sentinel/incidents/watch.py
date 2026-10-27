"""Verification watch: which incidents are not truly finished, stated from recorded facts only."""

from datetime import datetime
from typing import Any

from sentinel.store.db import Store


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _unverified_steps(incident: dict[str, Any]) -> list[str]:
    return [
        s["step"]
        for s in incident["response_plan"]
        if s["required_for_close"] and s["state"] != "verified"
    ]


def report(store: Store, now: datetime, stale_hours: int = 24) -> dict[str, list[dict[str, Any]]]:
    """Open incidents (oldest first, flagged stale after `stale_hours`), steps whose verification
    FAILED, and incidents closed without verification. Test incidents are excluded."""
    open_rows: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    closed_unverified: list[dict[str, Any]] = []
    for incident in sorted(store.docs("incidents"), key=lambda i: i["created"]):
        if incident["is_test"]:
            continue
        row = {"id": incident["id"], "rule": incident["rule_id"], "severity": incident["severity"]}
        if incident["status"] == "closed":
            if not incident["verified"]:
                closed_unverified.append({**row, "note": incident["close_note"]})
            continue
        age = (now - _parse(incident["created"])).total_seconds() / 3600
        open_rows.append(
            {
                **row,
                "age_hours": int(age),
                "stale": age >= stale_hours,
                "unverified_steps": _unverified_steps(incident),
            }
        )
        failed += [
            {**row, "step": s["step"]}
            for s in incident["response_plan"]
            if s["state"] == "verification_failed"
        ]
    return {
        "open": open_rows,
        "verification_failed": failed,
        "closed_unverified": closed_unverified,
    }


def format_report(data: dict[str, list[dict[str, Any]]]) -> str:
    lines = ["Verification watch (real incidents only)", ""]
    lines.append(f"Open incidents: {len(data['open'])}")
    for r in data["open"]:
        stale = " STALE" if r["stale"] else ""
        lines.append(
            f"  {r['id']} {r['rule']} {r['severity']} age {r['age_hours']}h{stale}: "
            f"unverified {', '.join(r['unverified_steps']) or 'none'}"
        )
    lines.append(f"Verification failed: {len(data['verification_failed'])}")
    lines += [f"  {r['id']} {r['rule']}: {r['step']}" for r in data["verification_failed"]]
    lines.append(f"Closed WITHOUT verification: {len(data['closed_unverified'])}")
    lines += [f"  {r['id']} {r['rule']}: {r['note']}" for r in data["closed_unverified"]]
    return "\n".join(lines) + "\n"
