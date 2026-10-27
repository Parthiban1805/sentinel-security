"""GitHub protection audit (v0.4): is the default branch protected, is secret scanning on?

Read-only GETs to api.github.com with the existing token (ADR-0005). Pure evaluation here; the
network calls live in `GitHubCollector.audit_inputs`. Findings are facts about settings, labelled
with what the token could and could not see, because "cannot see" is not the same as "is off".
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel.events.schema import format_time, make_event
from sentinel.sources.github import asset_id_for_repo
from sentinel.store.db import Store

CHECKS = {
    "BP1": "default branch has no branch protection",
    "BP2": "branch protection allows force pushes",
    "BP3": "branch protection allows branch deletion",
    "BP4": "branch protection does not require pull request reviews",
    "BP5": "branch protection does not apply to administrators",
    "SS1": "secret scanning is not enabled",
    "SS2": "secret-scanning push protection is not enabled",
    "GP0": "repository settings could not be read",
    "GP9": "branch protection could not be verified",
    "SS0": "secret-scanning settings are not visible to this token",
}


@dataclass(frozen=True)
class AuditFinding:
    check: str
    severity: str
    detail: str


Probe = tuple[int, dict[str, Any] | None, str | None]  # (HTTP status, JSON body, error hint)


def evaluate(repo: Probe, protection: Probe) -> list[AuditFinding]:
    """Turn the two API answers into findings. `hint` comes from `sources.http.error_hint`."""
    status, meta, _ = repo
    if meta is None:
        return [AuditFinding("GP0", "low", f"{CHECKS['GP0']} (HTTP {status})")]
    out: list[AuditFinding] = []
    branch = meta.get("default_branch", "main")

    pstatus, pbody, hint = protection
    if pstatus == 200 and pbody is not None:
        if (pbody.get("allow_force_pushes") or {}).get("enabled"):
            out.append(AuditFinding("BP2", "high", f"{CHECKS['BP2']} on {branch}"))
        if (pbody.get("allow_deletions") or {}).get("enabled"):
            out.append(AuditFinding("BP3", "medium", f"{CHECKS['BP3']} on {branch}"))
        if not pbody.get("required_pull_request_reviews"):
            out.append(AuditFinding("BP4", "medium", f"{CHECKS['BP4']} on {branch}"))
        if not (pbody.get("enforce_admins") or {}).get("enabled"):
            out.append(AuditFinding("BP5", "low", f"{CHECKS['BP5']} on {branch}"))
    elif pstatus == 404 or hint == "not_protected":
        out.append(AuditFinding("BP1", "high", f"{CHECKS['BP1']} ({branch})"))
    elif pstatus == 403 and hint == "plan_limit":
        out.append(
            AuditFinding(
                "BP1",
                "high",
                f"{CHECKS['BP1']} ({branch}): not available for private repositories on this "
                "plan (upgrade, move the repository, or make it public)",
            )
        )
    elif pstatus == 403 and hint == "no_permission":
        out.append(
            AuditFinding(
                "GP9",
                "low",
                f"{CHECKS['GP9']}: the token lacks the Administration (read) permission",
            )
        )
    else:
        out.append(AuditFinding("GP9", "low", f"{CHECKS['GP9']} (HTTP {pstatus})"))

    analysis = meta.get("security_and_analysis")
    if not isinstance(analysis, dict):
        if hint == "plan_limit":
            # Branch protection already said "plan limit": the same limit very likely explains
            # why the scanning settings are absent. A hypothesis, not something GitHub states.
            why = (
                "most likely because secret scanning is not offered for private repositories on "
                "this plan (hypothesis: the branch-protection call reported the same plan limit)"
            )
        elif hint == "no_permission":
            why = "the token lacks the Administration (read) permission"
        else:
            why = "needs Administration read, or the feature is not on this plan"
        out.append(AuditFinding("SS0", "low", f"{CHECKS['SS0']}: {why}"))
    else:
        if (analysis.get("secret_scanning") or {}).get("status") != "enabled":
            out.append(AuditFinding("SS1", "medium", CHECKS["SS1"]))
        if (analysis.get("secret_scanning_push_protection") or {}).get("status") != "enabled":
            out.append(AuditFinding("SS2", "medium", CHECKS["SS2"]))
    return out


def snapshot_key(repo: str) -> str:
    return f"audit:{repo}"


def due(store: Store, repo: str, now: datetime, interval_hours: int) -> bool:
    previous = store.get_doc("snapshots", snapshot_key(repo))
    if previous is None or interval_hours <= 0:
        return True
    if "GP0" in previous.get("checks", []):
        return True  # the last audit could not even read the repository: try again next run
    last = datetime.fromisoformat(previous["time"].replace("Z", "+00:00"))
    return (now - last).total_seconds() >= interval_hours * 3600


def to_events(repo: str, findings: list[AuditFinding], now: datetime) -> list[dict[str, Any]]:
    """`config_drift` events with deterministic ids (re-runs do not duplicate)."""
    asset = asset_id_for_repo(repo)
    return [
        make_event(
            event_type="config_drift",
            source="github_audit",
            asset_id=asset,
            time=now,
            severity=f.severity,
            confidence="high" if f.check not in ("GP0", "GP9", "SS0") else "low",
            evidence_ref=f"github/{repo}/audit/{f.check}",
            event_id=f"audit:{repo}:{f.check}",
            attributes={"check": f.check, "path": "", "detail": f.detail, "repo": repo},
        )
        for f in findings
    ]


def new_snapshot(findings: list[AuditFinding], now: datetime) -> dict[str, Any]:
    return {"checks": sorted(f.check for f in findings), "time": format_time(now)}


def format_findings(results: dict[str, list[AuditFinding]]) -> str:
    lines: list[str] = []
    for repo, findings in results.items():
        lines.append(f"== {repo}: {len(findings)} finding(s)")
        for f in findings:
            lines.append(f"  [{f.severity.upper():<6}] {f.check}: {f.detail}")
    return "\n".join(lines) + "\n"
