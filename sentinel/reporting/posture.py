"""Security posture report (v0.7c item 4, ADR-0021): three separate indicators, each with evidence.

There is deliberately NO overall score. Each indicator has a status chosen by a fixed rule:
`attention` if any measured area has a high-severity finding, `review` if it has any lower-severity
finding, `good` if everything measured is clean, `unknown` if nothing could be measured. An area
that could not be measured is listed under `not_measured`; it is never counted as good.

Live data only: stored `config_drift` events outlive the problems they describe, so they are not
counted. Inputs that need I/O (a hygiene scan, the `doctor` checks) are passed in by the caller,
which keeps this module a read-only function of the store. References are ids, fingerprints and
check names, never names, file contents or values. Every indicator is built in its own guard: a
malformed stored document makes THAT indicator `unknown`, never a traceback for the whole report.
"""

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sentinel import audit, drills
from sentinel.config import CredentialPolicy
from sentinel.correlation.engine import context_from_store
from sentinel.correlation.session_risk import safe_text as _plain_text
from sentinel.correlation.session_risk import session_risk
from sentinel.doctor import Check
from sentinel.hygiene import Finding as HygieneFinding
from sentinel.incidents import watch
from sentinel.inventory import credentials
from sentinel.runner import HOOK_PIN_KEY
from sentinel.store.db import Store

MAX_REFS = 10
_REF_UNSAFE = re.compile(r"[^A-Za-z0-9_.:/ \-]")
STALE_RUN_HOURS = 6  # [confirm] the scheduler runs every 15 minutes
STALE_INCIDENT_HOURS = 24
AUDIT_MAX_AGE_HOURS = 72  # three daily audits; an older snapshot is not "current"
CLOCK_SKEW = timedelta(minutes=5)
DERIVED_ASSETS = frozenset({"ci_workflow", "scan_location"})  # created by Sentinel, never "unowned"
AUDIT_SEVERITY = {
    "BP1": "high",
    "BP2": "high",
    "BP3": "medium",
    "BP4": "medium",
    "BP5": "low",
    "SS1": "medium",
    "SS2": "low",
}
AUDIT_CANNOT_VERIFY = frozenset({"GP0", "GP9", "SS0"})  # "could not see", not "is off"
CREDENTIAL_SEVERITY = {"C1": "high", "C2": "medium", "C3": "medium", "C4": "low", "C5": "low"}
RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
NOTE = (
    "No overall score: each indicator stands alone and lists its evidence. `good` means measured "
    "and clean for the areas that were measured, not secure. This report maps weaknesses: keep it "
    "private."
)


def safe_text(value: Any, limit: int = 80) -> str:
    """A reference (asset id, fingerprint, check id, collector name): capped, safe characters only.
    Colons and slashes are allowed because refs look like `repo-a:H1` and `owner/name:BP1`."""
    return _REF_UNSAFE.sub("?", str(value))[:limit]


def _when(value: Any) -> datetime | None:
    """A UTC time from stored text, or None (missing, unreadable, or out of range)."""
    return credentials.parse_when(value) if isinstance(value, str) else None


@dataclass
class _Indicator:
    name: str
    question: str
    total_areas: int
    evidence: list[dict[str, Any]] = field(default_factory=list)
    not_measured: list[dict[str, str]] = field(default_factory=list)
    measured_areas: set[str] = field(default_factory=set)
    degraded: bool = False  # inputs are stale or broken: never report `good`

    def measured(self, area: str) -> None:
        self.measured_areas.add(area)

    def skip(self, area: str, why: str) -> None:
        self.not_measured.append({"area": area, "why": why})

    def degrade(self, why: str) -> None:
        self.degraded = True
        self.skip("freshness", why)

    def add(
        self, area_id: str, severity: str, refs: Iterable[str], detail: str | None = None
    ) -> None:
        unique = sorted({safe_text(r) for r in refs})
        self.evidence.append(
            {
                "id": area_id,
                "severity": severity,
                "count": len(unique),
                "refs": unique[:MAX_REFS],
                "more": max(len(unique) - MAX_REFS, 0),
                "detail": detail or f"{len(unique)} {area_id}",
            }
        )

    def add_count(self, area_id: str, severity: str, count: int, detail: str | None = None) -> None:
        self.evidence.append(
            {
                "id": area_id,
                "severity": severity,
                "count": count,
                "refs": [],
                "more": 0,
                "detail": detail or f"{count} {area_id}",
            }
        )

    def status(self) -> str:
        if not self.measured_areas:
            return "unknown"
        worst = max(
            (RANK[e["severity"]] for e in self.evidence if e["count"] and e["severity"] != "info"),
            default=0,
        )
        if worst >= 3:
            return "attention"
        if worst:
            return "review"
        return "unknown" if self.degraded else "good"

    def reasons(self) -> list[str]:
        flagged = [e for e in self.evidence if e["count"] and e["severity"] != "info"]
        flagged.sort(key=lambda e: (-RANK[e["severity"]], e["id"]))
        out = [e["detail"] for e in flagged]
        if self.degraded and self.status() == "unknown":
            out += [n["why"] for n in self.not_measured if n["area"] == "freshness"]
        return out

    def render(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "question": self.question,
            "status": self.status(),
            "reasons": self.reasons(),
            "measured": len(self.measured_areas),
            "total_areas": self.total_areas,
            "evidence": self.evidence,
            "not_measured": self.not_measured,
        }


def _by_severity(ind: _Indicator, prefix: str, items: dict[str, set[str]]) -> None:
    """One evidence entry per severity (zero counts included, to show what was checked)."""
    for severity in ("high", "medium", "low"):
        ind.add(f"{prefix} ({severity})", severity, items.get(severity, set()))


# security posture ------------------------------------------------------------------
def _audit_snapshot(
    store: Store, repo: str, now: datetime, max_age: timedelta
) -> tuple[list[str] | None, str]:
    """(checks, why) for one repository: checks is None when the audit cannot be trusted."""
    name = safe_text(repo)
    snap = store.get_doc("snapshots", audit.snapshot_key(repo))
    if snap is None:
        return None, f"{name}: not audited yet (run `sentinel audit`)"
    checks = snap.get("checks") if isinstance(snap, dict) else None
    taken = _when(snap.get("time")) if isinstance(snap, dict) else None
    if not isinstance(checks, list) or not all(isinstance(c, str) for c in checks):
        return None, f"{name}: the stored audit result is unreadable"
    if taken is None:
        return None, f"{name}: the audit time is unreadable"
    if now - taken > max_age:
        return None, f"{name}: the audit is {int((now - taken).total_seconds() // 3600)} hours old"
    if "GP0" in checks:
        return None, f"{name}: the repository settings could not be read (GP0)"
    return checks, ""


def _security(
    store: Store,
    now: datetime,
    policy: CredentialPolicy,
    hygiene: dict[str, Sequence[HygieneFinding]] | None,
    hygiene_skipped: Sequence[str],
    repos: Sequence[str],
    audit_max_age: timedelta,
) -> dict[str, Any]:
    ind = _Indicator("security posture", "Is the configuration sound?", total_areas=5)
    assets = [a for a in store.assets() if a["asset_type"] not in DERIVED_ASSETS]
    if assets:
        ind.measured("assets")
        ind.add("unowned assets", "low", (a["asset_id"] for a in assets if not a.get("owner")))
        ind.add(
            "unapproved assets", "low", (a["asset_id"] for a in assets if not a.get("approved"))
        )
        ind.add(
            "unmonitored assets",
            "low",
            (a["asset_id"] for a in assets if a.get("monitoring") == "none"),
        )
    else:
        ind.skip("assets", "no assets in the inventory")

    for skipped in hygiene_skipped:
        ind.skip("hygiene", f"{safe_text(skipped)}: not scanned (not a readable Git repository)")
    if not hygiene:  # None (not run) or {} (nothing could be scanned)
        ind.skip(
            "hygiene", "no repository was scanned (no scan paths, --no-hygiene, or all failed)"
        )
    else:
        ind.measured("hygiene")
        grouped: dict[str, set[str]] = {}
        total: set[str] = set()
        for asset_id, found in hygiene.items():
            for f in found:
                ref = f"{asset_id}:{f.check}"
                total.add(ref)
                grouped.setdefault(f.severity if f.severity in RANK else "low", set()).add(ref)
        ind.add(
            "hygiene", "info", total, f"{len(total)} hygiene finding(s) in {len(hygiene)} repo(s)"
        )
        _by_severity(ind, "hygiene findings", grouped)

    audited: dict[str, set[str]] = {}
    for repo in repos:
        checks, why = _audit_snapshot(store, repo, now, audit_max_age)
        if checks is None:
            ind.skip("github audit", why)
            continue
        ind.measured("github audit")
        for check in checks:
            if check in AUDIT_CANNOT_VERIFY:
                ind.skip(
                    "github audit", f"{safe_text(repo)}: cannot verify ({safe_text(check, 8)})"
                )
            elif check in AUDIT_SEVERITY:
                audited.setdefault(AUDIT_SEVERITY[check], set()).add(f"{safe_text(repo)}:{check}")
    if "github audit" in ind.measured_areas:
        _by_severity(ind, "github audit findings", audited)
    elif not repos:
        ind.skip("github audit", "no GitHub repositories are configured")

    views = credentials.review(store, now, policy)
    fresh = [v for v in views if not v.deleted and not any("stale" in u for u in v.unknown)]
    if fresh:
        ind.measured("credentials")
    else:
        ind.skip("credentials", "no current credential asset or SSH key list is known")
    if views:
        problems: dict[str, set[str]] = {}
        for v in views:
            for p in v.problems:
                if p.check in CREDENTIAL_SEVERITY:
                    problems.setdefault(CREDENTIAL_SEVERITY[p.check], set()).add(v.ref)
        _by_severity(ind, "credential problems", problems)
        ind.add(
            "credentials with unknown facts",
            "info",
            (v.ref for v in views if v.unknown and not v.deleted),
        )

    agent_assets = [a for a in store.assets() if a["asset_type"] in ("ai_agent", "mcp_server")]
    pinned = store.get_doc("snapshots", HOOK_PIN_KEY) is not None
    if agent_assets or pinned:
        ind.measured("agent configuration")
        ind.add_count(
            "agent hooks pin recorded",
            "medium",
            0 if pinned else 1,
            "no human-made pin of the agent hooks is recorded"
            if not pinned
            else "a pin of the agent hooks is recorded",
        )
        ind.skip(
            "agent hooks drift",
            "the current hooks are not compared with the pin here (`incident verify-agent-hooks`)",
        )
        ind.add(
            "unapproved MCP servers",
            "low",
            (
                a["asset_id"]
                for a in agent_assets
                if a["asset_type"] == "mcp_server" and not a.get("approved")
            ),
        )
    else:
        ind.skip(
            "agent configuration", "no AI agent or MCP server is registered (`inventory agents`)"
        )
    return ind.render()


# threat exposure -------------------------------------------------------------------
def _run_state(
    store: Store, now: datetime, stale_run_hours: int
) -> tuple[dict[str, Any] | None, bool]:
    """(last run snapshot or None, stale-or-unreadable). Never raises on a malformed snapshot."""
    run = store.get_doc("snapshots", "health:last_run")
    if not isinstance(run, dict):
        return None, False
    when = _when(run.get("time"))
    stale = when is None or when > now + CLOCK_SKEW or now - when > timedelta(hours=stale_run_hours)
    return run, stale


def _health_kinds(run: dict[str, Any] | None) -> dict[str, set[str]]:
    """Collector names by state. Only the kind before ':' is read; the text is never copied."""
    states: dict[str, set[str]] = {"error": set(), "warn": set(), "skipped": set(), "ok": set()}
    health = run.get("health") if run else None
    if not isinstance(health, dict):
        return states
    for name, text in sorted(health.items(), key=lambda kv: str(kv[0])):
        kind = str(text).split(":", 1)[0].strip()
        states[kind if kind in states else "warn"].add(str(name))  # unknown kind = a warning
    return states


def _threat(
    store: Store, now: datetime, policy: CredentialPolicy, stale_run_hours: int
) -> dict[str, Any]:
    ind = _Indicator("threat exposure", "What risk exists now?", total_areas=3)
    docs = [d for d in store.docs("findings") if isinstance(d, dict)]
    report = watch.report(store, now, stale_hours=STALE_INCIDENT_HOURS)
    run, stale = _run_state(store, now, stale_run_hours)
    if run or report["open"] or report["closed_unverified"]:
        ind.measured("incidents")
        ind.add(
            "open incidents (high or critical)",
            "high",
            (r["id"] for r in report["open"] if r["severity"] in ("high", "critical")),
        )
        ind.add(
            "open incidents (medium or low)",
            "medium",
            (r["id"] for r in report["open"] if r["severity"] not in ("high", "critical")),
        )
        ind.add("stale open incidents", "medium", (r["id"] for r in report["open"] if r["stale"]))
        ind.add("verification failed", "high", (r["id"] for r in report["verification_failed"]))
        ind.add(
            "closed without verification", "medium", (r["id"] for r in report["closed_unverified"])
        )
    else:
        ind.skip("incidents", "no run is recorded and no incident exists: exposure is not known")
    if run or docs:
        ind.measured("leaked credentials")
        live = ("open", "revoke_pending", "revoked_unverified")
        ind.add(
            "live leaked credentials",
            "high",
            (d["cred_ref"] for d in docs if d.get("status") in live),
        )
        expired: set[str] = set()
        active: set[str] = set()
        for d in docs:
            if d.get("status") != "risk_accepted":
                continue
            until = _when(d.get("accepted_until"))
            # No readable expiry is not a valid acceptance: counted as expired, never as active.
            (expired if until is None or until <= now else active).add(d["cred_ref"])
        ind.add("expired risk acceptances", "medium", expired)
        ind.add("risk-accepted credentials (active)", "info", active)
        views = credentials.review(store, now, policy)
        ind.add(
            "credentials aliased to a live leak", "high", (v.ref for v in views if v.exposed_as)
        )
        ind.add(
            "leaked credential in several assets",
            "medium",
            (d.ref for d in credentials.duplicates(store)),
        )
    else:
        ind.skip("leaked credentials", "no run is recorded: exposure is not known")

    if run is not None and stale:
        ind.degrade(
            "the last run is old or its time is unreadable: this exposure data may be out of date"
        )
    kinds = _health_kinds(run)
    if (
        run is not None
        and kinds["error"]
        and not (kinds["ok"] or kinds["warn"] or kinds["skipped"])
    ):
        ind.degrade("every collector failed in the last run: no fresh data was collected")

    ctx = context_from_store(store)
    sessions: dict[str, list[dict[str, Any]]] = {}
    for e in store.events():
        if e["source"] == "agent_hook" and not e["is_test"]:
            attrs = e.get("attributes")
            session = attrs.get("session", "") if isinstance(attrs, dict) else ""
            key = _plain_text(session, 64) or f"unknown-{e['asset_id']}"
            sessions.setdefault(key, []).append(e)
    if sessions:
        ind.measured("agent sessions")
        high = [s for s, ev in sessions.items() if session_risk(ev, ctx)["level"] == "high"]
        ind.add("agent sessions scored high (advisory)", "info", high)
    else:
        ind.skip("agent sessions", "no agent decisions are logged")
    return ind.render()


# operational health ----------------------------------------------------------------
def _health(
    store: Store, now: datetime, checks: Sequence[Check] | None, stale_run_hours: int
) -> dict[str, Any]:
    ind = _Indicator("operational health", "Is Sentinel itself working?", total_areas=4)
    ind.measured("last run")
    run, _ = _run_state(store, now, stale_run_hours)
    when = _when(run.get("time")) if run else None
    if run is None:
        ind.add_count("last run", "high", 1, "no run recorded (`sentinel run`)")
    elif when is None:
        ind.add_count("last run", "high", 1, "the time of the last run is unreadable")
    elif when > now + CLOCK_SKEW:
        ind.add_count("last run", "high", 1, "the time of the last run is in the future")
    else:
        hours = int((now - when).total_seconds() // 3600)
        late = now - when > timedelta(hours=stale_run_hours)
        ind.add_count("last run", "high", 1 if late else 0, f"last run {hours} hours ago")
    if run is not None:
        ind.measured("collector health")
        kinds = _health_kinds(run)
        ind.add("collector errors", "high", kinds["error"])
        ind.add("collector warnings", "medium", kinds["warn"])
        ind.add("collectors skipped", "low", kinds["skipped"])
    else:
        ind.skip("collector health", "no run is recorded")
    latest = drills.last(store)
    when = drills.drill_time(latest)
    scenario = safe_text(latest.get("scenario"), 20) if latest else ""
    if latest is None:
        ind.skip("detection drill", "no detection drill is recorded (`sentinel drill run`)")
    elif when is None or when > now + CLOCK_SKEW:
        ind.skip(
            "detection drill", "the time of the last detection drill is unreadable or in the future"
        )
    else:
        ind.measured("detection drill")
        ind.add_count(
            "detection drill failed",
            "high",
            0 if latest.get("passed") is True else 1,  # only a real True counts as a pass
            f"the last detection drill ({scenario}) failed",
        )
        age = now - when
        ind.add_count(
            "detection drill is old",
            "medium",
            1 if age > drills.STALE_AFTER else 0,
            f"the last detection drill ({scenario}) is {age.days} days old",
        )
        if scenario != "leaked-key":
            ind.skip(
                "detection drill",
                f"the last drill was {scenario}: the secret-leak path was not drilled",
            )
    if checks is None:
        ind.skip("doctor", "the doctor checks were not run")
    else:
        ind.measured("doctor")
        ind.add("doctor failures", "high", (c.name for c in checks if c.status == "fail"))
        ind.add("doctor warnings", "medium", (c.name for c in checks if c.status == "warn"))
    return ind.render()


# entry point -----------------------------------------------------------------------
def _guarded(
    name: str, question: str, total: int, build_one: Callable[[], dict[str, Any]]
) -> dict[str, Any]:
    """One malformed stored document must not take the whole report down: that indicator becomes
    `unknown` and names the exception TYPE only (never its text, which may echo stored content)."""
    try:
        return build_one()
    except Exception as exc:  # noqa: BLE001
        ind = _Indicator(name, question, total)
        ind.skip(
            "report", f"could not be built ({type(exc).__name__}); stored data may be malformed"
        )
        return ind.render()


def _executive(indicators: list[dict[str, Any]]) -> list[str]:
    lines = []
    for ind in indicators:
        top = (
            "; ".join(ind["reasons"][:3])
            or f"{ind['measured']} of {ind['total_areas']} areas measured"
        )
        partial = ""
        if ind["status"] != "unknown" and ind["measured"] < ind["total_areas"]:
            partial = f" (partial: {ind['measured']} of {ind['total_areas']} areas measured)"
        lines.append(f"{ind['name'].capitalize()}: {ind['status']}{partial}. {top}")
    return lines


def build(
    store: Store,
    now: datetime,
    *,
    policy: CredentialPolicy,
    hygiene: dict[str, Sequence[HygieneFinding]] | None = None,
    hygiene_skipped: Sequence[str] = (),
    repos: Sequence[str] = (),
    checks: Sequence[Check] | None = None,
    stale_run_hours: int = STALE_RUN_HOURS,
    audit_max_age_hours: int = AUDIT_MAX_AGE_HOURS,
) -> dict[str, Any]:
    """The posture report. Pure over the store and the passed-in hygiene results and checks."""
    audit_age = timedelta(hours=audit_max_age_hours)
    indicators = [
        _guarded(
            "security posture",
            "Is the configuration sound?",
            5,
            lambda: _security(store, now, policy, hygiene, hygiene_skipped, repos, audit_age),
        ),
        _guarded(
            "threat exposure",
            "What risk exists now?",
            3,
            lambda: _threat(store, now, policy, stale_run_hours),
        ),
        _guarded(
            "operational health",
            "Is Sentinel itself working?",
            4,
            lambda: _health(store, now, checks, stale_run_hours),
        ),
    ]
    return {
        "time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": NOTE,
        "indicators": indicators,
        "executive": _executive(indicators),
    }


def exit_code(report: dict[str, Any]) -> int:
    """For `--check`: 2 = an indicator needs attention, 3 = nothing at all could be measured,
    0 otherwise. (1 stays the generic error code of the CLI.)"""
    statuses = [i["status"] for i in report["indicators"]]
    if "attention" in statuses:
        return 2
    return 3 if all(s == "unknown" for s in statuses) else 0


def format_report(report: dict[str, Any]) -> str:
    lines = [f"Security posture report {report['time']}", report["note"], ""]
    for ind in report["indicators"]:
        lines.append(
            f"{ind['name'].capitalize()}: {ind['status'].upper()}  "
            f"({ind['measured']} of {ind['total_areas']} areas measured)"
        )
        lines.append(f"  {ind['question']}")
        for e in ind["evidence"]:
            mark = "!" if e["count"] and e["severity"] != "info" else " "
            level = f" [{e['severity']}]" if e["count"] or e["severity"] == "info" else ""
            refs = ", ".join(e["refs"]) + (f" (+{e['more']} more)" if e["more"] else "")
            lines.append(f"  {mark} {e['id']}: {e['count']}{level}" + (f"  {refs}" if refs else ""))
        for n in ind["not_measured"]:
            lines.append(f"    not measured: {n['area']}: {n['why']}")
        lines.append("")
    lines.append("For founders and CTOs:")
    lines += [f"  {line}" for line in report["executive"]]
    return "\n".join(lines) + "\n"
