"""`sentinel coverage`: which scenarios the pipeline handles, stated honestly.

Two different claims are kept in separate columns and must never be merged:
- LOGIC VERIFIED ON SIMULATED INPUT: the real pipeline (ingest, correlate, incident, plan) handles
  a simulated chain of events. This proves the rule logic, NOT that real telemetry would produce
  those events.
- LIVE SOURCE: a real collector for the needed events exists and its last run was healthy.
"""

import json
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinel.events.refs import cred_ref as make_cred_ref
from sentinel.events.schema import SCHEMA_DIR, format_time
from sentinel.incidents import lifecycle
from sentinel.simulation import scenarios
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
_CRED = make_cred_ref("ab" * 8)
_REVOKED = make_cred_ref("ef" * 8)  # a credential whose revocation was verified (R11 scenario)

# Steps whose verification Sentinel performs itself (fresh provider evidence). Everything else is a
# recorded human attestation.
AUTO_VERIFIED_STEPS = {
    "revoke_credential": "Google API key status (verify-key)",
    "verify_path_closed": "re-probe of the exposed path (verify-probe)",
    "revoke_token_or_ssh_key": "GitHub /user/keys listing (verify-ssh-key; SSH keys only)",
    "rescan_clean": "gitleaks re-scan of the recorded locations (verify-rescan)",
    "verify_agent_hooks": "installed hooks match the reviewed patch, log chain intact",
}

# Which event types have a real producer today, which are simulation-only, and the rest have none.
REAL_PRODUCERS = {
    "secret_exposure": "gitleaks (scan)",
    "credential_usage_anomaly": "gcp collector (never run live)",
    "spend_anomaly": "gcp collector (never run live)",
    "ssh_key_added": "github collector",
    "workflow_changed": "github collector",
    "release_published": "github collector",
    "config_drift": "hygiene checks (sentinel hygiene)",
    "dependency_added": "dependency snapshots (sentinel run)",
    "exposed_service": "exposure probes (sentinel probe)",
    "canary_triggered": "canary decoys (sentinel canary): copy, tamper, read; not provider use",
    "agent_tool_denied": "agent hook decision log (sentinel run)",
    "agent_tool_allowed": "agent hook decision log, MCP calls only (sentinel run)",
}
SIMULATION_ONLY = {
    "login_anomaly": "no login-history API for personal GitHub accounts",
    "token_created": "no real producer",
}


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    rule: str
    build: Callable[[], list[dict[str, Any]]]
    live_sources: tuple[str, ...]  # collector health prefixes that must be ok for a live source
    live_note: str
    setup: Callable[[Store], None] | None = None  # state the chain needs (e.g. a verified finding)


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "S0",
        "Exposed key later used",
        "R1",
        lambda: scenarios.exposure(_CRED, "repo-demo", NOW)
        + scenarios.provider_usage(_CRED, "gcp-demo", NOW),
        ("scan:", "gcp:"),
        "needs a scan AND a live Google usage source (not run live yet)",
    ),
    Scenario(
        "S0",
        "Credential used after its revocation was verified",
        "R11",
        lambda: scenarios.provider_usage(_REVOKED, "gcp-demo", NOW + timedelta(hours=1)),
        ("gcp:",),
        "needs the Google collector (never run live); detects a revocation that did not hold",
        setup=lambda store: store.put_doc(
            "findings",
            _REVOKED,
            {
                "cred_ref": _REVOKED,
                "status": "revoked_verified",
                "verified_at": format_time(NOW),
                "locations": [],
            },
        ),
    ),
    Scenario(
        "S1/S15",
        "Sensitive file served by our own host",
        "R10",
        lambda: scenarios.exposed_path("host-demo", NOW),
        ("probes:",),
        "needs hosts listed under [probes] in the config (owner-confirmed)",
    ),
    Scenario(
        "S8/S10",
        "Risky workflow change by a non-maintainer",
        "R2",
        lambda: scenarios.risky_workflow_change("gh-demo", NOW),
        ("github:",),
        "GitHub collector",
    ),
    Scenario(
        "S10",
        "Workflow change shortly before a release",
        "R8",
        lambda: scenarios.workflow_then_release("gh-demo", NOW),
        ("github:",),
        "GitHub collector",
    ),
    Scenario(
        "S0",
        "Spend spike",
        "R4",
        lambda: scenarios.spend_spike("gcp-demo", NOW),
        ("gcp:",),
        "request volume proxy only; Google collector not run live",
    ),
    Scenario(
        "S4/S6",
        "Anomalous login then new token or key",
        "R6",
        lambda: scenarios.login_then_token("ab12cd34", "gh-demo", NOW),
        (),
        "personal GitHub accounts expose no login history; only SSH keys are collectable",
    ),
    Scenario(
        "S11",
        "Agent session retries blocked actions (possible injection)",
        "R5b",
        lambda: scenarios.steered_agent("5e55105e55105e55", "agent-demo", NOW),
        ("agentlog",),
        "agent hook decision log; only blocked actions and MCP calls are visible",
    ),
    Scenario(
        "S12",
        "Agent uses an MCP server that is not approved",
        "R5c",
        lambda: scenarios.unapproved_mcp("unknown-server", "agent-demo", NOW),
        ("agentlog",),
        "active once at least one MCP server is approved; user-scope servers are invisible",
        setup=lambda store: store.upsert_asset(
            {
                "asset_id": "mcp-approved-server",
                "asset_type": "mcp_server",
                "name": "approved-server",
                "owner": "demo",
                "importance": "high",
                "monitoring": "partial",
                "approved": True,
                "last_seen": format_time(NOW),
            }
        ),
    ),
    Scenario(
        "All",
        "Canary copied, tampered with or used",
        "R7",
        lambda: scenarios.canary("decoy-demo", NOW),
        ("canary:",),
        "decoy files: copy, tamper (detectable); use at a provider is not",
    ),
)


def schema_event_types() -> list[str]:
    schema = json.loads((SCHEMA_DIR / "event.schema.json").read_text(encoding="utf-8"))
    return list(schema["properties"]["event_type"]["enum"])


def run_scenario(spec: Scenario) -> dict[str, Any]:
    """Run one chain through the real pipeline in a throwaway state dir."""
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "coverage.db")
        if spec.setup is not None:
            spec.setup(store)
        for event in spec.build():
            store.add_event(event)
        created = lifecycle.open_incidents(store, NOW)
        incidents = [store.get_doc("incidents", iid) for iid in created]
        match = next((i for i in incidents if i and i["rule_id"] == spec.rule), None)
        required = [s for s in (match or {}).get("response_plan", []) if s["required_for_close"]]
        auto = [s for s in required if s["step"] in AUTO_VERIFIED_STEPS]
        return {
            "logic_verified_simulated": match is not None,
            "plan_generated": bool(match and match["response_plan"]),
            "required_steps": len(required),
            "auto_verifiable_steps": len(auto),
        }


def live_status(spec: Scenario, health: dict[str, str] | None) -> str:
    if not spec.live_sources:
        return "none"
    if health is None:
        return "unknown (no `sentinel run` recorded)"
    states = []
    for prefix in spec.live_sources:
        matching = [v for k, v in health.items() if k.startswith(prefix)]
        states.append(bool(matching) and all(v == "ok" for v in matching))
    return "live" if all(states) else ("partial" if any(states) else "none")


def build_report(health: dict[str, str] | None, asset_types_seen: set[str]) -> dict[str, Any]:
    rows = []
    for spec in SCENARIOS:
        result = run_scenario(spec)
        rows.append(
            {
                "scenario": spec.id,
                "name": spec.name,
                "rule": spec.rule,
                **result,
                "live_source": live_status(spec, health),
                "live_note": spec.live_note,
            }
        )
    types = schema_event_types()
    no_producer = sorted(t for t in types if t not in REAL_PRODUCERS and t not in SIMULATION_ONLY)
    asset_schema = json.loads((SCHEMA_DIR / "asset.schema.json").read_text(encoding="utf-8"))
    all_assets = asset_schema["properties"]["asset_type"]["enum"]
    return {
        "scenarios": rows,
        "event_types_with_no_producer": no_producer,
        "event_types_simulation_only": dict(SIMULATION_ONLY),
        "asset_types_never_seen": sorted(set(all_assets) - asset_types_seen),
    }


def format_report(report: dict[str, Any]) -> str:
    lines = [
        "Coverage (LOGIC = pipeline handles a simulated chain; LIVE = real source healthy; "
        "these are different claims)",
        "",
        f"{'scenario':<8} {'rule':<5} {'logic':<6} {'plan':<5} {'auto-verify':<12} "
        f"{'live source':<10}  note",
    ]
    for r in report["scenarios"]:
        logic = "yes" if r["logic_verified_simulated"] else "NO"
        plan = "yes" if r["plan_generated"] else "NO"
        auto = f"{r['auto_verifiable_steps']}/{r['required_steps']}"
        lines.append(
            f"{r['scenario']:<8} {r['rule']:<5} {logic:<6} {plan:<5} {auto:<12} "
            f"{r['live_source']:<10}  {r['live_note']}"
        )
    lines += [
        "",
        "Event types with NO producer: "
        + (", ".join(report["event_types_with_no_producer"]) or "none"),
        "Event types simulation-only: "
        + (", ".join(report["event_types_simulation_only"]) or "none"),
        "Asset types never seen: " + (", ".join(report["asset_types_never_seen"]) or "none"),
    ]
    return "\n".join(lines) + "\n"


def regressions(report: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """Rules whose simulated logic or plan was verified in the baseline but is not any more."""
    current = {r["rule"]: r for r in report["scenarios"]}
    bad: list[str] = []
    for rule, was in baseline.get("rules", {}).items():
        now = current.get(rule)
        if now is None:
            bad.append(f"{rule}: scenario removed")
            continue
        for field in ("logic_verified_simulated", "plan_generated"):
            if was.get(field) and not now[field]:
                bad.append(f"{rule}: {field} regressed")
    return bad


def baseline_from(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "note": "Simulated-logic baseline only; says nothing about live sources.",
        "rules": {
            r["rule"]: {
                "logic_verified_simulated": r["logic_verified_simulated"],
                "plan_generated": r["plan_generated"],
            }
            for r in report["scenarios"]
        },
    }


def report_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, default=asdict)
