"""One pass of continuous operation: scan, collect, correlate, alert. Failures are isolated.

A failing source never aborts the run; it is recorded in collector health (shown in reports).
"""

import os
from collections.abc import Callable
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

from sentinel import (
    agentlog,
    alerts,
    audit,
    canaries,
    dependencies,
    findings,
    hygiene,
    probes,
)
from sentinel.config import ProbeHost, Settings
from sentinel.events.schema import format_time
from sentinel.incidents import lifecycle
from sentinel.inventory.assets import asset_id_for
from sentinel.scanners import gitleaks
from sentinel.security import load_key
from sentinel.sources.gcp import AdcTokenProvider, GcpCollector, TokenProvider
from sentinel.sources.github import GitHubCollector
from sentinel.sources.http import HttpClient, HttpError
from sentinel.store.db import Store

GITHUB_TOKEN_ENV = "SENTINEL_GITHUB_TOKEN"  # noqa: S105 (env var name, not a secret)
GITHUB_TOKEN_FILE = "github-token.txt"  # noqa: S105 (file name inside the git-ignored state dir)


SHADOW_WARNING = (
    f"the environment variable {GITHUB_TOKEN_ENV} overrides the saved token file and they differ: "
    "an old value in the environment keeps winning. Remove the variable if the file is the right one "
    f"(this window: set {GITHUB_TOKEN_ENV}=   permanently: reg delete HKCU\\Environment /v "
    f"{GITHUB_TOKEN_ENV} /f)"
)


def github_token_source(home: Path) -> tuple[str, str, bool]:
    """(token, source, shadowed). Source is 'environment', 'file' or 'none'.

    `shadowed` is True when both exist, differ, and the environment wins: the usual cause of
    "I saved a new token but it still fails". Values are compared in memory and never shown."""
    env = os.environ.get(GITHUB_TOKEN_ENV, "").strip()
    path = home / GITHUB_TOKEN_FILE
    saved = path.read_text(encoding="utf-8-sig").strip() if path.exists() else ""
    if env:
        return env, "environment", bool(saved) and saved != env
    if saved:
        return saved, "file", False
    return "", "none", False


def github_token(home: Path) -> str:
    """Token from the environment, else from <home>/github-token.txt (created by the user)."""
    return github_token_source(home)[0]


def run_once(
    store: Store,
    home: Path,
    settings: Settings,
    now: datetime,
    *,
    client: HttpClient | None = None,
    gcp_tokens: Callable[[], TokenProvider] = AdcTokenProvider,
    toast: Callable[[str, str], bool] = alerts.toast,
    scan: bool = True,
    probe_fetch: probes.FetchFn | None = None,
    probe_pause: float = 0.25,
) -> dict[str, Any]:
    key = load_key(home)
    http = client or HttpClient()
    lookback = timedelta(days=settings.first_run_lookback_days)
    health: dict[str, str] = {}
    stored = 0

    def guard(name: str, action: Callable[[], int]) -> None:
        nonlocal stored
        try:
            stored += action()
            health[name] = "ok"
        except (HttpError, gitleaks.ScanError, ValueError) as exc:  # scrubbed messages only
            health[name] = f"error: {exc}"
        except Exception as exc:  # noqa: BLE001 (isolate every source; type only, never the text)
            health[name] = f"error: {type(exc).__name__}"

    def add(events: list[dict[str, Any]]) -> int:
        return sum(store.add_event(e) for e in events)

    if scan:
        for path in settings.scan_paths:
            target = Path(path)

            def scan_one(target: Path = target) -> int:
                found = gitleaks.run(target, "dir", key, home)
                if (target / ".git").exists():
                    found += gitleaks.run(target, "git", key, home)
                # Decoy values are never "live credential" findings: a decoy found anywhere but
                # its own planted file is a COPIED canary event (rule R7).
                canary_events, found = canaries.filter_findings(store, target, found, now)
                add(canary_events)
                return len(findings.ingest(store, asset_id_for(target), found, now))

            guard(f"scan:{target.name}", scan_one)

            def hygiene_one(target: Path = target) -> int:
                found = hygiene.scan_repo(target, settings.hygiene_ignore)
                asset = asset_id_for(target)
                stored_count = add(hygiene.to_events(target, asset, found, now))
                # New dependencies since the last run (first run = baseline only). The snapshot
                # advances only after the events were stored.
                deps = dependencies.collect(target).dependencies
                previous = store.get_doc("snapshots", dependencies.snapshot_key(asset))
                events, snapshot = dependencies.new_dependency_events(asset, deps, previous, now)
                stored_count += add(events)
                store.put_doc("snapshots", dependencies.snapshot_key(asset), snapshot)
                return stored_count

            guard(f"hygiene:{target.name}", hygiene_one)

    if store.docs("canaries"):  # tripwire pass over armed decoys (stat only; never reads them)
        guard("canary:check", lambda: add(canaries.check(store, now)))

    if settings.github_repos or settings.github_user_keys:
        github_credential: str | None = None
        try:
            github_credential = github_token(home)
        except (OSError, UnicodeDecodeError) as exc:  # type only: never the file content
            health["github"] = f"error: token file unreadable ({type(exc).__name__})"
        else:
            if not github_credential:
                health["github"] = (
                    f"skipped: no token (env {GITHUB_TOKEN_ENV} or {home / GITHUB_TOKEN_FILE})"
                )
        if github_credential:
            if github_token_source(home)[2]:  # an old environment value shadows the saved file
                health["github:token-source"] = "warn: " + SHADOW_WARNING
            gh = GitHubCollector(http, github_credential, key)

            def collect_keys() -> int:
                stored_count = add(gh.collect_user_keys(store, now))
                gh.commit(store)  # state advances only after the events were stored
                return stored_count

            if settings.github_user_keys:
                guard("github:user_keys", collect_keys)

            def collect_repo(repo: str) -> int:
                stored_count = add(gh.collect_repo(store, repo, now, lookback))
                gh.commit(store)
                return stored_count

            for repo in settings.github_repos:
                guard(f"github:{repo}", partial(collect_repo, repo))

            def audit_repo(repo: str) -> int:
                if not audit.due(store, repo, now, settings.github_audit_interval_hours):
                    return 0
                repo_probe, protection = gh.audit_inputs(repo)
                if repo_probe[0] == 401:  # a rejected token is a health failure, not a finding
                    raise ValueError(
                        "GitHub rejected the token (HTTP 401): expired, revoked or wrong"
                    )
                found = audit.evaluate(repo_probe, protection)
                stored_count = add(audit.to_events(repo, found, now))
                store.put_doc("snapshots", audit.snapshot_key(repo), audit.new_snapshot(found, now))
                return stored_count

            if settings.github_audit:
                for repo in settings.github_repos:
                    guard(f"audit:{repo}", partial(audit_repo, repo))

    for host in settings.probe_hosts:  # exposure probes (S1/S15): only hosts the owner confirmed

        def probe_one(host: ProbeHost = host) -> int:
            if not probes.due(store, host.base_url, now, settings.probe_interval_hours):
                return 0
            fetch = probe_fetch or probes.make_fetcher(host.allow_http)
            events, cleared, reachable, snapshot = probes.collect(
                store, host.base_url, now, fetch, pause=probe_pause
            )
            stored_count = add(events)
            store.put_doc("snapshots", probes.snapshot_key(host.base_url), snapshot)
            for path in cleared:
                store.add_audit(
                    format_time(now),
                    {"action": "exposure_cleared", "host": host.base_url, "path": path},
                )
            if not reachable:
                raise ValueError("host did not answer any probe")
            return stored_count

        guard(f"probes:{probes.host_label(host.base_url)}", probe_one)

    if settings.gcp_projects:
        try:
            gcp = GcpCollector(http, gcp_tokens())
        except Exception as exc:  # noqa: BLE001
            health["gcp"] = f"error: credentials unavailable ({type(exc).__name__})"
        else:

            def sync_keys(project: str) -> int:
                gcp.sync_key_assets(store, project, now)
                return 0  # assets, not events

            def collect_usage(project: str) -> int:
                stored_count = add(
                    gcp.collect_usage(
                        store,
                        project,
                        now,
                        lookback=lookback,
                        multiple=settings.usage_multiple,
                        floor=settings.usage_floor,
                        spend_multiple=settings.usage_multiple,
                    )
                )
                gcp.commit(store)  # baselines/cursor advance only after the events were stored
                return stored_count

            for project in settings.gcp_projects:
                guard(f"gcp:{project}:keys", partial(sync_keys, project))
                guard(f"gcp:{project}:usage", partial(collect_usage, project))

    log_path = home / agentlog.LOG_NAME
    if log_path.exists():

        def check_agent_log() -> int:
            result = agentlog.verify_with_anchor(store, log_path)
            if not result.ok:
                line = f"{format_time(now)} CRITICAL agent decision log failed verification"
                (home / "alerts.log").open("a", encoding="utf-8").write(line + "\n")
                raise ValueError("; ".join(result.problems[:3]))
            if result.dropped:
                raise ValueError(
                    f"{result.dropped} decision(s) could not be chained (log may be incomplete)"
                )
            return 0

        guard("agentlog", check_agent_log)

    created = lifecycle.open_incidents(store, now)
    alerted = []
    for iid in created:
        incident = store.get_doc("incidents", iid)
        if incident and alerts.should_alert(incident):
            alerted.append(alerts.write_log(home, incident, now))
            if settings.toast:
                toast(f"Sentinel {incident['severity'].upper()}: {iid}", incident["title"])
    result = {
        "time": format_time(now),
        "events_stored": stored,
        "incidents_created": created,
        "alerts": alerted,
        "health": health,
    }
    store.put_doc("snapshots", "health:last_run", result)
    return result


def verify_key(
    store: Store, iid: str, actor: str, now: datetime, collector: GcpCollector
) -> tuple[bool, str]:
    """Verify revoke_credential from fresh provider evidence (API Keys list, read-only)."""
    incident = store.get_doc("incidents", iid)
    if incident is None:
        raise KeyError(f"unknown incident: {iid}")
    cred = incident.get("cred_ref")
    aliases = [a for a in store.docs("aliases") if a["cred_ref"] == cred]
    if not cred or not aliases:
        raise ValueError("incident credential has no provider alias; run `inventory alias` first")
    known_keys = {a["asset_id"] for a in store.assets()}
    results = []
    passed = True
    for alias in aliases:
        status = collector.key_status(alias["project"], alias["uid"])
        if status["found"]:
            ok = bool(status["deleteTime"])  # only a recorded deletion time counts as proof
            state = f"deleted at {status['deleteTime']}" if ok else "ACTIVE"
        elif f"gcp-key-{alias['uid']}" in known_keys:
            ok = True  # Sentinel saw this exact key before; it is now gone
            state = "absent (previously seen in inventory, now gone)"
        else:
            ok = False  # never seen: could be a mistyped alias or project, so no proof
            state = "NOT FOUND and never seen before (check the alias for typos); not verified"
        passed = passed and ok
        results.append(f"gcp {alias['project']} key uid {alias['uid']}: {state}")
    evidence = f"apikeys.list (showDeleted) at {format_time(now)}: " + "; ".join(results)
    lifecycle.verify(store, iid, "revoke_credential", actor, now, passed=passed, evidence=evidence)
    return passed, evidence


def verify_probe(
    store: Store, iid: str, actor: str, now: datetime, fetch: probes.FetchFn
) -> tuple[bool, str]:
    """Verify `verify_path_closed` by re-probing the exposed path (fresh, read-only evidence).

    Passes only on a definitive answer without the file. A network error proves nothing."""
    incident = store.get_doc("incidents", iid)
    if incident is None:
        raise KeyError(f"unknown incident: {iid}")
    if incident["rule_id"] != "R10":
        raise ValueError("verify-probe applies to exposure incidents (rule R10) only")
    wanted = {t["event_id"] for t in incident["timeline"]}
    events = [e for e in store.events(event_type="exposed_service") if e["event_id"] in wanted]
    if not events:
        raise ValueError("the incident's exposure event was not found")
    lines = []
    passed = True
    for event in events:
        attrs = event["attributes"]
        state, status = probes.reprobe(attrs["base_url"], attrs["path"], fetch)
        ok = state == "clear"
        passed = passed and ok
        shown = "no answer (network error)" if status is None else f"HTTP {status}"
        verdict = {
            "clear": "no longer served",
            "exposed": "STILL SERVED",
            "inconclusive": "inconclusive",
        }[state]
        lines.append(f"GET {attrs['base_url']}{attrs['path']} -> {shown}: {verdict}")
    evidence = f"re-probe at {format_time(now)}: " + "; ".join(lines)
    lifecycle.verify(store, iid, "verify_path_closed", actor, now, passed=passed, evidence=evidence)
    return passed, evidence
