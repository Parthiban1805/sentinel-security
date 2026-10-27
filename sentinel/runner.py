"""One pass of continuous operation: scan, collect, correlate, alert. Failures are isolated.

A failing source never aborts the run; it is recorded in collector health (shown in reports).
"""

import os
from collections.abc import Callable
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

from sentinel import agentlog, alerts, dependencies, findings, hygiene
from sentinel.config import Settings
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


def github_token(home: Path) -> str:
    """Token from the environment, else from <home>/github-token.txt (created by the user)."""
    token = os.environ.get(GITHUB_TOKEN_ENV, "").strip()
    if token:
        return token
    path = home / GITHUB_TOKEN_FILE
    if path.exists():
        return path.read_text(encoding="utf-8-sig").strip()
    return ""


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
