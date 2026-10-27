"""One pass of continuous operation: scan, collect, correlate, alert. Failures are isolated.

A failing source never aborts the run; it is recorded in collector health (shown in reports).
"""

import os
from collections.abc import Callable
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

from sentinel import alerts, findings
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
        except (HttpError, gitleaks.ScanError) as exc:  # messages are scrubbed by design
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

    token = os.environ.get(GITHUB_TOKEN_ENV, "")
    if settings.github_repos or settings.github_user_keys:
        if not token:
            health["github"] = f"skipped: env {GITHUB_TOKEN_ENV} not set"
        else:
            gh = GitHubCollector(http, token, key)
            if settings.github_user_keys:
                guard("github:user_keys", lambda: add(gh.collect_user_keys(store, now)))

            def collect_repo(repo: str) -> int:
                return add(gh.collect_repo(store, repo, now, lookback))

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
                return add(
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

            for project in settings.gcp_projects:
                guard(f"gcp:{project}:keys", partial(sync_keys, project))
                guard(f"gcp:{project}:usage", partial(collect_usage, project))

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
    results = []
    passed = True
    for alias in aliases:
        status = collector.key_status(alias["project"], alias["uid"])
        ok = bool(status["deleted"])
        passed = passed and ok
        state = (
            "absent"
            if not status["found"]
            else (f"deleted at {status['deleteTime']}" if ok else "ACTIVE")
        )
        results.append(f"gcp {alias['project']} key uid {alias['uid']}: {state}")
    evidence = f"apikeys.list (showDeleted) at {format_time(now)}: " + "; ".join(results)
    lifecycle.verify(store, iid, "revoke_credential", actor, now, passed=passed, evidence=evidence)
    return passed, evidence
