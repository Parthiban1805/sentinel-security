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
from sentinel.config import ProbeHost, Settings, validate_extra_path
from sentinel.events.schema import format_time
from sentinel.incidents import lifecycle
from sentinel.inventory import credentials, graph
from sentinel.inventory.agents import approved_servers, discover_mcp, register_agent
from sentinel.inventory.assets import asset_id_for, location_asset_id, register_location
from sentinel.scanners import gitleaks
from sentinel.security import load_key
from sentinel.sources.agent import AgentLogSource
from sentinel.sources.gcp import AdcTokenProvider, GcpCollector, TokenProvider
from sentinel.sources.github import GitHubCollector
from sentinel.sources.http import HttpClient, HttpError
from sentinel.store.db import Store

GITHUB_TOKEN_ENV = "SENTINEL_GITHUB_TOKEN"  # noqa: S105 (env var name, not a secret)
GITHUB_TOKEN_FILE = "github-token.txt"  # noqa: S105 (file name inside the git-ignored state dir)


SHADOW_WARNING = (
    f"the environment variable {GITHUB_TOKEN_ENV} overrides the saved token file and they "
    "differ: an old value in the environment keeps winning. Remove the variable if the file is "
    f"the right one (this window: set {GITHUB_TOKEN_ENV}=   permanently: reg delete "
    f"HKCU\\Environment /v {GITHUB_TOKEN_ENV} /f)"
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


def scan_extra_location(
    store: Store,
    home: Path,
    key: bytes,
    raw: str,
    now: datetime,
    *,
    allow_credential_stores: bool = False,
    notes: list[str] | None = None,
) -> int:
    """Scan one opt-in location outside Git (S2): dir mode only, fingerprints only.

    A path that is gone, unreadable or a symlink is a health error, never "clean". Files that
    could not be read (permissions, symlinks, oversized JSON) are added to `notes` so the caller can
    show a warning instead of a plain "ok". Nothing here reads Git history, runs hygiene or
    dependency checks, or stores file content."""
    validate_extra_path(
        raw, allow_credential_stores=allow_credential_stores
    )  # also for code-built Settings
    target = Path(raw)
    if not target.exists():
        raise ValueError(f"extra scan location does not exist: {target.name}")
    if target.is_symlink():
        raise ValueError(f"extra scan location is a symlink; list the real path: {target.name}")
    gaps = gitleaks.coverage(target)
    asset_id = register_location(store, target, now)
    found = gitleaks.run(target, "dir", key, home)
    if gaps.gaps and notes is not None:
        notes.append(f"{gaps.gaps} item(s) not scanned in {target.name} ({gaps.describe()})")
    canary_events, found = canaries.filter_findings(store, target, found, now)
    stored = sum(store.add_event(e) for e in canary_events)
    return stored + len(findings.ingest(store, asset_id, found, now))


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
    notes: list[str] = []  # facts for the operator that are not errors (e.g. first-run baseline)
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

            graph_warnings: list[str] = []

            def graph_one(target: Path = target, out: list[str] = graph_warnings) -> int:
                # Repository -> workflow edges (ADR-0018); only for a registered repository.
                asset = asset_id_for(target)
                if any(a["asset_id"] == asset for a in store.assets()):
                    out.extend(graph.discover_workflows(store, asset, target, now).warnings())
                return 0

            guard(f"graph:{target.name}", graph_one)
            if graph_warnings and health[f"graph:{target.name}"] == "ok":
                health[f"graph:{target.name}"] = "warn: " + "; ".join(graph_warnings)

    if scan:
        for raw in settings.extra_scan_paths:
            name = f"scan-extra:{location_asset_id(Path(raw))}"  # name + path hash: no collisions
            gaps: list[str] = []
            guard(
                name,
                partial(
                    scan_extra_location,
                    store,
                    home,
                    key,
                    raw,
                    now,
                    allow_credential_stores=settings.allow_credential_stores,
                    notes=gaps,
                ),
            )
            if gaps and health[name] == "ok":
                health[name] = "warn: " + gaps[0]

    if store.docs("canaries"):  # tripwire pass over armed decoys (stat only; never reads them)
        guard("canary:check", lambda: add(canaries.check(store, now, key)))

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
                try:
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
                except BaseException:
                    # The collector is shared across projects: a project that failed part-way
                    # must not have its half-done baselines committed by the next project.
                    gcp.discard()
                    raise
                gcp.commit(store)  # baselines/cursor advance only after the events were stored
                return stored_count

            for project in settings.gcp_projects:
                guard(f"gcp:{project}:keys", partial(sync_keys, project))
                guard(f"gcp:{project}:usage", partial(collect_usage, project))
            notes.extend(gcp.notes)

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

        # Agent visibility (v0.3b): inventory of the agent and the project's MCP servers, then
        # the log's new entries as events. Nothing is emitted from a log that fails verification.
        agent_source = AgentLogSource()
        workspace = home.resolve().parent  # the hooks keep the log in <project>/.sentinel

        def collect_agent() -> int:
            stored_count = add(agent_source.collect(store, home, now))
            agent_source.commit(store)  # the cursor advances only after the events were stored
            return stored_count

        def agent_inventory() -> int:
            agent = register_agent(store, workspace, now)
            servers, _skipped = discover_mcp(store, workspace, now)
            graph.refresh_agent_edges(store, agent, servers, now)  # ADR-0018
            return 0

        # Events first, in their own guard: a broken .mcp.json (which an agent can write) must
        # never stop the log from being read.
        guard("agentlog:events", collect_agent)
        guard("inventory:agents", agent_inventory)
        if not approved_servers(store):
            notes.append(
                "R5c (unapproved MCP server) is inactive: no MCP server is approved yet "
                "(`sentinel inventory agents`, then `inventory set mcp-<name> --approve`)"
            )

    if probe_fetch is not None or settings.probe_hosts:
        guard("reverify:paths", lambda: reverify_open_paths(store, now, probe_fetch))

    def check_credentials() -> int:
        # Credential lifecycle checks C1-C9 (ADR-0019), after the collectors so this run's key
        # data is used. config_drift events only: no rule turns them into incidents.
        views = credentials.review(store, now, settings.credentials)
        return add(credentials.to_events(views, credentials.duplicates(store), now))

    guard("credentials", check_credentials)

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
        "notes": notes,
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
    # (asset id, project): a key seen in ANOTHER project is no proof that this alias is gone
    known_keys = {
        (a["asset_id"], (a.get("attributes") or {}).get("project")) for a in store.assets()
    }
    results = []
    passed = True
    for alias in aliases:
        status = collector.key_status(alias["project"], alias["uid"])
        if status["found"]:
            ok = bool(status["deleteTime"])  # only a recorded deletion time counts as proof
            state = f"deleted at {status['deleteTime']}" if ok else "ACTIVE"
        elif (f"gcp-key-{alias['uid']}", alias["project"]) in known_keys:
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


def verify_ssh_key(
    store: Store, iid: str, actor: str, now: datetime, collector: GitHubCollector
) -> tuple[bool, str]:
    """Verify revoke_token_or_ssh_key: every flagged SSH key id must be absent from a fresh,
    successful /user/keys listing. A failed listing raises; it never counts as proof."""
    incident = store.get_doc("incidents", iid)
    if incident is None:
        raise KeyError(f"unknown incident: {iid}")
    if incident["rule_id"] != "R6":
        raise ValueError("verify-ssh-key applies to new-key incidents (rule R6) only")
    wanted = {t["event_id"] for t in incident["timeline"]}
    events = [e for e in store.events() if e["event_id"] in wanted]
    if any(e["event_type"] == "token_created" for e in events):
        raise ValueError("the incident also flags a token, which cannot be verified automatically")
    key_ids = sorted(
        str(e["attributes"]["key_id"])
        for e in events
        if e["event_type"] == "ssh_key_added" and "key_id" in e["attributes"]
    )
    if not key_ids:
        raise ValueError("the incident has no recorded SSH key id to verify")
    present = collector.list_user_key_ids()
    still = [k for k in key_ids if k in present]
    passed = not still
    lines = [f"key {k}: {'STILL PRESENT' if k in present else 'absent'}" for k in key_ids]
    evidence = f"GET /user/keys at {format_time(now)}: " + "; ".join(lines)
    lifecycle.verify(
        store, iid, "revoke_token_or_ssh_key", actor, now, passed=passed, evidence=evidence
    )
    return passed, evidence


ScanFn = Callable[[Path, str], list[gitleaks.Finding]]


def verify_rescan(
    store: Store, iid: str, actor: str, now: datetime, scan: ScanFn
) -> tuple[bool, str]:
    """Verify rescan_clean: re-scan each recorded location of the incident's credential.

    Passes only when every scan succeeded and none still finds the credential. A scan error, a
    missing or unrecognisable folder, or nothing to scan raises and records nothing; none of
    these counts as proof. History locations are re-scanned in git mode, so they stay failed until
    history is rewritten.

    The result is a fact about the scanned scope only: a working-tree scan skips dependency and
    build folders (dist, build, target, ...), and other repositories are not scanned. The caller
    must pass a scanner keyed with the SAME fingerprint key that produced the stored finding."""
    incident = store.get_doc("incidents", iid)
    if incident is None:
        raise KeyError(f"unknown incident: {iid}")
    if not any(s["step"] == "rescan_clean" for s in incident["response_plan"]):
        raise ValueError("this incident has no rescan_clean step (it applies to R1 incidents)")
    cred = incident.get("cred_ref")
    finding = store.get_doc("findings", cred) if cred else None
    if finding is None:
        raise ValueError("the incident has no registered credential finding to re-scan")
    assets = {a["asset_id"]: a for a in store.assets()}
    targets = sorted(
        {(loc["asset_id"], "git" if loc["commit"] else "dir") for loc in finding["locations"]}
    )
    if not targets:
        raise ValueError("the credential finding has no recorded location; nothing to re-scan")
    results = []
    passed = True
    for asset_id, mode in targets:
        asset = assets.get(asset_id)
        if asset is None or asset["asset_type"] not in ("repository", "scan_location"):
            raise ValueError(
                f"{asset_id} is not a known repository or scan location; cannot re-scan"
            )
        raw = (asset.get("attributes") or {}).get("path")
        if not raw or not Path(raw).is_absolute():
            raise ValueError(f"asset {asset_id} has no absolute local path recorded")
        folder = Path(raw)
        if not folder.exists():  # a scan location may be a single file
            raise ValueError(f"the folder for {asset_id} no longer exists; nothing was verified")
        if mode == "git" and not (folder / ".git").exists():
            raise ValueError(f"the folder for {asset_id} is not a Git repository")
        gaps = gitleaks.coverage(folder) if mode == "dir" else gitleaks.Coverage()
        found = any(f.cred_ref == cred for f in scan(folder, mode))
        where = "history" if mode == "git" else "working tree, build folders skipped"
        if not found and gaps.gaps:
            # Files that could not be read might hold the credential: absent proves nothing.
            passed = False
            results.append(f"{asset_id} ({where}): INCONCLUSIVE, not scanned: {gaps.describe()}")
            continue
        passed = passed and not found
        results.append(f"{asset_id} ({where}): {'STILL FOUND' if found else 'absent'}")
    evidence = f"re-scan at {format_time(now)} (scanned scope only): " + "; ".join(results)
    lifecycle.verify(store, iid, "rescan_clean", actor, now, passed=passed, evidence=evidence)
    return passed, evidence


def reverify_open_paths(
    store: Store,
    now: datetime,
    fetch: probes.FetchFn | None,
    min_gap: timedelta = timedelta(hours=6),
) -> int:
    """Re-probe the exposed path of every open real R10 incident whose verify_path_closed step is
    not verified yet. Read-only; an inconclusive probe records a failed verification,
    never a pass."""
    for incident in store.docs("incidents"):
        if incident["status"] != "open" or incident["rule_id"] != "R10" or incident["is_test"]:
            continue
        step = next(s for s in incident["response_plan"] if s["step"] == "verify_path_closed")
        if step["state"] == "verified":
            continue
        last = step["events"][-1]["time"] if step["events"] else None
        if last and now - datetime.fromisoformat(last.replace("Z", "+00:00")) < min_gap:
            continue  # checked recently: do not pile up evidence entries every run
        verify_probe(
            store,
            incident["id"],
            "sentinel-auto",
            now,
            fetch or probes.make_fetcher(allow_http=True),
        )
    return 0  # verifications are not new events


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


AGENT_HOOK_FILES = (
    "_decision_log.py",
    "bash_guard.py",
    "protect_sensitive_files.py",
    "mcp_log.py",
    "session_log.py",
)


HOOK_PIN_KEY = "agent_hooks:pin"


def _hooks_state(workspace: Path) -> tuple[dict[str, str], str | None, list[str]]:
    """(sha256 per installed hook file, hash of settings.json's `hooks` block, problems).

    Problems are fixed texts: a missing file, a settings file that disables hooks, or a local
    settings file that overrides them. File contents are never returned or stored."""
    import hashlib
    import json

    files: dict[str, str] = {}
    problems: list[str] = []
    for name in AGENT_HOOK_FILES:
        path = workspace / ".claude" / "hooks" / name
        if path.is_file():
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            problems.append(f"{name}: MISSING")
    settings_hash = None
    for name in ("settings.json", "settings.local.json"):
        path = workspace / ".claude" / name
        if not path.is_file():
            if name == "settings.json":
                problems.append("settings.json: MISSING")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            problems.append(f"{name}: unreadable")
            continue
        if not isinstance(data, dict):
            problems.append(f"{name}: unexpected shape")
            continue
        if data.get("disableAllHooks"):
            problems.append(f"{name}: DISABLES all hooks")
        if name == "settings.json":
            block = json.dumps(data.get("hooks"), sort_keys=True, separators=(",", ":"))
            settings_hash = hashlib.sha256(block.encode("utf-8")).hexdigest()
        elif "hooks" in data:
            problems.append("settings.local.json: OVERRIDES hooks")
    return files, settings_hash, problems


def pin_agent_hooks(store: Store, workspace: Path, actor: str, now: datetime) -> dict[str, Any]:
    """Record the reviewed hook state in Sentinel's store (which the agent cannot write).

    Human-only: the CLI refuses without an interactive terminal. `verify_agent_hooks` compares
    against this pin, never against files the agent can edit (such as docs/patches)."""
    files, settings_hash, problems = _hooks_state(workspace)
    if problems:
        raise ValueError("cannot pin an incomplete or overridden hook set: " + "; ".join(problems))
    pin = {"files": files, "settings_hooks": settings_hash, "by": actor, "time": format_time(now)}
    store.put_doc("snapshots", HOOK_PIN_KEY, pin)
    store.add_audit(format_time(now), {"action": "agent_hooks_pinned", "by": actor})
    return pin


def verify_agent_hooks(
    store: Store, iid: str, actor: str, now: datetime, home: Path
) -> tuple[bool, str]:
    """Verify `verify_agent_hooks` (R5b): the installed hook files and the settings.json `hooks`
    block equal the human-made pin, nothing disables or overrides them, and the decision log
    chain and anchor are intact with no dropped decisions. The workspace is the folder that holds
    the state dir, never a path the caller chooses. Without a pin it raises and records nothing.
    Evidence holds file names and hash prefixes only."""
    incident = store.get_doc("incidents", iid)
    if incident is None:
        raise KeyError(f"unknown incident: {iid}")
    if not any(s["step"] == "verify_agent_hooks" for s in incident["response_plan"]):
        raise ValueError("this incident has no verify_agent_hooks step (it applies to R5b)")
    pin = store.get_doc("snapshots", HOOK_PIN_KEY)
    if pin is None:
        raise ValueError(
            "no reviewed hook pin; a human runs `sentinel agentlog pin-hooks` first (interactive)"
        )
    workspace = home.resolve().parent
    files, settings_hash, problems = _hooks_state(workspace)
    lines = list(problems)
    for name in AGENT_HOOK_FILES:
        if name in files:
            same = files[name] == pin["files"].get(name)
            lines.append(f"{name}: {'matches pin' if same else 'CHANGED'} ({files[name][:12]})")
    settings_same = settings_hash is not None and settings_hash == pin["settings_hooks"]
    lines.append(f"settings.json hooks: {'match pin' if settings_same else 'CHANGED'}")
    log = agentlog.verify(home / agentlog.LOG_NAME, store.get_doc("snapshots", "agentlog:anchor"))
    chain_ok = log.ok and not log.dropped and (home / agentlog.LOG_NAME).exists()
    passed = (
        not problems
        and all(files.get(n) == pin["files"].get(n) for n in AGENT_HOOK_FILES)
        and settings_same
        and chain_ok
    )
    chain = (
        f"chain intact ({log.entries} entries)"
        if chain_ok
        else f"chain NOT intact ({len(log.problems)} problem(s), {log.dropped} dropped)"
    )
    evidence = (
        f"hook check at {format_time(now)} against the pin of {pin['time']}: "
        + "; ".join(lines)
        + f"; {chain}"
    )
    lifecycle.verify(store, iid, "verify_agent_hooks", actor, now, passed=passed, evidence=evidence)
    return passed, evidence
