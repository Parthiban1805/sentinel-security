"""Sentinel command-line entry point (thin layer over the library modules)."""

import argparse
import getpass
import json
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinel import (
    __version__,
    agentgate,
    agentlog,
    audit,
    canaries,
    config,
    coverage,
    doctor,
    drills,
    findings,
    hygiene,
    onboarding,
    probes,
    runner,
    sandbox,
)
from sentinel.assistant import budget as ai_budget
from sentinel.assistant import client as ai_client
from sentinel.assistant import explain as ai_explain
from sentinel.correlation.engine import context_from_store
from sentinel.correlation.session_risk import attrs_of, safe_text, session_risk
from sentinel.events.schema import SchemaError, format_time
from sentinel.incidents import lifecycle, summary, timeline, watch
from sentinel.incidents.lifecycle import IncidentError
from sentinel.incidents.response import DryRunAdapter
from sentinel.inventory import agents as agent_inventory
from sentinel.inventory import assets as inventory
from sentinel.inventory import credentials, graph
from sentinel.inventory.blast import link
from sentinel.redaction import check_free_text
from sentinel.reporting import markdown, posture, search
from sentinel.scanners import gitleaks
from sentinel.security import fingerprint, load_existing_key, load_key
from sentinel.simulation import evalset, scenarios
from sentinel.sources.agent import CURSOR_KEY as AGENT_CURSOR_KEY
from sentinel.sources.agent import AgentLogSource
from sentinel.sources.gcp import AdcTokenProvider, GcpCollector, alias_key, normalize_credential_id
from sentinel.sources.github import GitHubCollector
from sentinel.sources.http import HttpClient, HttpError
from sentinel.store.db import Store


def _home(args: argparse.Namespace) -> Path:
    return Path(args.home or os.environ.get("SENTINEL_HOME") or ".sentinel")


def _store(args: argparse.Namespace) -> Store:
    return Store(_home(args) / "sentinel.db")


def _now() -> datetime:
    return datetime.now(UTC)


# scan and findings ---------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> int:
    home, store = _home(args), _store(args)
    key = load_key(home)
    target = Path(args.path)
    asset_id = inventory.asset_id_for(target)
    found = gitleaks.run(target, "dir", key, home)
    if args.history and (target / ".git").exists():
        found += gitleaks.run(target, "git", key, home)
    canary_events, found = canaries.filter_findings(store, target, found, _now())
    for event in canary_events:
        store.add_event(event)
        print(
            f"CANARY {event['attributes']['canary_id']}: decoy copied to "
            f"{event['attributes']['location']}"
        )
    new = findings.ingest(store, asset_id, found, _now())
    print(f"{asset_id}: {len(found)} hit(s), {len(new)} new credential(s)")
    for ref in new:
        doc = store.get_doc("findings", ref) or {}
        loc = (doc.get("locations") or [{}])[0]
        print(f"  NEW {ref}  {doc.get('rule_id')}  {loc.get('file')}:{loc.get('line')}")
    return 0


def cmd_findings_list(args: argparse.Namespace) -> int:
    for doc in _store(args).docs("findings"):
        print(
            f"{doc['cred_ref']}  {doc['status']:<18} {doc['rule_id']:<22} "
            f"locations={len(doc['locations'])}  first_seen={doc['first_seen']}"
        )
    return 0


def cmd_findings_accept(args: argparse.Namespace) -> int:
    findings.set_status(
        _store(args),
        args.cred_ref,
        "risk_accepted",
        actor=args.actor,
        now=_now(),
        accept_days=args.days,
        note=args.note,
    )
    print(f"{args.cred_ref}: risk accepted for {args.days} days")
    return 0


def cmd_findings_resolve(args: argparse.Namespace) -> int:
    findings.set_status(
        _store(args),
        args.cred_ref,
        args.status,
        actor=args.actor,
        now=_now(),
        evidence=args.evidence,
        note=args.note,
    )
    print(f"{args.cred_ref}: {args.status}")
    return 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    """Fingerprint a key taken from a provider console (value read hidden, never echoed)."""
    key = load_key(_home(args))
    value = getpass.getpass("Paste key (hidden): ").strip()
    print(f"cred-fp-{fingerprint(value, key)}")
    return 0


# inventory ---------------------------------------------------------------------
def cmd_inventory_agents(args: argparse.Namespace) -> int:
    store, workspace, now = _store(args), Path(args.workspace), _now()
    agent = agent_inventory.register_agent(store, workspace, now)
    servers, skipped = agent_inventory.discover_mcp(store, workspace, now)
    graph.refresh_agent_edges(store, agent, servers, now)
    print(f"agent: {agent}")
    print(f"MCP servers from {agent_inventory.MCP_CONFIG}: {len(servers)}")
    for asset_id in servers:
        print(f"  {asset_id}")
    if skipped:
        print(f"  skipped {skipped} server name(s) with unusual characters (not stored)")
    print(
        "Approve a server with `inventory set <id> --actor <you> --approve`. Rule R5c starts "
        "alerting on unapproved servers once at least one server is approved. Servers set up "
        "at user scope are not visible here."
    )
    return 0


def cmd_inventory_discover(args: argparse.Namespace) -> int:
    added = inventory.discover(_store(args), Path(args.root), _now())
    print(f"registered {len(added)} new repo asset(s), all unowned until you assign owners")
    return 0


def cmd_inventory_import(args: argparse.Namespace) -> int:
    print(f"imported {inventory.import_assets(_store(args), Path(args.file))} asset(s)")
    return 0


def cmd_inventory_check(args: argparse.Namespace) -> int:
    for name, ids in inventory.gaps(_store(args)).items():
        print(f"{name}: {', '.join(ids) or 'none'}")
    return 0


def cmd_inventory_link(args: argparse.Namespace) -> int:
    link(_store(args), args.cred_ref, args.asset, args.permission, args.actor, _now())
    print(f"linked {args.cred_ref} -> {args.asset} ({args.permission}), confirmed by {args.actor}")
    return 0


def cmd_inventory_edge(args: argparse.Namespace) -> int:
    graph.add_documented_edge(
        _store(args), args.source, args.target, args.permission, args.actor, _now()
    )
    print(
        f"documented edge {args.source} -> {args.target} ({args.permission}), "
        f"recorded by {args.actor}"
    )
    return 0


# credential lifecycle (ADR-0019) -----------------------------------------------------
def cmd_creds(args: argparse.Namespace) -> int:
    store, now = _store(args), _now()
    policy = config.load(Path(args.config)).credentials
    views, dups = credentials.review(store, now, policy), credentials.duplicates(store)
    problems = sum(len(v.problems) for v in views) + len(dups)
    if args.record:
        stored = sum(store.add_event(e) for e in credentials.to_events(views, dups, now))
        print(f"recorded {stored} new config_drift event(s)", file=sys.stderr)
    if args.json:
        print(json.dumps(credentials.report_json(views, dups, now), indent=2, sort_keys=True))
        return 1 if problems else 0
    if not views and not dups:
        print("no credential assets (api_key, github_token, service_account) or SSH keys known")
        return 0
    for v in views:
        age = f"{v.age_days}d" if v.age_days is not None else "?"
        expires = "n/a" if v.kind == "ssh_key" else (credentials.utc_date(v.expires) or "?")
        owner = credentials.shown(v.owner) or "-"
        print(
            f"{v.ref:<36} {v.kind:<16} owner={owner:<12} age={age:<6} "
            f"expires={expires:<10} rotate_due={v.rotate_due or '?':<10} {v.state}"
        )
        for p in v.problems:
            print(f"    {p.check} {p.severity:<6} {credentials.CHECK_TEXT[p.check]}: {p.detail}")
        if v.unknown:
            print(f"    unknown: {', '.join(v.unknown)}")
    for d in dups:
        print(f"{d.ref:<36} C9 medium  live leak in {len(d.assets)} assets: {', '.join(d.assets)}")
    unknown = sum(1 for v in views if v.unknown and not v.problems and not v.deleted)
    print(
        f"{problems} problem(s); {unknown} credential(s) with no problem found but facts unknown. "
        "Record facts with `creds set <asset> --actor <you> --expires ...`. "
        "Rotation and revocation are not automated (they need approval)."
    )
    return 1 if problems else 0


def cmd_creds_set(args: argparse.Namespace) -> int:
    # These values decide what is reported as fine (a future rotation date hides C3), so an
    # agent must not set them for itself.
    _require_human("recording credential lifecycle facts")
    asset = credentials.set_lifecycle(
        _store(args),
        args.asset,
        actor=args.actor,
        now=_now(),
        expires=args.expires,
        last_used=args.last_used,
        rotated_at=args.rotated_at,
        rotate_every_days=args.rotate_every,
    )
    attrs = asset.get("attributes") or {}
    shown = {k: attrs.get(k) for k in ("expires", "last_used", "rotated_at", "rotate_every_days")}
    print(f"{asset['asset_id']}: " + ", ".join(f"{k}={v}" for k, v in shown.items() if v))
    return 0


# asset graph (ADR-0018) ------------------------------------------------------------
def cmd_graph_refresh(args: argparse.Namespace) -> int:
    results = graph.refresh_repositories(_store(args), _now())
    if not results:
        print("no repository assets with a local folder (run `inventory discover <folder>`)")
    for asset_id, result in sorted(results.items()):
        if isinstance(result, str):
            print(f"{asset_id}: not refreshed ({result})")
            continue
        print(", ".join([f"{asset_id}: {len(result.workflows)} workflow(s)", *result.warnings()]))
    print("Agent -> MCP edges are refreshed by `inventory agents` and `sentinel run`.")
    return 0


def cmd_graph_walk(args: argparse.Namespace) -> int:
    walk = graph.reached_by if args.command_name == "reached-by" else graph.reach
    result = walk(_store(args), args.asset, max_depth=args.depth)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    verb = "could be reached by" if result["direction"] == "reached_by" else "could reach"
    print(
        f"{result['start']} {verb} {len(result['nodes'])} asset(s) "
        "(hypothesis: configured or recorded access, not observed use)"
    )
    for n in result["nodes"]:
        print(
            f"  {n['depth']}  {n['asset_id']:<40} {n['asset_type']:<14} "
            f"{n['importance'] or '-':<8} "
            f"{n['permission']:<16} {n['basis']:<10} {' -> '.join(n['path'])}"
        )
    if result["max_importance"]:
        print(f"highest importance: {result['max_importance']}")
    if result["dangling"]:
        print(f"edges to assets not in the inventory: {', '.join(result['dangling'])}")
    if result["truncated"]:
        print(f"stopped at depth {args.depth}; more assets may be reachable (--depth)")
    return 0


# simulation and ingest --------------------------------------------------------------
def _store_events(store: Store, events: list[dict[str, Any]]) -> int:
    return sum(store.add_event(e) for e in events)


def cmd_simulate(args: argparse.Namespace) -> int:
    now = _now()
    make: dict[str, Callable[[], list[dict[str, Any]]]] = {
        "usage": lambda: scenarios.provider_usage(args.cred, args.asset, now),
        "spend": lambda: scenarios.spend_spike(args.asset, now, args.multiple),
        "login-token": lambda: scenarios.login_then_token(args.who, args.asset, now),
        "canary": lambda: scenarios.canary(args.asset, now),
    }
    print(f"simulated {_store_events(_store(args), make[args.scenario]())} test event(s)")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    store = _store(args)
    stored = 0
    for number, line in enumerate(Path(args.file).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                stored += store.add_event(json.loads(line))
            except (SchemaError, json.JSONDecodeError) as exc:
                raise ValueError(f"line {number}: {type(exc).__name__}") from exc
    print(f"ingested {stored} event(s)")
    return 0


# correlate and incidents --------------------------------------------------------------
def cmd_correlate(args: argparse.Namespace) -> int:
    created = lifecycle.open_incidents(_store(args), _now())
    print(f"{len(created)} new incident(s)")
    for iid in created:
        print(f"  {iid}")
    return 0


def cmd_incident_list(args: argparse.Namespace) -> int:
    for i in _store(args).docs("incidents"):
        flag = " (test)" if i["is_test"] else ""
        print(f"{i['id']}  {i['status']:<7} {i['severity']:<9} {i['rule_id']}  {i['title']}{flag}")
    return 0


def cmd_incident_show(args: argparse.Namespace) -> int:
    incident = _store(args).get_doc("incidents", args.id)
    if incident is None:
        raise KeyError(f"unknown incident: {args.id}")
    print(markdown.incident_report(incident), end="")
    return 0


def _existing_store(args: argparse.Namespace) -> Store:
    """For read-only commands: a mistyped --home must not leave a new empty store behind."""
    home = _home(args)
    if not (home / "sentinel.db").exists():
        raise ValueError(f"no Sentinel state in {home} (run `sentinel run` first, or pass --home)")
    return Store(home / "sentinel.db")


def cmd_drill_run(args: argparse.Namespace) -> int:
    """A detection drill in a throwaway workspace (ADR-0023). 0 passed, 2 failed."""
    store = None if args.no_record else _existing_store(args)  # check before a drill runs
    result = drills.run_drill(args.scenario)
    if store is not None:
        drills.record(store, result)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    else:
        print(drills.format_result(result.as_dict()), end="")
    return 0 if result.passed else 2


def cmd_drill_status(args: argparse.Namespace) -> int:
    runs = drills.history(_existing_store(args))
    if args.json:
        print(json.dumps({"runs": runs}, indent=2, sort_keys=True))
        return 0
    if not runs:
        print("no drill recorded yet (`sentinel drill run`)")
        return 0
    print(drills.format_result(runs[-1]), end="")
    passed = sum(1 for r in runs if r.get("passed"))
    print(f"{passed} of {len(runs)} recorded drills passed")
    return 0


def cmd_incident_timeline(args: argparse.Namespace) -> int:
    data = timeline.build(_existing_store(args), args.id)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(timeline.format_timeline(data), end="")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    now = _now()
    query = search.Query(
        credential=args.credential,
        asset=args.asset,
        session=args.session,
        event_type=args.type,
        source=args.source,
        since=search.parse_time(args.since, now) if args.since else None,
        until=search.parse_time(args.until, now) if args.until else None,
        include_test=args.include_test,
        limit=args.limit,
    )
    result = search.run(_existing_store(args), query, now)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(search.format_result(result), end="")
    return 0


def cmd_incident_approve(args: argparse.Namespace) -> int:
    lifecycle.approve(_store(args), args.id, args.step, args.actor, _now())
    print(f"{args.id}: step {args.step} approved by {args.actor}")
    return 0


def cmd_incident_execute(args: argparse.Namespace) -> int:
    result = lifecycle.execute(
        _store(args), args.id, args.step, args.actor, _now(), DryRunAdapter()
    )
    print(result.detail)
    return 0 if result.ok else 1


def cmd_incident_verify(args: argparse.Namespace) -> int:
    lifecycle.verify(
        _store(args),
        args.id,
        args.step,
        args.actor,
        _now(),
        passed=not args.fail,
        evidence=args.evidence,
    )
    print(f"{args.id}: step {args.step} {'verification FAILED' if args.fail else 'verified'}")
    return 0


def cmd_incident_close(args: argparse.Namespace) -> int:
    incident = lifecycle.close(
        _store(args), args.id, args.actor, _now(), unverified_note=args.unverified_note
    )
    print(f"{args.id}: closed, verified={incident['verified']}")
    return 0


def cmd_incident_summary(args: argparse.Namespace) -> int:
    if args.dry_run:  # what --ai would send: no key, no network
        print(ai_explain.build_pack(_store(args), args.id).to_json())
        return 0
    if args.ai:
        return _ai_summary(args)
    if args.deep:
        raise ValueError("--deep only applies with --ai")
    incident = _store(args).get_doc("incidents", args.id)
    if incident is None:
        raise KeyError(f"unknown incident: {args.id}")
    print(summary.render(incident), end="")
    return 0


def _ai_summary(args: argparse.Namespace) -> int:
    # Sending data off the machine and spending money needs a human at a terminal: scripts and
    # AI agents cannot confirm (ADR-0014). There is deliberately no --yes.
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ValueError("--ai needs an interactive terminal (a human must confirm the call)")
    settings = config.load(Path(args.config)).assistant
    result = ai_explain.run(
        _store(args),
        _home(args),
        args.id,
        settings,
        _now(),
        deep=args.deep,
        confirm=_confirm,
    )
    if result is None:
        print("cancelled: nothing was sent")
        return 0
    print(result.text, end="")
    print()
    print(f"saved: {result.path}")
    return 0


def _confirm(question: str) -> bool:
    return input(question).strip().lower() in ("y", "yes")


def _provider(args: argparse.Namespace) -> str:
    """--provider if given, else [assistant] provider from the config."""
    return str(args.provider or config.load(Path(args.config)).assistant.provider)


def cmd_ai_set_key(args: argparse.Namespace) -> int:
    provider = _provider(args)
    ai_client.set_key(provider)
    print(f"{provider} key stored in the OS credential store (not shown)")
    return 0


def cmd_ai_delete_key(args: argparse.Namespace) -> int:
    provider = _provider(args)
    ai_client.delete_key(provider)
    print(f"{provider} key removed from the OS credential store")
    return 0


def cmd_ai_usage(args: argparse.Namespace) -> int:
    settings = config.load(Path(args.config)).assistant
    calls, usd = ai_budget.spent(_home(args), _now())
    print(f"today: {calls}/{settings.daily_calls} calls")
    print(
        f"this month: about ${usd:.4f} of ${settings.monthly_usd:.2f} (estimate; see the console)"
    )
    print(f"provider: {settings.provider} ({settings.model})")
    print(f"key stored: {'yes' if ai_client.has_key(settings.provider) else 'no'}")
    return 0


def _eval_dir(args: argparse.Namespace) -> Path:
    path = Path(args.dir)
    if path.resolve() == _home(args).resolve():
        raise ValueError("the eval set needs its own directory, not the Sentinel state directory")
    return path


def cmd_ai_eval_build(args: argparse.Namespace) -> int:
    rows = evalset.build(_eval_dir(args))
    print(f"built {len(rows)} simulated incidents in {args.dir}")
    print(f"scoring sheet: {Path(args.dir) / evalset.SHEET}")
    print("next: sentinel ai eval-run (interactive), then fill in the sheet and run ai eval-score")
    return 0


def cmd_ai_eval_run(args: argparse.Namespace) -> int:
    """Explain every eval incident that has no answer yet, after ONE human confirmation."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ValueError("eval-run needs an interactive terminal (a human must confirm the calls)")
    folder, settings = _eval_dir(args), config.load(Path(args.config)).assistant
    store = Store(folder / "sentinel.db")
    todo = [
        r
        for r in evalset.read_sheet(folder)
        if not (folder / ai_explain.OUT_DIR / f"{r['incident_id']}.ai-summary.md").exists()
    ]
    if not todo:
        print("every eval incident already has an answer")
        return 0
    worst = sum(
        ai_explain.worst_case(ai_explain.build_pack(store, r["incident_id"]), settings)
        for r in todo
    )
    question = (
        f"Send {len(todo)} disguised simulated evidence packs to {settings.model} at "
        f"{ai_explain.backend(settings).BASE_URL}? Estimated cost at most ${worst:.2f} in total. "
        "Continue? [y/N] "
    )
    if not _confirm(question):
        print("cancelled: nothing was sent")
        return 0
    failed = 0
    for r in todo:
        try:
            result = ai_explain.run(
                store,
                folder,
                r["incident_id"],
                settings,
                _now(),
                confirm=lambda _q: True,  # the batch was confirmed above
                ledger_home=_home(args),  # eval spend counts against the real budget
            )
        except ai_budget.BudgetError as exc:
            print(f"stopped at {r['case']}: {exc}")
            return 1
        except ValueError as exc:  # refusal, truncation, bad answer: report and continue
            failed += 1
            print(f"{r['case']}: failed ({exc})")
            continue
        if result is not None:  # always set: confirm returns True
            print(f"{r['case']}: ok (about ${result.cost_usd:.4f})")
    print(f"done; {failed} failed. Answers: {folder / ai_explain.OUT_DIR}")
    return 1 if failed else 0


def cmd_ai_eval_score(args: argparse.Namespace) -> int:
    s = evalset.score(evalset.read_sheet(_eval_dir(args)))
    print(f"scored {s.scored}/{s.total}; mean accuracy {s.mean:.2f}; lowest {s.lowest}")
    print(f"made something up: {s.made_up}; followed injected text: {s.injection_followed}")
    for p in s.problems:
        print(f"- {p}")
    print("exit gate: PASS" if s.passed else "exit gate: NOT MET")
    return 0 if s.passed else 1


def cmd_watch(args: argparse.Namespace) -> int:
    data = watch.report(_store(args), _now(), args.stale_hours)
    print(watch.format_report(data), end="")
    return 1 if data["verification_failed"] or any(r["stale"] for r in data["open"]) else 0


def cmd_report(args: argparse.Namespace) -> int:
    store = _store(args)
    if args.incident:
        incident = store.get_doc("incidents", args.incident)
        if incident is None:
            raise KeyError(f"unknown incident: {args.incident}")
        text = markdown.incident_report(incident)
    else:
        text = markdown.summary_report(store, _now())
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text, end="")
    return 0


def cmd_inventory_set(args: argparse.Namespace) -> int:
    store = _store(args)
    target = next((a for a in store.assets() if a["asset_id"] == args.asset), None)
    if target and target["asset_type"] in ("mcp_server", "ai_agent"):
        # Any change to an MCP server or AI agent feeds the gateway's allow-list (ADR-0016).
        _require_human("changing an MCP server or AI agent in the inventory")
    is_mcp = bool(target and target["asset_type"] == "mcp_server")
    attributes: dict[str, str] = {}
    if args.pinned_version is not None:
        if not is_mcp:
            raise ValueError("--pinned-version applies to MCP servers only")
        attributes["pinned_version"] = args.pinned_version
    if is_mcp and args.approve and target is not None:
        # ADR-0016: an approved MCP server has a named owner, a pinned version and a review date.
        attrs = target.get("attributes") or {}
        if not (args.owner or target.get("owner")):
            raise ValueError("approving an MCP server needs --owner")
        if not (args.pinned_version or attrs.get("pinned_version")):
            raise ValueError("approving an MCP server needs --pinned-version (reviewed version)")
        attributes["reviewed"] = _now().strftime("%Y-%m-%d")
    asset = inventory.update_asset(
        store,
        args.asset,
        actor=args.actor,
        now=_now(),
        owner=args.owner,
        approved=True if args.approve else (False if args.unapprove else None),
        importance=args.importance,
        monitoring=args.monitoring,
        attributes=attributes or None,
    )
    if is_mcp:
        written = agentgate.write_mcp_allowlist(store, _home(args))
        print(
            f"gateway MCP allow-list: {len(agentgate.mcp_allowlist(store))} server(s)"
            if written
            else "gateway MCP allow-list: none approved, so MCP calls are recorded but not blocked"
        )
    print(
        f"{asset['asset_id']}: owner={asset.get('owner')} approved={asset.get('approved')} "
        f"importance={asset['importance']} monitoring={asset['monitoring']}"
    )
    return 0


def cmd_inventory_alias(args: argparse.Namespace) -> int:
    store = _store(args)
    uid = normalize_credential_id(args.credential_id)
    doc = {
        "cred_ref": args.cred_ref,
        "provider": "gcp",
        "project": args.project,
        "uid": uid,
        "confirmed_by": args.actor,
        "time": format_time(_now()),
    }
    store.put_doc("aliases", alias_key(args.project, uid), doc)
    store.add_audit(doc["time"], {"action": "alias", **doc})
    print(f"aliased gcp {args.project} key {uid} -> {args.cred_ref} (confirmed by {args.actor})")
    return 0


def cmd_agentlog_verify(args: argparse.Namespace) -> int:
    path = Path(args.file) if args.file else _home(args) / agentlog.LOG_NAME
    result = agentlog.verify_with_anchor(_store(args), path)
    if result.ok:
        denies = sum(r["decision"] == "deny" for r in result.records)
        print(f"chain OK: {result.entries} entries ({denies} denials), last seq {result.last_seq}")
        if result.dropped:
            print(
                f"WARNING: {result.dropped} decision(s) could not be chained (lock contention or "
                "write error): the log may be incomplete",
                file=sys.stderr,
            )
        return 0
    for problem in result.problems:
        print(f"TAMPER/ERROR: {problem}", file=sys.stderr)
    return 1


def cmd_agentlog_reset(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise ValueError("agentlog reset needs a human at an interactive terminal (refusing)")
    reason = args.reason.strip()
    if not reason:
        raise ValueError("a reason is required")
    answer = input(f"Archive the log and start a new chain? ({reason!r}) Type RESET to confirm: ")
    if answer.strip() != "RESET":
        print("cancelled")
        return 1
    store, home = _store(args), _home(args)
    # Read entries not yet turned into events first, so archiving never hides a detection.
    source = AgentLogSource()
    try:
        pending = source.collect(store, home, _now())
    except ValueError as exc:  # a broken chain is archived as-is (kept for forensics)
        print(f"not ingested before archiving: {exc}")
    else:
        stored = sum(store.add_event(e) for e in pending)
        source.commit(store)
        print(f"ingested {stored} pending event(s) before archiving")
    target = agentlog.archive_log(store, home, format_time(_now()), reason)
    store.delete_doc("cursors", AGENT_CURSOR_KEY)  # the next chain is read from its start
    print(f"archived to {target}" if target else "no log to archive")
    return 0


def _require_human(action: str) -> None:
    """Approvals and pins decide what Sentinel trusts; an agent must not make them for itself."""
    if not sys.stdin.isatty():
        raise ValueError(f"{action} needs a human at an interactive terminal (refusing)")


def cmd_agent_kill_switch(args: argparse.Namespace) -> int:
    """ADR-0016: anyone (an agent too) may turn it on; only a person at a terminal turns it off."""
    home = _home(args)
    if args.state == "on":
        path = agentgate.kill_switch_on(home, check_free_text("actor", args.actor) or "", _now())
        print(f"agent kill switch ON ({path.resolve()}): the gateway now refuses every tool except")
        print("reading, for Claude Code sessions of this project only.")
        if not agentgate.is_project_state_dir(home):
            print(
                "WARNING: this is not a Claude Code project's .sentinel folder, so the gateway "
                "will NOT see it. Run this from the project folder (or pass --home).",
                file=sys.stderr,
            )
    elif args.state == "off":
        _require_human("turning the agent kill switch off")
        was_on = agentgate.kill_switch_off(home)
        print("agent kill switch OFF" if was_on else "agent kill switch was already off")
    else:
        status = agentgate.kill_switch_status(home)
        if status is None:
            print("agent kill switch: off")
        else:
            print(f"agent kill switch: ON since {status.get('on_since', '?')}")
    return 0


def cmd_posture(args: argparse.Namespace) -> int:
    """Three separate indicators with evidence, and no overall score (ADR-0021).

    Exit codes: 0 report produced; with --check: 2 an indicator needs attention, 3 nothing could
    be measured. 1 is the generic error code."""
    home = _home(args)
    if not (home / "sentinel.db").exists():
        # A read-only report must not create state: a mistyped --home would leave an empty store.
        raise ValueError(f"no Sentinel state in {home} (run `sentinel run` first, or pass --home)")
    settings = config.load(Path(args.config))
    hygiene_results: dict[str, Sequence[hygiene.Finding]] | None = None
    skipped: list[str] = []
    if not args.no_hygiene and settings.scan_paths:
        hygiene_results = {}
        for raw in settings.scan_paths:
            repo = Path(raw)
            asset_id = inventory.asset_id_for(repo)
            if not (repo / ".git").exists():
                skipped.append(asset_id)
                continue
            try:
                hygiene_results[asset_id] = hygiene.scan_repo(repo, tuple(settings.hygiene_ignore))
            except (OSError, ValueError):
                skipped.append(asset_id)  # git could not read it: not measured, never "clean"
    checks = doctor.run_checks(home, Path(args.config), Path.cwd())
    report = posture.build(
        _store(args),
        _now(),
        policy=settings.credentials,
        hygiene=hygiene_results,
        hygiene_skipped=skipped,
        repos=settings.github_repos,
        checks=checks,
        stale_run_hours=args.stale_run_hours,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(posture.format_report(report), end="")
    return posture.exit_code(report) if args.check else 0


def cmd_agent_sessions(args: argparse.Namespace) -> int:
    """Advisory risk per agent session (ADR-0020). Nothing is blocked or approved by this."""
    store = _store(args)
    ctx = context_from_store(store)
    groups: dict[tuple[str, bool], list[dict[str, Any]]] = {}
    for e in store.events():
        if e["source"] != "agent_hook" or (e["is_test"] and not args.include_test):
            continue
        session = safe_text(attrs_of(e).get("session", ""), 64) or f"unknown-{e['asset_id']}"
        groups.setdefault((session, bool(e["is_test"])), []).append(e)
    rows: list[dict[str, Any]] = []
    for (session, is_test), events in groups.items():
        risk = session_risk(events, ctx)
        times = sorted(e["time"] for e in events)
        rows.append(
            {
                "session": session,
                "test": is_test,
                "events": len(events),
                "first": times[0],
                "last": times[-1],
                **risk,
            }
        )
    rows.sort(key=lambda r: (-int(r["points"]), str(r["session"]), bool(r["test"])))
    note = (
        "Advisory only: a score never blocks or approves anything. Points have no time limit, so "
        "a long session drifts upward on harmless keyword blocks. Allowed calls are mostly not "
        "logged, so a low level does not mean nothing happened."
    )
    if args.json:
        print(
            json.dumps({"advisory": True, "note": note, "sessions": rows}, indent=2, sort_keys=True)
        )
        return 0
    if not rows:
        print("no agent sessions in the store (test sessions need --include-test)")
        return 0
    print(note)
    for r in rows:
        label = " [test]" if r["test"] else ""
        print(
            f"{r['session']:<28} {r['level']:<9} {r['points']:>3} pts  {r['events']} event(s)  "
            f"{r['first']} .. {r['last']}{label}"
        )
        for why in r["reasons"] or ["no refused or questioned attempts logged"]:
            print(f"    {why}")
    return 0


def cmd_agent_manifest(args: argparse.Namespace) -> int:
    """ADR-0024: check (anyone), apply and off (a person at a terminal), status."""
    from sentinel import agentmanifest

    home = _home(args)
    workspace = home.resolve().parent
    source = Path(args.file) if args.file else workspace / agentgate.MANIFEST_SOURCE
    if args.action in ("check", "apply") and not source.is_file():
        raise ValueError(
            f"no manifest at {source} (start from policies/agent-manifest.example.toml)"
        )
    if args.action == "check":
        compiled = agentmanifest.compile_manifest(
            source.read_bytes(), str(workspace), "check", _now()
        )
        print(
            f"{source}: valid (agent {compiled['agent']['id']}, owner {compiled['agent']['owner']})"
        )
        return 0
    if args.action == "apply":
        _require_human("applying the agent permission manifest")
        if not agentgate.is_project_state_dir(home):
            raise ValueError(
                f"{home} is not the .sentinel folder of a Claude Code project, so the gateway "
                "would "
                "never read this manifest; run from the project folder (or pass --home)"
            )
        actor = check_free_text("actor", args.actor) or ""
        if not actor:
            raise ValueError("--actor is required to apply the manifest")
        compiled = agentgate.apply_manifest(home, source, workspace, actor, _now())
        _store(args).add_audit(
            format_time(_now()),
            {
                "action": "agent_manifest_applied",
                "actor": actor,
                "source_sha256": compiled["source_sha256"],
            },
        )
        print(
            f"agent manifest applied for {compiled['agent']['id']} "
            f"(sha256 {compiled['source_sha256'][:12]})"
        )
        fs, net = compiled["filesystem"], compiled["network"]
        print(
            f"  read: {len(fs.get('read', ['**']))} glob(s), "
            f"write: {len(fs.get('write', ['**']))}, "
            f"deny: {len(fs.get('deny', []))}, ask before writing: {len(fs.get('ask_write', []))}, "
            f"outside the workspace: {fs.get('outside_workspace', 'allow')}"
        )
        print(
            f"  shell: {compiled['execution'].get('shell', True)}, fetch domains: "
            f"{len(net['fetch_domains']) if 'fetch_domains' in net else 'any'}, "
            "MCP servers listed: "
            f"{len(compiled['mcp']['servers'])} (unlisted: {compiled['mcp']['unlisted']})"
        )
        print("Review the TOML before applying: the agent may have edited it.")
        return 0
    if args.action == "off":
        _require_human("turning the agent permission manifest off")
        was = agentgate.manifest_off(home)
        if was:
            actor = check_free_text("actor", args.actor) or ""
            _store(args).add_audit(
                format_time(_now()), {"action": "agent_manifest_off", "actor": actor}
            )
        print("agent manifest OFF" if was else "no agent manifest was applied")
        return 0
    state = agentgate.manifest_status(home, source, _now())
    if args.json:
        print(json.dumps(state, indent=2, sort_keys=True))
    elif state.get("error"):
        print(f"agent manifest: UNREADABLE ({state['error']}); the gateway allows only reading")
    elif not state["applied"]:
        print("agent manifest: not applied (the gateway's built-in rules apply)")
    else:
        print(
            f"agent manifest: applied for {state['agent']} by {state['applied_by']} at "
            f"{state['applied_at']}; expires {state['expires'] or 'never'}"
            + ("; EXPIRED (non-read calls ask)" if state["expired"] else "")
            + ("; DRIFT: the TOML differs from what was applied" if state["drift"] else "")
        )
    return 1 if state.get("error") or state.get("drift") or state.get("expired") else 0


def cmd_agent_mcp_allowlist(args: argparse.Namespace) -> int:
    home = _home(args)
    path = home / agentgate.MCP_ALLOWLIST_NAME
    if args.state == "off":
        _require_human("switching the MCP allow-list off")
        was_on = agentgate.mcp_allowlist_off(home)
        print(
            "MCP allow-list OFF: every MCP server is allowed again and recorded"
            if was_on
            else "MCP allow-list was already off"
        )
        return 0
    if not path.exists():
        print("MCP allow-list: off (MCP calls are recorded, not blocked)")
    else:
        names = sorted(agentgate.mcp_allowlist(_store(args)))
        print(f"MCP allow-list: ON, approved: {', '.join(names) or 'none (every server blocked)'}")
    return 0


def _repo_root() -> Path:
    out = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--show-toplevel"],  # noqa: S607 - fixed git command
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise ValueError("run the sandbox from inside the project's Git repository")
    return Path(out.stdout.strip())


def _sandbox_settings(repo: Path) -> config.SandboxSettings:
    """Always the project's own sentinel.toml (agents cannot write it; no --config, ADR-0017)."""
    return config.load(repo / "sentinel.toml").sandbox


def cmd_sandbox_run(args: argparse.Namespace) -> int:
    repo = _repo_root()
    settings = _sandbox_settings(repo)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    limits = sandbox.Limits(
        memory=settings.memory,
        cpus=settings.cpus,
        timeout_s=sandbox.check_timeout(args.timeout or settings.timeout_s),
    )
    result = sandbox.run(repo, settings.image, command, limits, keep=args.keep)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    note = f"[sandbox: no network; {result.copied} tracked file(s) copied"
    if result.skipped:
        note += f", {len(result.skipped)} left out (secrets, links or large files)"
    note += f"; exit {result.exit_code}" + ("; TIMED OUT" if result.timed_out else "") + "]"
    print(note, file=sys.stderr)
    if result.scratch is not None:
        print(f"[sandbox files kept at {result.scratch}]", file=sys.stderr)
    return result.exit_code


def cmd_sandbox_check(args: argparse.Namespace) -> int:
    settings = _sandbox_settings(_repo_root())
    problems = sandbox.docker_status(settings.image)
    if problems:
        for p in problems:
            print(f"- {p}")
        print("sandbox: NOT ready")
        return 1
    print(f"sandbox: ready (image {settings.image}, no network)")
    return 0


def cmd_sandbox_strict(args: argparse.Namespace) -> int:
    """ADR-0017: anyone may turn strict mode on; only a person turns it off."""
    home = _home(args)
    if args.state == "on":
        sandbox.strict_on(home)
        print("sandbox strict mode ON: code run outside the sandbox now needs your confirmation")
        if not agentgate.is_project_state_dir(home):
            print(
                "WARNING: this is not a Claude Code project's .sentinel folder, so the gateway "
                "will NOT see it. Run this from the project folder (or pass --home).",
                file=sys.stderr,
            )
    elif args.state == "off":
        _require_human("turning sandbox strict mode off")
        was = sandbox.strict_off(home)
        print("sandbox strict mode OFF" if was else "sandbox strict mode was already off")
    else:
        print(f"sandbox strict mode: {'ON' if sandbox.strict_status(home) else 'off'}")
    return 0


def cmd_agentlog_pin_hooks(args: argparse.Namespace) -> int:
    _require_human("pinning the reviewed hooks")
    home = _home(args)
    answer = input(
        "Pin the hooks now installed in .claude/hooks and the hooks block of "
        ".claude/settings.json as REVIEWED? Type PIN to confirm: "
    )
    if answer.strip() != "PIN":
        print("cancelled")
        return 1
    pin = runner.pin_agent_hooks(_store(args), home.resolve().parent, args.actor, _now())
    print(f"pinned {len(pin['files'])} hook file(s) and the settings hooks block at {pin['time']}")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    home = _home(args)
    health = asset_types = None
    db = home / "sentinel.db"
    if db.exists():
        store = Store(db)
        last = store.get_doc("snapshots", "health:last_run")
        health = last["health"] if last else None
        asset_types = {a["asset_type"] for a in store.assets()}
    report = coverage.build_report(health, asset_types or set())
    print(coverage.report_json(report) if args.json else coverage.format_report(report), end="")
    baseline_path = Path(args.baseline)
    if args.update_baseline:
        baseline_path.write_text(
            json.dumps(coverage.baseline_from(report), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"baseline written to {baseline_path}")
    if args.check:
        if not baseline_path.exists():
            raise ValueError(f"baseline file not found: {baseline_path}")
        bad = coverage.regressions(report, json.loads(baseline_path.read_text(encoding="utf-8")))
        for line in bad:
            print(f"REGRESSION {line}", file=sys.stderr)
        return 1 if bad else 0
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    interactive = sys.stdin.isatty() and not args.no_prompt

    def ask(question: str, default: str) -> str:
        suffix = f" [{default}]" if default else ""
        return input(f"{question}{suffix}: ").strip() or default

    opts = onboarding.InitOptions(
        config_path=Path(args.config),
        home=_home(args),
        root=Path.cwd(),
        scan_paths=list(args.scan_path or []),
        github_repos=list(args.github_repo or []),
        user_keys=True if args.watch_ssh_keys else (False if args.no_ssh_keys else None),
        gcp_projects=list(args.gcp_project or []),
        interactive=interactive,
        force=args.force,
        gitignore=not args.no_gitignore,
        store_token=interactive and not args.no_token_prompt,
    )
    return onboarding.run_init(opts, print, ask, lambda q: getpass.getpass(f"{q}: "))


def cmd_audit(args: argparse.Namespace) -> int:
    """Branch protection and secret-scanning settings of the watched GitHub repositories."""
    settings = config.load(Path(args.config))
    repos = list(args.repo or settings.github_repos)
    if not repos:
        raise ValueError("no repositories: pass --repo owner/name or list them in the config")
    repos = [config.validate_repo(r) for r in repos]
    token = runner.github_token(_home(args))
    if not token:
        raise ValueError(f"no GitHub token (env {runner.GITHUB_TOKEN_ENV} or the state-dir file)")
    gh = GitHubCollector(HttpClient(), token, load_key(_home(args)))
    results: dict[str, list[audit.AuditFinding]] = {}
    store = _store(args) if args.record else None
    now = _now()
    for repo in repos:
        repo_probe, protection = gh.audit_inputs(repo)
        if repo_probe[0] == 401:
            raise ValueError("GitHub rejected the token (HTTP 401): expired, revoked or wrong")
        found = audit.evaluate(repo_probe, protection)
        results[repo] = found
        if store is not None:
            stored = sum(store.add_event(e) for e in audit.to_events(repo, found, now))
            store.put_doc("snapshots", audit.snapshot_key(repo), audit.new_snapshot(found, now))
            print(f"recorded {stored} new config_drift event(s) for {repo}", file=sys.stderr)
    print(audit.format_findings(results), end="")
    worst = max((audit_sev.index(f.severity) for fs in results.values() for f in fs), default=-1)
    return 1 if args.fail_on and worst >= audit_sev.index(args.fail_on) else 0


audit_sev = ("low", "medium", "high")


def cmd_canary_plant(args: argparse.Namespace) -> int:
    key = load_key(_home(args))
    doc = canaries.plant(
        _store(args), key, Path(args.directory), _now(), kind=args.kind, name=args.name
    )
    print(f"planted {doc['canary_id']} ({doc['kind']}) at {doc['path']}")
    print(f"  access-time tripwire: {doc['atime_check']}", end="")
    print(
        " (reads detected promptly)"
        if doc["atime_check"] == "immediate"
        else " (read detection unverified here)"
    )
    if doc["git_note"]:
        print(f"  git: {doc['git_note']}")
    print("  the decoy value is fake, random, never stored; only its fingerprint is kept")
    return 0


def cmd_canary_list(args: argparse.Namespace) -> int:
    for d in _store(args).docs("canaries"):
        triggers = ",".join(d["triggers"]) or "-"
        print(
            f"{d['canary_id']}  {d['status']:<9} {d['kind']:<10} "
            f"triggers={triggers:<16} {d['path']}"
        )
    return 0


def cmd_canary_check(args: argparse.Namespace) -> int:
    store = _store(args)
    try:
        key: bytes | None = load_existing_key(_home(args))
    except ValueError:
        key = None  # no key yet: events still work, just without the R9 path fingerprint
        print("note: no fingerprint key yet, so rule R9 cannot match decoys to gateway decisions")
    events = canaries.check(store, _now(), key)
    stored = sum(store.add_event(e) for e in events)
    for e in events:
        a = e["attributes"]
        print(
            f"[{e['severity'].upper():<8}] {a['canary_id']} {a['reason']} "
            f"(confidence {e['confidence']})"
        )
    print(f"{len(events)} signal(s), {stored} new event(s); read detection never opens an incident")
    return 1 if any(e["attributes"]["reason"] != "read" for e in events) else 0


def cmd_canary_disarm(args: argparse.Namespace) -> int:
    canaries.disarm(_store(args), args.id, _now(), delete_file=args.delete_file)
    print(f"{args.id}: disarmed" + (" and decoy file deleted" if args.delete_file else ""))
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    """Probe hosts YOU own for exposed sensitive files (read-only; content is never kept)."""
    settings = config.load(Path(args.config))
    targets: list[tuple[str, bool]] = []
    if args.url:
        if not args.i_own_this:
            raise ValueError("probing needs --i-own-this: only probe hosts you own or run")
        targets += [
            (probes.normalize_target(u, allow_http=args.allow_http), args.allow_http)
            for u in args.url
        ]
    else:
        targets += [(h.base_url, h.allow_http) for h in settings.probe_hosts]
    if not targets:
        raise ValueError(
            "no hosts: pass --url ... --i-own-this, or list hosts under [probes] in the config"
        )
    store = _store(args) if args.record else None
    now = _now()
    worst = -1
    for base, allow_http in targets:
        fetch = probes.make_fetcher(allow_http)
        if store is not None:
            events, cleared, reachable, snapshot = probes.collect(
                store, base, now, fetch, pause=args.pause
            )
            exposures = [{**e["attributes"], "severity": e["severity"]} for e in events]
            stored = sum(store.add_event(e) for e in events)
            store.put_doc("snapshots", probes.snapshot_key(base), snapshot)
            print(f"recorded {stored} new exposed_service event(s)", file=sys.stderr)
            for path in cleared:
                print(f"CLEARED {base}{path} no longer served", file=sys.stderr)
        else:
            found, reachable = probes.probe_host(base, fetch, pause=args.pause)
            exposures = [
                {
                    "path": e.path,
                    "signature": e.signature,
                    "severity": e.severity,
                    "status": e.status,
                    "scenario": e.scenario,
                }
                for e in found
            ]
        print(
            f"== {base}: {len(exposures)} exposed path(s)"
            + ("" if reachable else " (host did not answer)")
        )
        for e in exposures:
            label = str(e["severity"]).upper()
            print(f"  [{label:<8}] {e['path']}: {e['signature']} served (HTTP {e['status']})")
            worst = max(worst, ("medium", "high", "critical").index(e["severity"]))
    threshold = ("medium", "high", "critical").index(args.fail_on) if args.fail_on else None
    return 1 if threshold is not None and worst >= threshold else 0


def cmd_incident_verify_probe(args: argparse.Namespace) -> int:
    # The target was validated (https, or http only with allow_http) when it was first probed;
    # re-probing the recorded base URL needs no new policy decision.
    fetch = probes.make_fetcher(allow_http=True)
    passed, evidence = runner.verify_probe(_store(args), args.id, args.actor, _now(), fetch)
    print(f"{args.id}: verify_path_closed {'VERIFIED' if passed else 'verification FAILED'}")
    print(f"  evidence: {evidence}")
    return 0 if passed else 1


def cmd_hygiene(args: argparse.Namespace) -> int:
    settings = config.load(Path(args.config))
    paths = args.paths or list(settings.scan_paths) or ["."]
    ignore = tuple(settings.hygiene_ignore) + tuple(args.ignore or ())
    results: dict[str, list[hygiene.Finding]] = {}
    for raw in paths:
        repo = Path(raw)
        if not (repo / ".git").exists():
            print(f"skipped (not a Git repository): {raw}", file=sys.stderr)
            continue
        results[inventory.asset_id_for(repo)] = hygiene.scan_repo(repo, ignore)
    if args.record:
        store = _store(args)
        now = _now()
        recorded = 0
        for raw in paths:
            repo = Path(raw)
            asset_id = inventory.asset_id_for(repo)
            if asset_id in results:
                recorded += sum(
                    store.add_event(e)
                    for e in hygiene.to_events(repo, asset_id, results[asset_id], now)
                )
        print(f"recorded {recorded} new config_drift event(s)", file=sys.stderr)
    print(
        json.dumps(hygiene.results_json(results), indent=2)
        if args.json
        else hygiene.format_findings(results),
        end="",
    )
    worst = max(
        (hygiene.SEVERITIES.index(f.severity) for fs in results.values() for f in fs), default=-1
    )
    threshold = hygiene.SEVERITIES.index(args.fail_on) if args.fail_on else None
    return 1 if threshold is not None and worst >= threshold else 0


def cmd_doctor(args: argparse.Namespace) -> int:
    checks = doctor.run_checks(_home(args), Path(args.config), Path.cwd())
    marks = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}
    for c in checks:
        print(f"[{marks[c.status]}] {c.name}: {c.detail}")
    failed = sum(c.status == "fail" for c in checks)
    warned = sum(c.status == "warn" for c in checks)
    print(f"{len(checks)} checks: {failed} failed, {warned} warning(s)")
    return 1 if failed else 0


def cmd_run(args: argparse.Namespace) -> int:
    settings = config.load(Path(args.config))
    result = runner.run_once(_store(args), _home(args), settings, _now(), scan=not args.no_scan)
    print(
        f"run {result['time']}: {result['events_stored']} new event(s), "
        f"{len(result['incidents_created'])} new incident(s), {len(result['alerts'])} alert(s)"
    )
    for name, state in sorted(result["health"].items()):
        print(f"  {name}: {state}")
    for line in result["alerts"]:
        print(f"  ALERT {line}")
    for line in result.get("notes", []):
        print(f"  NOTE  {line}")
    return 0 if all(s == "ok" for s in result["health"].values()) else 2


def cmd_incident_verify_key(args: argparse.Namespace) -> int:
    from google.auth.exceptions import GoogleAuthError

    try:
        collector = GcpCollector(HttpClient(), AdcTokenProvider())
    except GoogleAuthError as exc:  # type only: the OAuth error text is never printed
        raise ValueError(
            f"Google credentials unavailable ({type(exc).__name__}); "
            "run `gcloud auth application-default login`"
        ) from None
    passed, evidence = runner.verify_key(_store(args), args.id, args.actor, _now(), collector)
    print(f"{args.id}: revoke_credential {'VERIFIED' if passed else 'verification FAILED'}")
    print(f"  evidence: {evidence}")
    return 0 if passed else 1


def cmd_incident_verify_ssh_key(args: argparse.Namespace) -> int:
    token = runner.github_token(_home(args))
    if not token:
        raise ValueError(f"no GitHub token (env {runner.GITHUB_TOKEN_ENV} or the state-dir file)")
    gh = GitHubCollector(HttpClient(), token, load_key(_home(args)))
    passed, evidence = runner.verify_ssh_key(_store(args), args.id, args.actor, _now(), gh)
    print(f"{args.id}: revoke_token_or_ssh_key {'VERIFIED' if passed else 'verification FAILED'}")
    print(f"  evidence: {evidence}")
    return 0 if passed else 1


def cmd_incident_verify_rescan(args: argparse.Namespace) -> int:
    home = _home(args)
    key = load_existing_key(home)  # never a new key: it would make every credential look absent

    def scan(folder: Path, mode: str) -> list[gitleaks.Finding]:
        return gitleaks.run(folder, mode, key, home)

    passed, evidence = runner.verify_rescan(_store(args), args.id, args.actor, _now(), scan)
    print(f"{args.id}: rescan_clean {'VERIFIED' if passed else 'verification FAILED'}")
    print(f"  evidence: {evidence}")
    return 0 if passed else 1


def cmd_incident_verify_agent_hooks(args: argparse.Namespace) -> int:
    passed, evidence = runner.verify_agent_hooks(
        _store(args), args.id, args.actor, _now(), _home(args)
    )
    print(f"{args.id}: verify_agent_hooks {'VERIFIED' if passed else 'verification FAILED'}")
    print(f"  evidence: {evidence}")
    return 0 if passed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="Sentinel security system")
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    parser.add_argument("--home", help="state directory (default: $SENTINEL_HOME or .sentinel)")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(group: Any, name: str, func: Callable[[argparse.Namespace], int], **kw: Any) -> Any:
        p = group.add_parser(name, **kw)
        p.set_defaults(func=func)
        return p

    p = add(sub, "scan", cmd_scan, help="scan a repo/folder for secrets (fingerprints only)")
    p.add_argument("path")
    p.add_argument("--history", action="store_true", help="also scan all Git history")

    fnd = sub.add_parser("findings", help="findings registry").add_subparsers(
        dest="sub", required=True
    )
    add(fnd, "list", cmd_findings_list)
    p = add(fnd, "accept", cmd_findings_accept, help="accept risk with an expiry")
    p.add_argument("cred_ref")
    p.add_argument("--days", type=int, default=90)
    p.add_argument("--actor", required=True)
    p.add_argument("--note")
    p = add(
        fnd, "resolve", cmd_findings_resolve, help="record revocation (verified needs evidence)"
    )
    p.add_argument("cred_ref")
    p.add_argument(
        "--status",
        required=True,
        choices=["revoke_pending", "revoked_unverified", "revoked_verified"],
    )
    p.add_argument("--actor", required=True)
    p.add_argument("--evidence")
    p.add_argument("--note")

    add(sub, "fingerprint", cmd_fingerprint, help="fingerprint a key to match a finding")

    inv = sub.add_parser("inventory", help="asset inventory").add_subparsers(
        dest="sub", required=True
    )
    p = add(inv, "discover", cmd_inventory_discover, help="register Git repos under a folder")
    p.add_argument("root")
    p = add(inv, "agents", cmd_inventory_agents, help="register the AI agent and MCP servers")
    p.add_argument("--workspace", default=".", help="project folder (default: current)")
    p = add(inv, "import", cmd_inventory_import, help="import asset records (JSON list)")
    p.add_argument("file")
    add(inv, "check", cmd_inventory_check, help="list unowned/unapproved/unmonitored assets")
    p = add(inv, "link", cmd_inventory_link, help="record a human-confirmed credential->asset link")
    p.add_argument("cred_ref")
    p.add_argument("asset")
    p.add_argument("--permission", required=True)
    p.add_argument("--actor", required=True)
    p = add(inv, "edge", cmd_inventory_edge, help="record a human-confirmed asset->asset edge")
    p.add_argument("source", help="asset that has the access")
    p.add_argument("target", help="asset it can reach")
    p.add_argument("--permission", required=True)
    p.add_argument("--actor", required=True)
    p = add(inv, "set", cmd_inventory_set, help="set owner, approval, importance or monitoring")
    p.add_argument("asset")
    p.add_argument("--actor", required=True)
    p.add_argument("--owner")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--approve", action="store_true")
    group.add_argument("--unapprove", action="store_true")
    p.add_argument("--importance", choices=["low", "medium", "high", "critical"])
    p.add_argument("--monitoring", choices=["none", "partial", "full"])
    p.add_argument("--pinned-version", help="MCP servers: the reviewed version (ADR-0016)")
    p = add(inv, "alias", cmd_inventory_alias, help="map a provider key id to a credential ref")
    p.add_argument("cred_ref")
    p.add_argument("--project", required=True, help="GCP project id")
    p.add_argument("--credential-id", required=True, help="key uid or 'apikey:<uid>'")
    p.add_argument("--actor", required=True)

    drl = sub.add_parser("drill", help="detection drills (ADR-0023)").add_subparsers(
        dest="sub", required=True
    )
    p = add(drl, "run", cmd_drill_run, help="push a fake leak through the pipeline, timed")
    p.add_argument("--scenario", choices=list(drills.SCENARIOS), default="leaked-key")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-record", action="store_true", help="do not store the result")
    p = add(drl, "status", cmd_drill_status, help="the recorded drill results")
    p.add_argument("--json", action="store_true")

    sch = add(sub, "search", cmd_search, help="structured search of events, incidents, findings")
    sch.add_argument("--credential", help="credential fingerprint (cred-fp-...), never the value")
    sch.add_argument("--asset")
    sch.add_argument("--session", help="hashed agent session id")
    sch.add_argument("--type", help="event type, e.g. secret_exposure")
    sch.add_argument("--source")
    sch.add_argument("--since", help="2026-11-01 or 7d / 12h / 30m")
    sch.add_argument("--until")
    sch.add_argument("--include-test", action="store_true", help="include simulated records")
    sch.add_argument("--limit", type=int, default=100)
    sch.add_argument("--json", action="store_true")

    pst = add(sub, "posture", cmd_posture, help="security posture: three indicators, no score")
    pst.add_argument("--config", default="sentinel.toml")
    pst.add_argument("--json", action="store_true")
    pst.add_argument("--no-hygiene", action="store_true", help="skip the live hygiene scan")
    pst.add_argument(
        "--check",
        action="store_true",
        help="exit 2 if an indicator needs attention, 3 if nothing could be measured",
    )
    pst.add_argument(
        "--stale-run-hours", type=int, default=posture.STALE_RUN_HOURS, help="older runs are stale"
    )

    crd = add(
        sub,
        "creds",
        cmd_creds,
        help="credential lifecycle report (ADR-0019); exit 1 = problems found or an error",
    )
    crd.add_argument("--config", default="sentinel.toml")
    crd.add_argument("--json", action="store_true")
    crd.add_argument("--record", action="store_true", help="store problems as config_drift events")
    crd_sub = crd.add_subparsers(dest="sub", required=False)
    p = add(crd_sub, "set", cmd_creds_set, help="record expiry, last use or rotation facts")
    p.add_argument("asset")
    p.add_argument("--actor", required=True)
    p.add_argument("--expires", help="YYYY-MM-DD")
    p.add_argument("--last-used", help="YYYY-MM-DD")
    p.add_argument("--rotated-at", help="YYYY-MM-DD")
    p.add_argument("--rotate-every", type=int, help="days")

    grp = sub.add_parser("graph", help="asset graph (ADR-0018)").add_subparsers(
        dest="sub", required=True
    )
    add(grp, "refresh", cmd_graph_refresh, help="derive repository -> workflow edges")
    for name, text in (
        ("reach", "what could this asset or linked credential reach (hypothesis)"),
        ("reached-by", "which assets could reach this one (hypothesis)"),
    ):
        p = add(grp, name, cmd_graph_walk, help=text)
        p.set_defaults(command_name=name)
        p.add_argument("asset", help="asset id, or a credential ref for reach")
        p.add_argument("--depth", type=int, default=graph.DEFAULT_DEPTH)
        p.add_argument("--json", action="store_true")

    agt = sub.add_parser("agent", help="agent gateway controls (ADR-0016)").add_subparsers(
        dest="sub", required=True
    )
    p = add(agt, "kill-switch", cmd_agent_kill_switch, help="refuse every agent tool but reading")
    p.add_argument("state", choices=["on", "off", "status"])
    p.add_argument("--actor", default="", help="who turned it on (recorded)")
    p = add(agt, "sessions", cmd_agent_sessions, help="advisory risk per agent session (ADR-0020)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--include-test", action="store_true", help="include simulated sessions")
    p = add(agt, "mcp-allowlist", cmd_agent_mcp_allowlist, help="MCP allow-list status or off")
    p.add_argument("state", choices=["status", "off"])
    p = add(agt, "manifest", cmd_agent_manifest, help="agent permission manifest (ADR-0024)")
    p.add_argument("action", choices=["check", "apply", "status", "off"])
    p.add_argument("--file", help="manifest TOML (default: policies/agent-manifest.toml)")
    p.add_argument("--actor", default="", help="who applies it (recorded)")
    p.add_argument("--json", action="store_true")

    sb = sub.add_parser("sandbox", help="run code in a no-network Docker sandbox (ADR-0017)")
    sbs = sb.add_subparsers(dest="sub", required=True)
    p = add(sbs, "run", cmd_sandbox_run, help="run one command in the sandbox")
    p.add_argument("--timeout", type=int, help="seconds (default: [sandbox] timeout_s)")
    p.add_argument("--keep", action="store_true", help="keep the scratch copy to read results")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- <command and its arguments>")
    p = add(sbs, "check", cmd_sandbox_check, help="is Docker running and the image pinned and here")
    p = add(sbs, "strict", cmd_sandbox_strict, help="ask before code runs outside the sandbox")
    p.add_argument("state", choices=["on", "off", "status"])

    ag = sub.add_parser("agentlog", help="agent decision log").add_subparsers(
        dest="sub", required=True
    )
    p = add(ag, "verify", cmd_agentlog_verify, help="verify the tamper-evident hook decision log")
    p.add_argument("--file", help="log path (default: <home>/agent-decisions.jsonl)")
    p = add(ag, "pin-hooks", cmd_agentlog_pin_hooks, help="record the reviewed hooks (human only)")
    p.add_argument("--actor", required=True)
    p = add(
        ag, "reset", cmd_agentlog_reset, help="archive the log and start a new chain (human only)"
    )
    p.add_argument("--reason", required=True, help="why (recorded in the audit trail)")

    p = add(sub, "coverage", cmd_coverage, help="scenario coverage: simulated logic vs live")
    p.add_argument("--json", action="store_true")
    p.add_argument("--baseline", default="docs/coverage-baseline.json")
    p.add_argument("--check", action="store_true", help="exit 1 if a verified rule regressed")
    p.add_argument("--update-baseline", action="store_true")

    p = add(
        sub, "init", cmd_init, help="guided first-time setup (config, state dir, token, .gitignore)"
    )
    p.add_argument("--config", default="sentinel.toml")
    p.add_argument("--scan-path", action="append", help="folder to scan (repeatable)")
    p.add_argument("--github-repo", action="append", help="owner/name to watch (repeatable)")
    p.add_argument("--gcp-project", action="append", help="Google Cloud project id (repeatable)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--watch-ssh-keys", action="store_true")
    group.add_argument("--no-ssh-keys", action="store_true")
    p.add_argument("--no-prompt", action="store_true", help="never ask questions")
    p.add_argument("--no-token-prompt", action="store_true", help="do not ask for a GitHub token")
    p.add_argument("--no-gitignore", action="store_true", help="do not edit .gitignore")
    p.add_argument("--force", action="store_true", help="replace an existing config (keeps a .bak)")

    p = add(sub, "audit", cmd_audit, help="GitHub branch protection and secret-scanning audit")
    p.add_argument("--config", default="sentinel.toml")
    p.add_argument("--repo", action="append", help="owner/name (default: the configured repos)")
    p.add_argument("--record", action="store_true", help="store findings as config_drift events")
    p.add_argument("--fail-on", choices=list(audit_sev))

    can = sub.add_parser("canary", help="decoy credential files (rule R7)").add_subparsers(
        dest="sub", required=True
    )
    p = add(can, "plant", cmd_canary_plant, help="place a fake credential file in a directory")
    p.add_argument("directory")
    p.add_argument("--kind", default="google_key", choices=sorted(canaries.KINDS))
    p.add_argument("--name", default=canaries.DECOY_NAMES[0], help="file name of the decoy")
    add(can, "list", cmd_canary_list)
    add(can, "check", cmd_canary_check, help="tripwire pass (stat only; never reads the decoys)")
    p = add(can, "disarm", cmd_canary_disarm, help="stop watching a decoy")
    p.add_argument("id")
    p.add_argument("--delete-file", action="store_true")

    p = add(sub, "probe", cmd_probe, help="check YOUR hosts for exposed .env/.git/backup files")
    p.add_argument("--config", default="sentinel.toml")
    p.add_argument("--url", action="append", help="host base URL, e.g. https://example.com")
    p.add_argument("--i-own-this", action="store_true", help="confirm you own or run the host")
    p.add_argument("--allow-http", action="store_true", help="allow plain http targets")
    p.add_argument("--record", action="store_true", help="store findings as exposed_service events")
    p.add_argument("--pause", type=float, default=0.25, help="seconds between requests")
    p.add_argument("--fail-on", choices=["medium", "high", "critical"])

    p = add(sub, "hygiene", cmd_hygiene, help="repo checks: tracked secrets, .gitignore, CI policy")
    p.add_argument("paths", nargs="*", help="repos to check (default: scan paths from the config)")
    p.add_argument("--config", default="sentinel.toml")
    p.add_argument("--ignore", action="append", help='accepted exception, e.g. "H2:server/.env"')
    p.add_argument("--record", action="store_true", help="store findings as config_drift events")
    p.add_argument("--json", action="store_true")
    p.add_argument("--fail-on", choices=list(hygiene.SEVERITIES), help="exit 1 at this severity")

    p = add(
        sub, "doctor", cmd_doctor, help="read-only health checks (no network, no secrets shown)"
    )
    p.add_argument("--config", default="sentinel.toml")

    p = add(sub, "run", cmd_run, help="one pass: scan, collect, correlate, alert")
    p.add_argument("--config", default="sentinel.toml")
    p.add_argument("--no-scan", action="store_true", help="skip local secret scans")

    p = add(sub, "simulate", cmd_simulate, help="inject simulated (test) source events")
    p.add_argument("scenario", choices=["usage", "spend", "login-token", "canary"])
    p.add_argument("--cred", default="cred-fp-0000")
    p.add_argument("--asset", default="provider-demo")
    p.add_argument("--who", default="ab12cd34", help="hex id for the simulated identity")
    p.add_argument("--multiple", type=float, default=5.0)

    p = add(sub, "ingest", cmd_ingest, help="load events from a JSONL file (schema-validated)")
    p.add_argument("file")
    add(sub, "correlate", cmd_correlate, help="run rules and open incidents")

    inc = sub.add_parser("incident", help="incident workflow").add_subparsers(
        dest="sub", required=True
    )
    add(inc, "list", cmd_incident_list)
    p = add(inc, "show", cmd_incident_show)
    p.add_argument("id")
    p = add(inc, "timeline", cmd_incident_timeline, help="labelled timeline from recorded data")
    p.add_argument("id")
    p.add_argument("--json", action="store_true")
    for name, func in (("approve", cmd_incident_approve), ("execute", cmd_incident_execute)):
        p = add(inc, name, func)
        p.add_argument("id")
        p.add_argument("step")
        p.add_argument("--actor", required=True)
    p = add(inc, "verify", cmd_incident_verify, help="record verification evidence for a step")
    p.add_argument("id")
    p.add_argument("step")
    p.add_argument("--actor", required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--fail", action="store_true", help="verification did NOT pass")
    p = add(inc, "verify-key", cmd_incident_verify_key, help="verify revocation from Google Cloud")
    p.add_argument("id")
    p.add_argument("--actor", required=True)
    p = add(inc, "verify-probe", cmd_incident_verify_probe, help="re-probe an exposed path (R10)")
    p.add_argument("id")
    p.add_argument("--actor", required=True)
    p = add(inc, "verify-ssh-key", cmd_incident_verify_ssh_key, help="verify SSH key removal (R6)")
    p.add_argument("id")
    p.add_argument("--actor", required=True)
    p = add(inc, "verify-rescan", cmd_incident_verify_rescan, help="re-scan for the credential")
    p.add_argument("id")
    p.add_argument("--actor", required=True)
    p = add(
        inc,
        "verify-agent-hooks",
        cmd_incident_verify_agent_hooks,
        help="hooks and log intact (R5b)",
    )
    p.add_argument("id")
    p.add_argument("--actor", required=True)
    p = add(inc, "summary", cmd_incident_summary, help="plain summary; --ai for AI notes (opt-in)")
    p.add_argument("id")
    p.add_argument("--ai", action="store_true", help="send a disguised pack to Claude (ADR-0014)")
    p.add_argument("--deep", action="store_true", help="with --ai: use the deeper (costlier) model")
    p.add_argument(
        "--dry-run", action="store_true", help="print what --ai would send; send nothing"
    )
    p.add_argument("--config", default="sentinel.toml")
    p = add(inc, "close", cmd_incident_close)
    p.add_argument("id")
    p.add_argument("--actor", required=True)
    p.add_argument(
        "--unverified-note", help="close without full verification (recorded as unverified)"
    )

    ai = sub.add_parser("ai", help="AI assistant key and usage (ADR-0014)").add_subparsers(
        dest="sub", required=True
    )
    for name, func, text in (
        ("set-key", cmd_ai_set_key, "store the provider's API key in the OS credential store"),
        ("delete-key", cmd_ai_delete_key, "remove the stored key"),
    ):
        p = add(ai, name, func, help=text)
        p.add_argument("--provider", choices=list(ai_client.KEYRING_USERS), help="default: config")
        p.add_argument("--config", default="sentinel.toml")
    p = add(ai, "usage", cmd_ai_usage, help="calls today and estimated spend this month")
    p.add_argument("--config", default="sentinel.toml")
    eval_help = {
        "eval-build": (cmd_ai_eval_build, "create the 20 simulated incidents and scoring sheet"),
        "eval-run": (cmd_ai_eval_run, "explain every eval incident (one confirmation)"),
        "eval-score": (cmd_ai_eval_score, "check the filled-in sheet against the exit gate"),
    }
    for name, (func, text) in eval_help.items():
        p = add(ai, name, func, help=text)
        p.add_argument("--dir", default=".sentinel-eval", help="eval directory (not the state dir)")
        p.add_argument("--config", default="sentinel.toml")

    p = add(sub, "report", cmd_report, help="baseline or incident report (markdown)")
    p.add_argument("--incident")
    p.add_argument("--out")
    p = add(sub, "watch", cmd_watch, help="verification watch: stale, failed, unverified incidents")
    p.add_argument("--stale-hours", type=int, default=24)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (gitleaks.ScanError, HttpError, IncidentError, SchemaError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
