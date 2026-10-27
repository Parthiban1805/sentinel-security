"""Sentinel command-line entry point (thin layer over the library modules)."""

import argparse
import getpass
import json
import os
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinel import __version__, agentlog, config, coverage, doctor, findings, runner
from sentinel.events.schema import SchemaError, format_time
from sentinel.incidents import lifecycle
from sentinel.incidents.lifecycle import IncidentError
from sentinel.incidents.response import DryRunAdapter
from sentinel.inventory import assets as inventory
from sentinel.inventory.blast import link
from sentinel.reporting import markdown
from sentinel.scanners import gitleaks
from sentinel.security import fingerprint, load_key
from sentinel.simulation import scenarios
from sentinel.sources.gcp import AdcTokenProvider, GcpCollector, alias_key, normalize_credential_id
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
    asset = inventory.update_asset(
        _store(args),
        args.asset,
        actor=args.actor,
        now=_now(),
        owner=args.owner,
        approved=True if args.approve else (False if args.unapprove else None),
        importance=args.importance,
        monitoring=args.monitoring,
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
        return 0
    for problem in result.problems:
        print(f"TAMPER/ERROR: {problem}", file=sys.stderr)
    return 1


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
    return 0 if all(s == "ok" for s in result["health"].values()) else 2


def cmd_incident_verify_key(args: argparse.Namespace) -> int:
    collector = GcpCollector(HttpClient(), AdcTokenProvider())
    passed, evidence = runner.verify_key(_store(args), args.id, args.actor, _now(), collector)
    print(f"{args.id}: revoke_credential {'VERIFIED' if passed else 'verification FAILED'}")
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
    p = add(inv, "import", cmd_inventory_import, help="import asset records (JSON list)")
    p.add_argument("file")
    add(inv, "check", cmd_inventory_check, help="list unowned/unapproved/unmonitored assets")
    p = add(inv, "link", cmd_inventory_link, help="record a human-confirmed credential->asset link")
    p.add_argument("cred_ref")
    p.add_argument("asset")
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
    p = add(inv, "alias", cmd_inventory_alias, help="map a provider key id to a credential ref")
    p.add_argument("cred_ref")
    p.add_argument("--project", required=True, help="GCP project id")
    p.add_argument("--credential-id", required=True, help="key uid or 'apikey:<uid>'")
    p.add_argument("--actor", required=True)

    ag = sub.add_parser("agentlog", help="agent decision log").add_subparsers(
        dest="sub", required=True
    )
    p = add(ag, "verify", cmd_agentlog_verify, help="verify the tamper-evident hook decision log")
    p.add_argument("--file", help="log path (default: <home>/agent-decisions.jsonl)")

    p = add(sub, "coverage", cmd_coverage, help="scenario coverage: simulated logic vs live")
    p.add_argument("--json", action="store_true")
    p.add_argument("--baseline", default="docs/coverage-baseline.json")
    p.add_argument("--check", action="store_true", help="exit 1 if a verified rule regressed")
    p.add_argument("--update-baseline", action="store_true")

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
    p = add(inc, "close", cmd_incident_close)
    p.add_argument("id")
    p.add_argument("--actor", required=True)
    p.add_argument(
        "--unverified-note", help="close without full verification (recorded as unverified)"
    )

    p = add(sub, "report", cmd_report, help="baseline or incident report (markdown)")
    p.add_argument("--incident")
    p.add_argument("--out")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (gitleaks.ScanError, HttpError, IncidentError, SchemaError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
