"""Sentinel command-line entry point."""

import argparse
import getpass
import os
import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from sentinel import __version__, findings
from sentinel.scanners import gitleaks
from sentinel.security import fingerprint, load_key
from sentinel.store.db import Store


def _home(args: argparse.Namespace) -> Path:
    return Path(args.home or os.environ.get("SENTINEL_HOME") or ".sentinel")


def _store(args: argparse.Namespace) -> Store:
    return Store(_home(args) / "sentinel.db")


def _asset_id(path: Path) -> str:
    return "repo-" + re.sub(r"[^a-z0-9]+", "-", path.resolve().name.lower()).strip("-")


def cmd_scan(args: argparse.Namespace) -> int:
    home, store = _home(args), _store(args)
    key = load_key(home)
    target = Path(args.path)
    asset_id = _asset_id(target)
    now = datetime.now(UTC)
    found = gitleaks.run(target, "dir", key, home)
    if args.history and (target / ".git").exists():
        found += gitleaks.run(target, "git", key, home)
    new = findings.ingest(store, asset_id, found, now)
    print(f"{asset_id}: {len(found)} hit(s), {len(new)} new credential(s)")
    for ref in new:
        doc = store.get_doc("findings", ref)
        loc = doc["locations"][0] if doc else {}
        print(f"  NEW {ref}  {doc['rule_id'] if doc else ''}  {loc.get('file')}:{loc.get('line')}")
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
        now=datetime.now(UTC),
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
        now=datetime.now(UTC),
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="Sentinel security system")
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    parser.add_argument("--home", help="state directory (default: $SENTINEL_HOME or .sentinel)")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a repo/folder for secrets (fingerprints only)")
    scan.add_argument("path")
    scan.add_argument("--history", action="store_true", help="also scan all Git history")
    scan.set_defaults(func=cmd_scan)

    fnd = sub.add_parser("findings", help="findings registry").add_subparsers(
        dest="sub", required=True
    )
    lst = fnd.add_parser("list")
    lst.set_defaults(func=cmd_findings_list)
    acc = fnd.add_parser("accept", help="accept risk with an expiry")
    acc.add_argument("cred_ref")
    acc.add_argument("--days", type=int, default=90)
    acc.add_argument("--actor", required=True)
    acc.add_argument("--note")
    acc.set_defaults(func=cmd_findings_accept)
    res = fnd.add_parser("resolve", help="record revocation (verified needs evidence)")
    res.add_argument("cred_ref")
    res.add_argument(
        "--status",
        required=True,
        choices=["revoke_pending", "revoked_unverified", "revoked_verified"],
    )
    res.add_argument("--actor", required=True)
    res.add_argument("--evidence")
    res.add_argument("--note")
    res.set_defaults(func=cmd_findings_resolve)

    fp = sub.add_parser("fingerprint", help="fingerprint a key to match a finding")
    fp.set_defaults(func=cmd_fingerprint)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (gitleaks.ScanError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
