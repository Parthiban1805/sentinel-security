"""`sentinel doctor`: read-only health checks. Never prints secret values or token contents.

Each check returns (status, detail); status is ok / warn / fail. Nothing here changes state or
makes a network call, so it is safe to run anywhere.
"""

import os
import shutil
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sentinel import agentlog, config, runner
from sentinel.scanners import gitleaks
from sentinel.security import load_key
from sentinel.store.db import Store


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # ok | warn | fail
    detail: str


def _readable_by_others(path: Path) -> bool | None:
    """POSIX only: True if group/other can read. None where the mode bits are not meaningful."""
    if sys.platform == "win32":
        return None
    return bool(path.stat().st_mode & (stat.S_IRGRP | stat.S_IROTH))


def check_gitleaks() -> Check:
    try:
        return Check("gitleaks", "ok", gitleaks.find_gitleaks())
    except gitleaks.ScanError:
        return Check("gitleaks", "fail", "not found on PATH (install gitleaks)")


def check_state_dir(home: Path) -> Check:
    if not home.exists():
        return Check("state dir", "warn", f"{home} does not exist yet (created on first scan)")
    try:
        Store(home / "sentinel.db").assets()
    except Exception as exc:  # noqa: BLE001 (report only the type)
        return Check("state dir", "fail", f"database unusable ({type(exc).__name__})")
    return Check("state dir", "ok", f"{home} (database opens)")


def check_fingerprint_key(home: Path) -> Check:
    path = home / "fingerprint.key"
    if not path.exists():
        return Check("fingerprint key", "warn", "not created yet (created on first scan)")
    try:
        load_key(home)
    except ValueError as exc:
        return Check("fingerprint key", "fail", str(exc))
    if _readable_by_others(path):
        return Check("fingerprint key", "warn", "readable by group/others (chmod 600)")
    note = "" if sys.platform != "win32" else " (Windows: file permissions not inspected)"
    return Check("fingerprint key", "ok", f"32 bytes{note}")


def check_gitignore(root: Path) -> Check:
    gi = root / ".gitignore"
    text = gi.read_text(encoding="utf-8") if gi.exists() else ""
    missing = [p for p in (".sentinel/", "sentinel.toml") if p not in text]
    if missing:
        return Check("gitignore", "fail", "not ignored (would be committed): " + ", ".join(missing))
    return Check("gitignore", "ok", ".sentinel/ and sentinel.toml are ignored")


def check_config(path: Path) -> Check:
    if not path.exists():
        return Check("config", "warn", f"{path} not found (defaults: nothing configured)")
    try:
        settings = config.load(path)
    except Exception as exc:  # noqa: BLE001
        return Check("config", "fail", f"cannot parse ({type(exc).__name__})")
    parts = [
        f"{len(settings.scan_paths)} scan path(s)",
        f"{len(settings.github_repos)} GitHub repo(s)",
        f"{len(settings.gcp_projects)} GCP project(s)",
    ]
    missing = [p for p in settings.scan_paths if not Path(p).exists()]
    if missing:
        return Check("config", "warn", "scan path missing: " + ", ".join(missing))
    return Check("config", "ok", ", ".join(parts))


def check_github_token(home: Path, settings: config.Settings) -> Check:
    if not (settings.github_repos or settings.github_user_keys):
        return Check("github token", "ok", "GitHub not configured")
    try:
        token, _source, shadowed = runner.github_token_source(home)
    except (OSError, UnicodeDecodeError) as exc:
        return Check("github token", "fail", f"token file unreadable ({type(exc).__name__})")
    if shadowed:
        return Check("github token", "warn", runner.SHADOW_WARNING)
    if not token:
        return Check(
            "github token",
            "fail",
            f"missing: set env {runner.GITHUB_TOKEN_ENV} or create "
            f"{home / runner.GITHUB_TOKEN_FILE}",
        )
    source = "environment" if os.environ.get(runner.GITHUB_TOKEN_ENV, "").strip() else "file"
    shape = "fine-grained" if token.startswith("github_pat_") else "other format"
    file_path = home / runner.GITHUB_TOKEN_FILE
    if source == "file" and _readable_by_others(file_path):
        return Check("github token", "warn", f"from {source}, but readable by group/others")
    return Check("github token", "ok", f"found in {source} ({shape}, {len(token)} chars)")


def check_agent_log(home: Path) -> Check:
    path = home / agentlog.LOG_NAME
    if not path.exists():
        return Check(
            "agent log",
            "warn",
            "no decision log yet (patch docs/patches/agent-decision-log not applied, "
            "or nothing denied yet)",
        )
    anchor = None
    db = home / "sentinel.db"
    if db.exists():
        anchor = Store(db).get_doc("snapshots", "agentlog:anchor")
    result = agentlog.verify(path, anchor)
    if not result.ok:
        return Check("agent log", "fail", "chain broken: " + "; ".join(result.problems[:2]))
    note = "" if anchor else " (no anchor yet: run `sentinel agentlog verify`)"
    if result.dropped:
        return Check(
            "agent log",
            "warn",
            f"{result.entries} entries, chain intact, but {result.dropped} decision(s) "
            "could not be chained",
        )
    return Check("agent log", "ok", f"{result.entries} entries, chain intact{note}")


def check_gcp(settings: config.Settings) -> Check:
    if not settings.gcp_projects:
        return Check("google cloud", "ok", "not configured")
    if shutil.which("gcloud") is None:
        return Check("google cloud", "warn", "configured, but the gcloud CLI is not installed")
    return Check("google cloud", "ok", "gcloud present (credentials are checked at run time)")


def check_agent_manifest(home: Path) -> Check:
    """ADR-0024: is a manifest applied, readable, current (no drift) and not expired?"""
    from datetime import UTC, datetime

    from sentinel import agentgate

    workspace = home.resolve().parent
    state = agentgate.manifest_status(
        home, workspace / agentgate.MANIFEST_SOURCE, datetime.now(UTC)
    )
    if state.get("error"):
        return Check(
            "agent manifest",
            "fail",
            "the compiled manifest is unreadable: the gateway allows only reading",
        )
    if not state["applied"]:
        if state.get("source_present"):
            return Check(
                "agent manifest", "warn", "policies/agent-manifest.toml exists but is not applied"
            )
        return Check("agent manifest", "ok", "not used (the gateway's built-in rules apply)")
    if state["expired"]:
        return Check(
            "agent manifest", "warn", f"expired on {state['expires']}: every non-read call asks"
        )
    if state["drift"]:
        return Check(
            "agent manifest", "warn", "the TOML differs from what was applied (apply or revert it)"
        )
    return Check("agent manifest", "ok", f"applied for {state['agent']} by {state['applied_by']}")


def run_checks(home: Path, config_path: Path, root: Path) -> list[Check]:
    settings = config.load(config_path) if config_path.exists() else config.Settings()
    checks: list[Callable[[], Check]] = [
        check_gitleaks,
        lambda: check_state_dir(home),
        lambda: check_fingerprint_key(home),
        lambda: check_gitignore(root),
        lambda: check_config(config_path),
        lambda: check_github_token(home, settings),
        lambda: check_gcp(settings),
        lambda: check_agent_log(home),
        lambda: check_agent_manifest(home),
    ]
    return [check() for check in checks]
