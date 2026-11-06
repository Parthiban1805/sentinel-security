"""Detection drills (v0.7c item 6, ADR-0023): a fake leak through the real pipeline, timed.

Each drill runs in a throwaway folder and a throwaway store, which are deleted afterwards. The fake
key is generated at runtime (rule 3) and never reaches the live store, a real repository or the
network. Git runs isolated from the user's configuration: no global or system config, no hooks, no
templates, no signing, and no inherited GIT_* variables, so a user hook can never see or send the
fake key. Only the result (pass or fail, stage timings, rule, fixed check names, error type) is
recorded in the live store, in snapshot `drills:history`.

Timings are pipeline times only: they exclude the wait until the next scheduled run and any
provider reporting delay.
"""

import json
import os
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinel import findings
from sentinel.events.schema import format_time
from sentinel.incidents import lifecycle
from sentinel.inventory.credentials import parse_when
from sentinel.scanners import gitleaks
from sentinel.security import load_key
from sentinel.simulation import scenarios
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

SCENARIOS = ("leaked-key", "agent-sequence")
HISTORY_KEY = "drills:history"
MAX_HISTORY = 20
STALE_AFTER = timedelta(days=7)
CLOCK_SKEW = timedelta(minutes=5)
DRILL_ASSET = "drill-repo"
GIT_TIMEOUT = 15
SCAN_TIMEOUT = 60
MARKER = "# sentinel detection drill: fake value generated at runtime, not a credential\n"
_TABLES = (
    "findings",
    "incidents",
    "links",
    "snapshots",
    "cursors",
    "aliases",
    "baselines",
    "canaries",
)


@dataclass
class DrillResult:
    scenario: str
    time: str
    passed: bool = False
    stages: dict[str, float] = field(default_factory=dict)  # stage -> seconds
    time_to_detect_s: float | None = None
    time_to_incident_s: float | None = None
    incident_rule: str | None = None
    checks: list[str] = field(default_factory=list)  # fixed names of the checks that failed
    error: str | None = None  # an exception TYPE only, never its text

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _git_env(home: Path) -> dict[str, str]:
    """No user or system git config, and no inherited GIT_* (GIT_DIR would point git elsewhere)."""
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("GIT_") and not k.startswith("SENTINEL_")
    }
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        HOME=str(home),
        USERPROFILE=str(home),
    )
    return env


def _git(repo: Path, env: dict[str, str], hooks: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603 (fixed argv, no shell)
        [  # noqa: S607
            "git",
            "-c",
            f"core.hooksPath={hooks}",  # an empty folder: no user hook runs on the drill commit
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(repo),
            *args,
        ],
        check=True,
        capture_output=True,
        timeout=GIT_TIMEOUT,
        env=env,
    )


def _store_text(store: Store) -> str:
    """Every table of the drill store, keys included, to check that the fake never landed there."""
    parts: list[Any] = [store.events(), store.assets(), store.audit_rows()]
    for table in _TABLES:
        try:
            rows = store.docs(table)
        except ValueError:  # a table this store version does not have
            continue
        parts.append(rows)
    return json.dumps(parts, sort_keys=True, default=str)


def _leaked(fake: str, text: str) -> bool:
    """The whole value, the random part, or any 12-character slice of the random part."""
    random_part = fake[4:]
    if fake in text or random_part in text:
        return True
    return any(random_part[i : i + 12] in text for i in range(len(random_part) - 11))


def _leaked_key(work: Path, result: DrillResult, clock: Callable[[], float]) -> None:
    home, repo, hooks, template = (
        work / "home",
        work / "repo",
        work / "no-hooks",
        work / "no-template",
    )
    for folder in (home, repo, hooks, template):
        folder.mkdir()
    env = _git_env(home)
    store = Store(home / "sentinel.db")
    fake = fake_google_key()  # runtime-generated, lives only in this folder and this function
    start = clock()
    _git(repo, env, hooks, "init", "-q", f"--template={template}")
    secret_file = repo / "config.txt"
    secret_file.write_text(MARKER + f'api_key = "{fake}"\n', encoding="utf-8")
    _git(repo, env, hooks, "add", "config.txt")
    _git(
        repo,
        env,
        hooks,
        "-c",
        "user.email=drill@example.invalid",
        "-c",
        "user.name=sentinel-drill",
        "commit",
        "--no-verify",
        "-qm",
        "sentinel drill: fake key",
    )
    secret_file.write_text(MARKER, encoding="utf-8")  # only Git history still holds the value
    committed = clock()
    result.stages["commit"] = round(committed - start, 3)

    found = gitleaks.run(repo, "git", load_key(home), home, timeout=SCAN_TIMEOUT)
    scanned = clock()
    result.stages["scan"] = round(scanned - committed, 3)
    new = findings.ingest(store, DRILL_ASSET, found, datetime.now(UTC), is_test=True)
    detected = clock()
    result.stages["ingest"] = round(detected - scanned, 3)
    if len(new) == 1:  # a time to detect only when something was detected
        result.time_to_detect_s = round(detected - start, 3)

    for event in scenarios.provider_usage(new[0], DRILL_ASSET, datetime.now(UTC)) if new else []:
        store.add_event(event)
    created = lifecycle.open_incidents(store, datetime.now(UTC))
    opened = clock()
    result.stages["correlate"] = round(opened - detected, 3)
    rules = [str((store.get_doc("incidents", iid) or {}).get("rule_id")) for iid in created]
    result.incident_rule = rules[0] if rules else None
    if "R1" in rules:
        result.time_to_incident_s = round(opened - start, 3)

    if len(new) != 1:
        result.checks.append("expected exactly one new credential")
    if not store.events(event_type="secret_exposure"):
        result.checks.append("no secret_exposure event")
    if "R1" not in rules:
        result.checks.append("no R1 incident")
    if _leaked(fake, _store_text(store)):
        result.checks.append("leak: the fake value reached the drill store")


def _agent_sequence(work: Path, result: DrillResult, clock: Callable[[], float]) -> None:
    store = Store(work / "sentinel.db")
    start = clock()
    for event in scenarios.sensitive_then_outbound(
        "d0d0d0d0d0d0d0d0", "agent-drill", datetime.now(UTC)
    ):
        store.add_event(event)
    stored = clock()
    result.stages["events"] = round(stored - start, 3)
    created = lifecycle.open_incidents(store, datetime.now(UTC) + timedelta(minutes=10))
    opened = clock()
    result.stages["correlate"] = round(opened - stored, 3)
    rules = [str((store.get_doc("incidents", iid) or {}).get("rule_id")) for iid in created]
    result.incident_rule = rules[0] if rules else None
    if rules == ["R12"]:
        # For a rule on agent events, detection IS the incident: both times are the same.
        result.time_to_incident_s = result.time_to_detect_s = round(opened - start, 3)
    else:
        result.checks.append("expected exactly one R12 incident")


def run_drill(
    scenario: str = "leaked-key",
    *,
    now: datetime | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> DrillResult:
    """Run one drill in a throwaway workspace. Never raises for a pipeline failure: the result says
    what failed (fixed check names, or the exception type). A workspace that could not be removed
    fails the drill, because it may still hold the fake value."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown drill scenario (choose from {', '.join(SCENARIOS)})")
    result = DrillResult(scenario=scenario, time=format_time(now or datetime.now(UTC)))
    with tempfile.TemporaryDirectory(prefix="sentinel-drill-", ignore_cleanup_errors=True) as tmp:
        workspace = Path(tmp)
        try:
            if scenario == "leaked-key":
                _leaked_key(workspace, result, clock)
            else:
                _agent_sequence(workspace, result, clock)
        except Exception as exc:  # noqa: BLE001 (type only: the text may quote the workspace)
            result.error = type(exc).__name__
    if workspace.exists():
        result.checks.append("workspace not removed (it may still hold the fake value)")
    result.passed = result.error is None and not result.checks
    return result


# live store: results only ------------------------------------------------------------------
def history(store: Store) -> list[dict[str, Any]]:
    doc = store.get_doc("snapshots", HISTORY_KEY)
    runs = doc.get("runs") if isinstance(doc, dict) else None
    return [r for r in runs if isinstance(r, dict)] if isinstance(runs, list) else []


def record(store: Store, result: DrillResult) -> None:
    """Read-modify-write without a lock: two drills recorded at the same instant can lose one
    entry. Acceptable for a local history of results."""
    runs = [*history(store), result.as_dict()][-MAX_HISTORY:]
    store.put_doc("snapshots", HISTORY_KEY, {"runs": runs})


def last(store: Store) -> dict[str, Any] | None:
    runs = history(store)
    return runs[-1] if runs else None


def drill_time(run: dict[str, Any] | None) -> datetime | None:
    value = run.get("time") if run else None
    return parse_when(value) if isinstance(value, str) else None


def due(store: Store, now: datetime, interval_hours: int) -> bool:
    """Off when the interval is 0. A missing, unreadable or future time is due, so scheduled
    drills can never be silenced by a bad snapshot."""
    if interval_hours <= 0:
        return False
    when = drill_time(last(store))
    if when is None or when > now + CLOCK_SKEW:
        return True
    return now - when >= timedelta(hours=interval_hours)


def _text(value: Any, limit: int = 60) -> str:
    return "".join(c if c.isprintable() and c != "\x1b" else "?" for c in str(value))[:limit]


def format_result(result: dict[str, Any]) -> str:
    """Tolerates a tampered snapshot: wrong types are shown as '?', text is sanitised."""
    state = "PASSED" if result.get("passed") is True else "FAILED"
    lines = [f"drill {_text(result.get('scenario'))} at {_text(result.get('time'))}: {state}"]
    stages = result.get("stages")
    for name, seconds in stages.items() if isinstance(stages, dict) else []:
        shown = f"{seconds:.3f}" if isinstance(seconds, int | float) else "?"
        lines.append(f"  {_text(name, 20):<10} {shown} s")
    lines.append(f"  time to detect:   {_text(result.get('time_to_detect_s'))} s (pipeline only)")
    lines.append(
        f"  time to incident: {_text(result.get('time_to_incident_s'))} s "
        f"(rule {_text(result.get('incident_rule'), 10)})"
    )
    checks = result.get("checks")
    for check in checks if isinstance(checks, list) else []:
        lines.append(f"  failed check: {_text(check, 100)}")
    if result.get("error"):
        lines.append(f"  error: {_text(result['error'], 40)}")
    lines.append(
        "Pipeline time only: add the wait until the next scheduled run and, for real provider "
        "usage, the provider's reporting delay."
    )
    return "\n".join(lines) + "\n"
