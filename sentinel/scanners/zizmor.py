"""zizmor wrapper (v0.7e F3, ADR-0029): static analysis of GitHub Actions workflows (S8-S10).

zizmor (zizmorcore/zizmor, MIT) parses workflows as YAML and finds template injection, excessive
permissions, credential persistence (`artipacked`), dangerous triggers, impostor commits and more.
Sentinel's own W1-W6 checks are regex-only and stay as the fallback when zizmor is absent.

- Offline only: `--offline`, `ZIZMOR_OFFLINE=true`, and the GitHub token variables are removed from
  the child's environment (zizmor goes online by itself when one is set).
- Each finding keeps the audit name, a severity, a repo-relative path and a line. zizmor's
  `feature` (the workflow text) and `annotation` are dropped: a workflow line can hold a secret.
- No shell; the tool's output never appears in an error message.

Optional external tool, like gitleaks: found on PATH, reviewed version `PINNED_VERSION`.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sentinel.hygiene import Finding as HygieneFinding

PINNED_VERSION = "1.31.1"  # released 2026-10-15; reviewed for ADR-0029
TIMEOUT_SECONDS = 300
_TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN")
_OK_EXIT = {0, 11, 12, 13, 14}  # 0: no findings; 11-14: findings, by highest severity
_NO_INPUTS = 3
_SEVERITY = {"informational": "low", "low": "low", "medium": "medium", "high": "high"}
_RANK = {"low": 0, "medium": 1, "high": 2}
_AUDIT = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
# zizmor audits that Sentinel's regex checks already cover: no second alert on the same file.
COVERED_BY = {
    "unpinned-uses": ("W1",),
    "dangerous-triggers": ("W2", "W3"),
    "excessive-permissions": ("W4", "W5"),
    "template-injection": ("W6",),
}


class ZizmorError(RuntimeError):
    """zizmor failed or produced unreadable output (the message never contains its output)."""


@dataclass(frozen=True)
class ZFinding:
    audit: str
    severity: str  # low | medium | high
    path: str  # repo-relative, "/" separators
    line: int  # 1-based; 0 if unknown


def find_zizmor() -> str | None:
    return shutil.which("zizmor")


def version(exe: str) -> str:
    """The installed version ("1.31.1"), or "" if it cannot be read. Offline, no shell."""
    try:
        result = subprocess.run(  # noqa: S603 (fixed argv, no shell)
            [exe, "--version"],
            capture_output=True,
            text=True,
            check=False,
            env=_env(),
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    match = re.search(r"\b(\d+\.\d+\.\d+)\b", result.stdout)
    return match.group(1) if match else ""


def _env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.upper() not in _TOKEN_VARS}
    env["ZIZMOR_OFFLINE"] = "true"
    return env


def run(repo: Path, exe: str | None = None) -> str:
    """zizmor's JSON for the repository's workflows and actions. Raises ZizmorError."""
    exe = exe or find_zizmor()
    if not exe:
        raise ZizmorError("zizmor not found on PATH")
    try:
        result = subprocess.run(  # noqa: S603 (fixed argv, no shell)
            [exe, "--offline", "--format=json", str(repo)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env=_env(),
            timeout=TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ZizmorError(f"zizmor could not run ({type(exc).__name__})") from None
    if result.returncode == _NO_INPUTS:
        return "[]"  # no workflows or actions to audit
    if result.returncode not in _OK_EXIT:
        raise ZizmorError(f"zizmor failed with exit code {result.returncode}")
    return result.stdout


def _primary(item: dict[str, Any]) -> dict[str, Any]:
    locations = [loc for loc in item.get("locations") or [] if isinstance(loc, dict)]
    for loc in locations:
        if (loc.get("symbolic") or {}).get("kind") == "Primary":
            return loc
    return locations[0] if locations else {}


def _path(location: dict[str, Any], repo: Path) -> str:
    key = (location.get("symbolic") or {}).get("key") or {}
    local = key.get("Local") if isinstance(key, dict) else None
    raw = ""
    if isinstance(local, dict):
        raw = str(local.get("given_path") or local.get("verbatim_path") or "")
    if not raw:
        return ""
    path = Path(raw)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(repo.resolve())
        except ValueError:
            return path.name  # outside the repository: the file name only
    return path.as_posix()[:200]


def _line(location: dict[str, Any]) -> int:
    start = ((location.get("concrete") or {}).get("location") or {}).get("start_point") or {}
    row = start.get("row")
    return row + 1 if isinstance(row, int) and row >= 0 else 0  # json-v1 rows are 0-based


def parse(raw_json: str, repo: Path) -> list[ZFinding]:
    """zizmor json-v1 -> findings. Keeps only audit, severity, path and line."""
    text = raw_json.strip()
    if not text:
        return []
    try:
        items = json.loads(text)
    except json.JSONDecodeError:
        raise ZizmorError("zizmor output is not JSON") from None
    if not isinstance(items, list):
        raise ZizmorError("zizmor output is not a list of findings")
    out: list[ZFinding] = []
    for item in items:
        if not isinstance(item, dict) or item.get("ignored") is True:
            continue
        ident = item.get("ident")
        audit = ident if isinstance(ident, str) and _AUDIT.fullmatch(ident) else "unknown"
        level = str((item.get("determinations") or {}).get("severity", "")).lower()
        location = _primary(item)
        out.append(ZFinding(audit, _SEVERITY.get(level, "medium"), _path(location, repo),
                            _line(location)))  # fmt: skip
    return out


def to_hygiene(
    findings: Iterable[ZFinding], existing: Iterable[HygieneFinding]
) -> list[HygieneFinding]:
    """One hygiene finding per (audit, file), at the highest severity, check id `ZZ-<audit>`.
    A finding that a regex check (W1-W6) already raised on the same file is not repeated."""
    from sentinel.hygiene import Finding

    raised = {(f.check, f.path) for f in existing}
    groups: dict[tuple[str, str], list[ZFinding]] = {}
    for f in findings:
        if any((w, f.path) in raised for w in COVERED_BY.get(f.audit, ())):
            continue
        groups.setdefault((f.audit, f.path), []).append(f)
    out: list[Finding] = []
    for (audit, path), group in sorted(groups.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        severity = max((f.severity for f in group), key=_RANK.__getitem__)
        lines = sorted({f.line for f in group if f.line})
        where = f" (lines {', '.join(map(str, lines[:10]))})" if lines else ""
        detail = f"zizmor audit '{audit}'{where}: see https://docs.zizmor.sh/audits/"
        out.append(Finding(f"ZZ-{audit}", severity, path, detail))
    return out
