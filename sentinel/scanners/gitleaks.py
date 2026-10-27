"""gitleaks wrapper. Raw secret values exist only inside parse(): they are fingerprinted at once.

gitleaks runs WITHOUT --redact so each key gets one stable keyed-hash ref (see ADR-0004).
Its JSON is read from stdout (never written to disk); `Secret`/`Match` are dropped before
anything else sees a finding. Logs go to stderr and contain no values.
"""

import json
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

from sentinel.security import fingerprint

EXCLUDED_PATHS = (
    r"node_modules/",
    r"(^|/)\.venv/",
    r"(^|/)venv/",
    r"site-packages/",
    r"__pycache__/",
    r"(^|/)(dist|build|target)/",
)


class ScanError(RuntimeError):
    """gitleaks missing or failed (message never contains scan output)."""


@dataclass(frozen=True)
class Finding:
    cred_ref: str  # "cred-fp-<hmac>"
    rule_id: str
    file: str
    line: int
    commit: str  # "" for working-tree findings
    date: str  # commit date (RFC 3339) or ""


def find_gitleaks() -> str:
    found = shutil.which("gitleaks")
    if found:
        return found
    candidates = sorted(
        Path.home().glob("AppData/Local/Microsoft/WinGet/Packages/Gitleaks*/gitleaks.exe")
    )
    if candidates:
        return str(candidates[0])
    raise ScanError("gitleaks not found on PATH")


def parse(raw_json: str, key: bytes) -> list[Finding]:
    """Turn gitleaks JSON into findings. The only function that touches secret values."""
    text = raw_json.strip()
    if not text:
        return []
    findings: list[Finding] = []
    for item in json.loads(text) or []:
        digest = fingerprint(item["Secret"], key)
        findings.append(
            Finding(
                cred_ref=f"cred-fp-{digest}",
                rule_id=item["RuleID"],
                file=str(item.get("File", "")).replace("\\", "/"),
                line=int(item.get("StartLine", 0)),
                commit=str(item.get("Commit", "")),
                date=str(item.get("Date", "")),
            )
        )
        item.clear()  # drop Secret/Match references promptly
    return findings


def _config_text() -> str:
    paths = ", ".join(f"'''{p}'''" for p in EXCLUDED_PATHS)
    return f"[extend]\nuseDefault = true\n[allowlist]\npaths = [{paths}]\n"


def run(
    target: Path, mode: str, key: bytes, work_dir: Path, *, timeout: int = 300
) -> list[Finding]:
    """Scan `target`. mode: "dir" (working tree) or "git" (all history, all refs)."""
    if mode not in ("dir", "git"):
        raise ValueError("mode must be 'dir' or 'git'")
    work_dir.mkdir(parents=True, exist_ok=True)
    config = work_dir / "gitleaks-scan.toml"
    config.write_text(_config_text(), encoding="utf-8")
    cmd = [
        find_gitleaks(),
        mode,
        "--no-banner",
        "--config",
        str(config),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--exit-code",
        "0",
    ]
    if mode == "git":
        cmd.append("--log-opts=--all")
    cmd.append(str(target))
    try:
        proc = subprocess.run(  # noqa: S603 (fixed argv, no shell)
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"gitleaks timed out after {timeout}s") from exc
    if proc.returncode != 0:
        raise ScanError(f"gitleaks exited with code {proc.returncode}")
    return _relativize(parse(proc.stdout, key), target)


def _relativize(found: list[Finding], target: Path) -> list[Finding]:
    """Working-tree hits carry absolute paths; make them repo-relative like history hits."""
    base = str(target.resolve()).replace("\\", "/").rstrip("/") + "/"
    out: list[Finding] = []
    for f in found:
        file = f.file
        for prefix in (base, str(target).replace("\\", "/").rstrip("/") + "/"):
            if file.startswith(prefix):
                file = file[len(prefix) :]
                break
        out.append(replace(f, file=file))
    return out
