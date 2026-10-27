"""`sentinel hygiene`: repo checks that prevent credential and CI mistakes (v0.4; S8/S9/S10).

Privacy by design: only file NAMES (git metadata) and CI workflow / config text are inspected. The
content of `.env` files, keys and other sensitive files is never read. Findings carry a check id, a
severity, a relative path and a short description. No network calls.
"""

import fnmatch
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel import dependencies
from sentinel.events.schema import make_event

SEVERITIES = ("low", "medium", "high")

# Tracked or exposed files that should never be committed (matched on the file name only).
SENSITIVE_NAMES = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials*.json",
    "service-account*.json",
    "service_account*.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "*.tfstate",
    "*.tfstate.backup",
)
SAFE_NAMES = (".env.example", ".env.sample", ".env.template", ".env.dist")
# Files that often embed secrets or whole repo contents.
DUMP_NAMES = (
    "repomix-output.*",
    "*.sql",
    "*.dump",
    "*.bak",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "*.har",
    "*.pcap",
)
# Probe paths: if the .gitignore would NOT ignore these, a careless `git add .` would commit them.
IGNORE_PROBES = (
    ".env",
    ".env.local",
    ".env.production",
    "server.key",
    "cert.pem",
    "credentials.json",
)

CHECKS = {
    "H1": "sensitive file is tracked by Git",
    "H2": "sensitive file is not tracked but not ignored (one `git add .` from being committed)",
    "H3": ".gitignore would not ignore common secret files",
    "H4": "no pre-commit secret scan configured",
    "H5": "no secret scan in CI",
    "H6": "dump or archive file that may embed secrets is tracked or not ignored",
    "W1": "GitHub Action not pinned to a full commit SHA",
    "W2": "pull_request_target workflow checks out untrusted pull request code",
    "W3": "workflow uses pull_request_target",
    "W4": "workflow has no permissions block (default token may be broad)",
    "W5": "workflow grants write-all permissions",
    "W6": "untrusted GitHub context used inside a run script (script injection)",
    "D1": "dependency name closely imitates a popular package (possible typosquat: HYPOTHESIS)",
    "D2": "dependency version is not pinned",
    "D3": "manifest has no lockfile",
    "D4": "install-time scripts can run code when dependencies are installed",
    "D5": "dependency comes from a URL, a git repository or a custom package index",
}

_SHA = re.compile(r"^[0-9a-f]{40}$")
_USES = re.compile(r"^\s*-?\s*uses:\s*([^\s@#]+)@([^\s#]+)", re.MULTILINE)
_RUN = re.compile(r"^(\s*)(-\s+)?run:\s*(.*)$")
_UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)"
    r"|comment\.body|review\.body|head_commit\.message|commits\S*\.message|discussion\.(title|body))"
    r"|head_ref)\s*\}\}"
)
_PR_HEAD = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref")


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    path: str  # repo-relative; "" for repo-level findings
    detail: str


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 (fixed argv, no shell)
        ["git", "-C", str(repo), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )


def _names(output: str) -> list[str]:
    return [p for p in output.split("\0") if p]


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name.lower(), p.lower()) for p in patterns)


def _is_sensitive(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return _matches(path, SENSITIVE_NAMES) and name.lower() not in SAFE_NAMES


def check_files(repo: Path) -> list[Finding]:
    tracked = _names(_git(repo, "ls-files", "-z").stdout)
    untracked = _names(_git(repo, "ls-files", "-z", "--others", "--exclude-standard").stdout)
    out: list[Finding] = []
    for path in tracked:
        if _is_sensitive(path):
            out.append(Finding("H1", "high", path, CHECKS["H1"]))
        elif _matches(path, DUMP_NAMES):
            out.append(Finding("H6", "medium", path, CHECKS["H6"] + " (tracked)"))
    for path in untracked:  # --exclude-standard already drops ignored files
        if _is_sensitive(path):
            out.append(Finding("H2", "high", path, CHECKS["H2"]))
        elif _matches(path, DUMP_NAMES):
            out.append(Finding("H6", "medium", path, CHECKS["H6"] + " (not ignored)"))
    return out


def check_gitignore(repo: Path) -> list[Finding]:
    gaps = [
        probe
        for probe in IGNORE_PROBES
        if _git(repo, "check-ignore", "-q", "--no-index", "--", probe).returncode != 0
    ]
    if not gaps:
        return []
    return [Finding("H3", "medium", ".gitignore", f"{CHECKS['H3']}: {', '.join(gaps)}")]


def check_scanning(repo: Path) -> list[Finding]:
    out: list[Finding] = []
    pre_commit = repo / ".pre-commit-config.yaml"
    hook = repo / ".git" / "hooks" / "pre-commit"
    configured = (
        pre_commit.exists()
        and "gitleaks" in pre_commit.read_text(encoding="utf-8", errors="ignore").lower()
    )
    if not configured:
        out.append(Finding("H4", "medium", ".pre-commit-config.yaml", CHECKS["H4"]))
    elif not hook.exists():
        out.append(
            Finding(
                "H4",
                "medium",
                ".git/hooks/pre-commit",
                "configured but not installed (pre-commit install)",
            )
        )
    workflows = sorted((repo / ".github" / "workflows").glob("*.y*ml"))
    scanners = ("gitleaks", "trufflehog", "detect-secrets", "secret-scan")
    if not any(
        any(s in w.read_text(encoding="utf-8", errors="ignore").lower() for s in scanners)
        for w in workflows
    ):
        out.append(Finding("H5", "low", ".github/workflows", CHECKS["H5"]))
    return out


def _injection_in_run_blocks(text: str) -> bool:
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        match = _RUN.match(lines[i])
        if not match:
            i += 1
            continue
        base = len(match.group(1)) + (len(match.group(2)) if match.group(2) else 0)
        inline = match.group(3).strip()
        block: list[str] = []
        if inline and inline[0] not in "|>":
            block.append(inline)
        j = i + 1
        while j < len(lines) and (
            not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > base
        ):
            block.append(lines[j])
            j += 1
        if _UNTRUSTED.search("\n".join(block)):
            return True
        i = max(j, i + 1)
    return False


def check_workflow(path: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for action, ref in _USES.findall(text):
        if action.startswith(("./", "docker://")) or _SHA.match(ref):
            continue
        out.append(Finding("W1", "medium", path, f"{CHECKS['W1']}: {action}@{ref}"))
    if re.search(r"\bpull_request_target\b", text):
        if _PR_HEAD.search(text) and "actions/checkout" in text:
            out.append(Finding("W2", "high", path, CHECKS["W2"]))
        else:
            out.append(Finding("W3", "medium", path, CHECKS["W3"]))
    if not re.search(r"^\s*permissions\s*:", text, re.MULTILINE):
        out.append(Finding("W4", "low", path, CHECKS["W4"]))
    if re.search(r"^\s*permissions\s*:\s*write-all\b", text, re.MULTILINE):
        out.append(Finding("W5", "high", path, CHECKS["W5"]))
    if _injection_in_run_blocks(text):
        out.append(Finding("W6", "high", path, CHECKS["W6"]))
    return out


def check_workflows(repo: Path) -> list[Finding]:
    out: list[Finding] = []
    for wf in sorted((repo / ".github" / "workflows").glob("*.y*ml")):
        rel = wf.relative_to(repo).as_posix()
        out += check_workflow(rel, wf.read_text(encoding="utf-8", errors="ignore"))
    return out


def check_dependencies(repo: Path) -> list[Finding]:
    info = dependencies.collect(repo)
    out: list[Finding] = []
    unpinned: dict[str, list[str]] = {}
    for dep in info.dependencies:
        if dependencies.is_url_dependency(dep):
            out.append(Finding("D5", "medium", dep.source, f"{CHECKS['D5']}: {dep.name[:60]}"))
            continue
        if not dep.dev:
            squat = dependencies.typosquat_of(dep.ecosystem, dep.name)
            if squat:
                out.append(
                    Finding(
                        "D1", "medium", dep.source, f"{CHECKS['D1']}: {dep.name} looks like {squat}"
                    )
                )
        # A lockfile pins the real versions, so ranges in the manifest are fine (not noise).
        if not dependencies.is_pinned(dep) and dep.source not in info.locked_manifests:
            unpinned.setdefault(dep.source, []).append(dep.name)
    for source, names in sorted(unpinned.items()):
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        out.append(Finding("D2", "low", source, f"{CHECKS['D2']}: {shown}"))
    for note in info.index_notes:
        source, _, text = note.partition(": ")
        out.append(Finding("D5", "medium", source, f"{CHECKS['D5']}: {text}"))
    for manifest in info.missing_lockfiles:
        out.append(Finding("D3", "medium", manifest, CHECKS["D3"]))
    for manifest, hooks in info.own_install_hooks.items():
        out.append(
            Finding(
                "D4",
                "medium",
                manifest,
                f"{CHECKS['D4']}: this project declares {', '.join(hooks)}",
            )
        )
    for lockfile, names in info.lockfile_install_scripts.items():
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        out.append(
            Finding(
                "D4", "low", lockfile, f"{CHECKS['D4']}: packages with install scripts: {shown}"
            )
        )
    return out


def scan_repo(repo: Path, ignore: tuple[str, ...] = ()) -> list[Finding]:
    """Run every check. `ignore` entries look like "H2:server/.env" or "W4:*"."""
    if not (repo / ".git").exists():
        return []
    found = (
        check_files(repo)
        + check_gitignore(repo)
        + check_scanning(repo)
        + check_workflows(repo)
        + check_dependencies(repo)
    )
    return [f for f in found if not _ignored(f, ignore)]


def _ignored(finding: Finding, ignore: tuple[str, ...]) -> bool:
    for entry in ignore:
        check, _, pattern = entry.partition(":")
        if check == finding.check and (not pattern or fnmatch.fnmatch(finding.path, pattern)):
            return True
    return False


def to_events(
    repo: Path, asset_id: str, findings: list[Finding], now: datetime, *, is_test: bool = False
) -> list[dict[str, Any]]:
    """One `config_drift` event per finding; deterministic ids make re-runs idempotent."""
    return [
        make_event(
            event_type="config_drift",
            source="hygiene",
            asset_id=asset_id,
            time=now,
            severity=f.severity,
            confidence="high",
            evidence_ref=f"hygiene/{f.check}/{f.path or 'repo'}",
            event_id=f"hygiene:{asset_id}:{f.check}:{f.path}",
            is_test=is_test,
            attributes={"check": f.check, "path": f.path, "detail": f.detail},
        )
        for f in findings
    ]


def format_findings(results: dict[str, list[Finding]]) -> str:
    lines: list[str] = []
    total = 0
    for repo, findings in results.items():
        lines.append(f"== {repo}: {len(findings)} finding(s)")
        for f in sorted(findings, key=lambda x: (-SEVERITIES.index(x.severity), x.check, x.path)):
            lines.append(f"  [{f.severity.upper():<6}] {f.check} {f.path or '(repo)'}: {f.detail}")
        total += len(findings)
    lines.append(f"{total} finding(s) in {len(results)} repo(s)")
    return "\n".join(lines) + "\n"


def results_json(results: dict[str, list[Finding]]) -> dict[str, Any]:
    return {repo: [asdict(f) for f in findings] for repo, findings in results.items()}
