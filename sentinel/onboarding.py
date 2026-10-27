"""`sentinel init`: guided first-time setup (replaces hand-editing sentinel.toml).

Creates the config and state directory, detects GitHub repositories from Git remotes, stores the
GitHub token from a hidden prompt (never echoed, never printed, file permissions restricted), makes
sure `.sentinel/` and `sentinel.toml` are git-ignored, and finishes with the doctor checks.
All input/output goes through injected callables so the flow is testable.
"""

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sentinel import config, doctor, runner
from sentinel.security import load_key

GITIGNORE_ENTRIES = (".sentinel/", "sentinel.toml")
_REMOTE = re.compile(r"github\.com[:/]+([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$")
_TOKEN_OK = re.compile(r"^[A-Za-z0-9_\-]{20,255}$")


@dataclass
class InitOptions:
    config_path: Path
    home: Path
    root: Path  # where .gitignore lives (the repo this is run from)
    scan_paths: list[str] = field(default_factory=list)
    github_repos: list[str] = field(default_factory=list)
    user_keys: bool | None = None
    gcp_projects: list[str] = field(default_factory=list)
    interactive: bool = False
    force: bool = False
    gitignore: bool = True
    store_token: bool = False  # ask for the token with a hidden prompt (interactive only)


def detect_github_repo(path: Path) -> str | None:
    """owner/name from the origin remote of a Git repo, if it is on github.com."""
    try:
        proc = subprocess.run(  # noqa: S603 (fixed argv, no shell)
            ["git", "-C", str(path), "remote", "get-url", "origin"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = _REMOTE.search(proc.stdout.strip()) if proc.returncode == 0 else None
    return f"{match.group(1)}/{match.group(2)}" if match else None


def _toml_list(values: list[str]) -> str:
    # JSON string escaping is valid TOML basic-string escaping (handles quotes and backslashes).
    return "[" + ", ".join(json.dumps(v) for v in values) + "]"


def render_config(
    scan_paths: list[str],
    github_repos: list[str],
    user_keys: bool,
    gcp_projects: list[str],
) -> str:
    lines = [
        "# Local Sentinel config (git-ignored). No secrets here: the GitHub token lives in",
        "# <state dir>/github-token.txt or env SENTINEL_GITHUB_TOKEN. Created by `sentinel init`.",
        "first_run_lookback_days = 7",
        "",
        "[scan]",
        f"paths = {_toml_list(scan_paths)}",
        "",
        "[github]",
        f"repos = {_toml_list(github_repos)}",
        f"user_keys = {str(user_keys).lower()}",
        "",
    ]
    if gcp_projects:
        lines += [
            "[gcp]",
            f"projects = {_toml_list(gcp_projects)}",
            "usage_multiple = 3.0",
            "usage_floor = 50",
            "",
        ]
    lines += ["[alerts]", "toast = true", ""]
    return "\n".join(lines)


def ensure_gitignore(root: Path) -> list[str]:
    """Append missing entries to <root>/.gitignore. Returns what was added."""
    path = root / ".gitignore"
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    present = {line.strip() for line in existing.splitlines()}
    missing = [e for e in GITIGNORE_ENTRIES if e not in present]
    if missing:
        prefix = "" if not existing or existing.endswith("\n") else "\n"
        block = "# Sentinel local state and config (credential map, token file): never commit\n"
        path.write_text(existing + prefix + block + "\n".join(missing) + "\n", encoding="utf-8")
    return missing


def write_token(home: Path, token: str) -> Path:
    """Store the token with restricted permissions; ValueError (never echoing it) if malformed."""
    token = token.strip()
    if not _TOKEN_OK.fullmatch(token):
        raise ValueError(
            "that does not look like a token (20-255 letters, digits, '_' or '-', no spaces)"
        )
    home.mkdir(parents=True, exist_ok=True)
    path = home / runner.GITHUB_TOKEN_FILE
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best effort (Windows ACLs differ)
    return path


def run_init(
    opts: InitOptions,
    out: Callable[[str], None],
    ask: Callable[[str, str], str],
    ask_secret: Callable[[str], str],
) -> int:
    """Returns the exit code. `ask(question, default)` and `ask_secret(question)` read input."""
    if opts.config_path.exists() and not opts.force:
        out(f"{opts.config_path} already exists. Use --force to replace it (a .bak copy is kept).")
        return 1

    scan_paths = list(opts.scan_paths)
    if opts.interactive and not scan_paths:
        answer = ask("Folders to scan for secrets (comma separated)", str(opts.root))
        scan_paths = [p.strip() for p in answer.split(",") if p.strip()]
    scan_paths = scan_paths or [str(opts.root)]
    resolved = [Path(p).resolve().as_posix() for p in scan_paths]
    for p in resolved:
        if not Path(p).exists():
            out(f"warning: scan path does not exist: {p}")
        elif not (Path(p) / ".git").exists():
            out(f"note: {p} is not a Git repository (history scans and hygiene need Git)")

    repos = list(opts.github_repos)
    if not repos:
        detected = [r for p in resolved if (r := detect_github_repo(Path(p)))]
        if detected:
            out(
                "Detected GitHub repositories from Git remotes: " + ", ".join(sorted(set(detected)))
            )
        if opts.interactive:
            answer = ask(
                "GitHub repositories to watch (owner/name, comma separated)",
                ",".join(sorted(set(detected))),
            )
            repos = [r.strip() for r in answer.split(",") if r.strip()]
        else:
            repos = sorted(set(detected))
    try:
        repos = [config.validate_repo(r) for r in repos]
        projects = [config.validate_project(p) for p in opts.gcp_projects]
    except ValueError as exc:
        out(f"error: {exc}")
        return 1

    user_keys = opts.user_keys
    if user_keys is None:
        user_keys = (
            ask("Watch your account's SSH keys for new ones? (needs token permission) [y/N]", "n")
            .lower()
            .startswith("y")
            if opts.interactive
            else False
        )

    if opts.config_path.exists():
        shutil.copyfile(opts.config_path, opts.config_path.with_suffix(".toml.bak"))
    opts.config_path.write_text(
        render_config(resolved, repos, user_keys, projects), encoding="utf-8"
    )
    out(f"wrote {opts.config_path}")

    opts.home.mkdir(parents=True, exist_ok=True)
    load_key(opts.home)
    out(f"state directory ready: {opts.home}")

    if opts.gitignore:
        added = ensure_gitignore(opts.root)
        out(
            "added to .gitignore: " + ", ".join(added)
            if added
            else ".gitignore already covers Sentinel files"
        )

    if opts.store_token and opts.interactive and (repos or user_keys):
        out(
            "GitHub token: create a FINE-GRAINED, read-only token for the repos above "
            "(Contents: read, Metadata: read"
            + ("; Git SSH keys: read" if user_keys else "")
            + "). "
            "It is read from a hidden prompt and never shown."
        )
        secret = ask_secret("Paste the token (hidden, or press Enter to skip)")
        if secret.strip():
            try:
                path = write_token(opts.home, secret)
            except ValueError as exc:
                out(f"error: {exc}; token NOT saved")
            else:
                out(f"token saved to {path} (restricted permissions)")
    elif repos or user_keys:
        token_file = opts.home / runner.GITHUB_TOKEN_FILE
        out(f"GitHub token: set env {runner.GITHUB_TOKEN_ENV}, or save it in {token_file}")

    out("")
    out("Health check:")
    for check in doctor.run_checks(opts.home, opts.config_path, opts.root):
        out(f"  [{check.status.upper():<4}] {check.name}: {check.detail}")
    out("")
    out("Next: uv run sentinel run")
    return 0
