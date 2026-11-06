"""gitleaks wrapper. Raw secret values exist only inside parse(): they are fingerprinted at once.

gitleaks runs WITHOUT --redact so each key gets one stable keyed-hash ref (see ADR-0004).
Its JSON is read from stdout (never written to disk); `Secret`/`Match` are dropped before
anything else sees a finding. Logs go to stderr and contain no values.
"""

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

from sentinel.security import fingerprint

# Working-tree scans skip dependency/build/state folders (noise, and the state dir holds the
# user's own token file by design). History scans exclude NOTHING: a secret committed under
# build/ or target/, or a committed .sentinel/ directory, is a real exposure.
WORKING_TREE_EXCLUDES = (
    r"(^|/)\.sentinel/",
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


def _config_text(mode: str) -> str:
    if mode == "git":
        return "[extend]\nuseDefault = true\n"
    paths = ", ".join(f"'''{p}'''" for p in WORKING_TREE_EXCLUDES)
    return f"[extend]\nuseDefault = true\n[allowlist]\npaths = [{paths}]\n"


def _child_env() -> dict[str, str]:
    """gitleaks does not need our tokens. An inherited GIT_DIR, GIT_WORK_TREE or GIT_INDEX_FILE
    would make its `git log` read another repository than the target: every GIT_* is dropped."""
    return {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("SENTINEL_") and not k.startswith("GIT_")
    }


def run(
    target: Path, mode: str, key: bytes, work_dir: Path, *, timeout: int = 300
) -> list[Finding]:
    """Scan `target`. mode: "dir" (working tree) or "git" (all history, all refs)."""
    if mode not in ("dir", "git"):
        raise ValueError("mode must be 'dir' or 'git'")
    if str(target).startswith("-"):
        raise ValueError("scan target must not start with '-'")
    work_dir.mkdir(parents=True, exist_ok=True)
    config = work_dir / f"gitleaks-scan-{mode}.toml"
    config.write_text(_config_text(mode), encoding="utf-8")
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
            cmd, capture_output=True, text=True, timeout=timeout, check=False, env=_child_env()
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"gitleaks timed out after {timeout}s") from exc
    if proc.returncode != 0:
        raise ScanError(f"gitleaks exited with code {proc.returncode}")
    found = _relativize(parse(proc.stdout, key), target)
    if mode == "dir":
        found += _scan_json_files(
            target, key, config, timeout, {(f.cred_ref, f.file) for f in found}
        )
    return found


# --- JSON-escaped secrets (scenario S2) ---------------------------------------------------
# gitleaks misses a key wrapped in JSON-escaped quotes (nested JSON in agent transcripts and
# logs). We decode the JSON strings in memory and feed the decoded text to `gitleaks stdin`, so
# nothing extra is written to disk.
_JSON_SUFFIXES = {".json", ".jsonl"}
_MAX_JSON_BYTES = 20 * 1024 * 1024
_SKIP_DIRS = {
    ".git",
    ".sentinel",
    "node_modules",
    ".venv",
    "venv",
    "site-packages",
    "__pycache__",
    "dist",
    "build",
    "target",
}


def _json_strings(value: object, depth: int = 0) -> Iterator[str]:
    """Yield every string inside a JSON value, also decoding strings that hold JSON."""
    if isinstance(value, str):
        yield value
        stripped = value.strip()
        if depth < 4 and stripped[:1] in ("{", "["):
            try:
                yield from _json_strings(json.loads(stripped), depth + 1)
            except json.JSONDecodeError:
                pass
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _json_strings(v, depth)
    elif isinstance(value, list):
        for item in value:
            yield from _json_strings(item, depth)


def decoded_json_text(raw: str) -> str:
    """Decoded string values of a .json/.jsonl document, one per line ('' if not JSON)."""
    docs: list[object] = []
    for line in raw.splitlines():
        line = line.strip()
        if line[:1] in ("{", "["):
            try:
                docs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not docs:
        try:
            docs.append(json.loads(raw))
        except json.JSONDecodeError:
            return ""
    return "\n".join(s for doc in docs for s in _json_strings(doc))


@dataclass(frozen=True)
class Coverage:
    """What a working-tree scan could not look at. A scan with gaps must not read as clean."""

    unreadable: int = 0  # files or folders that raised a permission or I/O error
    symlinks: int = 0  # not followed: they could lead outside the listed scope
    oversized_json: int = 0  # .json/.jsonl over the decoding limit (plain scanning still applies)

    @property
    def gaps(self) -> int:
        return self.unreadable + self.symlinks + self.oversized_json

    def describe(self) -> str:
        return (
            f"{self.unreadable} unreadable, {self.symlinks} symlink(s) not followed, "
            f"{self.oversized_json} JSON file(s) over {_MAX_JSON_BYTES // (1024 * 1024)} MB"
        )


def coverage(target: Path) -> Coverage:
    """Walk what a `dir` scan would visit and count what it cannot read (no file is read past
    its first byte). Raises ValueError when the location itself is not readable."""
    unreadable = symlinks = oversized = 0
    if target.is_file():
        candidates: Iterator[Path] = iter([target])
    else:
        if not os.access(target, os.R_OK | os.X_OK):
            raise ValueError("the scan location is not readable")

        def on_error(_exc: OSError) -> None:
            nonlocal unreadable
            unreadable += 1

        def walk() -> Iterator[Path]:
            for current, dirs, files in os.walk(target, onerror=on_error):
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                for name in files:
                    yield Path(current) / name

        candidates = walk()
    for path in candidates:
        if path.is_symlink():
            symlinks += 1
            continue
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                handle.read(1)
        except OSError:
            unreadable += 1
            continue
        if path.suffix.lower() in _JSON_SUFFIXES and size > _MAX_JSON_BYTES:
            oversized += 1
    return Coverage(unreadable, symlinks, oversized)


def scan_base(target: Path) -> Path:
    """Folder that finding paths are made relative to (a single file reports its own name)."""
    return target.parent if target.is_file() else target


def _iter_json_files(target: Path) -> Iterator[Path]:
    if target.is_file():
        if target.suffix.lower() in _JSON_SUFFIXES:
            yield target
        return
    for current, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            if path.suffix.lower() in _JSON_SUFFIXES and not path.is_symlink():
                yield path  # a symlink could pull in content from outside the listed scope


def _scan_json_files(
    target: Path, key: bytes, config: Path, timeout: int, seen: set[tuple[str, str]]
) -> list[Finding]:
    cmd = [
        find_gitleaks(), "stdin", "--no-banner", "--config", str(config),
        "--report-format", "json", "--report-path", "-", "--exit-code", "0",
    ]  # fmt: skip
    out: list[Finding] = []
    base = scan_base(target).resolve()
    for path in _iter_json_files(target):
        try:
            if path.stat().st_size > _MAX_JSON_BYTES:
                continue
            decoded = decoded_json_text(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        if not decoded:
            continue
        try:
            proc = subprocess.run(  # noqa: S603 (fixed argv, no shell)
                cmd, input=decoded, capture_output=True, text=True, timeout=timeout,
                check=False, env=_child_env(),
            )  # fmt: skip
        except subprocess.TimeoutExpired as exc:
            raise ScanError(f"gitleaks timed out after {timeout}s") from exc
        if proc.returncode != 0:
            raise ScanError(f"gitleaks exited with code {proc.returncode}")
        try:
            rel = path.resolve().relative_to(base).as_posix()
        except ValueError:  # resolves outside the scanned folder: skip it, never echo the paths
            continue
        for f in parse(proc.stdout, key):
            if (f.cred_ref, rel) not in seen:
                seen.add((f.cred_ref, rel))
                out.append(replace(f, file=rel, line=0))
    return out


def _relativize(found: list[Finding], target: Path) -> list[Finding]:
    """Working-tree hits carry absolute paths; make them repo-relative like history hits."""
    folder = scan_base(target)
    base = str(folder.resolve()).replace("\\", "/").rstrip("/") + "/"
    out: list[Finding] = []
    for f in found:
        file = f.file
        for prefix in (base, str(folder).replace("\\", "/").rstrip("/") + "/"):
            if file.startswith(prefix):
                file = file[len(prefix) :]
                break
        out.append(replace(f, file=file))
    return out
