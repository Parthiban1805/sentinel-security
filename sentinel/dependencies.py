"""Dependency checks (scenario S7). Offline and read-only: manifests and lockfiles are parsed as text.

Heuristics only. A typosquat finding is a HYPOTHESIS (some near-identical names are legitimate); it
flags a package for a human to look at. No network calls, no package is ever installed or imported.
"""

import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.events.schema import make_event

PYPI_POPULAR = frozenset(
    """requests urllib3 numpy pandas boto3 botocore setuptools pip wheel certifi idna charset-normalizer
    typing-extensions python-dateutil six pyyaml cryptography packaging s3transfer jmespath pytz attrs
    aiohttp pydantic jsonschema click flask django jinja2 markupsafe werkzeug sqlalchemy psycopg2 pytest
    scipy matplotlib pillow tqdm protobuf grpcio google-auth rsa pyasn1 colorama openpyxl beautifulsoup4
    lxml httpx fastapi uvicorn starlette redis celery scikit-learn tensorflow torch transformers openai
    anthropic langchain mypy ruff black tomli pluggy iniconfig filelock platformdirs virtualenv docutils
    pygments rich paramiko pexpect regex orjson ujson gunicorn selenium""".split()
)
NPM_POPULAR = frozenset(
    """react react-dom lodash express axios moment chalk commander debug typescript webpack eslint prettier
    jest mocha vue next tailwindcss postcss autoprefixer uuid dotenv cors body-parser mongoose mongodb mysql
    mysql2 pg redis socket.io jsonwebtoken bcrypt bcryptjs passport nodemon rimraf glob minimist yargs async
    request bluebird underscore jquery bootstrap rxjs core-js tslib vite rollup esbuild ts-node supertest
    cross-env concurrently inquirer ora semver fs-extra node-fetch ws nanoid zod dayjs date-fns classnames
    prop-types redux react-router react-router-dom styled-components""".split()
)
_POPULAR = {"pypi": PYPI_POPULAR, "npm": NPM_POPULAR}
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"})
_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")
_PYPI_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


@dataclass(frozen=True)
class Dependency:
    ecosystem: str  # "pypi" | "npm"
    name: str  # normalized
    spec: str
    source: str  # repo-relative manifest path
    dev: bool = False


def normalize(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


# parsers ----------------------------------------------------------------------------------------
def parse_requirements(text: str, source: str) -> tuple[list[Dependency], list[str]]:
    """Returns (dependencies, extra notes such as an extra index URL)."""
    deps: list[Dependency] = []
    notes: list[str] = []
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("--extra-index-url", "--index-url", "-i ", "--find-links", "-f ")):
            notes.append(f"{source}: custom package index/location ({line.split()[0]})")
            continue
        if line.startswith(("-r", "-c", "--")):
            continue
        if line.startswith(("-e", "git+", "http://", "https://")):
            deps.append(Dependency("pypi", line, line, source))
            continue
        match = _PYPI_NAME.match(line.split(";", 1)[0])
        if match:
            deps.append(
                Dependency(
                    "pypi", normalize("pypi", match.group(1)), match.group(3).strip(), source
                )
            )
    return deps, notes


def _pep508(requirement: str, source: str, dev: bool = False) -> Dependency | None:
    match = _PYPI_NAME.match(requirement.split(";", 1)[0])
    if not match:
        return None
    return Dependency(
        "pypi", normalize("pypi", match.group(1)), match.group(3).strip(), source, dev
    )


def parse_pyproject(text: str, source: str) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    deps: list[Dependency] = []
    project = data.get("project", {})
    for req in project.get("dependencies", []):
        if dep := _pep508(req, source):
            deps.append(dep)
    for reqs in project.get("optional-dependencies", {}).values():
        deps += [d for r in reqs if (d := _pep508(r, source, dev=True))]
    for reqs in data.get("dependency-groups", {}).values():
        deps += [d for r in reqs if isinstance(r, str) and (d := _pep508(r, source, dev=True))]
    poetry = data.get("tool", {}).get("poetry", {})
    for name, spec in poetry.get("dependencies", {}).items():
        if name.lower() != "python":
            deps.append(Dependency("pypi", normalize("pypi", name), str(spec), source))
    return deps


def parse_package_json(text: str, source: str) -> tuple[list[Dependency], list[str]]:
    """Returns (dependencies, install-hook script names declared by this project itself)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], []
    if not isinstance(data, dict):
        return [], []
    deps: list[Dependency] = []
    for section, dev in (
        ("dependencies", False),
        ("optionalDependencies", False),
        ("devDependencies", True),
    ):
        for name, spec in (data.get(section) or {}).items():
            deps.append(Dependency("npm", normalize("npm", name), str(spec), source, dev))
    hooks = [h for h in _INSTALL_HOOKS if h in (data.get("scripts") or {})]
    return deps, hooks


def lockfile_install_script_packages(text: str) -> list[str]:
    """npm lockfile v2/v3: packages that run install scripts (`hasInstallScript`)."""
    try:
        packages = json.loads(text).get("packages", {})
    except (json.JSONDecodeError, AttributeError):
        return []
    names = []
    for path, meta in packages.items():
        if path and isinstance(meta, dict) and meta.get("hasInstallScript"):
            names.append(path.rsplit("node_modules/", 1)[-1])
    return sorted(set(names))


# heuristics ---------------------------------------------------------------------------------------
def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (insert, delete, substitute, adjacent transposition)."""
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[len(a)][len(b)]


def typosquat_of(ecosystem: str, name: str) -> str | None:
    """The popular package this name imitates, or None. HYPOTHESIS: some matches are legitimate."""
    popular = _POPULAR[ecosystem]
    if name in popular or name.startswith(("@", "git+", "http", "-e")) or "/" in name:
        return None
    homoglyph = name.translate(_HOMOGLYPHS)
    for candidate in sorted(popular):
        if len(candidate) < 5:
            continue  # short names are too close to many unrelated names
        if homoglyph == candidate and name != candidate:
            return candidate
        if abs(len(name) - len(candidate)) <= 1 and edit_distance(name, candidate) == 1:
            return candidate
    return None


def is_pinned(dep: Dependency) -> bool:
    if dep.ecosystem == "pypi":
        return dep.spec.startswith(("==", "==="))
    return bool(re.fullmatch(r"v?\d+\.\d+\.\d+([-+][\w.+-]*)?", dep.spec.strip()))


def is_url_dependency(dep: Dependency) -> bool:
    spec = dep.spec.lower()
    return (
        spec.startswith(("git+", "git:", "http://", "https://", "github:", "file:", "-e"))
        or bool(
            re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", spec)  # npm "owner/repo" shorthand
        )
        or dep.name.startswith(("git+", "http", "-e"))
    )


# repo level ---------------------------------------------------------------------------------------
@dataclass
class RepoDependencies:
    dependencies: list[Dependency]
    index_notes: list[str]
    own_install_hooks: dict[str, list[str]]  # manifest -> hook names
    lockfile_install_scripts: dict[str, list[str]]  # lockfile -> package names
    missing_lockfiles: list[str]  # manifests with no lockfile next to them
    locked_manifests: set[str] = field(default_factory=set)  # a lockfile pins their versions


# Install scripts that are ubiquitous and widely audited: reporting them only adds noise.
COMMON_INSTALL_SCRIPTS = frozenset({"fsevents", "esbuild"})


_SKIP_DIRS = {
    "node_modules",
    ".venv",
    "venv",
    ".git",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".sentinel",
}


def _manifests(repo: Path) -> list[Path]:
    found: list[Path] = []
    for path in repo.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.relative_to(repo).parts):
            continue
        name = path.name
        if path.is_file() and (
            name in ("package.json", "pyproject.toml") or re.fullmatch(r"requirements.*\.txt", name)
        ):
            found.append(path)
    return sorted(found)


def collect(repo: Path) -> RepoDependencies:
    result = RepoDependencies([], [], {}, {}, [])
    for path in _manifests(repo):
        rel = path.relative_to(repo).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        folder = path.parent
        if path.name == "package.json":
            deps, hooks = parse_package_json(text, rel)
            result.dependencies += deps
            if hooks:
                result.own_install_hooks[rel] = hooks
            locks = [folder / n for n in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")]
            if deps and not any(lock.exists() for lock in locks):
                result.missing_lockfiles.append(rel)
            elif any(lock.exists() for lock in locks):
                result.locked_manifests.add(rel)
            lock_json = folder / "package-lock.json"
            if lock_json.exists():
                names = lockfile_install_script_packages(
                    lock_json.read_text(encoding="utf-8", errors="ignore")
                )
                names = [n for n in names if n not in COMMON_INSTALL_SCRIPTS]
                if names:
                    result.lockfile_install_scripts[lock_json.relative_to(repo).as_posix()] = names
        elif path.name == "pyproject.toml":
            deps = parse_pyproject(text, rel)
            result.dependencies += deps
            has_lock = any(
                (folder / n).exists()
                for n in ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock")
            )
            if deps and not has_lock:
                result.missing_lockfiles.append(rel)
            elif has_lock:
                result.locked_manifests.add(rel)
        else:
            deps, notes = parse_requirements(text, rel)
            result.dependencies += deps
            result.index_notes += notes
    return result


# dependency_added events --------------------------------------------------------------------------
def snapshot_key(asset_id: str) -> str:
    return f"deps:{asset_id}"


def new_dependency_events(
    asset_id: str, deps: list[Dependency], previous: dict[str, Any] | None, now: datetime
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Diff against the stored snapshot. The first run only records a baseline (no events)."""
    current = sorted({f"{d.ecosystem}:{d.name}" for d in deps})
    snapshot = {"names": current, "time": now.isoformat()}
    if previous is None:
        return [], snapshot
    added = sorted(set(current) - set(previous["names"]))
    by_name = {f"{d.ecosystem}:{d.name}": d for d in deps}
    events = []
    for key in added[:50]:  # cap: a bulk change is reported by hygiene, not as 500 events
        dep = by_name[key]
        squat = typosquat_of(dep.ecosystem, dep.name)
        events.append(
            make_event(
                event_type="dependency_added",
                source="dependencies",
                asset_id=asset_id,
                time=now,
                severity="medium" if squat else "info",
                confidence="low" if squat else "high",
                evidence_ref=f"deps/{dep.source}",
                event_id=f"dep:{asset_id}:{key}",
                attributes={
                    "ecosystem": dep.ecosystem,
                    "name": dep.name,
                    "spec": dep.spec[:80],
                    "manifest": dep.source,
                    "typosquat_of": squat,  # hypothesis, not a verdict
                    "dev": dep.dev,
                },
            )
        )
    return events, snapshot
