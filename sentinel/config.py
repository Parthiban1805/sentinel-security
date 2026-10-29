"""sentinel.toml loader (the file itself is git-ignored; see sentinel.example.toml)."""

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProbeHost:
    base_url: str  # validated scheme://host[:port]
    allow_http: bool = False


def _probe_hosts(data: dict[str, Any]) -> tuple[ProbeHost, ...]:
    from sentinel import probes

    hosts: list[ProbeHost] = []
    for entry in data.get("probes", {}).get("hosts", []):
        url = str(entry.get("url", ""))
        if entry.get("confirm_ownership") is not True:
            raise ValueError(f"probes: confirm_ownership = true is required for {url!r}")
        allow_http = bool(entry.get("allow_http", False))
        hosts.append(ProbeHost(probes.normalize_target(url, allow_http=allow_http), allow_http))
    return tuple(hosts)


# Folders that hold credentials. Refused unless the owner sets `allow_credential_stores = true`:
# Sentinel would otherwise read and fingerprint real keys there (CLAUDE.md rule 2 spirit).
CREDENTIAL_STORE_NAMES = frozenset(
    {".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker", "gcloud"}
)


def validate_extra_path(raw: str, *, allow_credential_stores: bool = False) -> str:
    """An opt-in location outside Git (a log folder, a transcript, a history file).

    Strict on purpose: it is read by the secret scanner. Absolute only, no `..` segments, and
    after resolving links never a drive root, the home folder, or any folder that contains the
    home folder, so a typo cannot widen the scan to a disk or a profile. Messages carry only the
    final name, not the full path."""
    text = str(raw)
    name = Path(text).name or "(root)"
    if not text.strip() or text.startswith("-"):
        raise ValueError("scan.extra_paths: invalid path")
    path = Path(text)
    if not path.is_absolute():
        raise ValueError(f"scan.extra_paths: use an absolute path ({name})")
    if ".." in path.parts:
        raise ValueError(f"scan.extra_paths: '..' is not allowed ({name})")
    resolved = path.resolve()
    home = Path.home().resolve()
    if resolved.parent == resolved or resolved == home or resolved in home.parents:
        raise ValueError(f"scan.extra_paths: too broad, name a specific folder or file ({name})")
    if not allow_credential_stores and CREDENTIAL_STORE_NAMES & {p.lower() for p in resolved.parts}:
        raise ValueError(
            f"scan.extra_paths: {name} is inside a credential store; set "
            "allow_credential_stores = true only if you really want Sentinel to read it"
        )
    return text


@dataclass(frozen=True)
class Settings:
    scan_paths: tuple[str, ...] = ()
    extra_scan_paths: tuple[str, ...] = ()  # opt-in locations outside Git (S2); empty by default
    allow_credential_stores: bool = False  # explicit opt-in to scan ~/.ssh, ~/.aws and the like
    github_repos: tuple[str, ...] = ()  # "owner/name"
    github_user_keys: bool = False
    gcp_projects: tuple[str, ...] = ()
    usage_multiple: float = 3.0  # usage anomaly: volume > max(multiple * baseline, floor)
    usage_floor: int = 50
    first_run_lookback_days: int = 7
    toast: bool = True
    hygiene_ignore: tuple[str, ...] = ()  # "H2:server/.env" or "W4:*" (documented exceptions)
    probe_hosts: tuple[ProbeHost, ...] = ()  # hosts the owner confirmed they own
    probe_interval_hours: int = 24
    github_audit: bool = True  # branch protection / secret scanning audit of the watched repos
    github_audit_interval_hours: int = 24
    extra: dict[str, object] = field(default_factory=dict)


REPO_NAME = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{1,61}[a-z0-9]$")


def validate_repo(name: str) -> str:
    """GitHub 'owner/name'. Strict, because it is placed into request paths."""
    if not REPO_NAME.fullmatch(name) or ".." in name:
        raise ValueError(f"invalid GitHub repository (expected owner/name): {name!r}")
    return name


def validate_project(name: str) -> str:
    if not PROJECT_ID.fullmatch(name):
        raise ValueError(f"invalid Google Cloud project id: {name!r}")
    return name


def load(path: Path) -> Settings:
    if not path.exists():
        return Settings()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    scan = data.get("scan", {})
    allow_stores = scan.get("allow_credential_stores", False) is True
    gh = data.get("github", {})
    gcp = data.get("gcp", {})
    alerts = data.get("alerts", {})
    return Settings(
        scan_paths=tuple(scan.get("paths", [])),
        extra_scan_paths=tuple(
            validate_extra_path(p, allow_credential_stores=allow_stores)
            for p in scan.get("extra_paths", [])
        ),
        allow_credential_stores=allow_stores,
        github_repos=tuple(validate_repo(r) for r in gh.get("repos", [])),
        github_user_keys=bool(gh.get("user_keys", False)),
        gcp_projects=tuple(validate_project(p) for p in gcp.get("projects", [])),
        usage_multiple=float(gcp.get("usage_multiple", 3.0)),
        usage_floor=int(gcp.get("usage_floor", 50)),
        first_run_lookback_days=int(data.get("first_run_lookback_days", 7)),
        toast=bool(alerts.get("toast", True)),
        hygiene_ignore=tuple(data.get("hygiene", {}).get("ignore", [])),
        probe_hosts=_probe_hosts(data),
        probe_interval_hours=int(data.get("probes", {}).get("interval_hours", 24)),
        github_audit=bool(gh.get("audit", True)),
        github_audit_interval_hours=int(gh.get("audit_interval_hours", 24)),
    )
