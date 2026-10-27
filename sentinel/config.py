"""sentinel.toml loader (the file itself is git-ignored; see sentinel.example.toml)."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    scan_paths: tuple[str, ...] = ()
    github_repos: tuple[str, ...] = ()  # "owner/name"
    github_user_keys: bool = False
    gcp_projects: tuple[str, ...] = ()
    usage_multiple: float = 3.0  # usage anomaly: volume > max(multiple * baseline, floor)
    usage_floor: int = 50
    first_run_lookback_days: int = 7
    toast: bool = True
    extra: dict[str, object] = field(default_factory=dict)


def load(path: Path) -> Settings:
    if not path.exists():
        return Settings()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    scan = data.get("scan", {})
    gh = data.get("github", {})
    gcp = data.get("gcp", {})
    alerts = data.get("alerts", {})
    return Settings(
        scan_paths=tuple(scan.get("paths", [])),
        github_repos=tuple(gh.get("repos", [])),
        github_user_keys=bool(gh.get("user_keys", False)),
        gcp_projects=tuple(gcp.get("projects", [])),
        usage_multiple=float(gcp.get("usage_multiple", 3.0)),
        usage_floor=int(gcp.get("usage_floor", 50)),
        first_run_lookback_days=int(data.get("first_run_lookback_days", 7)),
        toast=bool(alerts.get("toast", True)),
    )
