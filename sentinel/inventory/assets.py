"""Asset discovery, import and inventory gap checks."""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.events.schema import format_time
from sentinel.store.db import Store

_SKIP_DIRS = {"node_modules", ".venv", "venv", "target", "dist", "build", "__pycache__"}


def asset_id_for(path: Path) -> str:
    return "repo-" + re.sub(r"[^a-z0-9]+", "-", path.resolve().name.lower()).strip("-")


def discover(store: Store, root: Path, now: datetime) -> list[str]:
    """Register every Git repository under `root` as an unowned asset. Returns new asset ids."""
    known = {a["asset_id"] for a in store.assets()}
    added: list[str] = []
    for current, dirs, _files in os.walk(root):
        if ".git" in dirs:
            dirs[:] = []  # do not descend into a repository
            repo = Path(current)
            asset_id = asset_id_for(repo)
            if asset_id in known:
                continue
            store.upsert_asset(
                {
                    "asset_id": asset_id,
                    "asset_type": "repository",
                    "name": repo.name,
                    "owner": None,
                    "importance": "medium",
                    "monitoring": "none",
                    "recovery_method": None,
                    "approved": False,
                    "last_seen": format_time(now),
                    "attributes": {"path": str(repo)},
                }
            )
            known.add(asset_id)
            added.append(asset_id)
        else:
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
    return added


def import_assets(store: Store, path: Path) -> int:
    records = json.loads(path.read_text(encoding="utf-8"))
    for record in records:
        store.upsert_asset(record)  # validates against the asset schema
    return len(records)


def gaps(store: Store) -> dict[str, list[str]]:
    assets: list[dict[str, Any]] = store.assets()
    return {
        "unowned": [a["asset_id"] for a in assets if not a.get("owner")],
        "unapproved": [a["asset_id"] for a in assets if not a.get("approved")],
        "unmonitored": [a["asset_id"] for a in assets if a.get("monitoring") == "none"],
    }
