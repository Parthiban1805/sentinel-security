"""Links between credentials and assets, and blast-radius analysis.

Confirmed access = a human linked the credential to an asset. Possible access = reachable through
asset access_edges from a confirmed asset (a hypothesis until investigated).
"""

from collections import deque
from datetime import datetime
from typing import Any

from sentinel.events.schema import format_time
from sentinel.store.db import Store

IMPORTANCE_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def link(
    store: Store, cred_ref: str, asset_id: str, permission: str, actor: str, now: datetime
) -> dict[str, Any]:
    if not any(a["asset_id"] == asset_id for a in store.assets()):
        raise KeyError(f"unknown asset: {asset_id}")
    doc = {
        "cred_ref": cred_ref,
        "asset_id": asset_id,
        "permission": permission,
        "origin": "documented",
        "confirmed_by": actor,
        "time": format_time(now),
    }
    store.put_doc("links", f"{cred_ref}|{asset_id}", doc)
    store.add_audit(format_time(now), {"action": "link", **doc})
    return doc


def blast_radius(store: Store, cred_ref: str) -> dict[str, Any]:
    assets = {a["asset_id"]: a for a in store.assets()}
    finding = store.get_doc("findings", cred_ref)
    exposed_in = sorted({loc["asset_id"] for loc in finding["locations"]}) if finding else []
    confirmed = []
    queue: deque[str] = deque()
    seen: set[str] = set()
    for doc in store.docs("links"):
        if doc["cred_ref"] != cred_ref:
            continue
        asset = assets.get(doc["asset_id"], {})
        confirmed.append(
            {
                "asset_id": doc["asset_id"],
                "permission": doc["permission"],
                "importance": asset.get("importance", "medium"),
                "confirmed_by": doc["confirmed_by"],
            }
        )
        seen.add(doc["asset_id"])
        queue.append(doc["asset_id"])
    possible = []
    while queue:
        current = queue.popleft()
        for edge in assets.get(current, {}).get("access_edges", []):
            target = edge["target_asset_id"]
            if target in seen:
                continue
            seen.add(target)
            queue.append(target)
            possible.append(
                {
                    "asset_id": target,
                    "via": current,
                    "permission": edge["permission"],
                    "origin": edge["origin"],
                    "importance": assets.get(target, {}).get("importance", "medium"),
                }
            )
    ranked = [IMPORTANCE_RANK.get(x["importance"], 2) for x in confirmed + possible]
    if not ranked:
        ranked = [
            IMPORTANCE_RANK.get(assets.get(a, {}).get("importance", "medium"), 2)
            for a in exposed_in
        ]
    return {
        "cred_ref": cred_ref,
        "exposed_in": exposed_in,
        "confirmed_access": confirmed,
        "possible_access": possible,
        "max_importance_rank": max(ranked) if ranked else 0,
        "unlinked": not confirmed,
    }
