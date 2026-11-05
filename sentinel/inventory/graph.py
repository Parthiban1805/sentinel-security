"""Asset graph: observed and documented edges, reach and reached-by (v0.7c, ADR-0018).

Nodes are inventory assets; edges are their `access_edges`. Every edge and every path is a
HYPOTHESIS of access until investigated: "could reach", never "reached".

- documented edge: a person recorded it (`inventory edge`), screened and audited.
- observed edge: a producer derived it from data Sentinel already reads. A producer only ever
  replaces its own observed edges (same `source`) on the asset it refreshes.
"""

import hashlib
import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.events.schema import format_time
from sentinel.redaction import check_free_text, looks_like_secret
from sentinel.store.db import Store

IMPORTANCE_ORDER = ("low", "medium", "high", "critical")
DEFAULT_DEPTH = 6
MAX_WORKFLOW_BYTES = 1_000_000

SOURCE_HUMAN = "human"
SOURCE_MCP = "mcp_config"
SOURCE_WORKFLOWS = "workflow_files"

MAX_WORKFLOW_FILES = 200
MAX_EXPRESSION_CHARS = 2000
WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})

# Applied only to bounded `${{ ... }}` bodies (see _expressions), never to the whole file.
_SECRET_DOT = re.compile(r"\bsecrets\.([A-Za-z0-9_\-]{1,200})")
_SECRET_INDEX = re.compile(r"\bsecrets\[\s*['\"]([^'\"]{1,200})['\"]\s*\]")
_SECRET_WHOLE = re.compile(r"\bsecrets\b(?!\s*[.\[])")  # e.g. toJSON(secrets)
_INHERIT = re.compile(r"secrets[ \t]*:[ \t]*inherit\b")  # reusable workflow call (stripped line)
_SAFE_SECRET_NAME = re.compile(r"^[A-Za-z0-9_]{1,100}$")


@dataclass(frozen=True)
class EdgeUpdate:
    added: int
    removed: int
    skipped: int  # edges to assets that are not in the inventory


@dataclass
class WorkflowScan:
    workflows: list[str] = field(default_factory=list)
    dropped_names: int = 0  # secret names refused as unsafe to store
    skipped_files: int = 0  # outside the repo, oversized, unreadable, over the cap, odd name
    collisions: int = 0  # id already used by a different asset: refused
    unscanned_expressions: int = 0  # `${{ }}` bodies over the cap: references may be missing
    over_cap: bool = False  # more files than MAX_WORKFLOW_FILES; the rest were not listed
    edges: EdgeUpdate | None = None

    def warnings(self) -> list[str]:
        out = []
        if self.over_cap:
            out.append(f"more than {MAX_WORKFLOW_FILES} workflow files; the rest were not read")
        if self.skipped_files:
            out.append(f"{self.skipped_files} workflow file(s) skipped (outside repo, size, cap)")
        if self.unscanned_expressions:
            out.append(
                f"{self.unscanned_expressions} oversize expression(s) not read; "
                "secret references may be missing"
            )
        if self.collisions:
            out.append(f"{self.collisions} workflow id collision(s) refused")
        if self.dropped_names:
            out.append(f"{self.dropped_names} secret name(s) not stored (unsafe shape)")
        return out


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "unnamed"


def _assets_by_id(store: Store) -> dict[str, dict[str, Any]]:
    return {a["asset_id"]: a for a in store.assets()}


def _edge_key(edge: dict[str, Any]) -> tuple[str, str]:
    return (edge["target_asset_id"], edge["permission"])


# writing edges -------------------------------------------------------------------
def set_observed_edges(
    store: Store,
    asset_id: str,
    source: str,
    edges: Iterable[tuple[str, str]],
    now: datetime,
) -> EdgeUpdate:
    """Replace `asset_id`'s observed edges from `source` with `edges` (target, permission).

    Documented edges and other producers' edges are kept. Targets not in the inventory are
    skipped and counted, never created. An audit entry is written only when the set changes."""
    assets = _assets_by_id(store)
    node = assets.get(asset_id)
    if node is None:
        raise KeyError(f"unknown asset: {asset_id}")
    stamp = format_time(now)
    wanted: dict[tuple[str, str], dict[str, Any]] = {}
    skipped = 0
    for target, permission in edges:
        if target not in assets:
            skipped += 1
            continue
        wanted[(target, permission)] = {
            "target_asset_id": target,
            "permission": permission,
            "origin": "observed",
            "source": source,
            "last_seen": stamp,
        }

    def owned(edge: dict[str, Any]) -> bool:
        return edge.get("origin") == "observed" and edge.get("source") == source

    current = list(node.get("access_edges") or [])
    before = {_edge_key(e) for e in current if owned(e)}
    kept = [e for e in current if not owned(e)]
    node["access_edges"] = sorted(
        kept + list(wanted.values()), key=lambda e: (e["target_asset_id"], e["permission"])
    )
    store.upsert_asset(node)  # validates against the asset schema
    added = len(set(wanted) - before)
    removed = len(before - set(wanted))
    if added or removed:
        store.add_audit(
            stamp,
            {
                "action": "edges_observed",
                "asset_id": asset_id,
                "source": source,
                "added": added,
                "removed": removed,
            },
        )
    return EdgeUpdate(added=added, removed=removed, skipped=skipped)


def add_documented_edge(
    store: Store, from_id: str, to_id: str, permission: str, actor: str, now: datetime
) -> dict[str, Any]:
    """A person records that `from_id` can reach `to_id` (screened, audited)."""
    permission = check_free_text("permission", permission) or ""
    actor = check_free_text("actor", actor) or ""
    if not permission.strip() or not actor.strip():
        raise ValueError("permission and actor are required")
    assets = _assets_by_id(store)
    for asset_id in (from_id, to_id):
        if asset_id not in assets:
            raise KeyError(f"unknown asset: {asset_id}")
    node = assets[from_id]
    stamp = format_time(now)
    edge = {
        "target_asset_id": to_id,
        "permission": permission,
        "origin": "documented",
        "source": SOURCE_HUMAN,
        "last_seen": stamp,
    }
    others = [
        e
        for e in node.get("access_edges") or []
        if not (e.get("origin") == "documented" and _edge_key(e) == (to_id, permission))
    ]
    node["access_edges"] = sorted(
        [*others, edge], key=lambda e: (e["target_asset_id"], e["permission"])
    )
    store.upsert_asset(node)
    store.add_audit(
        stamp,
        {
            "action": "edge_add",
            "from": from_id,
            "to": to_id,
            "permission": permission,
            "actor": actor,
        },
    )
    return edge


# queries -------------------------------------------------------------------------
def _adjacency(
    assets: dict[str, dict[str, Any]], reverse: bool
) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """node -> [(neighbour, edge)], sorted for determinism. Reverse = who points at node."""
    adj: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for asset_id, node in assets.items():
        for edge in node.get("access_edges") or []:
            target = edge["target_asset_id"]
            if reverse:
                adj.setdefault(target, []).append((asset_id, edge))
            else:
                adj.setdefault(asset_id, []).append((target, edge))
    for items in adj.values():
        # Documented before observed, so the path shown prefers what a person recorded.
        items.sort(
            key=lambda item: (item[0], item[1]["permission"], item[1]["origin"] != "documented")
        )
    return adj


def _link_edge(doc: dict[str, Any]) -> dict[str, Any]:
    return {"permission": doc["permission"], "origin": "documented", "source": SOURCE_HUMAN}


def _basis(origins: list[str]) -> str:
    unique = set(origins)
    return unique.pop() if len(unique) == 1 else "mixed"


def _walk(store: Store, start: str, max_depth: int, reverse: bool) -> dict[str, Any]:
    if max_depth < 1:
        raise ValueError("depth must be at least 1")
    assets = _assets_by_id(store)
    adj = _adjacency(assets, reverse)
    # A credential is not an asset: it reaches assets through human-confirmed links.
    links = sorted(store.docs("links"), key=lambda d: (d["asset_id"], d["permission"]))
    credentials = {d["cred_ref"] for d in links}
    if reverse:
        if start not in assets:
            if start in credentials:
                raise KeyError(
                    f"{start} is a credential: nothing is recorded as reaching it "
                    "(use `graph reach` for what it can reach)"
                )
            raise KeyError(f"unknown asset: {start}")
        for d in links:
            adj.setdefault(d["asset_id"], []).append((d["cred_ref"], _link_edge(d)))
            adj[d["asset_id"]].sort(key=lambda item: (item[0], item[1]["permission"]))
    elif start not in assets:
        own = [d for d in links if d["cred_ref"] == start]
        if not own:
            raise KeyError(f"unknown asset or unlinked credential: {start}")
        adj[start] = [(d["asset_id"], _link_edge(d)) for d in own]
    seen = {start}
    queue: deque[tuple[str, list[str], list[str]]] = deque([(start, [start], [])])
    nodes: list[dict[str, Any]] = []
    dangling: set[str] = set()
    truncated = False
    while queue:
        current, path, origins = queue.popleft()
        for neighbour, edge in adj.get(current, []):
            if neighbour in seen:
                continue
            is_credential = reverse and neighbour in credentials and neighbour not in assets
            if neighbour not in assets and not is_credential:
                dangling.add(neighbour)
                continue
            if len(path) > max_depth:
                truncated = True  # a real asset lies beyond the limit
                continue
            seen.add(neighbour)
            hop_origins = [*origins, edge["origin"]]
            hop_path = [*path, neighbour]
            info = assets.get(neighbour) or {"asset_type": "credential", "importance": None}
            nodes.append(
                {
                    "asset_id": neighbour,
                    "asset_type": info["asset_type"],
                    "importance": info.get("importance"),
                    "depth": len(hop_path) - 1,
                    "via": current,
                    "permission": edge["permission"],
                    "origin": edge["origin"],
                    "basis": _basis(hop_origins),
                    # Always in the direction of access: from the one that can reach.
                    "path": list(reversed(hop_path)) if reverse else hop_path,
                }
            )
            queue.append((neighbour, hop_path, hop_origins))
    nodes.sort(key=lambda n: (n["depth"], n["asset_id"]))
    ranks = [
        IMPORTANCE_ORDER.index(n["importance"])
        for n in nodes
        if n["importance"] in IMPORTANCE_ORDER
    ]
    return {
        "start": start,
        "direction": "reached_by" if reverse else "reach",
        "nodes": nodes,
        "dangling": sorted(dangling),
        "truncated": truncated,
        "max_importance": IMPORTANCE_ORDER[max(ranks)] if ranks else None,
        "hypothesis": True,  # paths show possible access, not observed use
    }


def reach(store: Store, start: str, max_depth: int = DEFAULT_DEPTH) -> dict[str, Any]:
    """What could `start` (an asset id or a linked credential ref) reach if compromised."""
    return _walk(store, start, max_depth, reverse=False)


def reached_by(store: Store, start: str, max_depth: int = DEFAULT_DEPTH) -> dict[str, Any]:
    """Which assets could reach `start`."""
    return _walk(store, start, max_depth, reverse=True)


# producers -----------------------------------------------------------------------
def refresh_agent_edges(
    store: Store, agent_id: str, server_ids: Iterable[str], now: datetime
) -> EdgeUpdate:
    """ai_agent -> mcp_server `can_call`: configured, which is not the same as called."""
    return set_observed_edges(
        store, agent_id, SOURCE_MCP, [(s, "can_call") for s in server_ids], now
    )


def workflow_asset_id(repo_asset_id: str, file_name: str) -> str:
    """Readable slug plus a hash of the exact (repository, file name): `deploy_.yml` and
    `deploy-.yml`, or repo `a` + `b-ci.yml` and repo `a-b` + `ci.yml`, never share an id."""
    digest = hashlib.sha256(f"{repo_asset_id}\0{file_name}".encode()).hexdigest()[:10]
    return f"wf-{repo_asset_id}-{_slug(file_name)}-{digest}"


@dataclass(frozen=True)
class SecretUse:
    names: list[str]  # safe names only, sorted
    uses_github_token: bool
    uses_all_secrets: bool  # `secrets: inherit`, `toJSON(secrets)`: names are not visible
    dropped: int  # names refused as unsafe to store
    unscanned: int  # expression bodies over the cap: not read, so references may be missing


def _expressions(text: str) -> tuple[list[str], int]:
    """(bodies of `${{ ... }}` expressions, number of oversize bodies not read).

    Plain string search only, so the cost is linear in the file size whatever the content (an
    agent can write a workflow file). The INNERMOST opener before each `}}` is used, so an
    unclosed `${{` earlier in the file cannot swallow a real expression that follows it."""
    bodies: list[str] = []
    unscanned = 0
    pos = 0
    while True:
        start = text.find("${{", pos)
        if start < 0:
            break
        end = text.find("}}", start + 3)
        if end < 0:
            break
        inner = text.rfind("${{", start, end)
        body = text[inner + 3 : end]
        if len(body) <= MAX_EXPRESSION_CHARS:
            bodies.append(body)
        else:
            unscanned += 1
        pos = end + 2
    return bodies, unscanned


def _secret_use(text: str) -> SecretUse:
    """Names only, never values. Regexes run on bounded expression bodies or line prefixes."""
    raw: set[str] = set()
    bodies, unscanned = _expressions(text)
    all_secrets = False
    for body in bodies:
        raw.update(_SECRET_DOT.findall(body))
        raw.update(_SECRET_INDEX.findall(body))
        all_secrets = all_secrets or bool(_SECRET_WHOLE.search(body))
    # Leading whitespace is stripped first, so padding cannot push `secrets: inherit` out of
    # the bounded prefix; a long trailing comment does not matter either.
    all_secrets = all_secrets or any(
        _INHERIT.match(line.lstrip(" \t")[:200]) for line in text.splitlines()
    )
    uses_token = "GITHUB_TOKEN" in raw
    raw.discard("GITHUB_TOKEN")
    safe = {n for n in raw if _SAFE_SECRET_NAME.fullmatch(n) and not looks_like_secret(n)}
    return SecretUse(sorted(safe), uses_token, all_secrets, len(raw) - len(safe), unscanned)


def _read_capped(path: Path) -> str | None:
    """At most MAX_WORKFLOW_BYTES; None if larger (read, not stat: the file can grow)."""
    with path.open("rb") as handle:
        data = handle.read(MAX_WORKFLOW_BYTES + 1)
    if len(data) > MAX_WORKFLOW_BYTES:
        return None
    return data.decode("utf-8", errors="ignore")


def _inside(path: Path, root: Path) -> bool:
    """True if `path` resolves inside `root` (catches symlinks and Windows junctions in any
    component, not only the last one)."""
    try:
        return path.resolve().is_relative_to(root)
    except OSError:
        return False


def discover_workflows(
    store: Store, repo_asset_id: str, repo_path: Path, now: datetime
) -> WorkflowScan:
    """Register each `.github/workflows/*.yml|*.yaml` as a ci_workflow asset and refresh the
    repository -> workflow edges. Owner, approval and importance set by a person are kept.

    Anything that resolves outside the repository, is too large, is past the file cap, has a
    credential-shaped name, or would overwrite a different asset is skipped and counted."""
    assets = _assets_by_id(store)
    if repo_asset_id not in assets:
        raise KeyError(f"unknown asset: {repo_asset_id}")
    scan = WorkflowScan()
    root = repo_path.resolve()
    folder = repo_path / ".github" / "workflows"
    files: list[Path] = []
    if folder.is_dir():
        if _inside(folder, root):
            # Stop collecting one past the cap: a folder with 100k files costs no more memory.
            for p in folder.iterdir():
                if p.suffix.lower() in WORKFLOW_SUFFIXES:
                    files.append(p)
                    if len(files) > MAX_WORKFLOW_FILES:
                        scan.over_cap = True
                        break
            files.sort()
        else:
            scan.skipped_files += 1  # the workflows folder leads outside the repository
    if len(files) > MAX_WORKFLOW_FILES:
        scan.skipped_files += len(files) - MAX_WORKFLOW_FILES
        files = files[:MAX_WORKFLOW_FILES]
    stamp = format_time(now)
    for wf in files:
        if wf.is_symlink() or not wf.is_file() or not _inside(wf, root):
            scan.skipped_files += 1  # never follow a link out of the repository
            continue
        if looks_like_secret(wf.name):
            scan.skipped_files += 1  # the file name itself is never stored if it looks secret
            continue
        try:
            text = _read_capped(wf)
        except OSError:
            text = None
        if text is None:
            scan.skipped_files += 1
            continue
        use = _secret_use(text)
        scan.dropped_names += use.dropped
        scan.unscanned_expressions += use.unscanned
        content = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        asset_id = workflow_asset_id(repo_asset_id, wf.name)
        relative = f".github/workflows/{wf.name}"
        existing = assets.get(asset_id) or {}
        if existing:
            attrs = existing.get("attributes") or {}
            if (
                existing.get("asset_type") != "ci_workflow"
                or attrs.get("repo") != repo_asset_id
                or attrs.get("file") != relative
            ):
                scan.collisions += 1  # never retype or take over another asset
                continue
        exposes = bool(use.names) or use.uses_all_secrets
        approved = bool(existing.get("approved", False))
        if approved and (existing.get("attributes") or {}).get("content_sha256") != content:
            # A reviewed workflow that changed is no longer the reviewed workflow (as for MCP).
            approved = False
            store.add_audit(
                stamp,
                {
                    "action": "workflow_approval_cleared",
                    "asset_id": asset_id,
                    "reason": "content changed",
                },
            )
        store.upsert_asset(
            {
                "asset_id": asset_id,
                "asset_type": "ci_workflow",
                "name": f"{assets[repo_asset_id]['name']}/{wf.name}",
                "owner": existing.get("owner"),
                "importance": existing.get("importance", "high" if exposes else "medium"),
                "monitoring": existing.get("monitoring", "partial"),
                "recovery_method": existing.get(
                    "recovery_method", "restore the last reviewed version of the workflow file"
                ),
                "approved": approved,
                "last_seen": stamp,
                "access_edges": existing.get("access_edges", []),
                "attributes": {
                    "repo": repo_asset_id,
                    "file": relative,
                    "content_sha256": content,  # prefix of the file hash: change detection only
                    "secret_refs": use.names,
                    "uses_github_token": use.uses_github_token,
                    "uses_all_secrets": use.uses_all_secrets,
                },
            }
        )
        scan.workflows.append(asset_id)
    scan.edges = set_observed_edges(
        store, repo_asset_id, SOURCE_WORKFLOWS, [(w, "runs_workflow") for w in scan.workflows], now
    )
    return scan


def refresh_repositories(store: Store, now: datetime) -> dict[str, WorkflowScan | str]:
    """Run the workflow producer for every repository asset with a local folder.
    Returns {asset id: scan, or an error text}; one broken repository never stops the rest."""
    results: dict[str, WorkflowScan | str] = {}
    for node in store.assets():
        if node["asset_type"] != "repository":
            continue
        path = (node.get("attributes") or {}).get("path")
        if not path:
            continue
        repo = Path(path)
        if not repo.is_dir():
            results[node["asset_id"]] = "folder not found"
            continue
        try:
            results[node["asset_id"]] = discover_workflows(store, node["asset_id"], repo, now)
        except (OSError, ValueError) as exc:
            results[node["asset_id"]] = type(exc).__name__
    return results
