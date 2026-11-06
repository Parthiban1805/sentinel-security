"""Sentinel's side of the agent gateway (v0.7a, ADR-0016): kill switch, MCP allow-list file, and
the path normalisation shared with the gateway hook (for rule R9).

The gateway hook (docs/patches/agent-gateway) reads two files in the state directory, which agents
cannot write (state-directory rules):
  agent-kill-switch   present = every tool except reading is refused
  mcp-allowlist.json  present = only the listed MCP servers may be called (allow-list mode)
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.events.schema import format_time
from sentinel.security import fingerprint
from sentinel.store.db import Store

KILL_SWITCH_NAME = "agent-kill-switch"
MCP_ALLOWLIST_NAME = "mcp-allowlist.json"


def normalize_path(path: str, cwd: str = "") -> str:
    """Absolute, forward slashes, lower case on Windows. Must match _policy.normalize_path in the
    gateway hook exactly, so one file gets one fingerprint (tested against the hook's copy)."""
    text = os.path.expanduser(str(path))
    if not os.path.isabs(text):
        text = os.path.join(cwd or os.getcwd(), text)
    text = os.path.normpath(text).replace("\\", "/")
    return text.lower() if os.name == "nt" else text


def path_fingerprint(path: str, key: bytes) -> str:
    """The fingerprint the gateway records for a file target (same key, same algorithm)."""
    return fingerprint(normalize_path(path), key)


# --- kill switch ----------------------------------------------------------------------------------
def kill_switch_on(home: Path, actor: str, now: datetime) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / KILL_SWITCH_NAME
    path.write_text(
        json.dumps({"on_since": format_time(now), "by": actor}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def kill_switch_off(home: Path) -> bool:
    """Returns True if it was on. The caller must make sure a human is at the terminal."""
    path = home / KILL_SWITCH_NAME
    if not path.exists():
        return False
    path.unlink()
    return True


def kill_switch_status(home: Path) -> dict[str, Any] | None:
    path = home / KILL_SWITCH_NAME
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"on_since": "?"}
    except (OSError, ValueError):
        return {"on_since": "?"}  # present but unreadable: still on (the hook only checks presence)


# --- MCP allow-list -------------------------------------------------------------------------------
def mcp_allowlist(store: Store) -> dict[str, dict[str, str]]:
    """Approved MCP servers: name -> owner, pinned version, review date."""
    out: dict[str, dict[str, str]] = {}
    for a in store.assets():
        if a["asset_type"] != "mcp_server" or not a.get("approved"):
            continue
        attrs = a.get("attributes") or {}
        name = str(attrs.get("server") or a["name"])
        out[name] = {
            "owner": str(a.get("owner") or ""),
            "pinned_version": str(attrs.get("pinned_version") or ""),
            "reviewed": str(attrs.get("reviewed") or ""),
        }
    return out


def write_mcp_allowlist(store: Store, home: Path) -> Path | None:
    """Write the file the gateway reads. Once allow-list mode is on it STAYS on: unapproving the
    last server leaves an empty list (every MCP server blocked), never "no file" (every server
    allowed). Only `sentinel agent mcp-allowlist off`, run by a person, returns to record-only.
    Written to a temp file first, then swapped in."""
    path = home / MCP_ALLOWLIST_NAME
    servers = mcp_allowlist(store)
    if not servers and not path.exists():
        return None  # never enabled: stay in record-only mode
    home.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps({"servers": servers}, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(tmp, path)
    return path


def mcp_allowlist_off(home: Path) -> bool:
    """Back to record-only mode (every MCP server allowed and recorded). A person's decision: the
    caller must make sure a human is at the terminal. Returns True if allow-list mode was on."""
    path = home / MCP_ALLOWLIST_NAME
    if not path.exists():
        return False
    path.unlink()
    return True


# --- agent permission manifest (ADR-0024) ---------------------------------------------------------
MANIFEST_SOURCE = Path("policies") / "agent-manifest.toml"


def apply_manifest(
    home: Path, source: Path, workspace: Path, actor: str, now: datetime
) -> dict[str, Any]:
    """Validate the owner's TOML and write the compiled copy the gateway reads (temp file, then
    swap). A person's decision: the caller makes sure a human is at the terminal."""
    from sentinel import agentmanifest

    as_given = Path(
        os.path.abspath(home)
    ).parent  # the spelling the hook may see (subst, mapped drives)
    compiled: dict[str, Any] = agentmanifest.compile_manifest(
        source.read_bytes(),
        str(as_given),
        actor,
        now,
        source_path=str(source.resolve()),
        workspace_real=str(workspace),
    )
    home.mkdir(parents=True, exist_ok=True)
    path = home / agentmanifest.COMPILED_NAME
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(compiled, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return compiled


def manifest_off(home: Path) -> bool:
    """Remove the compiled manifest (the gateway's built-in rules alone apply again)."""
    from sentinel import agentmanifest

    path = home / agentmanifest.COMPILED_NAME
    if not path.exists():
        return False
    path.unlink()
    return True


def manifest_status(home: Path, source: Path, now: datetime) -> dict[str, Any]:
    """What the gateway enforces now, and whether the owner's TOML has drifted from it."""
    import hashlib

    from sentinel import agentmanifest

    state: dict[str, Any] = {"applied": False, "drift": None, "expired": None, "error": None}
    try:
        compiled = agentmanifest.load_compiled(str(home))
    except agentmanifest.ManifestError as exc:
        return {**state, "error": str(exc)}
    if compiled is None:
        state["source_present"] = source.is_file()
        return state
    expires = agentmanifest.parse_day(compiled["agent"].get("expires"))
    state.update(
        applied=True,
        agent=compiled["agent"]["id"],
        applied_by=compiled["applied_by"],
        applied_at=compiled["applied_at"],
        expires=expires.isoformat() if expires else None,
        expired=bool(expires and now.date() > expires),
    )
    recorded = Path(compiled["source_path"]) if compiled.get("source_path") else source
    state["source"] = str(recorded)
    if recorded.is_file():
        current = hashlib.sha256(recorded.read_bytes()).hexdigest()
        state["drift"] = current != compiled["source_sha256"]
    else:
        state["drift"] = True  # applied, but the source it came from is gone
    return state


def is_project_state_dir(home: Path) -> bool:
    """True when `home` is the .sentinel folder of a Claude Code project, which is where the
    gateway hook looks ($CLAUDE_PROJECT_DIR/.sentinel, unless SENTINEL_HOME is set)."""
    resolved = home.resolve()
    return resolved.name == ".sentinel" and (resolved.parent / ".claude").is_dir()
