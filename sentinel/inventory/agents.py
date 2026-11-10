"""AI agent and MCP server inventory (v0.3b, ADR-0012).

One `ai_agent` asset per workspace (the project the hooks log for) and one `mcp_server` asset per
server in the project's `.mcp.json`. Only the server name, transport, host and command basename are
kept: env values, headers and arguments are dropped before anything is stored (they can hold
credentials). Servers configured at user scope are not visible: that configuration holds
credentials and is off limits, so such servers count as "not approved" for rule R5c.
"""

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sentinel import mcppin
from sentinel.events.schema import format_time
from sentinel.store.db import Store

MCP_CONFIG = ".mcp.json"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SAFE_COMMAND = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TRANSPORTS = frozenset({"stdio", "http", "sse"})
# Attributes a person sets with `inventory set` (reviewed version and date, pinned tool list,
# trusted source for the output guard). Rediscovery keeps them.
_PERSON_SET = ("pinned_version", "reviewed", "tools", "trusted")
# Cleared with an approval when the launch settings change (the tool list stays: it only narrows).
_STALE_ON_CHANGE = ("pinned_version", "reviewed", "trusted")
_PINNING_ENABLED = "mcp_pinning_enabled"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "unnamed"


def agent_asset_id(workspace: Path) -> str:
    return f"agent-claude-code-{_slug(workspace.resolve().name)}"


def mcp_asset_id(server: str) -> str:
    """Case- and character-preserving, so `GitHub`, `github` and `git_hub` never share an id
    (a look-alike name must not inherit another server's approval)."""
    return f"mcp-{server}"


def _keep(existing: dict[str, Any] | None, field: str, default: Any) -> Any:
    return existing.get(field, default) if existing else default


def register_agent(store: Store, workspace: Path, now: datetime) -> str:
    asset_id = agent_asset_id(workspace)
    existing = {a["asset_id"]: a for a in store.assets()}.get(asset_id)
    store.upsert_asset(
        {
            "asset_id": asset_id,
            "asset_type": "ai_agent",
            "name": f"Claude Code ({workspace.resolve().name})",
            "owner": _keep(existing, "owner", None),
            "importance": _keep(existing, "importance", "high"),
            "monitoring": "partial",  # only hook denials and MCP calls are logged
            "recovery_method": "end the session; revoke credentials it held",
            "approved": bool(_keep(existing, "approved", False)),
            "last_seen": format_time(now),
            "attributes": {"tool": "claude-code", "log": "hook decision log (ADR-0007)"},
        }
    )
    return asset_id


def _describe(config: Any) -> dict[str, Any]:
    """Name-level facts only. Never args, env, headers, URL userinfo or query strings."""
    if not isinstance(config, dict):
        return {"transport": "unknown"}
    url = config.get("url")
    command = config.get("command")
    declared = config.get("type") or ("stdio" if command else "http" if url else "unknown")
    facts: dict[str, Any] = {"transport": declared if declared in _TRANSPORTS else "unknown"}
    if isinstance(url, str):
        try:
            facts["host"] = urlsplit(url).hostname or "unknown"
        except ValueError:  # fixed text: the URL itself may hold a credential
            facts["host"] = "unparsable"
    if isinstance(command, str):
        # Only the program name: a single string such as "npx -y pkg --api-key X" must not
        # leave its arguments in the store. Anything unusual is stored as "unknown".
        first = command.strip().split()[0] if command.strip() else ""
        name = Path(first.replace("\\", "/")).name
        facts["command"] = name if _SAFE_COMMAND.fullmatch(name) else "unknown"
    return facts


def _identity(name: str, facts: dict[str, Any], pin: str = "") -> str:
    """What an approval is tied to: if any of these change, the approval no longer applies. With a
    key, `pin` is the keyed hash of the full launch settings (args, version, URL; ADR-0028)."""
    parts = [name, facts.get("transport", ""), facts.get("host", ""), facts.get("command", "")]
    if pin:
        parts.append(pin)
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def discover_mcp(
    store: Store, workspace: Path, now: datetime, key: bytes | None = None
) -> tuple[list[str], int]:
    """Register servers from `<workspace>/.mcp.json`. Returns (asset ids, names skipped as unsafe).

    Owner and approval set by a person are kept, but an approval is CLEARED (and audited) when the
    server's transport, host or command changes, and, given the fingerprint `key`, when ANY launch
    setting changes (args, package version, URL, env names; ADR-0028): approving `github` must not
    approve whatever `github` is later pointed at. An approval made before pinning existed is kept
    once and pinned to the current settings (audited as `mcp_pin_added`). A new server starts
    unowned and unapproved. Only the keyed hash of the settings is stored."""
    path = workspace / MCP_CONFIG
    if not path.is_file():
        return [], 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{MCP_CONFIG} is not readable JSON ({type(exc).__name__})") from None
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return [], 0
    known = {a["asset_id"]: a for a in store.assets()}
    # The one-time migration (approvals from before pinning keep working) is closed once a keyed
    # run has happened, so an approval that appears later cannot be pinned on the old terms.
    migration_open = key is not None and not any(
        entry.get("action") == _PINNING_ENABLED for entry in store.audit()
    )
    ids: list[str] = []
    skipped = 0
    for name, config in servers.items():
        if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name):
            skipped += 1  # never store a strange name: it could be anything
            continue
        asset_id = mcp_asset_id(name)
        existing = known.get(asset_id)
        facts = _describe(config)
        pin = mcppin.config_hash(config, key) if key else ""
        approved = bool(_keep(existing, "approved", False))
        old_attrs = (existing or {}).get("attributes") or {}
        before = old_attrs.get("identity")
        if not pin and old_attrs.get("config_hash"):
            # Pinned earlier, but no key now: the launch settings cannot be compared, so the old pin
            # stands; a change of transport, host or command still clears the approval.
            pin = str(old_attrs["config_hash"])
        identity = _identity(name, facts, pin)
        if approved and before != identity:
            legacy = not old_attrs.get("config_hash") and before == _identity(name, facts)
            if pin and legacy and migration_open:
                store.add_audit(  # approved before pinning existed: pin what was approved
                    format_time(now),
                    {"action": "mcp_pin_added", "asset": asset_id},
                )
            else:
                approved = False
                store.add_audit(
                    format_time(now),
                    {"action": "mcp_approval_cleared", "asset": asset_id,
                     "reason": "config changed"},
                )  # fmt: skip
                # What a person reviewed no longer describes this server: re-approval must state
                # the version again, and "trusted" must be granted again.
                old_attrs = {k: v for k, v in old_attrs.items() if k not in _STALE_ON_CHANGE}
        if pin:
            facts["config_hash"] = pin
        for field in _PERSON_SET:  # set by a person; rediscovery used to drop them
            if old_attrs.get(field):
                facts[field] = old_attrs[field]
        store.upsert_asset(
            {
                "asset_id": asset_id,
                "asset_type": "mcp_server",
                "name": name,
                "owner": _keep(existing, "owner", None),
                "importance": _keep(existing, "importance", "high"),
                "monitoring": "partial",
                "recovery_method": f"remove it from {MCP_CONFIG} and end agent sessions",
                "approved": approved,
                "last_seen": format_time(now),
                "attributes": {
                    "server": name,
                    "source": MCP_CONFIG,
                    "identity": identity,
                    **facts,
                },
            }
        )
        ids.append(asset_id)
    if migration_open:
        store.add_audit(format_time(now), {"action": _PINNING_ENABLED})
    return ids, skipped


def approved_servers(store: Store) -> frozenset[str]:
    """Exact names of MCP servers a person approved (`inventory set mcp-<name> --approve`)."""
    return frozenset(
        str((a.get("attributes") or {}).get("server") or a["name"])
        for a in store.assets()
        if a["asset_type"] == "mcp_server" and a["approved"]
    )
