"""Agent decision log -> events (v0.3b, ADR-0012). Local file only; no network.

Reads `<home>/agent-decisions.jsonl` (written by the hooks, ADR-0007) and emits:
- `agent_tool_denied` for each `deny` (a guard hook blocked a call), severity low;
- `agent_tool_allowed` for each `allow_mcp` (an MCP tool was called), severity info.
`session_start` heartbeats are not events.

Nothing is emitted from a log whose chain or anchor fails: a tampered log is not evidence (the
`agentlog` health check raises the alert). The cursor remembers the last emitted entry and the
first entry of its chain, so an archived log that starts a new chain is read from its beginning,
while a rewritten history of the same chain is refused. State is committed by the caller only after
the events were stored (DeferredState).
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel import agentlog
from sentinel.events.schema import make_event
from sentinel.inventory.agents import agent_asset_id, mcp_asset_id
from sentinel.sources.base import DeferredState
from sentinel.store.db import Store

CURSOR_KEY = "agentlog:events"


def parse_mcp_tool(tool: str) -> tuple[str, str]:
    """`mcp__<server>__<tool>` -> (server, tool). Server names may contain single underscores."""
    rest = tool[len("mcp__") :] if tool.startswith("mcp__") else tool
    server, sep, name = rest.rpartition("__")
    return (server, name) if sep else (rest, "")


def _digests(records: list[dict[str, Any]]) -> list[str]:
    prev, out = agentlog.GENESIS, []
    for entry in records:
        prev = agentlog.chain_hash(prev, entry)
        out.append(prev)
    return out


class AgentLogSource(DeferredState):
    name = "agentlog"

    def collect(self, store: Store, home: Path, now: datetime) -> list[dict[str, Any]]:
        path = home / agentlog.LOG_NAME
        if not path.exists():
            return []
        result = agentlog.verify(path, store.get_doc("snapshots", "agentlog:anchor"))
        if not result.ok:
            raise ValueError("agent decision log failed verification; no events emitted from it")
        records = result.records
        if not records:
            return []
        digests = _digests(records)
        chain_id = digests[0][:12]  # identifies this chain (an archived log starts a new one)
        cursor = store.get_doc("cursors", CURSOR_KEY)
        start = 0
        if cursor and cursor.get("chain") == chain_id:
            seqs = [r["seq"] for r in records]
            if cursor["seq"] in seqs:
                index = seqs.index(cursor["seq"])
                if digests[index] != cursor["hash"]:
                    raise ValueError("agent log history changed since it was last read")
                start = index + 1
            else:
                raise ValueError("agent log is shorter than when it was last read")
        workspace = home.resolve().parent  # the hooks keep the log in <project>/.sentinel
        asset_id = agent_asset_id(workspace)
        events = [
            e
            for record, digest in zip(records[start:], digests[start:], strict=True)
            if (e := self._event(record, chain_id, asset_id)) is not None
        ]
        self.defer(
            "cursors",
            CURSOR_KEY,
            {"chain": chain_id, "seq": records[-1]["seq"], "hash": digests[-1]},
        )
        return events

    @staticmethod
    def _event(record: dict[str, Any], chain_id: str, asset_id: str) -> dict[str, Any] | None:
        decision = record["decision"]
        # ADR-0016: the gateway records every call. Plain allowed calls become events only for file
        # tools (rule R9 joins decoy touches on their path fingerprint); "ask" always does.
        allowed_file = decision == "allow" and record.get("target_class") == "file_access"
        if decision not in ("deny", "allow_mcp", "ask") and not allowed_file:
            return None  # session_start heartbeat, other allowed calls, or an unknown decision
        session = str(record["session"])
        attrs: dict[str, Any] = {
            # the hooks write a 16-hex hash (or "" when no id was given); anything else is dropped
            "session": session if re.fullmatch(r"[0-9a-f]{16}", session) else "",
            "tool": str(record["tool"])[:128],
            "rule": str(record["rule"])[:16],
            "target_class": str(record["target_class"])[:32],
            "target_fp": str(record["target_fp"])[:32],
            "decision": decision,
        }
        if decision == "allow_mcp":
            server, tool = parse_mcp_tool(attrs["tool"])
            attrs.update(mcp_server=server, mcp_tool=tool, mcp_asset_id=mcp_asset_id(server))
        return make_event(
            event_type="agent_tool_denied" if decision == "deny" else "agent_tool_allowed",
            source="agent_hook",
            asset_id=asset_id,
            time=datetime.fromisoformat(str(record["time"]).replace("Z", "+00:00")),
            severity="low" if decision == "deny" else "info",
            confidence="high",  # the hook's own decision is a fact; what it means is not
            evidence_ref=f"agentlog/{chain_id}/{record['seq']}",
            event_id=f"agentlog:{chain_id}:{record['seq']}",
            attributes=attrs,
        )
