#!/usr/bin/env python3
"""SessionStart hook: the decision-log heartbeat, and the MCP launch-settings check (ADR-0028).

1. Records that the decision log was active when a session began (SS-01). A session that later
   shows tool activity but no heartbeat (or a log that stops growing) is a detectable gap.
2. Compares each pinned MCP server in the MCP allow-list with the project's `.mcp.json` and writes
   `<home>/mcp-drift.json`, which the gateway reads (MCP-04). Claude Code starts MCP servers when a
   session starts, so this is the moment that matters. A failed check leaves no drift file, and
   the gateway then denies every pinned server (fail closed); it is recorded as SS-98.

Always exits 0: the session itself is never affected.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _home():
    configured = os.environ.get("SENTINEL_HOME")
    if configured:
        return configured
    return os.path.join(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd(), ".sentinel")


def main() -> int:
    session = ""
    try:
        import _decision_log

        data = json.load(sys.stdin)
        session = str(data.get("session_id", "")) if isinstance(data, dict) else ""
        _decision_log.record("session_start", "session", "SS-01", "session", "", session)
    except Exception:  # noqa: BLE001 - never affect the session
        data = {}
    try:
        import _mcppin

        workspace = os.environ.get("CLAUDE_PROJECT_DIR") or str(data.get("cwd") or os.getcwd())
        found = _mcppin.write_drift(_home(), workspace, session)  # bound to this session
        if found:
            import _decision_log

            _decision_log.record("mcp_drift", "session", "SS-02", "mcp_drift", "", session)
    except Exception:  # noqa: BLE001
        try:
            os.remove(os.path.join(_home(), "mcp-drift.json"))  # stale "all clear" must not stay
        except OSError:
            pass
        try:
            import _decision_log

            _decision_log.record("mcp_drift_error", "session", "SS-98", "mcp_drift", "", session)
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
