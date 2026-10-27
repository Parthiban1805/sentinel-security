#!/usr/bin/env python3
"""PreToolUse logger for MCP tool calls (matcher `mcp__.*`). Records the call; never blocks.

Tool names look like mcp__<server>__<tool> (no secrets); arguments are never read or stored.
Always exits 0.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    try:
        import _decision_log

        data = json.load(sys.stdin)
        tool = str(data.get("tool_name", ""))
        if tool.startswith("mcp__"):
            _decision_log.record(
                "allow_mcp", tool, "MCP-01", "mcp_tool", "", str(data.get("session_id", ""))
            )
    except Exception:  # noqa: BLE001 - never affect the tool call
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
