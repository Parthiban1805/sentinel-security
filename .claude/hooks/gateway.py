#!/usr/bin/env python3
"""Agent gateway: the single PreToolUse hook for every tool call (matcher "*"; ADR-0016).

For each call: decide (policy engine), record the decision in the tamper-evident log (minimal
fields, never the command, path or arguments), then
  deny -> exit 2, reason on stderr (Claude sees it)
  ask  -> print permissionDecision "ask" (the user confirms)
  allow/allow_mcp -> print nothing, exit 0 (the user's normal permission rules still apply)
Malformed input never breaks a session (exit 0, as before); any other internal error denies.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import _decision_log
except Exception:  # noqa: BLE001 - logging is optional; the gateway must still decide
    _decision_log = None

try:
    import _policy
except Exception:  # noqa: BLE001 - without the policy engine nothing can be allowed safely
    _policy = None


def _home():
    if _decision_log is not None:
        return _decision_log.home()
    configured = os.environ.get("SENTINEL_HOME")
    if configured:
        return configured
    return os.path.join(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd(), ".sentinel")


def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    if not isinstance(data, dict):
        return 0
    if _policy is None:
        print(
            "SECURITY_POLICY: the agent gateway is not installed correctly; ask the user.",
            file=sys.stderr,
        )
        return 2
    decision = _policy.decide(data, _home())
    # Answer first, then log: a slow log lock must never delay or lose a block.
    code = 0
    if decision.decision == "deny":
        print(
            "SECURITY_POLICY: blocked (%s, %s). Do not retry with a variant. Explain to the user "
            "what you need and let them decide." % (decision.rule, decision.reason),
            file=sys.stderr,
        )
        code = 2
    elif decision.decision == "ask":
        reason = "Sentinel gateway %s: %s. Confirm only if you know what it does." % (
            decision.rule,
            decision.reason,
        )
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": reason,
                    }
                }
            )
        )
    sys.stdout.flush()
    sys.stderr.flush()
    if _decision_log is not None:
        _decision_log.record(
            decision.decision,
            str(data.get("tool_name", "")),
            decision.rule,
            decision.cls,
            decision.target,
            str(data.get("session_id", "")),
        )
    return code


if __name__ == "__main__":
    sys.exit(main())
