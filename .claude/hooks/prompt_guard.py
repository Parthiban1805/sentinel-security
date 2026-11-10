#!/usr/bin/env python3
"""UserPromptSubmit hook (v0.7d context firewall, ADR-0025).

Blocks a prompt that holds a credential in a known format or a private key, so it never reaches
the model provider. The reason (kinds and counts, never the value) is shown to the user only;
`suppressOriginalPrompt` keeps the text out of the block message. Claude Code still keeps the
prompt in its local transcript, so the user should rotate a real credential.

Every block is recorded in the tamper-evident decision log (rule and class only). An internal
error lets the prompt through (it is the user's own text; failing closed would lock them out)
and records FW-99.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _record(decision, rule, cls, session):
    try:
        import _decision_log

        _decision_log.record(decision, "UserPromptSubmit", rule, cls, "", session)
    except Exception:  # noqa: BLE001 - logging must never break the prompt
        pass


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 - malformed input never breaks a session, but is recorded
        _record("prompt_error", "FW-99", "firewall_error", "")
        return 0
    session = str(data.get("session_id", "")) if isinstance(data, dict) else ""
    try:
        import _firewall

        prompt = data.get("prompt") if isinstance(data, dict) else None
        verdict = _firewall.decide_prompt(prompt) if isinstance(prompt, str) else None
    except Exception:  # noqa: BLE001
        _record("prompt_error", "FW-99", "firewall_error", session)
        return 0
    if verdict is None:
        return 0
    _record("prompt_block", verdict[1], verdict[2], session)
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": verdict[3],
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "suppressOriginalPrompt": True,
                },
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
