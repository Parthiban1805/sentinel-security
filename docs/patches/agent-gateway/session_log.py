#!/usr/bin/env python3
"""SessionStart heartbeat: records that the decision log was active when a session began.

A session that later shows tool activity but no heartbeat (or a log that stops growing) is a
detectable gap. Always exits 0.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    try:
        import _decision_log

        data = json.load(sys.stdin)
        _decision_log.record(
            "session_start", "session", "SS-01", "session", "", str(data.get("session_id", ""))
        )
    except Exception:  # noqa: BLE001 - never affect the session
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
