#!/usr/bin/env python3
"""Compatibility wrapper (ADR-0016): the agent gateway now makes every decision. Kept so that any
setting or script that still calls mcp_log.py gets the same, single policy."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gateway  # noqa: E402

if __name__ == "__main__":
    sys.exit(gateway.main())
