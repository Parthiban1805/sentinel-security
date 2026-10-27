#!/usr/bin/env python3
"""PreToolUse guard: block Claude Code file tools from touching secrets.

Defence in depth alongside permissions.deny in settings.json.
Exit code 2 blocks the tool call; stderr is shown to Claude.
"""
import json
import os
import re
import sys

ALLOWED_TEMPLATES = (".env.example", ".env.sample", ".env.template")

BLOCKED_PATTERNS = [
    r"(^|/)\.env($|\.)",                # .env, .env.local, .env.production ...
    r"\.(pem|key|p12|pfx|jks|keystore)$",
    r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$",
    r"(^|/)\.ssh(/|$)",
    r"(^|/)\.aws(/|$)",
    r"(^|/)\.azure(/|$)",
    r"(^|/)\.kube(/|$)",
    r"(^|/)\.config/gcloud(/|$)",
    r"(^|/)\.docker/config\.json$",
    r"(^|/)\.netrc$",
    r"(^|/)\.git-credentials$",
    r"(^|/)secrets(/|$)",
    r"credentials[^/]*\.json$",
    r"service[-_]?account[^/]*\.json$",
    r"(^|/)\.claude/hooks/",            # protected from edits; reads allowed below
    r"(^|/)\.claude/settings\.json$",
]

READ_ONLY_OK = (r"(^|/)\.claude/hooks/", r"(^|/)\.claude/settings\.json$")


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0  # never break the session on malformed input

    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input", {}) or {}
    path = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("pattern") or ""
    if not path:
        return 0

    norm = os.path.expanduser(str(path)).replace("\\", "/")
    if norm.endswith(ALLOWED_TEMPLATES):
        return 0

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, norm):
            if tool in ("Read", "Grep", "Glob") and any(re.search(p, norm) for p in READ_ONLY_OK):
                return 0
            print(
                f"SECURITY_POLICY: {tool} on '{path}' is blocked (sensitive path). "
                "Do not retry or work around this. Ask the user to handle it, or refer to the "
                "secret by fingerprint only.",
                file=sys.stderr,
            )
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
