#!/usr/bin/env python3
"""PreToolUse guard: block Claude Code file tools from touching secrets.

PATCHED VERSION (docs/patches/agent-decision-log): stable rule ids, every denial recorded in the
tamper-evident decision log (never the raw path), and Sentinel's own state directory protected.

Defence in depth alongside permissions.deny in settings.json.
Exit code 2 blocks the tool call; stderr is shown to Claude.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import _decision_log
except Exception:  # noqa: BLE001 - logging is optional; the guard must still work
    _decision_log = None

ALLOWED_TEMPLATES = (".env.example", ".env.sample", ".env.template")

# (id, class, pattern)
BLOCKED_PATTERNS = [
    ("PF-01", "env_file", r"(^|/)\.env($|\.)"),
    ("PF-02", "key_file", r"\.(pem|key|p12|pfx|jks|keystore)$"),
    ("PF-03", "ssh_key", r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$"),
    ("PF-04", "ssh_dir", r"(^|/)\.ssh(/|$)"),
    ("PF-05", "cloud_credentials", r"(^|/)\.aws(/|$)"),
    ("PF-06", "cloud_credentials", r"(^|/)\.azure(/|$)"),
    ("PF-07", "cloud_credentials", r"(^|/)\.kube(/|$)"),
    ("PF-08", "cloud_credentials", r"(^|/)\.config/gcloud(/|$)"),
    ("PF-09", "cloud_credentials", r"(^|/)\.docker/config\.json$"),
    ("PF-10", "credential_store", r"(^|/)\.netrc$"),
    ("PF-11", "credential_store", r"(^|/)\.git-credentials$"),
    ("PF-12", "secrets_dir", r"(^|/)secrets(/|$)"),
    ("PF-13", "credential_json", r"credentials[^/]*\.json$"),
    ("PF-14", "credential_json", r"service[-_]?account[^/]*\.json$"),
    ("PF-15", "guard_config", r"(^|/)\.claude/hooks/"),  # protected from edits; reads allowed below
    ("PF-16", "guard_config", r"(^|/)\.claude/settings\.json$"),
    # Sentinel state: credential map, GitHub token file, fingerprint key and the decision log.
    ("PF-17", "state_dir", r"(^|/)\.sentinel(/|$)"),
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

    for rule_id, rule_class, pattern in BLOCKED_PATTERNS:
        if re.search(pattern, norm):
            if tool in ("Read", "Grep", "Glob") and any(re.search(p, norm) for p in READ_ONLY_OK):
                return 0
            if _decision_log is not None:
                _decision_log.record(
                    "deny", tool, rule_id, rule_class, norm, str(data.get("session_id", ""))
                )
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
