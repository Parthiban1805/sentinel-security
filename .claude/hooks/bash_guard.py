#!/usr/bin/env python3
"""PreToolUse guard for Bash: block exfiltration, secret dumping and approval-only actions.

PATCHED VERSION (docs/patches/agent-decision-log): every rule has a stable id and class, and every
denial is recorded in the tamper-evident decision log (never the raw command).

Exit code 2 blocks the command; stderr explains why to Claude.
Pattern matching is a safety net, not a sandbox: keep permissions.deny and isolation too.
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

# (id, class, pattern, reason)
RULES = [
    (
        "BG-01",
        "network_tool",
        r"\b(curl|wget|nc|ncat|netcat|socat|telnet)\b",
        "network transfer tools are not allowed; ask the user",
    ),
    (
        "BG-02",
        "remote_access",
        r"\b(ssh|scp|sftp|rsync)\b",
        "remote access/copy is not allowed from the agent",
    ),
    (
        "BG-03",
        "env_dump",
        r"(^|[;&|]\s*)(printenv|env|set|export\s+-p)\s*($|[;&|])",
        "dumping environment variables can expose secrets",
    ),
    (
        "BG-04",
        "credential_read",
        r"\b(cat|less|more|head|tail|type|bat|strings|xxd|base64|grep)\b[^|;&]*(\.env\b(?!\.example)|\.ssh|\.aws|\.kube|gcloud|\.netrc|\.git-credentials|\.pem\b|\.key\b|id_rsa|id_ed25519)",
        "reading credential files is not allowed",
    ),
    ("BG-05", "shell_history", r"(^|[;&|]\s*)history\b", "shell history may contain secrets"),
    (
        "BG-06",
        "force_push",
        r"git\s+push\b.*(--force|\s-f\b|--force-with-lease)",
        "force push requires human approval",
    ),
    (
        "BG-07",
        "history_rewrite",
        r"git\s+(filter-repo|filter-branch)|\bbfg\b",
        "rewriting Git history requires human approval; propose the exact command to the user",
    ),
    (
        "BG-08",
        "global_git_config",
        r"git\s+config\s+--global",
        "changing global git config is not allowed",
    ),
    (
        "BG-09",
        "destructive_delete",
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|~|\$HOME)(\s|$)",
        "destructive delete of root or home",
    ),
    (
        "BG-10",
        "privilege_escalation",
        r"\bsudo\b|(^|[;&|]\s*)su\s",
        "privilege escalation is not allowed",
    ),
    (
        "BG-11",
        "cloud_cli",
        r"(^|[;&|]\s*)(aws|gcloud|az|kubectl|heroku|vercel|netlify)\b|terraform\s+apply",
        "cloud/deploy CLIs are run by the user after approval",
    ),
    (
        "BG-12",
        "world_writable",
        r"chmod\s+(-R\s+)?777",
        "world-writable permissions are not allowed",
    ),
    (
        "BG-13",
        "pipe_to_shell",
        r"\|\s*(sh|bash|zsh|pwsh|powershell)\b",
        "piping into a shell is not allowed",
    ),
    # Sentinel's state dir holds the credential map, a token file and the decision log itself.
    (
        "BG-14",
        "state_dir_access",
        r"(\b(cat|type|more|less|head|tail|get-content|gc|grep|rg|sed|awk|rm|del|erase|mv|move|cp|copy|truncate|remove-item|set-content|add-content|out-file|tee|dd)\b|>)[^|;&\n]*\.sentinel\b",
        "Sentinel's state directory is protected; use the sentinel CLI instead",
    ),
]


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    command = (data.get("tool_input") or {}).get("command", "")
    if not command:
        return 0
    for rule_id, rule_class, pattern, reason in RULES:
        if re.search(pattern, command, flags=re.IGNORECASE | re.MULTILINE):
            if _decision_log is not None:
                _decision_log.record(
                    "deny",
                    data.get("tool_name", "Bash"),
                    rule_id,
                    rule_class,
                    command,
                    str(data.get("session_id", "")),
                )
            print(
                f"SECURITY_POLICY: blocked command ({reason}). Do not retry with a variant. "
                "Explain to the user what you need and let them decide.",
                file=sys.stderr,
            )
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
