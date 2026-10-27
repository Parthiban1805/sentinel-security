#!/usr/bin/env python3
"""PreToolUse guard for Bash: block exfiltration, secret dumping and approval-only actions.

Exit code 2 blocks the command; stderr explains why to Claude.
Pattern matching is a safety net, not a sandbox: keep permissions.deny and isolation too.
"""
import json
import re
import sys

RULES = [
    (r"\b(curl|wget|nc|ncat|netcat|socat|telnet)\b", "network transfer tools are not allowed; ask the user"),
    (r"\b(ssh|scp|sftp|rsync)\b", "remote access/copy is not allowed from the agent"),
    (r"(^|[;&|]\s*)(printenv|env|set|export\s+-p)\s*($|[;&|])", "dumping environment variables can expose secrets"),
    (r"\b(cat|less|more|head|tail|type|bat|strings|xxd|base64|grep)\b[^|;&]*(\.env\b(?!\.example)|\.ssh|\.aws|\.kube|gcloud|\.netrc|\.git-credentials|\.pem\b|\.key\b|id_rsa|id_ed25519)",
     "reading credential files is not allowed"),
    (r"(^|[;&|]\s*)history\b", "shell history may contain secrets"),
    (r"git\s+push\b.*(--force|\s-f\b|--force-with-lease)", "force push requires human approval"),
    (r"git\s+(filter-repo|filter-branch)|\bbfg\b", "rewriting Git history requires human approval; propose the exact command to the user"),
    (r"git\s+config\s+--global", "changing global git config is not allowed"),
    (r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|~|\$HOME)(\s|$)", "destructive delete of root or home"),
    (r"\bsudo\b|(^|[;&|]\s*)su\s", "privilege escalation is not allowed"),
    (r"(^|[;&|]\s*)(aws|gcloud|az|kubectl|heroku|vercel|netlify)\b|terraform\s+apply", "cloud/deploy CLIs are run by the user after approval"),
    (r"chmod\s+(-R\s+)?777", "world-writable permissions are not allowed"),
    (r"\|\s*(sh|bash|zsh|pwsh|powershell)\b", "piping into a shell is not allowed"),
]


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    command = (data.get("tool_input") or {}).get("command", "")
    if not command:
        return 0
    for pattern, reason in RULES:
        if re.search(pattern, command, flags=re.IGNORECASE | re.MULTILINE):
            print(
                f"SECURITY_POLICY: blocked command ({reason}). Do not retry with a variant. "
                "Explain to the user what you need and let them decide.",
                file=sys.stderr,
            )
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
