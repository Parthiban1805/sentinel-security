#!/usr/bin/env python3
"""PostToolUse check: flag likely secrets in files Claude just wrote or edited.

Lightweight regex net; gitleaks in pre-commit and CI is the authoritative scanner.
Findings are reported by fingerprint only; the secret value is never printed.
Exit code 2 sends the message back to Claude so it can remove the value.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

PATTERNS = {
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "github_fine_grained_pat": r"github_pat_[A-Za-z0-9_]{50,}",
    "aws_access_key_id": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "anthropic_key": r"sk-ant-[A-Za-z0-9\-_]{20,}",
    "openai_style_key": r"\bsk-[A-Za-z0-9]{32,}\b",
    "slack_token": r"xox[abposr]-[A-Za-z0-9-]{10,}",
    "private_key_block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}
ALLOW_MARKER = "sentinel:allow-fake-secret"  # only for runtime-generated canary fixtures
SKIP_FILES = ("scan_written_file.py", ".gitleaks.toml")  # files that define detection patterns


def fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:12]


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    path = (data.get("tool_input") or {}).get("file_path")
    if not path:
        return 0
    p = Path(path)
    if p.name in SKIP_FILES or not p.is_file() or p.stat().st_size > 2_000_000:
        return 0
    try:
        lines = p.read_text(errors="ignore").splitlines()
    except OSError:
        return 0

    findings = []
    for lineno, line in enumerate(lines, 1):
        if ALLOW_MARKER in line:
            continue
        for name, pattern in PATTERNS.items():
            for match in re.finditer(pattern, line):
                findings.append(f"{p.name}:{lineno} {name} {fingerprint(match.group(0))}")

    if findings:
        print(
            "SECRET_SCAN: possible secret written. Remove it now and load it from the environment "
            "or a secret store instead. Findings (fingerprints only):\n  " + "\n  ".join(findings),
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
