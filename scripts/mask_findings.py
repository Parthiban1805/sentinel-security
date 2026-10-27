"""Run YOURSELF (not by the agent): prints first4...last4 of each exposed key per repo.

Usage: python scripts/mask_findings.py <repo_path> [<repo_path> ...]
Needs gitleaks on PATH. Raw values stay in a temp file that is deleted; only masks are printed.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def mask(value: str) -> str:
    return f"{value[:4]}...{value[-4:]}" if len(value) >= 12 else "(too short to mask)"


def main(repos: list[str]) -> None:
    for repo in repos:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "r.json"
            subprocess.run(
                [
                    "gitleaks",
                    "git",
                    "--no-banner",
                    "--log-opts=--all",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report),
                    repo,
                ],
                capture_output=True,
                check=False,
            )
            findings = json.loads(report.read_text()) if report.exists() else []
        print(f"\n== {repo}")
        seen = set()
        for f in findings:
            row = (f["RuleID"], f["File"], f["StartLine"], mask(f["Secret"]))
            if row not in seen:
                seen.add(row)
                print(f"{row[0]:20} {row[1]}:{row[2]}  key={row[3]}  first seen {f['Date'][:10]}")


if __name__ == "__main__":
    main(sys.argv[1:])
