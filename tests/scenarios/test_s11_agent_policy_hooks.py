"""S11/S12 (policy enforcement slice): guard hooks must block agent actions outside policy.

Feeds PreToolUse JSON to the real hook scripts. No network, no real secrets, nothing executed.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOKS = Path(__file__).resolve().parents[2] / ".claude" / "hooks"


def run_hook(script: str, payload: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOKS / script)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )


def bash(command: str) -> subprocess.CompletedProcess:
    return run_hook("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": command}})


def file_tool(tool: str, path: str) -> subprocess.CompletedProcess:
    return run_hook(
        "protect_sensitive_files.py", {"tool_name": tool, "tool_input": {"file_path": path}}
    )


BLOCKED_COMMANDS = [
    "curl https://example.invalid",
    "CURL https://example.invalid",
    "wget -qO- https://example.invalid",
    "ssh host.invalid",
    "scp a.txt host.invalid:/tmp",
    "printenv",
    "cat .env",
    "cat server/.env.production",
    "tail -n 5 ~/.aws/credentials",
    "grep -r key ~/.ssh",
    "history",
    "git push --force origin main",
    "git push origin main -f",
    "git filter-repo --path x",
    "git config --global user.name x",
    "sudo ls",
    "aws s3 ls",
    "kubectl get pods",
    "terraform apply",
    "chmod 777 file",
    "echo hi | bash",
]

ALLOWED_COMMANDS = [
    "git status",
    "git diff",
    "pytest -q",
    "ruff check .",
    "ls -la",
    "cat .env.example",
]


@pytest.mark.parametrize("command", BLOCKED_COMMANDS)
def test_bash_guard_blocks(command):
    r = bash(command)
    assert r.returncode == 2, f"not blocked: {command}"
    assert "SECURITY_POLICY" in r.stderr


@pytest.mark.parametrize("command", ALLOWED_COMMANDS)
def test_bash_guard_allows_normal_work(command):
    assert bash(command).returncode == 0


@pytest.mark.parametrize(
    "tool,path",
    [
        ("Read", "/work/repo/.env"),
        ("Read", "C:\\work\\repo\\server\\.env.production"),
        ("Read", "/home/u/.ssh/id_ed25519"),
        ("Grep", "/home/u/.aws/credentials"),
        ("Write", "/work/repo/certs/server.key"),
        ("Edit", "/work/repo/.claude/settings.json"),
        ("Edit", "/work/repo/.claude/hooks/bash_guard.py"),
        ("Read", "/work/repo/google_credentials.json"),
        ("Read", "/work/repo/service-account-prod.json"),
    ],
)
def test_file_guard_blocks(tool, path):
    r = file_tool(tool, path)
    assert r.returncode == 2, f"not blocked: {tool} {path}"
    assert "SECURITY_POLICY" in r.stderr


@pytest.mark.parametrize(
    "tool,path",
    [
        ("Read", "/work/repo/.env.example"),
        ("Read", "/work/repo/README.md"),
        ("Read", "/work/repo/.claude/settings.json"),  # read-only allowed by design
        ("Write", "/work/repo/sentinel/inventory/models.py"),
    ],
)
def test_file_guard_allows(tool, path):
    assert file_tool(tool, path).returncode == 0


def test_hooks_do_not_break_on_malformed_input():
    for script in ("bash_guard.py", "protect_sensitive_files.py"):
        r = subprocess.run(
            [sys.executable, str(HOOKS / script)],
            input="not json",
            capture_output=True,
            text=True,
            check=False,
        )
        assert r.returncode == 0


@pytest.mark.xfail(
    strict=True,
    reason="KNOWN GAP: regex guard is a safety net, not a sandbox (see agent-policy rule 10)",
)
@pytest.mark.parametrize(
    "command",
    [
        "python -c \"import urllib.request as u; u.urlopen('https://example.invalid')\"",
        "python -c \"print(open('.env').read())\"",
    ],
)
def test_known_bypasses_documented(command):
    assert bash(command).returncode == 2
