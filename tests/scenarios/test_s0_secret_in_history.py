"""S0: key committed then deleted is still found in history. Fake key is generated at runtime."""
import hashlib
import json
import secrets
import shutil
import string
import subprocess
import time
from pathlib import Path

import pytest

GITLEAKS = shutil.which("gitleaks") or next(
    iter(Path.home().glob("AppData/Local/Microsoft/WinGet/Packages/Gitleaks*/gitleaks.exe")), None
)
pytestmark = pytest.mark.skipif(GITLEAKS is None, reason="gitleaks not installed")

ALPHABET = string.ascii_letters + string.digits + "_-"


def fake_key() -> str:
    return "AIza" + "".join(secrets.choice(ALPHABET) for _ in range(35))


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def run(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)


def scan(mode, repo, report):
    return run(
        [str(GITLEAKS), mode, "--redact", "--no-banner", "--report-format", "json",
         "--report-path", str(report), "."],
        repo,
    )


def test_s0_deleted_key_found_in_history(tmp_path):
    key = fake_key()
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["git", "init", "-q"], ["git", "config", "user.email", "t@example.invalid"],
                ["git", "config", "user.name", "sentinel-test"]):
        run(cmd, repo)
    (repo / "config.txt").write_text(f'gemini_api_key = "{key}"\n')
    run(["git", "add", "."], repo)
    run(["git", "commit", "-qm", "add config"], repo)
    t0 = time.monotonic()
    (repo / "config.txt").unlink()
    run(["git", "add", "-A"], repo)
    run(["git", "commit", "-qm", "remove config"], repo)

    dir_report, hist_report = tmp_path / "dir.json", tmp_path / "hist.json"
    r_dir = scan("dir", repo, dir_report)
    r_hist = scan("git", repo, hist_report)
    ttd = time.monotonic() - t0

    assert r_dir.returncode == 0, "working tree should be clean after deletion"
    assert r_hist.returncode != 0, "history scan must flag the deleted key"
    findings = json.loads(hist_report.read_text())
    assert len(findings) >= 1 and findings[0]["File"] == "config.txt"
    print(f"fingerprint={fingerprint(key)} time_to_detect_s={ttd:.2f}")

    outputs = [r_dir.stdout, r_dir.stderr, r_hist.stdout, r_hist.stderr, hist_report.read_text()]
    assert all(key not in o for o in outputs), "secret value leaked into output"
