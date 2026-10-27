"""S2: secrets outside Git (shell history, CI log, agent transcript, build artifact, image-layer dump).

Fake keys are generated at runtime in a temp dir; nothing is committed. Uses gitleaks `dir` mode
(no Git needed), always redacted.
"""

import json
import secrets
import shutil
import string
import subprocess
from pathlib import Path

import pytest

GITLEAKS = shutil.which("gitleaks") or next(
    iter(Path.home().glob("AppData/Local/Microsoft/WinGet/Packages/Gitleaks*/gitleaks.exe")), None
)
pytestmark = pytest.mark.skipif(GITLEAKS is None, reason="gitleaks not installed")

ALPHABET = string.ascii_letters + string.digits + "_-"


def fake_key() -> str:
    return "AIza" + "".join(secrets.choice(ALPHABET) for _ in range(35))


def scan(path: Path, report: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            str(GITLEAKS),
            "dir",
            "--redact",
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


# location name -> file content template ({k} = fake key)
LOCATIONS = {
    "shell_history": ("bash_history", "ls\nexport GEMINI_API_KEY={k}\npython app.py\n"),
    "ci_log": ("ci-run-4821.log", "Run tests\nGEMINI_API_KEY: {k}\nall passed\n"),
    "agent_transcript": ("session.jsonl", '{"role":"tool","content":"used key {k} today"}\n'),
    "build_artifact": ("dist/bundle.js", 'const cfg = { gemini_api_key: "{k}" };\n'),
    "image_layer_dump": ("layer/app/config.txt", 'gemini_api_key = "{k}"\n'),
}


@pytest.mark.parametrize("name", LOCATIONS)
def test_s2_secret_found_in_non_git_location(tmp_path, name):
    key = fake_key()
    filename, template = LOCATIONS[name]
    target = tmp_path / "scan" / filename
    target.parent.mkdir(parents=True)
    target.write_text(template.replace("{k}", key))

    report = tmp_path / "r.json"
    r = scan(tmp_path / "scan", report)

    assert r.returncode != 0, f"{name}: secret not detected"
    findings = json.loads(report.read_text())
    assert any(Path(f["File"]).name == Path(filename).name for f in findings)
    outputs = [r.stdout, r.stderr, report.read_text()]
    assert all(key not in o for o in outputs), "secret value leaked into output"


def test_s2_plain_gitleaks_still_misses_json_escaped_quotes(tmp_path):
    """Documents WHY Sentinel decodes JSON first: plain gitleaks misses escaped-quote keys."""
    key = fake_key()
    d = tmp_path / "scan"
    d.mkdir()
    (d / "session.jsonl").write_text('{"c":"gemini_api_key = \\"' + key + '\\""}\n')
    assert scan(d, tmp_path / "r.json").returncode == 0  # the blind spot, in raw gitleaks


def test_s2_sentinel_scanner_closes_the_json_escaped_gap(tmp_path):
    """Fixed in v0.3a: Sentinel's scanner decodes JSON strings before scanning."""
    from sentinel.scanners import gitleaks as sentinel_gitleaks
    from sentinel.security import load_key

    key = fake_key()
    d = tmp_path / "scan"
    d.mkdir()
    (d / "session.jsonl").write_text('{"c":"gemini_api_key = \\"' + key + '\\""}\n')
    home = tmp_path / "home"
    hits = sentinel_gitleaks.run(d, "dir", load_key(home), home)
    assert [h.file for h in hits] == ["session.jsonl"]
    assert key not in repr(hits)


def test_s2_clean_location_has_no_findings(tmp_path):
    (tmp_path / "scan").mkdir()
    (tmp_path / "scan" / "notes.txt").write_text("nothing secret here\n")
    assert scan(tmp_path / "scan", tmp_path / "r.json").returncode == 0
