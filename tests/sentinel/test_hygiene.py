"""hygiene: tracked/exposed secret files, .gitignore gaps, scanning setup and CI workflow policy.

Real throwaway Git repos. A fake key lives inside the sensitive files to prove their CONTENT is never read.
"""

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel import hygiene
from sentinel.cli import main
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
PINNED = "a" * 40


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S603, S607


def make_repo(tmp_path: Path, name: str = "demo repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "sentinel-test")
    return repo


def checks(findings: list[hygiene.Finding]) -> set[tuple[str, str]]:
    return {(f.check, f.path) for f in findings}


# H1/H2/H6 ---------------------------------------------------------------------------------------
def test_tracked_env_is_high_and_content_is_never_read(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    key = fake_google_key()
    (repo / "server").mkdir()
    (repo / "server" / ".env").write_text(f"GEMINI_API_KEY={key}\n")
    git(repo, "add", "-f", ".")
    found = hygiene.scan_repo(repo)
    assert ("H1", "server/.env") in checks(found)
    assert next(f for f in found if f.check == "H1").severity == "high"
    assert key not in json.dumps(hygiene.results_json({"r": found}))
    assert key not in hygiene.format_findings({"r": found})


def test_untracked_but_not_ignored_env_is_h2_and_ignored_one_is_not(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / ".env").write_text("X=1\n")
    assert ("H2", ".env") in checks(hygiene.scan_repo(repo))
    (repo / ".gitignore").write_text(".env\n")
    assert ("H2", ".env") not in checks(hygiene.scan_repo(repo))


def test_env_example_and_normal_files_are_not_flagged(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / ".env.example").write_text("KEY=placeholder\n")
    (repo / "README.md").write_text("hi\n")
    git(repo, "add", ".")
    found = checks(hygiene.scan_repo(repo))
    assert not {c for c in found if c[0] in ("H1", "H2")}


@pytest.mark.parametrize("name", ["server.key", "cert.pem", "id_rsa", "credentials.json", ".npmrc"])
def test_other_sensitive_names_are_flagged(tmp_path: Path, name: str) -> None:
    repo = make_repo(tmp_path)
    (repo / name).write_text("x")
    git(repo, "add", "-f", ".")
    assert ("H1", name) in checks(hygiene.scan_repo(repo))


def test_dump_files(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "repomix-output.xml").write_text("<x/>")
    (repo / "backup.sql").write_text("select 1;")
    found = checks(hygiene.scan_repo(repo))
    assert ("H6", "repomix-output.xml") in found and ("H6", "backup.sql") in found


# H3 -----------------------------------------------------------------------------------------------
def test_gitignore_gaps_are_reported_and_fixed(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    gap = next(f for f in hygiene.scan_repo(repo) if f.check == "H3")
    assert ".env" in gap.detail and "server.key" in gap.detail
    (repo / ".gitignore").write_text(".env\n.env.*\n*.key\n*.pem\ncredentials*.json\n")
    assert not [f for f in hygiene.scan_repo(repo) if f.check == "H3"]


# H4/H5 --------------------------------------------------------------------------------------------
def test_scanning_setup_checks(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    found = checks(hygiene.scan_repo(repo))
    assert ("H4", ".pre-commit-config.yaml") in found and ("H5", ".github/workflows") in found
    (repo / ".pre-commit-config.yaml").write_text("repos:\n  - repo: x/gitleaks\n")
    assert ("H4", ".git/hooks/pre-commit") in checks(hygiene.scan_repo(repo))  # not installed yet
    (repo / ".git" / "hooks").mkdir(exist_ok=True)
    (repo / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
    wf = repo / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "scan.yml").write_text("steps:\n  - run: gitleaks git\n")
    found = checks(hygiene.scan_repo(repo))
    assert not {c for c in found if c[0] in ("H4", "H5")}


# workflows (S8/S9/S10) -------------------------------------------------------------------------------
def wf(text: str) -> set[str]:
    return {f.check for f in hygiene.check_workflow(".github/workflows/x.yml", text)}


def test_unpinned_actions() -> None:
    assert "W1" in wf("steps:\n  - uses: actions/checkout@v4\n")
    assert "W1" in wf("steps:\n  - uses: owner/act@main\n")
    assert "W1" not in wf(f"steps:\n  - uses: actions/checkout@{PINNED}  # v4\n")
    assert "W1" not in wf("steps:\n  - uses: ./local-action\n  - uses: docker://alpine:3\n")


def test_pull_request_target_variants() -> None:
    safe = "on:\n  pull_request_target:\njobs:\n  l:\n    steps:\n      - run: echo hi\n"
    assert "W3" in wf(safe) and "W2" not in wf(safe)
    unsafe = (
        "on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n"
        f"      - uses: actions/checkout@{PINNED}\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert "W2" in wf(unsafe) and "W3" not in wf(unsafe)
    assert not {"W2", "W3"} & wf("on:\n  pull_request:\n")


def test_permissions_checks() -> None:
    assert "W4" in wf("on: push\njobs:\n  a:\n    steps:\n      - run: x\n")
    assert "W4" not in wf("permissions:\n  contents: read\njobs: {}\n")
    assert "W5" in wf("permissions: write-all\n")
    assert "W5" not in wf("permissions:\n  contents: read\n")


@pytest.mark.parametrize(
    "script",
    [
        "      - run: echo ${{ github.event.issue.title }}\n",
        '      - run: |\n          echo hello\n          echo "${{ github.event.pull_request.body }}"\n',
        "      - name: x\n        run: git checkout ${{ github.head_ref }}\n",
    ],
)
def test_script_injection_in_run_blocks(script: str) -> None:
    assert "W6" in wf("jobs:\n  a:\n    steps:\n" + script)


def test_untrusted_context_outside_run_is_not_injection() -> None:
    text = (
        "jobs:\n  a:\n    if: ${{ github.event.pull_request.title != '' }}\n    steps:\n"
        "      - uses: x/y@"
        + PINNED
        + "\n        with:\n          t: ${{ github.event.issue.title }}\n"
        "      - run: echo ${{ github.sha }}\n"
    )
    assert "W6" not in wf(text)


def test_clean_workflow_has_only_the_expected_low_noise() -> None:
    text = (
        f"permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: x/y@{PINNED}\n"
        "      - run: echo ok\n"
    )
    assert wf(text) == set()


# repo handling, ignore, events, CLI -------------------------------------------------------------------
def test_non_git_folder_is_skipped(tmp_path: Path) -> None:
    assert hygiene.scan_repo(tmp_path) == []


def test_ignore_entries_suppress_documented_exceptions(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / ".env").write_text("X=1\n")
    assert ("H2", ".env") in checks(hygiene.scan_repo(repo))
    assert ("H2", ".env") not in checks(hygiene.scan_repo(repo, ("H2:.env",)))
    assert not [f for f in hygiene.scan_repo(repo, ("H3:*", "H4:*")) if f.check in ("H3", "H4")]


def test_events_are_valid_idempotent_and_carry_no_content(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    key = fake_google_key()
    (repo / ".env").write_text(f"K={key}\n")
    findings = hygiene.scan_repo(repo)
    store = Store(tmp_path / "s.db")
    events = hygiene.to_events(repo, "repo-demo", findings, NOW)
    assert sum(store.add_event(e) for e in events) == len(events)
    assert sum(store.add_event(e) for e in hygiene.to_events(repo, "repo-demo", findings, NOW)) == 0
    assert {e["event_type"] for e in events} == {"config_drift"}
    assert key not in json.dumps(events)


def test_cli_reports_exit_code_and_records(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = make_repo(tmp_path, "my project")  # a path with a space
    (repo / ".env").write_text("X=1\n")
    home = str(tmp_path / "home")
    assert (
        main(["--home", home, "hygiene", str(repo), "--config", str(tmp_path / "none.toml")]) == 0
    )
    out = capsys.readouterr().out
    assert "H2" in out and "repo-my-project" in out
    code = main(["--home", home, "hygiene", str(repo), "--fail-on", "high", "--record",
                 "--config", str(tmp_path / "none.toml")])  # fmt: skip
    assert code == 1
    assert Store(Path(home) / "sentinel.db").events(event_type="config_drift")
    capsys.readouterr()  # discard the previous output
    assert main(["--home", home, "hygiene", str(repo), "--json",
                 "--config", str(tmp_path / "none.toml")]) == 0  # fmt: skip
    parsed = json.loads(capsys.readouterr().out)
    assert any(f["check"] == "H2" for f in parsed["repo-my-project"])


def test_run_includes_hygiene_in_health(tmp_path: Path) -> None:
    from sentinel import runner
    from sentinel.config import Settings

    repo = make_repo(tmp_path)
    (repo / ".env").write_text("X=1\n")
    home = tmp_path / "home"
    result = runner.run_once(
        Store(home / "sentinel.db"), home, Settings(scan_paths=(str(repo),)), NOW
    )
    assert result["health"]["hygiene:demo repo"] == "ok"
    assert Store(home / "sentinel.db").events(event_type="config_drift")
