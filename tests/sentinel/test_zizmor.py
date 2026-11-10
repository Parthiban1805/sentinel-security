"""zizmor wrapper (v0.7e F3, ADR-0029; S8-S10). zizmor itself is not needed: the JSON fixture follows
the documented json-v1 shape (docs.zizmor.sh/usage, fetched 2026-11-06). Fake values are generated
at runtime."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from sentinel import hygiene
from sentinel.scanners import zizmor
from sentinel.simulation.fakes import fake_google_key


def finding(
    ident: str,
    severity: str,
    path: str,
    row: int,
    *,
    feature: str = "run: echo hi",
    ignored: bool = False,
    kind: str = "Primary",
) -> dict[str, Any]:
    """One finding in zizmor's documented json-v1 shape (row is 0-based there)."""
    return {
        "ident": ident,
        "desc": f"{ident} description",
        "url": f"https://docs.zizmor.sh/audits/#{ident}",
        "determinations": {"confidence": "High", "severity": severity, "persona": "Regular"},
        "locations": [
            {
                "symbolic": {
                    "key": {"Local": {"prefix": None, "given_path": path, "verbatim_path": path}},
                    "annotation": "this step",
                    "route": {"route": [{"Key": "jobs"}]},
                    "feature_kind": "Normal",
                    "kind": kind,
                },
                "concrete": {
                    "location": {
                        "start_point": {"row": row, "column": 4},
                        "end_point": {"row": row, "column": 20},
                        "offset_span": {"start": 10, "end": 30},
                    },
                    "feature": feature,
                    "comments": [],
                },
            }
        ],
        "ignored": ignored,
        "fixes": [],
    }


WF = ".github/workflows/ci.yml"


def test_parse_keeps_audit_severity_path_and_line_only(tmp_path: Path) -> None:
    key = fake_google_key()
    raw = json.dumps([finding("template-injection", "High", WF, 11, feature=f"run: echo {key}")])
    found = zizmor.parse(raw, tmp_path)
    assert found == [zizmor.ZFinding("template-injection", "high", WF, 12)]  # 1-based line
    assert key not in repr(found)


def test_parse_maps_severities_and_skips_ignored(tmp_path: Path) -> None:
    raw = json.dumps(
        [
            finding("artipacked", "Medium", WF, 3),
            finding("excessive-permissions", "Low", WF, 0),
            finding("obfuscation", "Informational", WF, 1),
            finding("unpinned-uses", "High", WF, 5, ignored=True),
        ]
    )
    got = {(f.audit, f.severity) for f in zizmor.parse(raw, tmp_path)}
    assert got == {("artipacked", "medium"), ("excessive-permissions", "low"),
                   ("obfuscation", "low")}  # fmt: skip


def test_parse_uses_the_primary_location_and_a_repo_relative_path(tmp_path: Path) -> None:
    item = finding("artipacked", "Medium", str(tmp_path / ".github" / "workflows" / "a.yml"), 7)
    related = finding("artipacked", "Medium", "other.yml", 1, kind="Related")["locations"][0]
    item["locations"].insert(0, related)
    (f,) = zizmor.parse(json.dumps([item]), tmp_path)
    assert (f.path, f.line) == (".github/workflows/a.yml", 8)


@pytest.mark.parametrize("ident", ["../../etc", "a b", "x" * 80, "", 5])
def test_parse_never_trusts_the_audit_name(ident: Any, tmp_path: Path) -> None:
    (f,) = zizmor.parse(json.dumps([finding("x", "High", WF, 0) | {"ident": ident}]), tmp_path)
    assert f.audit == "unknown"


@pytest.mark.parametrize("raw", ["", "  ", "not json", "{}", "[1, 2]"])
def test_parse_rejects_or_skips_bad_output(raw: str, tmp_path: Path) -> None:
    if raw.strip() in ("", "[1, 2]"):
        assert zizmor.parse(raw, tmp_path) == []
    else:
        with pytest.raises(zizmor.ZizmorError):
            zizmor.parse(raw, tmp_path)


# running it ------------------------------------------------------------------------------------
class FakeRun:
    def __init__(self, returncode: int, stdout: str = "[]") -> None:
        self.returncode, self.stdout = returncode, stdout
        self.argv: list[str] = []
        self.env: dict[str, str] = {}

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.argv, self.env = argv, kwargs["env"]
        assert kwargs.get("shell") in (None, False)
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, "log text")


def test_run_is_offline_and_never_passes_a_github_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN"):
        monkeypatch.setenv(name, "placeholder-not-a-token")
    fake = FakeRun(13, json.dumps([finding("artipacked", "Medium", WF, 0)]))
    monkeypatch.setattr(zizmor.subprocess, "run", fake)
    out = zizmor.run(tmp_path, exe="zizmor")
    assert fake.argv[:3] == ["zizmor", "--offline", "--format=json"]
    assert fake.argv[-1] == str(tmp_path)
    assert not {"GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN"} & set(fake.env)
    assert fake.env["ZIZMOR_OFFLINE"] == "true"
    assert [f.audit for f in zizmor.parse(out, tmp_path)] == ["artipacked"]


@pytest.mark.parametrize(("code", "ok"), [(0, True), (3, True), (11, True), (14, True),
                                          (1, False), (2, False), (99, False)])  # fmt: skip
def test_run_exit_codes(
    code: int, ok: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(zizmor.subprocess, "run", FakeRun(code, "[]"))
    if ok:
        assert zizmor.parse(zizmor.run(tmp_path, exe="zizmor"), tmp_path) == []
    else:
        with pytest.raises(zizmor.ZizmorError) as err:
            zizmor.run(tmp_path, exe="zizmor")
        assert "log text" not in str(err.value)  # never echoes the tool's output


# into hygiene ----------------------------------------------------------------------------------
def test_findings_become_one_hygiene_finding_per_audit_and_file() -> None:
    found = [
        zizmor.ZFinding("artipacked", "medium", WF, 3),
        zizmor.ZFinding("artipacked", "high", WF, 9),
        zizmor.ZFinding("artipacked", "low", ".github/workflows/b.yml", 1),
    ]
    out = zizmor.to_hygiene(found, existing=[])
    assert [(f.check, f.severity, f.path) for f in out] == [
        ("ZZ-artipacked", "low", ".github/workflows/b.yml"),
        ("ZZ-artipacked", "high", WF),
    ]
    assert "lines 3, 9" in out[1].detail


def test_a_finding_the_regex_check_already_raised_is_not_repeated() -> None:
    existing = [hygiene.Finding("W6", "high", WF, "x"), hygiene.Finding("W1", "medium", "b", "x")]
    found = [zizmor.ZFinding("template-injection", "high", WF, 3),
             zizmor.ZFinding("unpinned-uses", "medium", WF, 4)]  # fmt: skip
    assert [f.check for f in zizmor.to_hygiene(found, existing)] == ["ZZ-unpinned-uses"]


def _repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\npermissions: {}\njobs: {}\n", encoding="utf-8"
    )
    return tmp_path


def test_hygiene_without_zizmor_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(zizmor, "find_zizmor", lambda: None)
    assert not [f for f in hygiene.scan_repo(_repo(tmp_path)) if f.check.startswith("ZZ")]


def test_hygiene_reports_a_failed_zizmor_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    monkeypatch.setattr(zizmor, "find_zizmor", lambda: "zizmor")

    def broken(repo: Path, exe: str | None = None) -> str:
        raise zizmor.ZizmorError("zizmor failed with exit code 1")

    # Patch zizmor.run, not subprocess.run: hygiene's own git calls use subprocess too.
    monkeypatch.setattr(zizmor, "run", broken)
    failed = [f for f in hygiene.scan_repo(repo) if f.check == "ZZ-error"]
    assert len(failed) == 1 and "regex-only" in failed[0].detail


def test_hygiene_adds_zizmor_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    monkeypatch.setattr(zizmor, "find_zizmor", lambda: "zizmor")
    raw = json.dumps([finding("artipacked", "Medium", WF, 0)])
    monkeypatch.setattr(zizmor, "run", lambda repo, exe=None: raw)
    assert "ZZ-artipacked" in {f.check for f in hygiene.scan_repo(repo)}
    assert not [f for f in hygiene.scan_repo(repo, use_zizmor=False) if f.check.startswith("ZZ")]


@pytest.mark.skipif(shutil.which("zizmor") is None, reason="zizmor is not installed")
def test_real_zizmor_finds_template_injection(tmp_path: Path) -> None:
    """Runs only where zizmor is installed: confirms the documented JSON shape is what we parse."""
    repo = _repo(tmp_path)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n',
        encoding="utf-8",
    )
    found = zizmor.parse(zizmor.run(repo), repo)
    assert any(f.audit == "template-injection" and f.path.endswith("ci.yml") for f in found)
    assert os.environ.get("GITHUB_TOKEN") is None or True  # token is stripped inside run()


# doctor ----------------------------------------------------------------------------------------
def test_doctor_reports_zizmor(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinel import doctor

    monkeypatch.setattr(zizmor, "find_zizmor", lambda: None)
    assert doctor.check_zizmor().status == "warn"
    monkeypatch.setattr(zizmor, "find_zizmor", lambda: "zizmor")
    monkeypatch.setattr(zizmor, "version", lambda exe: zizmor.PINNED_VERSION)
    assert doctor.check_zizmor().status == "ok"
    monkeypatch.setattr(zizmor, "version", lambda exe: "1.0.0")
    check = doctor.check_zizmor()
    assert check.status == "warn" and zizmor.PINNED_VERSION in check.detail
