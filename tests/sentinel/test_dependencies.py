"""Dependency checks (S7): parsers, typosquat heuristic, hygiene findings D1-D5, dependency_added events."""

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel import dependencies as dep
from sentinel import hygiene
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def names(deps: list[dep.Dependency]) -> list[str]:
    return [d.name for d in deps]


# parsers -----------------------------------------------------------------------------------------
def test_parse_requirements() -> None:
    text = (
        "# comment\nRequests==2.32.3  # pinned\nflask[async]>=2.0 ; python_version > '3.8'\n"
        "-r other.txt\n--extra-index-url https://pkgs.example.invalid/simple\n"
        "git+https://example.invalid/x/y.git#egg=y\nPyYAML\n"
    )
    deps, notes = dep.parse_requirements(text, "requirements.txt")
    assert names(deps)[:3] == ["requests", "flask", "git+https://example.invalid/x/y.git#egg=y"]
    assert "pyyaml" in names(deps) and len(deps) == 4
    assert [d.spec for d in deps][:2] == ["==2.32.3", ">=2.0"]
    assert notes and "custom package index" in notes[0]


def test_parse_pyproject_pep508_groups_and_poetry() -> None:
    text = (
        '[project]\ndependencies = ["jsonschema==4.23.0", "Typing_Extensions>=4; python_version<\'3.12\'"]\n'
        '[project.optional-dependencies]\nextra = ["httpx"]\n'
        '[dependency-groups]\ndev = ["pytest==8.3.4"]\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\nflask = "^3.0"\n'
    )
    deps = dep.parse_pyproject(text, "pyproject.toml")
    assert set(names(deps)) == {"jsonschema", "typing-extensions", "httpx", "pytest", "flask"}
    assert {d.name for d in deps if d.dev} == {"httpx", "pytest"}
    assert dep.parse_pyproject("not = = toml", "p") == []


def test_parse_package_json_and_hooks() -> None:
    text = json.dumps(
        {
            "dependencies": {"express": "^4.18.0", "lodash": "4.17.21", "x": "github:o/r"},
            "devDependencies": {"jest": "~29.0.0"},
            "scripts": {"test": "jest", "postinstall": "node setup.js"},
        }
    )
    deps, hooks = dep.parse_package_json(text, "package.json")
    assert set(names(deps)) == {"express", "lodash", "x", "jest"} and hooks == ["postinstall"]
    assert dep.parse_package_json("{bad", "p") == ([], [])


def test_lockfile_install_scripts() -> None:
    lock = json.dumps(
        {"packages": {"": {}, "node_modules/esbuild": {"hasInstallScript": True},
                      "node_modules/a/node_modules/sharp": {"hasInstallScript": True},
                      "node_modules/lodash": {}}}
    )  # fmt: skip
    assert dep.lockfile_install_script_packages(lock) == ["esbuild", "sharp"]


# heuristics ----------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ecosystem,name,expected",
    [
        ("pypi", "reqeusts", "requests"),  # transposition
        ("pypi", "requets", "requests"),  # deletion
        ("pypi", "requestss", "requests"),  # insertion
        ("pypi", "p4ndas", "pandas"),  # homoglyph + still caught
        ("npm", "l0dash", "lodash"),  # homoglyph
        ("npm", "expres", "express"),
        ("npm", "reacts", "react"),
    ],
)
def test_typosquat_detected(ecosystem: str, name: str, expected: str) -> None:
    assert dep.typosquat_of(ecosystem, name) == expected


@pytest.mark.parametrize(
    "ecosystem,name",
    [
        ("pypi", "requests"),  # the real thing
        ("pypi", "requests-oauthlib"),  # legitimate extension (edit distance too large)
        ("pypi", "sentinel"),
        ("npm", "lodash"),
        ("npm", "@types/node"),  # scoped
        ("npm", "left-pad"),
        ("pypi", "git+https://example.invalid/x.git"),
    ],
)
def test_legitimate_names_are_not_flagged(ecosystem: str, name: str) -> None:
    assert dep.typosquat_of(ecosystem, name) is None


def test_edit_distance() -> None:
    assert dep.edit_distance("abc", "abc") == 0
    assert dep.edit_distance("abc", "acb") == 1  # transposition counts once
    assert dep.edit_distance("kitten", "sitting") == 3


def test_pinning_and_url_detection() -> None:
    assert dep.is_pinned(dep.Dependency("pypi", "x", "==1.0", "r"))
    assert not dep.is_pinned(dep.Dependency("pypi", "x", ">=1.0", "r"))
    assert dep.is_pinned(dep.Dependency("npm", "x", "4.17.21", "p"))
    assert not dep.is_pinned(dep.Dependency("npm", "x", "^4.17.21", "p"))
    assert not dep.is_pinned(dep.Dependency("npm", "x", "latest", "p"))
    for spec in ("github:o/r", "git+https://x/y.git", "https://x/y.tgz", "o/r#main", "file:../x"):
        assert dep.is_url_dependency(dep.Dependency("npm", "x", spec, "p")), spec
    assert not dep.is_url_dependency(dep.Dependency("npm", "x", "^1.2.3", "p"))


# hygiene integration (real repos) ------------------------------------------------------------------------
def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "proj"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)  # noqa: S603, S607
    return repo


def checks(findings: list[hygiene.Finding]) -> set[tuple[str, str]]:
    return {(f.check, f.path) for f in findings}


def test_hygiene_dependency_findings(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "requirements.txt").write_text(
        "requets==2.0\nflask>=2.0\n--extra-index-url https://pkgs.example.invalid/simple\n"
    )
    (repo / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"express": "^4.0.0", "tool": "github:o/r"},
                "scripts": {"postinstall": "node x.js"},
            }
        )
    )
    found = hygiene.check_dependencies(repo)
    got = checks(found)
    assert ("D1", "requirements.txt") in got  # typosquat (hypothesis)
    assert ("D2", "requirements.txt") in got and ("D2", "package.json") in got
    assert ("D3", "package.json") in got  # no lockfile
    assert ("D4", "package.json") in got  # postinstall
    assert ("D5", "package.json") in got and ("D5", "requirements.txt") in got
    d1 = next(f for f in found if f.check == "D1")
    assert "HYPOTHESIS" in d1.detail and "requests" in d1.detail


def test_ranges_are_fine_when_a_lockfile_pins_versions(tmp_path: Path) -> None:
    """Real-world noise fix: npm ranges with a lockfile are not an unpinned-dependency finding."""
    repo = make_repo(tmp_path)
    (repo / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.0.0"}}))
    assert ("D2", "package.json") in checks(hygiene.check_dependencies(repo))  # no lockfile yet
    lock = {"packages": {"": {}, "node_modules/fsevents": {"hasInstallScript": True},
                         "node_modules/esbuild": {"hasInstallScript": True}}}  # fmt: skip
    (repo / "package-lock.json").write_text(json.dumps(lock))
    got = checks(hygiene.check_dependencies(repo))
    assert not {c for c in got if c[0] in ("D2", "D3")}
    assert not {c for c in got if c[0] == "D4"}  # only ubiquitous install scripts: not reported
    lock["packages"]["node_modules/sharp"] = {"hasInstallScript": True}
    (repo / "package-lock.json").write_text(json.dumps(lock))
    d4 = [f for f in hygiene.check_dependencies(repo) if f.check == "D4"]
    assert len(d4) == 1 and "sharp" in d4[0].detail and "fsevents" not in d4[0].detail


def test_clean_pinned_project_has_no_dependency_findings(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "pyproject.toml").write_text('[project]\ndependencies = ["requests==2.32.3"]\n')
    (repo / "uv.lock").write_text("version = 1\n")
    assert hygiene.check_dependencies(repo) == []


def test_dev_dependencies_are_not_typosquat_flagged_but_node_modules_are_skipped(
    tmp_path: Path,
) -> None:
    repo = make_repo(tmp_path)
    (repo / "node_modules" / "bad").mkdir(parents=True)
    (repo / "node_modules" / "bad" / "package.json").write_text(
        json.dumps({"dependencies": {"l0dash": "1.0.0"}})
    )
    assert dep.collect(repo).dependencies == []


# dependency_added events ------------------------------------------------------------------------------------
def test_first_run_is_baseline_then_new_dependencies_emit_events(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    first = [dep.Dependency("pypi", "requests", "==2.0", "requirements.txt")]
    events, snap = dep.new_dependency_events("repo-x", first, None, NOW)
    assert events == []  # baseline only
    store.put_doc("snapshots", dep.snapshot_key("repo-x"), snap)

    second = first + [
        dep.Dependency("pypi", "reqeusts", "==1.0", "requirements.txt"),
        dep.Dependency("npm", "left-pad", "1.3.0", "package.json"),
    ]
    events, snap2 = dep.new_dependency_events(
        "repo-x", second, store.get_doc("snapshots", dep.snapshot_key("repo-x")), NOW
    )
    assert {e["attributes"]["name"] for e in events} == {"reqeusts", "left-pad"}
    squat = next(e for e in events if e["attributes"]["name"] == "reqeusts")
    assert squat["attributes"]["typosquat_of"] == "requests" and squat["severity"] == "medium"
    assert all(store.add_event(e) for e in events)
    store.put_doc("snapshots", dep.snapshot_key("repo-x"), snap2)

    again, _ = dep.new_dependency_events("repo-x", second, snap2, NOW)
    assert again == []  # nothing new
    assert not any(store.add_event(e) for e in events)  # deterministic ids: no duplicates


def test_run_tracks_new_dependencies_across_runs(tmp_path: Path) -> None:
    from sentinel import runner
    from sentinel.config import Settings

    repo = make_repo(tmp_path)
    (repo / "requirements.txt").write_text("requests==2.32.3\n")
    home = tmp_path / "home"
    store = Store(home / "sentinel.db")
    settings = Settings(scan_paths=(str(repo),))
    runner.run_once(store, home, settings, NOW, scan=True)
    assert store.events(event_type="dependency_added") == []  # baseline
    (repo / "requirements.txt").write_text("requests==2.32.3\nreqeusts==1.0\n")
    runner.run_once(store, home, settings, NOW, scan=True)
    [event] = store.events(event_type="dependency_added")
    assert event["attributes"]["name"] == "reqeusts"
