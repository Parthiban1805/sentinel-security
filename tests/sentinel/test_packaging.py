"""Packaging (ADR-0013): bundled schemas, single version source, release checks."""

import hashlib
import importlib.util
import sys
import tomllib
import zipfile
from pathlib import Path
from types import ModuleType

from sentinel import __version__
from sentinel.events.schema import locate_schemas

ROOT = Path(__file__).resolve().parents[2]


def build_release() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "build_release", ROOT / "scripts" / "build_release.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_release"] = module
    spec.loader.exec_module(module)
    return module


def test_the_wheel_bundles_the_schemas_from_their_single_source() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    hatch = config["tool"]["hatch"]
    assert hatch["build"]["targets"]["wheel"]["force-include"] == {
        "docs/schemas": "sentinel/_schemas"
    }
    assert config["project"]["dynamic"] == ["version"] and "version" not in config["project"]
    assert hatch["version"]["path"] == "sentinel/__init__.py"
    assert __version__ == "0.5.0"


def test_the_source_archive_ships_only_what_a_build_needs() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    include = config["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert all(p.startswith("/") for p in include)  # anchored: never tests/sentinel by accident
    assert "/tests" not in include and not any(p.startswith("/docs/spec") for p in include)


def test_bundled_schemas_win_over_the_repo_copy(tmp_path: Path) -> None:
    bundled, repo = tmp_path / "_schemas", tmp_path / "docs"
    repo.mkdir()
    assert locate_schemas(bundled, repo) == repo  # source checkout
    bundled.mkdir()
    assert locate_schemas(bundled, repo) == bundled  # installed wheel


def test_sha256sums_format(tmp_path: Path) -> None:
    files = []
    for name, body in (("b.whl", b"wheel"), ("a.tar.gz", b"sdist")):
        (tmp_path / name).write_bytes(body)
        files.append(tmp_path / name)
    text = build_release().sha256sums(files)
    assert text == (
        f"{hashlib.sha256(b'sdist').hexdigest()}  a.tar.gz\n"
        f"{hashlib.sha256(b'wheel').hexdigest()}  b.whl\n"
    )


def test_wheel_check_finds_missing_schemas_and_stray_files(tmp_path: Path) -> None:
    good, bad = tmp_path / "good.whl", tmp_path / "bad.whl"
    with zipfile.ZipFile(good, "w") as z:
        for name in ("sentinel/__init__.py", *build_release().REQUIRED_IN_WHEEL):
            z.writestr(name, "x")
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("sentinel/__init__.py", "x")
        z.writestr("tests/test_x.py", "x")
        z.writestr(".sentinel/sentinel.db", "x")
    assert build_release().check_wheel(good) == []
    problems = build_release().check_wheel(bad)
    assert any("missing sentinel/_schemas/event.schema.json" in p for p in problems)
    assert any("unexpected tests/" in p for p in problems)
    assert any("unexpected .sentinel/" in p for p in problems)


def test_the_installer_verifies_the_checksum_and_never_downloads_tools() -> None:
    """Static checks of the PowerShell installer (it is not executed in tests)."""
    script = (ROOT / "scripts" / "install-sentinel.ps1").read_text(encoding="utf-8")
    assert "Get-FileHash -Algorithm SHA256" in script and "checksum mismatch" in script
    assert script.index("Get-FileHash") < script.index("uv tool install")  # verify before install
    for forbidden in (
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "iwr ",
        "curl",
        "Start-BitsTransfer",
    ):
        assert forbidden not in script, forbidden
    assert "-CheckOnly" in script and "winget install Gitleaks.Gitleaks" in script
