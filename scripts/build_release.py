"""Build a Sentinel release: wheel + source archive + SHA256SUMS, with checks (ADR-0013).

Usage (repository root):  uv run python scripts/build_release.py
Output: dist/<version>/sentinel-<version>-py3-none-any.whl, .tar.gz and SHA256SUMS.

Checks before anything is published: the working tree is clean (a release must match a commit), the
wheel carries both schemas and no tests or internal docs, and a staged-secret scan is the
publisher's job before tagging. Network: `uv build` may fetch the pinned build backend
(hatchling) from PyPI if it is not cached; nothing else is contacted.
"""

import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_IN_WHEEL = ("sentinel/_schemas/event.schema.json", "sentinel/_schemas/asset.schema.json")
FORBIDDEN_PREFIXES = ("tests/", "docs/", ".claude/", ".sentinel/")


def version() -> str:
    sys.path.insert(0, str(ROOT))
    from sentinel import __version__

    return __version__


def sha256sums(files: list[Path]) -> str:
    """Lines in the `sha256sum` format: '<hex>  <name>'."""
    lines = []
    for path in sorted(files, key=lambda p: p.name):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    return "\n".join(lines) + "\n"


def check_wheel(wheel: Path) -> list[str]:
    names = zipfile.ZipFile(wheel).namelist()
    problems = [f"missing {n}" for n in REQUIRED_IN_WHEEL if n not in names]
    problems += [f"unexpected {n}" for n in names if n.startswith(FORBIDDEN_PREFIXES)]
    return problems


def main() -> int:
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()  # fmt: skip
    if dirty and "--allow-dirty" not in sys.argv:
        print(
            "refusing: uncommitted changes (a release must match a commit; --allow-dirty to test)"
        )
        return 1
    out = ROOT / "dist" / version()
    if out.exists() and any(out.iterdir()):
        print(f"refusing: {out} already has files (versions are never rebuilt in place)")
        return 1
    subprocess.run(["uv", "build", "--out-dir", str(out)], cwd=ROOT, check=True)
    wheels = list(out.glob("*.whl"))
    if len(wheels) != 1:
        print(f"expected one wheel, found {len(wheels)}")
        return 1
    problems = check_wheel(wheels[0])
    if problems:
        print("wheel check failed: " + "; ".join(problems))
        return 1
    artifacts = [p for p in out.iterdir() if p.suffix in (".whl", ".gz")]
    (out / "SHA256SUMS").write_text(sha256sums(artifacts), encoding="utf-8")
    print(f"release {version()} in {out}:")
    for path in sorted(out.iterdir()):
        print(f"  {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
