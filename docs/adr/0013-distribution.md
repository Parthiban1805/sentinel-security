# ADR-0013: Distribute Sentinel as a versioned wheel installed with uv, verified by SHA-256
Date: 2026-10-31 | Status: proposed (needs human review)

## Context
The product plan's installability track starts in v0.5: Sentinel must run on machines other than the one it was built
on. Until now it only ran from a source checkout (`uv run sentinel`), and it read its JSON schemas from `docs/schemas`
by a path relative to the repository, so an installed copy would have failed on the first event.

## Decision
- **Package:** a standard Python wheel built with hatchling (pinned). The version lives in one place,
  `sentinel/__init__.py` (hatch dynamic version); this release is 0.5.0.
- **Schemas:** `docs/schemas` stays the single source of truth; the wheel carries a copy at `sentinel/_schemas`
  (force-include at build time). At runtime the bundled copy wins, else the repository copy is used.
- **Source archive:** ships only `sentinel/`, `docs/schemas/`, `README.md` and `pyproject.toml` (anchored patterns),
  never tests, internal docs, research or patches.
- **Release:** `scripts/build_release.py` refuses to build from uncommitted changes or into an existing version folder,
  checks the wheel (both schemas present; no `tests/`, `docs/`, `.claude/`, `.sentinel/`), and writes `SHA256SUMS`.
- **Install (Windows first):** `scripts/install-sentinel.ps1 -Release <folder>` checks that uv exists (never downloads
  it), verifies the wheel against `SHA256SUMS` before anything else, installs with `uv tool install`, checks for gitleaks
  (prints the winget command; never installs it) and prints `sentinel init` / `doctor` / `run`. `-CheckOnly` does
  everything except install.
- **Network:** `uv build` may fetch the pinned build backend and `uv tool install` fetches Sentinel's pinned dependencies,
  both from PyPI (`pypi.org`, `files.pythonhosted.org`). Sentinel's own code makes no new network calls. The scripts
  contain no download commands (a test checks this).

## Consequences (security, operations, cost)
- An installed Sentinel works outside the repository (verified 2026-10-31: clean virtual environment, run from a scratch
  folder, `simulate` and `correlate` used the bundled schemas).
- **Integrity, current limit (fact):** SHA-256 proves the wheel matches the published `SHA256SUMS`, but both files come
  from the same place; anyone who can replace one can replace both. Signing (Authenticode for an installer, or a signed
  checksum file) is planned with the endpoint agent (v0.8).
- **Supply chain:** dependency versions are pinned, but `uv tool install` does not verify dependency hashes yet. A hashed
  lock for the tool install is a follow-up.
- Hook protection, the agent decision log and the hooks pin are per project (`.claude/`, `.sentinel/`); installing the
  CLI does not install hooks on another machine. The endpoint agent (v0.8) will cover enrolment and hooks.
- The machine needs uv and gitleaks; the installer checks for both but installs neither (no unreviewed downloads).

## Alternatives considered
- `pip install` into the system Python: rejected, pollutes the system and needs admin on some machines; `uv tool` isolates it.
- A single-file executable (PyInstaller): deferred; larger, harder to review, and antivirus false positives are common.
- An MSI with Authenticode signing: the target for v0.8 (managed push to employee machines); needs a code-signing
  certificate decision.
- Publishing to PyPI: rejected for an internal tool (the name `sentinel` is also taken publicly); releases go to an internal
  share or a GitHub release in a private repository.
