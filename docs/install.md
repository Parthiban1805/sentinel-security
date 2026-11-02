# Installing Sentinel on a Windows machine

For the person who installs Sentinel on a developer machine. About 10 minutes. Design: ADR-0013.

## What you need
- **uv** (Python tool manager). Check: `uv --version`. If missing, install it from the official uv documentation
  (docs.astral.sh/uv) and open a new terminal.
- **gitleaks** (secret scanner). Check: `gitleaks version`. If missing: `winget install Gitleaks.Gitleaks`, then open a new
  terminal.
- **The release folder** you were given, for example `\\share\sentinel\0.5.0`, containing
  `sentinel-0.5.0-py3-none-any.whl` and `SHA256SUMS`.

## Install
1. Read `install-sentinel.ps1` before running it (it is short).
2. Check first, without installing anything:
   ```
   powershell -ExecutionPolicy Bypass -File install-sentinel.ps1 -Release \\share\sentinel\0.5.0 -CheckOnly
   ```
   You should see `[OK] uv`, `[OK] checksum` and `[OK] gitleaks`. **If the checksum fails, stop** and tell the security
   owner: the file is not the published release.
3. Install:
   ```
   powershell -ExecutionPolicy Bypass -File install-sentinel.ps1 -Release \\share\sentinel\0.5.0
   ```
4. Open a **new** terminal and check: `sentinel --version` should print `sentinel 0.5.0`.

## Set up a project
In the folder of the project you want to protect:
```
sentinel init       guided setup; asks for a GitHub token without showing it
sentinel doctor     every line should say OK
sentinel run        the first run learns normal Google usage and raises no usage alerts
```

## What this does NOT do yet
- It does not install the AI-agent guard hooks; those are applied per project (`docs/patches/agent-decision-log`).
- It does not schedule runs; use `scripts/schedule-sentinel.ps1` (read it first).
- The release is checked against its checksum file but is not code-signed yet (planned for the endpoint agent, v0.8).

## Upgrade or remove
- Upgrade: run the installer with the new release folder (it replaces the old version).
- Remove: `uv tool uninstall sentinel`. Your project's `.sentinel` folder and `sentinel.toml` are left in place.

## For the security owner: making a release
From a clean, committed checkout:
```
uv run python scripts/build_release.py
```
It writes `dist/<version>/` with the wheel, the source archive and `SHA256SUMS`, and refuses to run with uncommitted
changes or to overwrite an existing version. Copy that folder and `scripts/install-sentinel.ps1` to the share.
