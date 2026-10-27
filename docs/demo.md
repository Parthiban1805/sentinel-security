# Sentinel v0.1 demo: from leaked key to verified closure

Everything below uses a throwaway repo and a runtime-generated fake key. No network calls. Run from the repo
root; state goes to `.sentinel/` (git-ignored, treat as sensitive). Add `--home <dir>` to use another state dir.

```
uv sync --python 3.11
uv run sentinel scan <path-to-repo> --history        # fingerprints only, one ID per key
uv run sentinel findings list
uv run sentinel inventory import assets.json         # or: inventory discover <folder>
uv run sentinel inventory link <cred-fp-...> <asset-id> --permission write --actor me
uv run sentinel simulate usage --cred <cred-fp-...> --asset <asset-id>   # simulated provider event
uv run sentinel correlate                            # R1 fires -> incident
uv run sentinel incident list
uv run sentinel incident show <INC-...>              # facts, hypotheses, timeline, blast radius, plan
uv run sentinel incident approve <INC-...> revoke_credential --actor me
uv run sentinel incident execute <INC-...> revoke_credential --actor me   # DRY RUN only
# revoke the key yourself in the provider console, then record fresh evidence:
uv run sentinel incident verify <INC-...> revoke_credential --actor me --evidence "console shows key deleted"
uv run sentinel incident close <INC-...> --actor me  # refused until every required step is verified
uv run sentinel report --out report.md
```

Rules enforced by the tests (`tests/sentinel/test_e2e_incident.py`):
- A failed verification (`--fail`) keeps the incident open and the finding `revoke_pending`.
- Closing without full verification needs an explicit `--unverified-note` and is recorded as `verified: false`.
- Steps that change things need explicit human approval first; investigation steps do not.
- The fake key value never appears in output, the database, the key store or reports.

Sentinel recommends; it never executes real response actions in v0.1 (the adapter is a dry run).

## v0.2: real signals and continuous operation

Setup (all done by you, never by the agent):
1. Run the guided setup: `uv run sentinel init`. It asks which folders to scan, detects your GitHub repositories from Git
   remotes, writes `sentinel.toml`, creates the state folder and key, adds `.sentinel/` and `sentinel.toml` to `.gitignore`,
   and runs the health checks. Non-interactive form: `uv run sentinel init --no-prompt --scan-path <repo>`.
2. GitHub: create a fine-grained, read-only token (Contents + Metadata read for the watched repos; Git SSH keys read if you
   watch your SSH keys). `init` reads it from a hidden prompt and saves it with restricted permissions; it is never shown.
   Or set env `SENTINEL_GITHUB_TOKEN`, or put it in `.sentinel/github-token.txt` yourself.
3. Google Cloud (optional): `gcloud auth application-default login` with a principal that can only read monitoring and
   list API keys (`apikeys.keys.list`, `monitoring.timeSeries.list`), then `sentinel init --force --gcp-project <id>`.
4. Check anything at any time: `uv run sentinel doctor`.

```
uv run sentinel run                     # scan + collect + correlate + alert, prints collector health
uv run sentinel inventory alias <cred-fp-...> --project <p> --credential-id <key uid> --actor me
uv run sentinel incident verify-key <INC-...> --actor me   # checks Google: is the key really deleted?
uv run sentinel report                  # includes "Collector health"
powershell -File scripts\schedule-sentinel.ps1              # YOU run this: every 15 minutes
```

Facts to keep in mind:
- Google usage data is up to ~30 minutes late and has no caller IP/region (see `docs/research/collectors.md`).
- The first run only builds baselines (SSH key snapshot, 7-day usage history); alerts start after that.
- Alerts (real high/critical incidents only) go to `.sentinel/alerts.log` and a Windows notification.
- `verify-key` passes only when the provider lists the key as deleted or no longer lists it. Otherwise the
  step is marked `verification_failed` and the incident stays open.
