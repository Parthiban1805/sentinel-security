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
