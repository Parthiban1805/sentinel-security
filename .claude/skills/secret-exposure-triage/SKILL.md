---
name: secret-exposure-triage
description: Use when scanning for leaked credentials (Git history, working tree, artifacts, workstations) or triaging scanner findings. Covers running gitleaks safely, redacting output, classifying findings, and producing a fingerprint-only report. Trigger for Phase A baseline scans, scenario S0/S2/S3 work, or any "find secrets" request.
---

# Secret exposure triage

Goal: find every exposed credential, record it safely, and drive it to revoked-and-verified.

## Hard rules
- Always run scanners with redaction (`gitleaks ... --redact`) when you run them by hand. Never print raw match values.
  Exception (ADR-0004): Sentinel's own scanner (`sentinel scan`) runs unredacted in-process, keyed-hashes each
  value immediately and discards it. Prefer `sentinel scan` over hand-run gitleaks for registry work.
- Record findings by fingerprint (keyed hash `cred-fp-...`, or SHA-256 prefix by hand) + file + line + commit + date. Never the value.
- Reports go to `reports/` (git-ignored). Never commit reports.
- You do not revoke keys. You produce the revoke list; a human revokes and confirms.

## Procedure
1. Confirm scope with the user: which repos/paths, and whether history is included.
2. Run, from the repo root:
   - Full history: `gitleaks git --redact --report-format json --report-path reports/gitleaks-history.json`
   - Working tree / folder: `gitleaks dir --redact --report-format json --report-path reports/gitleaks-dir.json .`
   (Older gitleaks versions use `gitleaks detect`; check `gitleaks version` and adapt.)
3. Parse the JSON with a script; drop the `Secret`/`Match` fields before anything is displayed.
4. Classify each finding:
   | Class | Meaning | Next step |
   |---|---|---|
   | live-suspected | Real provider key format, not known fake | Add to revoke list, severity High (Critical if usage anomalies) |
   | fake/test | Canary or documented fixture | Add allowlist entry with justification |
   | false-positive | Not a credential | Add a narrow `.gitleaks.toml` allowlist entry with reason |
5. For live-suspected: identify provider, owning person, first-seen commit date, whether the repo
   is or was public, and blast radius (see `docs/spec/design-spec.md`, section 4).
6. Output a table: fingerprint, provider, location, first seen, public?, owner, status
   (`revoke-pending` / `revoked-unverified` / `revoked-verified`).
7. Emit one `secret_exposure` event per finding conforming to `docs/schemas/event.schema.json`.

## Verification
A finding is closed only when the user confirms revocation and a provider check (or failed auth
with the old key, performed by the user) is recorded. Otherwise `verified: false`.

## History cleanup
Rewriting history (`git filter-repo`) is approval-only and blocked for the agent. Propose the exact
command and backup steps; the user runs it. Remind them forks/clones/caches keep old data, so
revocation is the real fix.
