# ADR-0004: Credential fingerprints via keyed hash; gitleaks runs without --redact
Date: 2026-10-27 | Status: proposed (user approved the approach in chat; needs human review)

## Context
Location-based IDs (commit + file + line) make one key look like many findings and cannot be joined to
provider usage logs (R1). Project guidance said "always run gitleaks with --redact".

## Decision
- gitleaks runs without `--redact`; JSON is read from the child's stdout (never written to disk).
- `sentinel/scanners/gitleaks.py:parse()` is the only code that sees `Secret`. It computes
  `HMAC-SHA256(secret, local key)[:16]`, keeps `cred-fp-<digest>` and discards the value immediately.
- The local key is `<home>/fingerprint.key` (32 random bytes, created once, git-ignored with `.sentinel/`).
- `sentinel fingerprint` reads a key from a provider console with hidden input and prints only its ref,
  so a human can match it to a finding.
- Tests assert the fake value is absent from stdout, stderr and every file under the state directory.
- Updates the `secret-exposure-triage` skill: Sentinel's own scanner is the exception to `--redact`;
  agents running gitleaks by hand still use `--redact`.

## Consequences (security, operations, cost)
- Security: raw values live briefly in Sentinel process memory and gitleaks' pipe. Fingerprints cannot be
  reversed or brute-forced without the local key. Losing the key changes all refs (re-scan fixes it).
  Anyone who reads the key file and has a candidate value can test it: protect `.sentinel/`.
- Operations: refs are stable per machine/key file, so a second machine needs the same key to share refs.
- Cost: none.

## Alternatives considered
- Keep `--redact`, location-only IDs: safest, but duplicates findings and blocks provider linking.
- Unkeyed SHA-256: stable across machines but guessable for low-entropy values.
