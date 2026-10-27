# ADR-0005: Read-only network collectors (GitHub, Google Cloud)
Date: 2026-10-27 | Status: proposed (needs human review)

## Context
v0.1 correlates only simulated provider and GitHub events. Project rule 5 forbids network calls unless the
destination is documented in the module README and an ADR. Research: `docs/research/collectors.md`.

## Decision
- Allowed hosts, enforced by an allowlist in `sentinel/sources/http.py` (any other host raises an error):
  `api.github.com`, `monitoring.googleapis.com`, `apikeys.googleapis.com`, `oauth2.googleapis.com`.
- HTTPS only, GET only (plus the OAuth token refresh POST), timeouts on every request, bounded retries with
  backoff, pagination.
- Path denylist: any URL containing `getKeyString` (or `:getKeyString`) is refused before sending.
- Credentials: GitHub fine-grained read-only token from env `SENTINEL_GITHUB_TOKEN`; Google Application Default
  Credentials with read-only scope `cloud-platform.read-only`. Created by the user, never by the agent; never logged,
  stored, or included in error messages (errors carry status code and host only).
- Stored data is minimal: ids, timestamps, counts, flags and fingerprints. No public key bodies, diffs, request
  bodies or tokens.
- Each collector has a README naming its destinations and scopes.
- Tests never touch the network: they use a fake transport and documented-shape fixtures.

## Amendments after the 2026-10-27 security review (tests in `tests/sentinel/test_collectors.py`)
- **Redirects are never followed** (3xx is an error). Verified with local servers: urllib's default handler forwards
  `Authorization` to the redirect target, which would have sent the token off-allowlist.
- The path check runs on the percent-decoded path (repeatedly): `keystring` anywhere, `..` segments and any port other
  than 443 are refused. Response bodies are capped at 10 MB.
- The GitHub token is read from env `SENTINEL_GITHUB_TOKEN`, else from `<home>/github-token.txt` (created by the user in
  the git-ignored state dir; excluded from working-tree scans). Errors never include its content.
- Child processes get a minimal environment (the toast) or no `SENTINEL_*` variables (gitleaks).
- `verify-key` passes only on a recorded `deleteTime`, or when the exact key was previously seen in the inventory and is
  now gone. "Never seen" is not proof (a mistyped alias must not make a live key look revoked).
- History scans exclude no paths (a key under `build/` is still an exposure).
- **Open (not fixed):** `google-auth` makes its own HTTPS calls via `requests`, bypassing `HttpClient`, so its hosts
  (token refresh; other hosts depend on the ADC credential type) are not enforced by the allowlist. Restrict to
  `authorized_user` ADC and document the hosts before enabling the GCP collector. Cursors can advance before events are
  stored if storing fails. The usage baseline can be inflated by a slow ramp. Missing diff `patch` is treated as "no
  risky lines". Free-text CLI evidence is not screened for secrets. SQLite connections are not closed explicitly.

## Consequences (security, operations, cost)
- Security: new outbound traffic from the workstation to 4 hosts; read-only tokens limit blast radius if Sentinel
  is compromised. Token compromise is still possible from the environment; prefer short-lived ADC.
- Operations: Google usage data is visible up to ~30 minutes late (documented), so provider-signal MTTD is ~30 minutes or more.
- Cost: Cloud Monitoring read API calls are within free quotas at this volume (assumption; check billing).

## Alternatives considered
- Pub/Sub budget alerts or billing export: better cost data, needs more cloud setup (later).
- GitHub organisation audit log: not available for personal accounts.
