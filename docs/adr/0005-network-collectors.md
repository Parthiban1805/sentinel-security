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

## Consequences (security, operations, cost)
- Security: new outbound traffic from the workstation to 4 hosts; read-only tokens limit blast radius if Sentinel
  is compromised. Token compromise is still possible from the environment; prefer short-lived ADC.
- Operations: Google usage data is visible up to ~30 minutes late (documented), so provider-signal MTTD is ~30 minutes or more.
- Cost: Cloud Monitoring read API calls are within free quotas at this volume (assumption; check billing).

## Alternatives considered
- Pub/Sub budget alerts or billing export: better cost data, needs more cloud setup (later).
- GitHub organisation audit log: not available for personal accounts.
