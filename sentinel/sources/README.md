# sentinel/sources: signal collectors

Network rules (project rule 5, ADR-0005): every request goes through `http.HttpClient`, which enforces HTTPS,
the host allowlist below, GET-only (POST only for OAuth refresh), timeouts, bounded retries, and refuses any
path containing `keyString` (raw API key retrieval).

| Collector | Destination | Auth | Reads | Emits |
|---|---|---|---|---|
| `github.py` | `api.github.com` | env `SENTINEL_GITHUB_TOKEN`, fine-grained, read-only | `/user`, `/user/keys`, repo commits (workflow paths + 90-day authors), commit detail, releases | `ssh_key_added`, `workflow_changed`, `release_published` |
| `gcp.py` | `monitoring.googleapis.com`, `apikeys.googleapis.com`, `oauth2.googleapis.com` | Application Default Credentials, scope `cloud-platform.read-only` | `consumed_api` request counts by `credential_id`; API key metadata (never key strings) | `credential_usage_anomaly`, `spend_anomaly` (proxy) |

Stored: ids, times, counts, flags, fingerprints. Never stored: tokens, public key bodies, diffs, request bodies.
Tests use a fake transport (`tests/sentinel/test_collectors.py`); they never touch the network.

## Separate network module: exposure probes (`sentinel/probes.py`, ADR-0008)
Not a collector and NOT on the fixed allowlist above: its destinations are the **owner's own hosts**, listed in the git-ignored config
with `confirm_ownership = true` (or `--i-own-this`). Without that confirmation nothing is contacted. GET only, a fixed list of at most
25 paths, a pause between requests, no redirects, at most 512 bytes read per path and only to test the file's shape; content is never
stored or printed. Its tests use local servers on 127.0.0.1 only.
