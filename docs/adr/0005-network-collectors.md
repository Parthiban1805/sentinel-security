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
  Credentials (`authorized_user` only). Created by the user, never by the agent; never logged, stored, or included in
  error messages (errors carry status code and host only). **Scopes (corrected twice on 2026-10-31):** Sentinel
  requests `cloud-platform.read-only` and `monitoring.read`. google-auth sends the requested scopes with every token
  refresh (checked in the google-auth 2.36.0 source: `google/oauth2/credentials.py` and `google/oauth2/_client.py`),
  so the access token IS narrowed to these read-only scopes. (The pre-live review had said the opposite; that claim
  was wrong and was briefly recorded here.) Sentinel's HttpClient (GET only, host allowlist) is a second, independent
  limit. `monitoring.read` was added after the first live run: Cloud Monitoring answered 403 to a token carrying only
  `cloud-platform.read-only` on all three projects of an Owner account, while API Keys accepted it (observed fact; the
  reason, that Monitoring does not accept that scope, is a hypothesis until the next run passes).
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
- **Fixed in the follow-up:** collector state (cursors, baselines, key snapshot) is committed only after the events
  were stored; the usage baseline ignores anomalous hours (a slow ramp cannot raise it) and warm-up flags a burst on a
  new key; a withheld diff (`patch` missing) is treated as unknown and risky (R2); ADC accepts only `authorized_user`
  credentials (service-account keys and external_account are refused); free text (evidence, notes, actor) is screened for
  credential-shaped strings; SQLite connections are closed, with a 30 s lock timeout and WAL.
- **GitHub protection audit (v0.4):** two more read-only GETs per repository, at most once per `audit_interval_hours` (default 24):
  `GET /repos/{owner}/{repo}` (default branch, visibility, `security_and_analysis`) and
  `GET /repos/{owner}/{repo}/branches/{default}/protection`. Same host, token and client rules as above. Reading these fully needs the
  fine-grained token permission **Administration: read**; without it GitHub answers 403 "Resource not accessible", which the audit reports as
  "cannot verify" (low confidence), not as a problem. On a free plan private repositories answer 403 "Upgrade to GitHub Pro ...", reported as
  a plan limit. HTTP error bodies are read (2 KB) only to map them to a fixed label (`plan_limit`, `no_permission`, `not_protected`) and are
  never stored or shown. A 401 is a health failure ("token expired, revoked or wrong"), never a finding.
- **TLS:** certificates are always verified. Sentinel uses the OS verifier (`truststore==0.10.0`) because Python's
  bundled path failed with "unable to get issuer certificate" on a machine behind a VPN/TLS-inspecting tool (the same
  failure occurred with plain `urllib`). A test asserts `CERT_REQUIRED` and hostname checking stay on. Note
  `google-auth` (via `requests`) still uses its own CA bundle and may hit the same error.
- **Still open:** `google-auth` still performs its own HTTPS token refresh via `requests` (oauth2.googleapis.com for
  `authorized_user`), outside HttpClient's allowlist; the free-text screen is a heuristic; `alerts.log` and the token
  file have default Windows permissions (no ACL hardening); how GitHub's `since` filter treats backdated commits is
  unverified against its docs.

## Amendment after the 2026-10-31 pre-live review of the Google collector
Found before the collector's first run on real data; all fixed and tested in `tests/sentinel/test_gcp.py`.
- **First contact learns, it does not alert.** With no cursor, the lookback window (7 days) is added to the baseline and no
  volume anomaly is raised; a NOTE says so. Without this, normal busy use would have looked anomalous (no baseline yet) and
  opened incidents for days of ordinary traffic. Use of a key whose revocation was verified still alerts on the first run.
  **Limit (fact):** abuse already running before the first run is learned as normal.
- **Warm-up is bounded:** warm-up hours are learned (still flagged above floor x multiple, with confidence `low`), so a busy
  new key stops being flagged after 24 hours instead of forever.
- **A project that fails part-way commits nothing:** the shared collector discards its pending baselines and cursor, so the
  window is read again next run instead of being skipped.
- **`verify-key`** treats "previously seen, now gone" as proof only if the key was seen in the SAME project as the alias.
- **Quota project:** requests carry `x-goog-user-project` (the quota project from the gcloud login, else the project being
  read), which user credentials need on some Google APIs. This uses the permission `serviceusage.services.use` on that
  project. **Unverified** against a live project until the first run.
- **No metadata-server probe:** `NO_GCE_CHECK=True` is set before loading credentials, so google-auth does not contact
  169.254.169.254 (an undocumented destination). Based on google-auth's documented environment variable; unverified live.
- **Errors give a next step:** Google error bodies are mapped to fixed labels (`api_disabled`, `scope_insufficient`,
  `quota_project`, `rate_limited`, `no_permission`) with fixed advice text; the body itself is never shown or stored.
  Malformed data points raise a fixed message (no response values in health). An empty or non-object body is an error,
  never "no keys". Pagination stops on a repeated token or after 50 pages. `key_status` reports `deleted: None` (unknown)
  for a key it did not find. `verify-key` reports credential problems by type only, without a traceback.
- **Recommended IAM (recommendation, not verified):** `roles/monitoring.viewer` and `roles/serviceusage.apiKeysViewer` on
  each project, plus `serviceusage.services.use` (for example `roles/serviceusage.serviceUsageConsumer`) on the quota
  project; the Cloud Monitoring and API Keys APIs enabled. Prefer a separate low-privilege Google identity over an Owner
  account.
- **Still open from this review:** `Retry-After` is not honoured on 429 (about 7 s of backoff in total); hour buckets are
  not aligned to the hour (possible overlap between runs, hypothesis); `displayName` is stored without the free-text screen;
  `doctor` does not check the Google credential type, quota project or enabled APIs; the unused OAuth POST allowance in
  `check_url` remains.

## Consequences (security, operations, cost)
- Security: new outbound traffic from the workstation to 4 hosts; read-only tokens limit blast radius if Sentinel
  is compromised. Token compromise is still possible from the environment; prefer short-lived ADC.
- Operations: Google usage data is visible up to ~30 minutes late (documented), so provider-signal MTTD is ~30 minutes or more.
- Cost: Cloud Monitoring read API calls are within free quotas at this volume (assumption; check billing).

## Alternatives considered
- Pub/Sub budget alerts or billing export: better cost data, needs more cloud setup (later).
- GitHub organisation audit log: not available for personal accounts.
