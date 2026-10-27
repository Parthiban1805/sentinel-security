# S1 / S15: Sensitive file or backup served by our own host

- **Threat:** a web server (for example Nginx) serves `.env`, `.git/` or a database backup, so anyone can download credentials, source or data.
- **Priority:** 1 (S1), 3 (S15)
- **Preconditions:** local throwaway HTTP servers on 127.0.0.1; fake secrets generated at runtime inside the served files; no third-party hosts.
- **Simulated events (ordered):**
  1. A server serves `/.env`, `/.git/config`, `/backup.sql`, `/backup.zip` and `/db.sqlite` (bodies shaped like the real files).
  2. `sentinel probe` sweeps the fixed path list; findings become `exposed_service` events; rule R10 opens an incident.
  3. The owner removes the files; the incident step `verify_path_closed` re-probes and verifies automatically.
- **Expected detections:** rule R10 (one incident per host and path). Severity critical for secret-bearing files, high for source or data, medium for information leaks.
- **Expected incident:** critical or high, confidence high that the file is served; whether it was already fetched or used is unknown (hypothesis).
- **Expected response class:** approval-required (block the path, rotate secrets), investigate-first (access logs, re-probe).
- **Pass criteria:** (`tests/sentinel/test_probes.py`, 37 tests)
  - [x] Exposed files are detected by shape; clean hosts, catch-all single-page sites, error statuses (401/403/404/410/500) and redirects are NOT
  - [x] Only the fixed paths are requested, with a byte range; at most 512 bytes are read; content never reaches events, snapshots, incidents or output
  - [x] Unsafe targets are refused (no scheme, plain http without opt-in, credentials, paths, bad ports, cloud-metadata addresses)
  - [x] No ownership confirmation means zero requests; the config loader rejects unconfirmed hosts
  - [x] An unreachable host is inconclusive (never "clear") and is abandoned after 3 unanswered requests; its previous exposures are kept
  - [x] Re-runs are idempotent; fixed exposures are reported as cleared; `sentinel run` probes at most once per interval
  - [x] The fix is verified by the system: a re-probe passes only on a definitive clean answer, fails while the file is served, and fails on a network error; the incident cannot close until it passes
  - [ ] Detection of a real exposure on a real host: **not done** (needs a host you own and your confirmation)
- **Metrics captured:** exposed paths per host by scenario; time from probe to verified closure.
- **Known limits (facts):** fixed path list; first 512 bytes only; WAF or authentication can hide a path from the probe; a deliberately public sample file that looks like an env file is a false positive.
- **Cleanup:** servers shut down by the test; temp state dirs removed by pytest.
