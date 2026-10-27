# S0: Secret in Git history abused

- **Threat:** API key committed, deleted in a later commit, still recoverable from history (origin incident).
- **Priority:** 1
- **Preconditions:** local temp git repo; gitleaks on PATH; no network; provider usage is mocked data only.
- **Simulated events (ordered, UTC offsets):**
  1. T+0: commit a file containing a runtime-generated fake key.
  2. T+1: delete the file in a second commit (working tree now clean).
  3. T+2: scan working tree (expect clean) and history (expect finding).
  4. T+3: mocked provider-usage event from an unknown IP (not correlated yet, see below).
- **Expected detections:** scanner stage of R1 (secret in commit). The usage-correlation half of R1 is Phase C and is NOT tested here.
- **Expected incident:** High (Critical once usage anomaly is correlated).
- **Expected response class:** emergency pre-approved (revoke), history rewrite approval-required.
- **Pass criteria:**
  - [x] History scan finds the deleted key; working-tree scan does not
  - [x] Finding recorded by fingerprint + file + commit only
  - [ ] R1 correlation with usage event (Phase C)
  - [x] No secret value in any output, log or report
- **Metrics captured:** time-to-detect (seconds from commit to finding).
- **Cleanup:** temp dir removed by pytest `tmp_path`.
