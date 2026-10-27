# S2: Secrets outside Git

- **Threat:** a key lands in a place Git scanning never sees: shell history, CI logs, agent transcripts, build artifacts, image layers.
- **Priority:** 1
- **Preconditions:** local temp dir; gitleaks on PATH; no network.
- **Simulated events (ordered):**
  1. Runtime-generated fake key written into each of five simulated locations (one file each).
  2. `gitleaks dir --redact` scan over each location.
  3. A clean location is scanned as the negative control.
- **Expected detections:** scanner stage only (finding per location). Usage correlation (R1) is Phase C.
- **Expected incident:** High.
- **Expected response class:** emergency pre-approved (revoke), then clean up the source.
- **Pass criteria:**
  - [x] Secret detected in each of the 5 location types
  - [x] Clean location produces no finding
  - [x] No secret value in any output or report
  - [ ] Keys inside JSON-escaped quotes (nested JSON in agent transcripts) detected: **known gap** found by this test, strict xfail. Hypothesis for fix: unescape JSON strings before scanning transcripts, or add a custom rule; then re-test.
  - [ ] Scanning real workstation locations (shell history, real CI logs, real transcripts): **not done**, needs user approval per path
- **Metrics captured:** detection per location type = 5/5.
- **Cleanup:** temp dir removed by pytest.
- **Limit (fact):** the test proves the scanner detects these file shapes, not that real history/log/transcript locations are being scanned regularly. That needs a collector (Phase C).
