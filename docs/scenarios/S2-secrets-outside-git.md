# S2: Secrets outside Git

- **Threat:** a key lands in a place Git scanning never sees: shell history, CI logs, agent transcripts, build artifacts, image layers.
- **Priority:** 1
- **Preconditions:** local temp dir; gitleaks on PATH; no network.
- **Simulated events (ordered):**
  1. Runtime-generated fake key written into each of five simulated locations (one file each).
  2. `gitleaks dir --redact` scan over each location.
  3. A clean location is scanned as the negative control.
- **Expected detections:** scanner stage only (finding per location). Usage correlation is rule R1.
- **Expected incident:** High.
- **Expected response class:** emergency pre-approved (revoke), then clean up the source.
- **Pass criteria:**
  - [x] Secret detected in each of the 5 location types
  - [x] Clean location produces no finding
  - [x] No secret value in any output or report
  - [x] Keys inside JSON-escaped quotes (nested JSON in agent transcripts, one and two levels deep) detected: **fixed in v0.3a**. Plain gitleaks still misses them (a test documents that); Sentinel's scanner decodes `.json` and `.jsonl` string values in memory and scans the decoded text through `gitleaks stdin`, so nothing extra is written to disk. Limits: only `.json`/`.jsonl` files up to 20 MB; log formats that are not JSON are not decoded.
  - [x] Opt-in locations (**built in v0.5, ADR-0011**): `[scan] extra_paths` lists folders or single files; `sentinel run` scans them in
    `dir` mode and records each as a `scan_location` asset. Tested with a runtime-generated fake key in a folder, a single history-style
    file and a JSON-escaped transcript; findings hold a fingerprint, a relative file name and a line, never the value. A missing path is a
    health error, not "clean". Default list is empty.
  - [ ] Scanning real workstation locations (shell history, real CI logs, real transcripts): **not done**; the owner must list each path
    in `sentinel.toml` first. Sentinel never scans a location that was not listed.
- **Metrics captured:** detection per location type = 5/5.
- **Cleanup:** temp dir removed by pytest.
- **Limit (fact):** the test proves the scanner detects these file shapes, not that real history/log/transcript locations are being scanned regularly. That needs a collector (later release).
