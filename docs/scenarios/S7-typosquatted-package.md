# S7: Malicious or typosquatted package (static-check slice)

- **Threat:** a dependency that imitates a popular package, or runs code at install time, is added and then reads credentials or sends data out.
- **Priority:** 1
- **Preconditions:** local throwaway Git repos; no network; no package is ever installed or imported.
- **What this slice covers (preventive and observational):**
  1. Parse `requirements*.txt`, `pyproject.toml` (PEP 508, optional and group dependencies, Poetry) and `package.json` / `package-lock.json`.
  2. Hygiene findings **D1** typosquat (a HYPOTHESIS: name within one edit of a popular package, or a digit-for-letter swap), **D2** version
     not pinned (only when no lockfile pins it), **D3** no lockfile, **D4** install-time scripts (the project's own and lockfile packages,
     ignoring the ubiquitous `fsevents` and `esbuild`), **D5** URL, git or custom-index dependencies.
  3. `dependency_added` events: each `sentinel run` compares the dependency set with the stored snapshot. The first run is a baseline
     (no events); new names produce one deterministic, deduplicated event each, flagged when they look like a typosquat.
- **Expected detections:** D1 to D5 findings (`config_drift` events via `sentinel hygiene --record`) and `dependency_added` events.
  The rule that links a new dependency to later credential access or unexpected egress is **R3** and needs endpoint or runner telemetry
  (later release): it is NOT tested here.
- **Expected incident:** none from this slice alone (R3 is the correlation).
- **Pass criteria:**
  - [x] Misspelled, transposed, extra-letter and digit-swap names of popular packages are flagged; the real names, legitimate
        extensions and scoped names are not (`tests/sentinel/test_dependencies.py`)
  - [x] First run builds a baseline; a newly added dependency emits one event; re-running emits none
  - [x] A lockfile suppresses unpinned-range noise (found on real projects); ubiquitous install scripts are not reported
  - [x] Nothing is installed, imported or fetched; manifests are parsed as text
  - [ ] New dependency followed by credential access or egress on the same machine or runner (R3): **not built**, needs telemetry
- **Known limits (facts):** the popular-package lists are small and static (about 75 per ecosystem); a typosquat of an unlisted package is
  missed; some near-identical names are legitimate (hence "hypothesis"); no vulnerability or malware database is consulted; transitive
  dependencies are seen only through npm lockfile install-script flags.
- **Metrics captured:** findings per repo by check id.
- **Cleanup:** temp dirs removed by pytest.
