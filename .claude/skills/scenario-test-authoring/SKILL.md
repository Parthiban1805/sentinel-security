---
name: scenario-test-authoring
description: Use when writing or updating continuous security test cases for threat scenarios S0-S15 (for example simulating a leaked fake key, a forbidden agent tool call, or an unauthorized workflow change). Defines the test case format, safe fake-credential handling, and pass criteria. Trigger for /new-scenario or "test whether our defenses catch X".
---

# Scenario test authoring

Continuous tests measure whether defences work, not whether scanners run.

## Safety rules
- Tests run only in an isolated test org/repo or local temp dirs. Never against production.
- Fake credentials are generated at runtime by the harness (random, provider-shaped, obviously fake
  prefix where possible). Never hard-code credential-shaped strings in the repo. If a fixture must
  be on disk, mark the line with `sentinel:allow-fake-secret` and add a gitleaks allowlist entry.
- Every emitted event sets `"is_test": true` so it is measured but pages nobody.
- No network calls to real providers. Mock provider responses.

## Test case format
Create `docs/scenarios/S<n>-<slug>.md` from `docs/scenarios/TEMPLATE.md`, then implement it in
`tests/scenarios/test_s<n>_<slug>.py`.

Required fields: scenario ID, threat, preconditions, simulated events (ordered), expected detections
(rule IDs), expected incident severity, expected response class, pass criteria, metrics captured
(time-to-detect, time-to-correlate), cleanup.

## Implementation pattern (pytest)
1. Arrange: build an isolated temp repo/workspace; generate fake credential via harness helper.
2. Act: replay the simulated events (e.g. commit the fake key, then inject a mocked provider-usage event).
3. Assert: the expected rule fired, the incident has the expected severity, the recommended action
   class is correct, and no secret value appears in any output, log or report.
4. Record time-to-detect. Clean up.

Always include a "no secret leaked in output" assertion.
