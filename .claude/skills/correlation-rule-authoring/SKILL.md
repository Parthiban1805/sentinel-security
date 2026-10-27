---
name: correlation-rule-authoring
description: Use when adding or changing detection and correlation rules (R1-R9 and new ones) that link normalized events into incidents, or when tuning risk scoring. Defines the rule spec format, determinism requirements, and test obligations. Trigger for /new-rule or work in sentinel/correlation.
---

# Correlation rule authoring

Rules are deterministic and explainable. AI may summarize incidents; it never decides blocking.

## Rule spec (add to `docs/spec/correlation-rules.md` first)
- ID, name, scenarios covered (S-IDs)
- Inputs: event types + required fields (from `docs/schemas/event.schema.json`)
- Join keys: e.g. `credential_ref`, `identity_ref`, `asset_id`
- Window: max time between events (justify it)
- Condition: plain-language + pseudocode
- Output: incident severity, confidence, recommended response class
- False-positive notes and suppression conditions
- Known gaps

## Implementation rules
- Pure functions over event lists; no I/O inside rule logic.
- Only safe identifiers (fingerprints/refs) in rule inputs and outputs.
- Output must state which facts matched and which link is a hypothesis.
- Test cases required: true positive, true negative, near-miss outside window, and test events
  (`is_test: true`) routed to metrics only.

## Risk scoring
R = f(E, I, X, P, C): exploitation evidence, asset importance, external exposure, privileges,
confidence. Use fixed severity bands in code (no learned scores). Keep severity, confidence and
urgency as separate fields.
