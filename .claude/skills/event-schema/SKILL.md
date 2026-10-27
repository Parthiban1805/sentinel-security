---
name: event-schema
description: Use when writing collectors, parsers or normalizers that turn tool output (gitleaks, GitHub audit log, provider usage, CI, agent logs) into Sentinel events or assets, or when changing docs/schemas. Ensures every event and asset conforms to the JSON schemas and contains no raw secrets.
---

# Event and asset schema

Schemas: `docs/schemas/event.schema.json`, `docs/schemas/asset.schema.json`.

## Rules
- Validate every produced event/asset against the schema in tests (use `jsonschema`).
- Credentials and identities appear only as refs/fingerprints (`cred-fp-...`, `user-fp-...`).
- Timestamps are UTC ISO 8601.
- `confidence` and `severity` are separate; `verified` defaults to false.
- `evidence_ref` points to stored evidence metadata, not to raw logs with secrets.
- Collectors are read-only and minimal: drop fields not needed for detection or investigation.

## Changing a schema
1. Bump `$id` version suffix and note the change in an ADR.
2. Update all producers and tests in the same change.
3. Keep backward compatibility for one version where feasible.

## Normalizer pattern
`parse(raw) -> list[RawFinding]` -> `redact(finding)` -> `to_event(finding) -> dict` -> `validate(event)`.
Redaction happens before any logging.
