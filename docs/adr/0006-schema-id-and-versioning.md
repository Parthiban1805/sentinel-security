# ADR-0006: Schema `$id` is a valid URI reference with the version in the path
Date: 2026-10-27 | Status: accepted by owner delegation (needs human review)

## Context
The event and asset schemas declared `"$id": "sentinel/event.schema.json#v1"`. JSON Schema forbids a non-empty
fragment in `$id`, so the validator rejected the schema itself. Since v0.1 the loader worked around it by dropping `$id`
before validating, which hid the bug and left the files wrong.

## Decision
- `$id` becomes `sentinel/v1/event.schema.json` and `sentinel/v1/asset.schema.json` (version in the path, no fragment).
- The loader no longer drops `$id`; a test asserts both schemas pass `check_schema`.
- Versioning rule (from the event-schema skill): a breaking change creates `sentinel/v2/...`; producers and tests are updated
  in the same change, and v1 stays readable for one version.
- The event and asset *shapes* are unchanged, so existing stored data stays valid.

## Consequences
- No data migration. Anything that referenced the old `$id` string (nothing in this repo does) must update.
- Schema errors can no longer hide behind the workaround.

## Alternatives considered
- Keep dropping `$id` in the loader: hides a real defect.
- Put the version in a `version` keyword: not interoperable; the path is the common convention.
