---
description: Run the Phase A baseline workflow (inventory, secret scans, canaries, baseline report)
argument-hint: [optional repo path or scope]
---

Run Phase A for scope: $ARGUMENTS (default: this repository).

Use the secret-exposure-triage and event-schema skills. Steps:
1. Confirm scope with me and list what you will scan. Wait for my OK.
2. Run redacted gitleaks scans of Git history and the working tree into reports/.
3. Produce the fingerprint-only findings table and a revoke list for me (you do not revoke).
4. Draft inventory entries for this repo's assets per docs/schemas/asset.schema.json, marking unknown owners.
5. Propose canary placements (no real permissions) for me to create.
6. Write reports/phase-a-baseline.md: findings, inventory gaps, metrics baseline (docs/spec/roadmap.md), Gate A status.
List everything that needs my action or approval at the end.
