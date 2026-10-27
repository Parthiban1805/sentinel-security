# ADR-0002: CI downloads a pinned, checksum-verified gitleaks from github.com
Date: 2026-10-27 | Status: proposed (needs human review)

## Context
`.github/workflows/secret-scan.yml` installs gitleaks in CI. Project rule 5 requires any network destination
used by code we write to be documented. Previously the version was old (8.18.4), unchecked, and
`actions/checkout` was referenced by a movable tag (supply-chain risk, scenario S8).

## Decision
- Destination: `https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/` (read-only download, runs in CI only).
- Pin gitleaks to 8.30.1 and verify the SHA-256 (from the GitHub release asset digest) before extracting.
- Pin `actions/checkout` to full commit `11d5960a326750d5838078e36cf38b85af677262` (the `v4` tag on 2026-10-27).
- Pre-commit gitleaks hook pinned to `v8.30.1`.

## Consequences (security, operations, cost)
- Security: a moved tag or tampered release asset fails the checksum / cannot change the pinned action. Residual risk: the checksum comes from the same GitHub release, so it detects accidental or partial tampering, not a compromise of the release itself. Out-of-band verification (e.g. signed provenance) would be stronger.
- Operations: bumping versions is a deliberate manual change (update SHA and checksum together).
- Cost: none.

## Alternatives considered
- Official `gitleaks/gitleaks-action`: adds a third-party action and licensing terms for orgs; rejected for now.
- Unpinned latest: rejected (supply-chain risk).
