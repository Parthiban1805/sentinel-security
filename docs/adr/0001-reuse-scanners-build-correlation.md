# ADR-0001: Reuse scanners, build inventory/correlation/response
Date: 2026-10-26 | Status: proposed
## Context
Mature secret, dependency and config scanners exist. Our gap is linking findings to impact and response.
## Decision
Use gitleaks (and optionally trufflehog), GitHub native security features and provider logs. Build the
inventory, event normalization, correlation rules, incident workflow and agent gateway ourselves.
Start as a local Python CLI; add a central service only when multiple machines need coordination.
## Consequences
Faster value, less maintenance. Depends on scanner output formats (pin versions, test parsers).
## Alternatives considered
Mostly custom scanners (slow, duplicative); commercial platform (cost, weak agent coverage).
