# ADR-0003: Local Python CLI and core library, SQLite store, pluggable sources
Date: 2026-10-27 | Status: proposed (needs human review)

## Context
ADR-0001 chose to reuse scanners and build inventory, correlation and response. The user chose a CLI plus a
core library for v0.1 (a FastAPI service or UI can wrap the library later) and uv for tooling.

## Decision
- Package `sentinel/` (events, scanners, sources, store, inventory, correlation, incidents, reporting, cli).
- State in SQLite (standard library) at `.sentinel/sentinel.db`. `.sentinel/` is git-ignored: it maps where
  secrets were found, so it is treated as sensitive and must not be synced, uploaded or committed.
- Sources implement `collect(since) -> Iterable[Event]`. v0.1 has gitleaks (real, local) and JSONL replay
  (simulated). Real network collectors (Google usage/billing, GitHub audit log) need their own README and ADR
  before any network call (project rule 5).
- Correlation rules are pure functions over event lists; AI never makes blocking decisions.
- Sentinel recommends and records approvals; it does not execute response actions.
- Tooling: uv with a lockfile, Python 3.11+, dependencies pinned exactly.

## Consequences (security, operations, cost)
- Security: no network in v0.1; the store is local and sensitive. Residual risk: anyone with disk access reads the store.
- Operations: single machine, single user. Multi-machine coordination is a later decision.
- Cost: none.

## Alternatives considered
- FastAPI + Next.js now: bigger scope, hosting decisions first.
- JSONL files only: no joins or transactions; harder dedup and lifecycle tracking.
