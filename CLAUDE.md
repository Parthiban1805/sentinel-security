# Sentinel: Internal AI & Developer Security System

Project memory for Claude Code. Read this first in every session.

## What we are building
One internal security system that prevents, detects, investigates and contains incidents across
our development and AI infrastructure. Origin incident: a Gemini API key committed to a repo,
deleted, but left in Git history and abused. The full design lives in `docs/spec/`.

Central question: detect a problem -> understand what it could affect -> determine whether it is
being exploited -> stop it safely -> verify -> improve.

## Current phase
**Building the product.** Follow `docs/product-plan.md` (releases v0.3 to v1.0) and `docs/spec/roadmap.md`
(phases B, C, D). The repos used as test material are dummy repos: baselining them is out of scope.
Confirm scope with the user before starting each release.

## Non-negotiable rules (security)
1. NEVER print, log, store, commit or echo a secret value. Refer to secrets only by fingerprint
   (first 4 + last 4 chars, or a SHA-256 prefix) and file:line location.
2. NEVER read `.env`, key files, `~/.ssh`, cloud CLI config or credential stores. Settings and hooks
   block this; do not try to work around a block. Ask the user instead.
3. NEVER generate real-looking credentials. Test data uses obviously fake canary values that the
   test harness generates at runtime (see `docs/scenarios/README.md`).
4. Disruptive actions need explicit human approval in chat first: revoking keys, rewriting Git
   history, force push, disabling accounts, firewall changes, deleting data, deploying.
5. No network calls from code you write unless the destination is documented in the module's README
   and in `docs/adr/`. Collectors are read-only by default.
6. Facts vs hypotheses: in code, reports and summaries, label inferences as hypotheses. Similar timing
   alone never proves a shared attacker.
7. Incidents close on verification evidence, never on assumption. Unverifiable = `verified: false`.
8. All generated code, infra and recommendations require human review before production use.

## Engineering conventions
- Language: Python 3 for the CLI and collectors (org scaffold standard applies when the
  service/UI repos are created: see "Open decision" below).
- Layout (create as needed): `sentinel/` package with `inventory/`, `scanners/`, `events/`,
  `correlation/`, `incidents/`, `reporting/`; tests in `tests/` mirroring the package.
- Reuse mature tools (gitleaks, trufflehog, GitHub native features, provider audit logs). Build glue,
  inventory, correlation and response; do not write new secret scanners.
- Every event conforms to `docs/schemas/event.schema.json`; every asset to `asset.schema.json`.
- Small, focused modules with typed interfaces. Tests first for rules and parsers.
- Lint/format: `ruff check . && ruff format .`; types: `mypy sentinel`; tests: `pytest -q`.
- Pin dependency versions; pin GitHub Actions to full commit SHAs once verified.
- Write an ADR in `docs/adr/` for each architectural decision (template: `docs/adr/0000-template.md`).

## Where things are
| Need | File |
|---|---|
| Full design spec | `docs/spec/design-spec.md` (export of the team doc) |
| Scope, phases, gates | `docs/spec/roadmap.md` |
| Threat scenarios S0-S15 | `docs/scenarios/README.md` |
| Correlation rules R1-R9 | `docs/spec/correlation-rules.md` |
| Event / asset schemas | `docs/schemas/` |
| AI agent policy | `policies/agent-policy.md` |
| Incident runbook | `docs/runbooks/credential-exposure.md` |

## Skills and commands available
Skills (auto-loaded when relevant): `secret-exposure-triage`, `incident-response`,
`scenario-test-authoring`, `correlation-rule-authoring`, `agent-policy-enforcement`,
`event-schema`.
Commands: `/new-scenario`, `/new-rule`, `/security-review`, `/incident`.
Subagents: `security-reviewer` (read-only review), `scenario-tester` (writes and runs tests).

## Workflow
1. Restate the task and which phase/scenario/rule it serves.
2. Check the relevant skill and spec file before writing code.
3. Plan in small steps; write tests first for rules, parsers and policy checks.
4. Run lint, types and tests. Run `gitleaks protect --staged` before suggesting a commit.
5. Summarize what changed, what is unverified, and what needs human review.

## Open decision
The org scaffold standard defaults new projects to two repos (Next.js frontend + FastAPI backend).
The spec starts with a local Python CLI. Ask the user before scaffolding service/UI repos.
