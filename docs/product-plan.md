# Sentinel: product plan to an end product

Status as of 2026-10-27. Sizes are relative (S = days, M = 1 to 2 weeks, L = several weeks), not commitments.
Revised after the plan review: tamper-evident agent telemetry, quieter R5, real verification evidence, honest
coverage claims, and unfinished foundations first.

## 1. The end product

**One line:** a security operations product that every employee system can run, which finds credential, CI and
AI-agent risks, connects the evidence into incidents, drives each one to *verified* containment, and shows the
organisation its security state in one place.

**Direction:** internal first, sell later. Internal means we run it across our own employee machines and
infrastructure. Later means other organisations can install and operate it.

### Product shape (v1.0, "internal general availability")
| Part | What it is |
|---|---|
| **Endpoint agent** | Small signed installer for Windows first, then macOS and Linux. Runs read-only collectors locally (secret scan, CI and dependency checks, agent activity), works offline, syncs to the service. Sends fingerprints and metadata, never raw secrets or source code. |
| **Central service** | Receives events from many machines, correlates across them, owns incidents, approvals and the audit log. |
| **Console** | Web UI: findings, incidents, asset and access graph, agent activity, coverage, collector health, approvals. |
| **Response** | Reversible actions (revoke a key or token, cap quota, suspend an agent credential) behind individual approvals, each followed by automatic verification. |
| **Assistant** | AI that summarizes an incident's evidence and unknowns. It never approves or blocks anything. |

### Definition of done for v1.0
- A new employee machine can be enrolled in under 10 minutes with one command or a managed push, no manual token handling.
- A leaked key is detected, correlated with real provider usage, and an incident opens within minutes, on real data.
- Every incident closes with verification evidence gathered by the system where a verifier exists; unverifiable closures are flagged.
- Every in-scope agent action has a recorded decision, and tampering with that record is detectable.
- The coverage report states, per scenario, what is verified on simulated input and what has a live source.
- Priority 1 scenario tests pass continuously in CI.
- Two or more operators with separate identities approve actions; the audit log records who.
- Documentation, runbooks and an upgrade path exist; the system has had an independent security review.

### Later, to sell (v1.x)
Multi-tenant isolation (organisation id on every record), single sign-on, billing and licensing, compliance
evidence, support tooling, a public API. Design hooks for these early (see section 5), build them after v1.0.

## 2. Principles
1. **Rules decide, AI explains.** Deterministic, explainable detection; AI never authorizes actions.
2. **Facts are separated from hypotheses**; unknowns are listed. Timing alone never proves a shared attacker.
3. **No raw secrets stored**; fingerprints only. Collectors are read-only and use documented hosts (ADRs).
4. **Closure needs evidence.** Evidence comes from a verifier or a recorded human attestation, labelled as such.
5. **Claims are honest.** "Verified on simulated input" and "live source present" are different columns.
6. **Prove before building on it.** A source or rule is not a foundation until it has run on real data.

## 3. Where we are

| Area | Built | Proven on real data | Gap |
|---|---|---|---|
| Secret scan, registry, fingerprints | yes | yes (local repos) | Locations outside Git (S2 gap) |
| Inventory and blast radius | yes | partly | Only repository and API key assets exist; no approve or owner command |
| GitHub collector, R2, R8 | yes | R2 live; first alert was a false positive, fixed | R8 not seen live |
| Google Cloud collector, R1 on real data | yes | **no** | Never run live; origin incident chain unproven end to end |
| Rules R4, R6, R7 | yes | no (simulated) | Real sources missing |
| Incidents, approvals, verified closure | yes | simulated incidents; one real R2 | Evidence mostly typed by a human; one automated verifier (Google) |
| Continuous run, alerts, doctor | yes | run live, alerts tested | Scheduler not enabled; no soak test |
| Agent security | guard hooks, S11 tests | n/a | Decisions not recorded; no agent or MCP inventory; no R5 |
| Service, console, installer, response actions, assistant | no | | Entire product shell |

## 4. Release plan (each release has exit criteria that must be demonstrated)

### v0.3a: Foundations and proof  [M]  (status 2026-10-27: code complete; Google live, soak run and patch application pending)
Done and tested (234 tests): schema `$id` fix (ADR-0006); S2 JSON-escape fix; "Gate A" wording removed; `inventory set`
(owner, approval, importance, monitoring; audited; secret-screened); `sentinel coverage` with a CI regression check and
committed baseline; tamper-evident decision log with chain plus anchor, `agentlog verify`, `doctor` check and run-time check
(ADR-0007); hook patch files in `docs/patches/agent-decision-log/` (not applied: protected files); hook facts verified
(`docs/research/agent-hooks.md`). **Still open:** you apply the hook patch; Google live and the 7-day soak (need `gcloud`
and the scheduler script); log rotation that preserves the chain and anchor.
Goal: what exists is correct, honest and proven before more is built on it.
- Fix the schema `$id` bug (ADR + version bump). Fix S2 (unescape JSON before scanning). Remove "Gate A" wording from reports.
- `sentinel coverage`: runs each scenario chain through the real pipeline in a temporary state dir; matrix columns are
  **logic verified on simulated input**, **live source present** (from collector health), **rule exists**, **plan
  generated**, **closure verifiable**; lists telemetry gaps (event types with no producer, asset types never seen);
  exits non-zero on regression; added to CI with a committed baseline.
- `inventory approve` and `inventory own` (set owner, approval, importance) so assets can leave the "unowned" state.
- Agent decision log, **tamper-evident**: hooks append one JSON line per *denial* and per MCP call (not every allowed
  call), holding time, session id, tool, rule id, target class and a keyed fingerprint (no raw command or path); each line
  carries a hash chained to the previous one; a session-start heartbeat; `doctor` checks that hooks are wired and the
  log chain is intact. Hooks and `settings.json` are protected files: **you apply these patches**; they also block agent
  writes to `.sentinel/`.
- Verify the hook facts in the official docs first: `session_id` in hook input, and the `mcp__.*` matcher.
- Google Cloud live (needs `gcloud` and a read-only login) and a scheduled 7-day soak run, if Google stays in scope.
- **Exit:** coverage matrix generated in CI; log tamper test fails the chain check when a line is edited or removed;
  7 days of scheduled runs with no collector errors; if Google is in scope, one real R1 path on a throwaway key.

### v0.3b: Agent visibility  [M]
Goal: see AI-agent behaviour. Only after v0.3a, and after a week of real log data shows the false-positive rate.
- `sentinel/sources/agent.py`: reads the log by offset (handles rotation and truncation), validates the chain,
  emits `agent_tool_denied` and `agent_tool_allowed` events, uses the deferred-state commit pattern, isolated like other sources.
- `inventory agents`: an `ai_agent` asset per workspace and `mcp_server` assets from project `.mcp.json` and project
  settings (server name, transport, host only; env and header values dropped before storage). **Limit stated in the
  docs:** servers configured at user scope are not visible, because that config holds credentials and is off limits.
- **R5** (spec first): **R5b** is the main alert (3 or more denials in one session within 30 minutes, configurable
  `[confirm]`, hypothesis: possible injection); **R5c** fires on an allowed call to an MCP server not approved in the
  inventory, only for servers that went through `inventory approve`; **R5a** (a single denied sensitive action) is
  recorded as context and counts toward R5b but does not open an incident, because the keyword guard produces harmless
  denials (it blocked this very session's commands that merely contained words like "curl" and "SSH").
- R5 response plan: review the session's untrusted inputs; suspend the agent session or credential (approval, dry run);
  approve or remove the MCP server (approval). **Verification evidence:** hook and settings files unchanged (hash), log
  chain intact, and the credential actually revoked or session ended: not "no more denials".
- Scenario docs and tests: extend S11 (decision logged, no raw command or path in the log, a hook still denies when
  logging fails); add S12 (unapproved MCP server used). Fake values generated at runtime.
- ADR-0006: decision log (location, fields, chain, retention, rotation, privacy, why this is not the gateway yet).
- **Exit:** R5b and R5c demonstrated end to end; a steered-agent simulation raises one incident, not a flood.

### v0.4: Prevent (CI, dependencies, hygiene)  [L]  (status 2026-10-27: `sentinel hygiene` built and run on real repos)
Done: `sentinel hygiene` (24 tests; 258 total). Checks use Git metadata and workflow text only, never file contents:
H1 sensitive file tracked, H2 untracked and not ignored, H3 `.gitignore` gaps, H4 no pre-commit scan, H5 no CI scan,
H6 repo-dump or database files; workflow checks W1 unpinned actions, W2 and W3 `pull_request_target`, W4 and W5 permissions,
W6 script injection. Findings become `config_drift` events (idempotent), `sentinel run` includes it, `--fail-on` gates CI,
`[hygiene] ignore` records documented exceptions. A real run on six repos found tracked `.env` files, a not-ignored `.env`
and unignored repomix dumps. **Dependency checks (S7) built:** D1 typosquat (hypothesis), D2 unpinned (only without a lockfile), D3 no lockfile, D4 install
scripts, D5 URL, git or custom-index dependencies, plus `dependency_added` events from snapshot diffs (284 tests); doc
`docs/scenarios/S7-typosquatted-package.md`. A first real run produced noise (every npm project flagged for ranges), which was
fixed by trusting lockfiles. **`sentinel init` built** (guided setup: config, state dir, GitHub repo detection, hidden token prompt, `.gitignore`, health check;
repo and project names validated). **Exposure probes (S1, S15) built:** `sentinel probe` checks owner-confirmed hosts for served
`.env`, `.git`, SQL dumps, archives and key files by file SHAPE (never storing content), rule R10, and the first automatic
verifier that is not Google-specific (`incident verify-probe` re-probes the path; a network error fails the step). ADR-0008, scenario
doc `S1-exposed-sensitive-path.md`. Exercised live on a local server (detected, verified failing while exposed and passing after the fix, closed verified).
**Canary decoys built** (R7 for real, ADR-0009): fake provider-shaped credential files; a COPIED decoy (found by the normal secret scan) is a
critical incident, tampering is a high incident, a READ is a low-confidence event that never pages; decoys never become live-credential
findings; exercised live in a scratch folder. **Not detectable with a self-built decoy:** use at a provider. **GitHub protection audit
built:** `sentinel audit` and a daily pass in `sentinel run` report default-branch protection, force pushes, required reviews, secret
scanning and push protection; a plan limit, a missing token permission ("cannot verify") and a rejected token (401, a health failure) are
told apart. Run live, it found that the configured token is being rejected by GitHub (expired or revoked); the product now says so clearly.
**v0.4 is functionally complete** (391 tests). Remaining from the original list: rule R3, which needs endpoint telemetry (v0.8).
- `sentinel hygiene`: tracked `.env`, missing `.gitignore` entries, missing pre-commit hook, dump files.
- Workflow policy checks (S8, S9, S10): unpinned actions, `pull_request_target` on untrusted code, broad permissions;
  extend R2. Dependency checks (S7): new dependency, typosquat heuristics, install scripts, lockfile pinning
  (`dependency_added` events, prepares R3). GitHub protection audit per repo.
- Canaries (R7, real): self-built decoys first (a permissionless key in a dedicated project, a decoy URL on a server
  we control); a hosted canary service can be added later for faster alerts.
- Exposure probes (S1, S15): read-only checks of our own hosts for reachable `.env`, `.git` and backups.
- **Exit:** hygiene clean or excepted on in-scope repos; Priority 1 scenarios S0, S1, S2, S7, S11 pass in CI; first recovery drill.

### v0.5: Evidence and verification automation  [M]
- Credential exposure beyond Git: logs, build artifacts, agent transcripts, shell history (opt-in paths).
- Verifiers per step type: re-scan clean, provider status (Google today; GitHub tokens and keys next), post-closure
  watch window that reopens an incident on renewed use of a "revoked" credential.
- Automatic blast-radius edges from provider metadata (what a key or token can actually reach).
- **Exit:** at least three step types verified by the system with no human-typed evidence.

### v0.6: AI investigation assistant  [M]
- Redacted evidence pack per incident; Claude summarizes impact, lists unknowns and proposes investigation steps; drafts
  the report. Never changes state. Secrets and personal data removed before any model call; untrusted text treated as data;
  prompt-injection tests; outputs labelled AI-generated.
- ADR for the outbound API destination and data rules; cost limits.
- **Exit:** 20 incidents scored by a human for accuracy; zero leakage and zero successful injection in tests; test proves the assistant is on no approval path.

### v0.7: Agent gateway  [L]
- Policy engine and local gateway for tool calls with per-agent identity and a decision record; default deny for
  sensitive actions; sandboxed risky tools (container or VM, egress allowlist); R9 (sensitive access with no decision);
  MCP allowlist with owner, pinned version and review; kill switch; injection suite in CI.
- **Exit:** every in-scope agent action has a decision; the two recorded hook-bypass tests turn green; kill-switch drill passes.

### v0.8: Endpoint agent and central service  [L]
Detailed design happens here; direction is decided (plug-and-play on every employee system).
- Installer and enrolment (see section 5), local-first agent that syncs, central service and datastore, authentication
  and roles, per-user approvals, immutable audit log, read-only console first, then approvals in the console.
- Telemetry from developer machines (editor extensions S5, credential-file access, shell history and transcript scans)
  and CI runners; rule R3.
- **Exit:** two operators and two machines on shared state; approvals attributed to individuals; restore drill passed;
  enrolment under 10 minutes.

### v0.9: Real response  [M]
- Adapters for specific actions with approval, dry run, rollback plan, audit entry and automatic verification: revoke a
  GitHub token or key, delete a Google API key, cap quota, suspend an agent credential, isolate a runner.
- Emergency pre-approved policies only where a human explicitly agreed.
- **Exit:** each adapter proven in a sandbox account; failed action leaves the incident open; drills pass.

### v1.0: Internal general availability  [M]
Everything in the definition of done (section 1): service levels, metrics, runbooks per rule, on-call and escalation,
documentation and onboarding, independent security review and penetration test of Sentinel itself.

### v1.x: To sell
Multi-tenant isolation, single sign-on, billing and licensing, compliance evidence, public API, support tooling.

## 5. Productization track (runs alongside the releases)

| Workstream | What | When |
|---|---|---|
| Installability | `uv`/pip package, then a signed Windows installer, then macOS and Linux; versioned releases with checksums; auto-update with rollback | v0.5 start, finish v0.8 |
| First-run experience | `sentinel init` wizard (state dir, scan paths, token guidance, doctor) replacing hand-edited TOML | v0.4 |
| Enrolment and identity | Per-device enrolment token and revocation; operator identities; every record carries an organisation id from v0.8 so multi-tenant is possible later | design v0.7, build v0.8 |
| Privacy and consent | What is collected per machine, retention, who sees it, opt-in paths, employee notice; log only denials and sampled counts, not every allowed action | policy before v0.3b, enforce v0.8 |
| Security of Sentinel itself | Threat model, state encryption and file permissions, signed releases, dependency and action pinning, review before every release (the v0.2 review found two blockers) | every release |
| Observability | Agent health, collector health, sync status, self-diagnosis (`doctor` grows into fleet health) | v0.3a onward |
| Documentation | Operator guide, onboarding, runbook per rule, ADR per decision, API docs | v0.9 to v1.0 |
| Support and operations | Upgrade runbook, backup and restore, incident process for Sentinel itself, severity targets | v1.0 |

## 6. Scenario and rule coverage

| Scenario | Release | Notes |
|---|---|---|
| S0 key in history abused | v0.3a (real) | Needs a live Google path to count as real |
| S1 public `.env` or `.git` | v0.4 | Probes of our hosts |
| S2 secrets outside Git | v0.3a, v0.5, v0.8 | JSON gap now; locations later; endpoint scans |
| S3 key in a public gist | v0.4 | Depends on GitHub alert availability (unverified) |
| S4 stolen session | later | Needs org-level audit data |
| S5 malicious editor extension | v0.8 | Endpoint agent |
| S6 stolen GitHub token | v0.4, v0.9 | Limited by available audit data |
| S7 typosquatted package | v0.4, v0.8 | Dependency checks, then R3 |
| S8 compromised Action, S9 fork PR, S10 poisoned release | v0.4 (S10 R8 built) | Workflow policy checks |
| S11 injection makes agent leak data | v0.3b, v0.7 | Log and R5 first, gateway later |
| S12 malicious MCP server | v0.3b, v0.7 | R5c, then allowlist |
| S13 agent pushes without review | v0.7 | Agent identities |
| S14 stale SSH key | v0.4 | GitHub returns last-used per key |
| S15 exposed backup | v0.4 | Exposure probes |

Rules: R1, R2, R4, R6, R7, R8 built (R1 on real data pending); R5 in v0.3b; R3 in v0.8; R9 in v0.7.

## 7. Metrics (from the roadmap)
Live exposed secrets 0; credentials with owner, scope, quota and expiry 100 percent; unowned assets 0; time to detect a
leaked secret under 15 minutes for scanner and GitHub signals (Google signals are about 30 minutes late by design);
time to contain a critical incident under 1 hour; Priority 1 scenario detection 100 percent; agent actions with a
recorded decision 100 percent; false positives under 20 percent per rule; recovery drills at least one per incident type per quarter.

## 8. Decisions needed
| Decision | Needed by | Options |
|---|---|---|
| Split v0.3 as above, or keep one milestone | now | Recommended: split |
| Apply hook and settings patches by hand (they are protected files) | v0.3a | You apply them; I prepare the patches |
| Google Cloud in scope before v0.3b | v0.3a | Install `gcloud` and run the soak, or drop provider usage for now |
| Canary approach | v0.4 | Self-built first (recommended) or hosted |
| Employee monitoring policy (what is logged, retention, notice) | before v0.3b | Needs a decision and sign-off |
| AI provider and data rules for the assistant | v0.6 | Which data may leave the machine |
| GitHub plan for branch and push protection | v0.4 | Upgrade, move the repo, or accept the gap |
| Windows-first, then macOS and Linux | v0.5 | Confirm the order and which OS employees use |
| Severity targets and `[confirm]` thresholds | v0.3a | R4 multiple, R5b count and window, R8 window |

## 9. Risks
| Risk | Impact | Mitigation |
|---|---|---|
| Building on unproven foundations (Google, R1 real data) | Features that fail in production | v0.3a proves them first |
| Agent can tamper with its own log | Blind spot exactly when needed | Hash chain, heartbeat, blocked writes, doctor check |
| Keyword guard noise | Alert fatigue | R5a as context only, R5b main alert, per-rule false-positive tracking |
| Coverage claims overstate | Loss of trust, mis-selling | Separate simulated and live columns; wording rules |
| Employee monitoring concerns | Legal and morale problems | Consent, minimal logging, retention limits, transparency |
| Sentinel store is a high-value target | Secret map exposed | Encryption, permissions, minimal retention, review |
| Scope across many parts | Nothing shipped | Release exit criteria; defer what lacks a data source |
| Provider data is late or thin | Weaker detection | State limits; volume and dead-key signals; billing export later |

## 10. Next steps
1. Confirm the decisions in section 8 that block v0.3a (split, hook patches, Google, monitoring policy).
2. Verify the hook documentation facts (`session_id`, `mcp__.*` matcher).
3. Build v0.3a in this order: schema and S2 fixes, `inventory approve`/`own`, `coverage`, then the tamper-evident log
   with the hook patches for you to apply, then Google live and the soak run if in scope.

All generated code, infrastructure and recommendations require human review before production use.
