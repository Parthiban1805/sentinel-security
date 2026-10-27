# Sentinel: complete product plan

Covers the whole product, from what exists today to a v1.0 that can be operated. Sizes are relative
(S = days, M = 1 to 2 weeks, L = several weeks), not commitments. Status as of 2026-10-27.

## 1. Goal and scope

**Goal.** One internal system that prevents, detects, investigates and contains security incidents across
our development and AI infrastructure, and proves containment with evidence.

**In scope:** secrets and credentials, GitHub and CI, cloud API usage, developer machines, dependencies, AI
agents and MCP tools.
**Out of scope (for now):** replacing mature tools (gitleaks, provider audit logs, GitHub native features),
network-wide monitoring, SIEM replacement, customer-facing security features.

**Success looks like (v1.0):**
- no live exposed credentials, and every asset has an owner;
- a leaked key is detected within minutes, correlated with usage, and an incident is opened automatically;
- every incident closes with verification evidence;
- every AI agent action goes through a policy decision that is logged;
- Priority 1 scenarios S0 to S15 are continuous tests that pass.

## 2. Where we are

| Module (design spec) | What exists | Gap |
|---|---|---|
| A Asset and identity graph | Repo discovery, owners, credential-to-asset links, blast radius, API key assets (Google) | No machines, servers, workflows, agents, MCP servers or identities as assets |
| B Prevention and policy | Guard hooks, pinned CI, pre-commit, S11 hook tests | No repo hygiene or workflow policy checks, no GitHub protection checks, no dependency checks |
| C Telemetry and detection | gitleaks scan, GitHub collector (workflows, releases, SSH keys), Google collector (tested only) | No endpoint, CI-runner, server, dependency or agent telemetry; Google not run live |
| D Correlation and investigation | Rules R1, R2, R4, R6, R7, R8; timeline; blast radius | R3, R5, R9 missing; several inputs still simulated |
| E Incident and response | Incidents, approvals, dry-run adapter, verified closure, audit trail | No real response actions; single user |
| F AI investigation assistant | None | Not started |
| G Agent security gateway | Command and file guard hooks only | No policy engine, identities, decision log or sandbox |

Done: v0.1 (full incident loop on simulated signals) and v0.2 (real GitHub signals, continuous run, hardening).
145 tests pass, CI is green, one live GitHub run was completed.

## 3. Release plan

Each release has a goal, a deliverable set and **exit criteria** that must be demonstrated, not asserted.

### v0.3: Trust the signals (finish what exists)  [M]
**Goal:** every shipped collector and rule has run on real data and is trustworthy.
- Run the Google Cloud collector live (needs `gcloud` installed and a read-only login); re-review it for security.
  Confirm the `credential_id` format and map real keys with `inventory alias`.
- Populate the registry with real state: record the already-revoked keys with their fingerprints, owners for all assets.
- Schedule `sentinel run` (user runs the script); add `sentinel doctor` (checks token, ADC, gitleaks, permissions).
- Harden Sentinel itself: restrict file permissions on `.sentinel` (Windows ACLs), encrypt the credential-map store or
  document why not, backup/restore of state.
- Close S2 gap (JSON-escaped keys in agent transcripts) with an unescape-before-scan step; real-location S2 scans.
- Fix schema `$id` bug with an ADR (version bump).
- **Exit:** 7 days of scheduled runs with no collector errors; one real R1 path demonstrated on a throwaway key in a
  throwaway Google project (leak, usage spike, incident, revoke, `verify-key` passes); S2 gap test turns green.

### v0.4: Prevent (Phase B)  [L]
**Goal:** stop recurrence with checks that run before and after commits.
- **Repo hygiene scanner:** `.env` tracked or not ignored, missing `.gitignore` entries, missing pre-commit hook,
  large dump files (checks that were done by hand become a command: `sentinel hygiene`).
- **Workflow policy checks** (S8, S9, S10): actions not pinned to commit SHAs, `pull_request_target` with checkout of
  untrusted code, broad `permissions`, secrets exposed to fork PRs. Extend R2 with these signals.
- **Dependency checks** (S7): new dependency detection, typosquat heuristics, install-script flags, lockfile pinning;
  prepares R3.
- **GitHub protection audit:** branch protection, secret scanning and push protection status per repo (reports the
  gap on the free plan honestly).
- **Canaries** (R7 for real): a generator for decoy credentials and files with a registry; alerts when a decoy is used
  (needs a decoy source that can actually notice use, such as a canary token service decision).
- **Exposure probes** (S1, S15): read-only checks of our own hosts for reachable `.env`, `.git` and backup paths.
- **Policy-as-code:** rules for checks live in versioned files with tests.
- **Exit:** all in-scope repos pass `hygiene` or have accepted exceptions; Priority 1 scenario tests S0, S1, S2, S7,
  S11 pass continuously in CI; first recovery drill completed and recorded.

### v0.5: Investigate with AI (Module F)  [M]
**Goal:** faster understanding without giving AI authority.
- **Evidence pack:** a redacted, minimal bundle per incident (facts, timeline, impact, unknowns).
- **Assistant:** Claude summarizes the pack, lists likely impact, flags unknowns, proposes investigation steps and
  drafts the incident report. It never changes state or approves anything.
- **Guardrails:** secrets and PII removed before any model call; untrusted text (commit messages, issue text, tool
  output) wrapped as data; prompt-injection tests; outputs labelled "AI-generated, unverified".
- ADR for the outbound API destination and data minimization; cost and rate limits.
- **Exit:** an evaluation set of at least 20 incidents scored by a human for accuracy; zero secret leakage and zero
  successful injection in the test suite; assistant removed from every approval path (verified by test).

### v0.6: Agent security gateway (Module G, Phase D)  [L]
**Goal:** every agent tool call passes a policy decision.
- **Policy engine:** per-agent identity, allowed tools, paths, network destinations, secrets scopes; default deny for
  sensitive actions; versioned policy files with tests.
- **Gateway:** a local proxy for tool calls (starting with MCP servers and Claude Code hooks), decision log (allow,
  deny, approved) with identity, action, target and reason; secrets redacted.
- **Rules:** R5 (tool outside allowlist or unusual secret use), R9 (sensitive access with no gateway decision = bypass).
- **Sandboxing:** run risky tools in a container or VM with filesystem isolation, limits and an egress allowlist;
  closes the known hook bypass (inline interpreter calls).
- **MCP allowlist:** owner, permissions, pinned version and review for every server (S12).
- **Kill switch:** suspend all agent credentials in one command; test it.
- **Injection test suite (S11) in CI:** attempts to make an agent leak data, push, or read secrets.
- **Exit:** 100 percent of agent actions in scope recorded with a decision; injection suite passes; the two known
  bypass tests turn green.

### v0.7: Endpoint and runtime telemetry  [L]
**Goal:** see what happens on developer machines and runners.
- **Developer machine collector** (read-only, opt-in): installed editor extensions (S5), new credential file reads,
  shell history and agent transcript scans (S2), unusual outbound connections.
- **CI runner telemetry:** workflow runs, egress, secret use (S8, S9).
- **Server basics** for the exposed services we run.
- **Rule R3:** new dependency, then the same machine or runner touches credential files or makes unexpected egress.
- **Privacy review:** what is collected, retention, who can see it; opt-in and transparent.
- **Exit:** R3 demonstrated end to end (S7 scenario test); collector overhead and privacy review signed off.

### v0.8: Service and team use  [L]
**Goal:** every employee system can run Sentinel with almost no setup, and one central service shows the whole
organisation. **Direction decided; design deferred** (see section 8).
- **Plug-and-play endpoint agent:** a small, signed installer that runs the local collectors (secret scan, extension and
  dependency checks, agent policy) read-only and reports to the central service. One command or a managed push
  (for example through the company's device management), no manual token handling; per-device enrolment and revocation.
- Local-first: the agent works offline and keeps its own state, then syncs; it sends fingerprints and metadata, never
  raw secrets or source code.
- Central service (FastAPI) and datastore (PostgreSQL) per the org scaffold standard; keep the CLI as a client.
- Authentication, roles, per-user approvals, immutable audit log.
- Read-only dashboard (Next.js): incidents, findings, graph, collector health.
- Secrets management for collector credentials; short-lived tokens; rotation runbook.
- Deployment, backup and restore, monitoring of Sentinel itself.
- **Exit:** two users and two machines operating on shared state; approvals attributed to individuals; restore drill passed.

### v0.9: Real response  [M]
**Goal:** safe, reversible actions behind approvals.
- Adapters for specific actions: revoke a GitHub token or SSH key, delete a Google API key, set a quota cap,
  suspend an agent credential, isolate a runner.
- Each action has: approval, dry run, rollback plan, audit entry and automatic verification afterwards.
- Pre-approved emergency policies only where a human has explicitly agreed (for example "key confirmed in a public repo").
- **Exit:** each adapter proven in a sandbox account; failed action leaves the incident open; kill-switch drill passed.

### v1.0: Operate  [M]
- Service level objectives and metrics dashboards (section 6), quarterly recovery drills per incident type.
- Runbooks for every rule; on-call and escalation paths; severity targets confirmed.
- Documentation, onboarding guide, security review of the whole system, penetration test of Sentinel itself.
- **Exit:** all phase gates met, or each exception owned and dated.

## 4. Scenario coverage (S0 to S15)

| ID | Scenario | Planned in | Notes |
|---|---|---|---|
| S0 | Secret in Git history abused | v0.3 (real) | Simulated now; real Google path in v0.3 |
| S1 | `.env` or `.git` served publicly | v0.4 | Read-only probes of our hosts |
| S2 | Secrets outside Git | v0.3 and v0.7 | Fix JSON gap; real locations; endpoint scans |
| S3 | Key in a public gist or forum | v0.4 | Needs GitHub secret scanning alerts (plan limits unverified) |
| S4 | Stolen session bypasses 2FA | later | Needs org audit log; unavailable on personal accounts |
| S5 | Malicious editor extension | v0.7 | Endpoint collector |
| S6 | Stolen GitHub token | v0.4 and v0.9 | Limited by available audit data; token inventory |
| S7 | Typosquatted package | v0.4 and v0.7 | Dependency checks, then R3 |
| S8 | Compromised third-party Action | v0.4 | Pin checks plus R2 |
| S9 | Fork PR exposes secrets | v0.4 | Workflow policy check |
| S10 | Workflow modified to ship poisoned release | done (R8) | Live validation in v0.3 |
| S11 | Prompt injection leaks data | v0.6 | Injection suite in CI |
| S12 | Malicious or overprivileged MCP server | v0.6 | MCP allowlist |
| S13 | Agent pushes or merges without review | v0.6 | Agent identities and protected branches |
| S14 | Stale SSH key or former member | v0.4 | GitHub returns `last_used` per key |
| S15 | Exposed database backup | v0.4 | Exposure probes and inventory |

## 5. Correlation rules

| Rule | Status | Planned |
|---|---|---|
| R1 exposed key then used | built; usage simulated | real data v0.3 |
| R2 risky workflow change | live | extended in v0.4 |
| R3 new dependency then credential access or egress | not built | v0.7 |
| R4 spend spike | built (request volume proxy) | real billing data later |
| R5 agent tool outside allowlist | not built | v0.6 |
| R6 login then new token or key | partly (keys only) | needs org-level audit data |
| R7 canary used | built (simulated) | real canaries v0.4 |
| R8 workflow change then release | built | live check v0.3 |
| R9 sensitive access with no gateway decision | not built | v0.6 |

## 6. Metrics and targets (from the roadmap)

Live exposed secrets 0; credentials with owner, scope, quota and expiry 100 percent; repos with push and branch
protection 100 percent (limited by plan); unowned assets 0; time to detect a leaked secret under 15 minutes (scanner
and GitHub signals; Google signals are about 30 minutes late by design); time to contain a critical incident under
1 hour; scenario detection rate 100 percent for Priority 1; agent actions via policy 100 percent; false positive rate
under 20 percent (tracked per rule, as with the R2 false positive found in v0.2); recovery drills at least one per
incident type per quarter.

## 7. Cross-cutting work (runs through every release)

- **Security of Sentinel itself:** it holds a map of our secrets. Threat model it, protect state with ACLs and
  encryption, minimize and expire stored data, review each release (the v0.2 review found two real blockers).
- **Testing:** scenario tests first, deterministic rules, runtime-generated fake credentials, no network in tests,
  a regression test for every false positive and bug.
- **Supply chain:** pinned dependencies and actions, checksummed downloads, one ADR per new dependency or network
  destination.
- **Governance:** one ADR per architectural decision; all generated code and recommendations reviewed by a human
  before production use; approvals recorded.
- **Documentation:** keep the spec, rule specs, runbooks and README in step with the code.

## 8. Decisions needed

| Decision | Needed by | Options |
|---|---|---|
| Team service shape | before v0.8 (decided in direction, details later) | **Decision: build a plug-and-play agent that can be installed on every employee system, reporting to a central service.** Design it later (see v0.8); stay a local tool until then |
| GitHub plan (branch protection and push protection need a paid plan on private repos) | v0.4 | Upgrade, move the repo, or accept the gap |
| Google Cloud usage in scope | v0.3 | Install `gcloud`, or drop provider usage |
| Canary approach | v0.4 | Hosted canary tokens or self-built decoys |
| AI provider and data rules for Module F | v0.5 | Which data may leave the machine |
| Severity targets and thresholds marked `[confirm]` | v0.3 | R4 multiple, R8 window, response times |

## 9. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Provider data is late or thin (Google about 30 minutes, no caller IP) | Slower or weaker detection | State limits honestly; use volume and dead-key signals; add billing export later |
| False positives erode trust | Alerts get ignored | Per-rule tracking, regression tests, owner and history awareness |
| Sentinel's own store is a high-value target | Secret map exposed | ACLs, encryption, minimal retention, review |
| Scope creep across seven modules | Nothing finished | Ship per release with exit criteria; defer what lacks a data source |
| Single owner, single machine | Bus factor and blind spots | v0.8 service, documented runbooks |
| Tokens and credentials needed for collectors | Becomes an attack path | Read-only scopes, short-lived tokens, allowlisted hosts, kill switch |

## 10. Next steps

1. Settle the open decisions above that affect v0.3.
2. Run v0.3: Google live (if in scope), scheduling, `doctor`, S2 fix, schema fix.
3. Start v0.4 with the hygiene scanner, which is the cheapest win for prevention.

All generated code, infrastructure and recommendations require human review before production use.
