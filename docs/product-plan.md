# Sentinel: product plan to an end product

Status as of 2026-10-27. Sizes are relative (S = days, M = 1 to 2 weeks, L = several weeks), not commitments.
Revised after the plan review: tamper-evident agent telemetry, quieter R5, real verification evidence, honest
coverage claims, and unfinished foundations first.

> Open owner actions are tracked in [`pending-tasks.md`](pending-tasks.md).

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

### v0.3b: Agent visibility  [M]  (status 2026-10-31: built on simulated input; monitoring policy approved; ADR-0012)
**Built:** `sentinel/sources/agent.py` (verified log -> `agent_tool_denied` / `agent_tool_allowed`; nothing from a tampered log;
chain-aware cursor), `sentinel inventory agents` (`ai_agent` + `mcp_server` from `.mcp.json`, name/transport/host only), rules R5a
(context only), R5b (3 denials in a session within 30 min, one Medium incident per session) and R5c (unapproved MCP server, active
once one server is approved, one High incident per server), R5b/R5c response plans, `incident verify-agent-hooks` (installed hooks
equal a human-made pin, settings not overriding them, chain intact), S11 update and S12 doc, coverage rows. The security review
("Block") found 13 issues; all code findings fixed (ADR-0012 amendment). 533 tests. **Not yet:** R5b/R5c seen on a real session;
thresholds tuned on real data (the log held 17 entries); owner actions in `pending-tasks.md` item 7.
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
**v0.5 "verification watch" in progress:** rule R11 (use of a credential after its revocation was verified; the finding records
`verified_at`) and `incident verify-ssh-key` (R6: passes only when every flagged SSH key id is absent from a fresh, successful
`/user/keys` listing; a failed listing never counts as proof; SSH keys only, tokens stay a human attestation).
**Verification watch built:** `sentinel watch` lists open incidents (stale after 24h by default), steps whose verification failed
and incidents closed without verification (exit 1 if any failed or stale); `sentinel run` re-probes the path of every open real R10
incident at most every 6 hours, so a fix is verified without anyone typing a command. 418 tests.
**Re-scan verifier built** (`incident verify-rescan`, new optional R1 step `rescan_clean`): re-scans every recorded location of the
incident's credential (working tree in dir mode, history locations in git mode) and passes only when every scan succeeded and none still
finds the credential fingerprint. A scan error or a missing folder records nothing, so it is never proof. History hits stay failed until
history is rewritten. Exercised with the real scanner on a runtime-generated fake key. The security review found four ways to a
false pass, all fixed: nothing to scan (refused), a missing or new fingerprint key (the command now refuses to create one), a folder that
is not an absolute path or not a Git repository (refused), and a result worded as proof (the evidence now says "scanned scope only";
working-tree scans skip build folders and other repositories are not scanned). 440 tests.
**Scanning outside Git built (S2, ADR-0011):** `[scan] extra_paths` in `sentinel.toml` lists folders or single files (logs, build output,
agent transcripts, history files). The list is empty by default and nothing is scanned unless listed; paths must be absolute and drive
roots or the whole home folder are refused. `sentinel run` scans each in `dir` mode, registers it as an unowned `scan_location` asset,
and records fingerprint, relative file name and line only. A missing path is a health error, never "clean". `verify-rescan` works on
these locations. Tested on a folder, a single history-style file and a JSON-escaped transcript with runtime-generated fake keys.
The security review found six problems, all fixed: path checks that could be bypassed (`..`, the folder above home; paths are now
resolved and re-checked at scan time), symlinks pulling in content from outside the listed scope (not followed; a listed symlink is
refused), same-named locations hiding each other's health errors (keyed by asset id), unreadable or oversized files reading as a clean
scan (now a `warn:` with counts, and an INCONCLUSIVE re-scan result), a false "copied" canary event for single-file locations, and
credential stores being scannable by accident (refused unless `allow_credential_stores = true`). 467 tests; 2 symlink tests are skipped
on this machine (Windows needs a privilege), so symlink handling is tested by simulating a link. How gitleaks itself treats a real
symlink is **unverified**.
**Not done:** no real workstation location is scanned yet; the owner must list each path (see pending-tasks.md item 6).
**Next in v0.5:** automatic blast-radius edges from provider metadata.
**v0.6 started (ADR-0010):** `sentinel incident summary <ID>` is a local, summary-only template. It makes no network call,
uses no AI model, copies only an allow-listed set of fields, never proposes actions, and refuses to print credential-shaped
text. An outside AI service would need a new ADR and a README first. 423 tests.
**v0.6 AI assistant (ADR-0014, ADR-0015, accepted 2026-11-02):** `incident summary <ID> --ai` sends a disguised
evidence pack (placeholders for every repo, path, credential, identity and person; reach and safe event flags; no notes or
evidence text) to Claude or, for simulated incidents only, NVIDIA's trial API.
- **Safeguards:**
  - An interactive confirmation is required, with no `--yes`. `--dry-run` shows the exact pack.
  - The model gets no tools and must answer in a fixed format.
  - Sentinel prints the record's facts, reach and plan state itself. The model writes only labelled interpretation,
    hypotheses, open questions and read-only checks.
  - Suggested checks that are response actions, or that would open, reveal or test a secret, are dropped.
  - Output goes to its own AI-labelled file. The store is never written.
  - Key only in Windows Credential Manager. A daily call cap and a monthly budget apply.
- **Exit gate: MET (2026-11-03).**
  - Run 4 of the 20-case eval (NVIDIA provider, simulated incidents) scored mean 4.55, lowest 3, 0 made-up claims and 0
    injection followed.
  - It was scored by an independent Claude reviewer; the owner spot-checked case 09 and accepted it.
  - On the way:
    - Run 3 failed on case 09 after the owner's spot-check. The cause was Sentinel's own R7 wording, now fixed.
    - Checks that would expose a secret (9 of 131 across runs 3 and 4) are now dropped, with no false drops.
  - The gate covers the NVIDIA provider only; Claude needs its own scored run before real incidents.

**v0.6 done.**
- **Value over the plain template:** modest. It mostly shows in the check lists, and where the credential's reach is
  known.

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
**v0.7a built (ADR-0016, 2026-11-03), split from 7b by the owner:**
- One gateway hook decides every Claude Code tool call and records every decision (no content).
- Inline interpreter code needs the user's confirmation (BG-15); encoded PowerShell is denied.
- Kill switch, with a drill test.
- MCP allow-list with owner, pinned version and review date, enforced by the gateway.
- R9: a decoy touched during an agent session with no gateway decision.
- Injection suite in the CI test job.

**v0.7a done (2026-11-03).** The owner applied the patch and the checks on the live hooks passed:
- 124 scenario tests pass, including the two former bypass tests.
- Kill-switch drill: `git status` refused (KS-01), reading still allowed, switched off by the owner.
- The owner pinned the hooks.
- Applying it found a real gap (a Grep naming a secret in `file_path`). It is fixed and tested for every file tool.

The 7a exit gate is met: every action has a decision, the two bypass tests are green, the kill-switch drill passed. The limits
listed in ADR-0016 remain until 7b.

**v0.7b built (ADR-0017, 2026-11-03): Docker sandbox.**
- `sentinel sandbox run -- <command>` runs code with no network, in a scratch copy of the tracked files without secrets,
  as a non-root user with a read-only system and resource limits. Nothing is written back to the repo.
- The image is pinned by digest.
- Docker never pulls an image by itself, and the image comes only from `sentinel.toml`, which the agent cannot write.
- The gateway asks before any Docker command and refuses Docker runs that reach the host.
- Optional strict mode (BG-23) asks whenever code runs outside the sandbox. It is advisory: it reduces risk, but it is
  not a security boundary.
- After an independent review blocked the first version, sandboxed one-liners still ask like any inline code; an
  exemption could be borrowed by a shell function.

No outgoing-traffic allow-list yet (owner choice; needs its own ADR).

**v0.7b done (2026-11-05).**
- Image pulled and pinned. The live test passed (no network, no `.env`, no Docker socket, not root), and a real run worked
  end to end.
- The owner re-applied the gateway patch, 124 scenario tests pass on the live hooks, and the hooks are pinned.
- **Open:** the Docker Desktop licence (on hold; see ADR-0017), and the egress allow-list, which needs its own ADR.

**v0.7 is complete.** The exit gate is met: every in-scope agent action has a decision, the two bypass tests are green, the
kill-switch drill passed, and a sandbox now covers code the gateway cannot see. The limits in ADR-0016 and ADR-0017 remain
(strict mode is advisory, the MCP allow-list trusts the server name, and so on).

### v0.7c: Connected view  [M]  (scope confirmed by the owner 2026-11-05; started)
**Item 1 built (ADR-0018, 2026-11-05):** `graph refresh`, `graph reach`, `graph reached-by` and `inventory edge`. The
agent -> MCP and repository -> workflow producers also run in `sentinel run`. It ran on the real local repos and found
7 workflows in 4 repositories.
The security review returned Block: a slow regex on hostile workflow text. That and every "should fix" item are fixed
and tested:
- collision-proof workflow ids;
- links and junctions out of the repo refused;
- file count and size caps;
- linked credentials in `reached-by`;
- skips reported in run health;
- `secrets: inherit` detected.

The re-review returned "Approve with fixes": references hidden by an unclosed `${{` or a padded `inherit` line, and
approval surviving a content change. Those are fixed too. 45 graph tests.
**Not yet:** provider-metadata edges (ADR-0005 amendment) and a runner-level test of the `warn:` health.
Added after the review of the feature proposal of 2026-11-05 (attack graph, posture, hunting, lifecycle, agent behaviour,
drills). Only features that run on data Sentinel already collects are in scope; the rest is placed in v0.8, v0.9 and v1.x
below. Positioning: "evidence-driven", not "autonomous" (principle 1, rule 4).
1. **Asset graph** (ADR-0018). Edges Sentinel observes itself, each labelled `documented` or `observed` and tagged with
   the producer that made it: agent -> MCP server (from `.mcp.json`), repository -> CI workflow -> secret *names* (from
   workflow files, never values), later token -> repositories and key -> allowed APIs (provider metadata, needs an ADR-0005
   amendment). `sentinel graph reach <asset>` (what could this reach: the "what if it were stolen" question) and
   `sentinel graph reached-by <asset>` (what can reach this). Every path is a hypothesis of access until investigated.
   This closes the v0.5 item "automatic blast-radius edges" and fixes the graph model before the v0.8 datastore design.
2. **Built 2026-11-05 (ADR-0019; review "Approve with fixes", all fixed; 44 tests).** On real data it found a Google
   key past rotation with no owner, and two SSH keys past rotation. **Credential lifecycle fields:** expiry, age, last used, owner, rotation due; `sentinel creds` report; a finding for
   expired or unowned credentials. Rotation itself is v0.9.
3. **Built 2026-11-05 (ADR-0020, spec R12; review "Approve with fixes", all fixed; 44 tests).** `sentinel agent sessions` (advisory score),
   rule R12, incident record carries the session score, new coverage scenario. On the real log one session scores
   "high" from three unrelated keyword denials over three days, so the score stays advisory until a time bound can be
   set from data. **Agent session risk:** a deterministic per-session score from gateway decisions and one sequence rule (for example a
   sensitive read followed by an outbound attempt), spec and tests first. Behaviour baselines wait for weeks of real log data.
4. **Built 2026-11-05 (ADR-0021; review "Approve with fixes", all fixed; 62 tests).** On the real store: threat
   exposure and operational health are "attention" (14 live leaked credentials, an old open incident, the last run
   115 hours ago, 4 collector errors); security posture is "review, partial" because the GitHub audit is older than
   72 hours. **`sentinel posture`:** three separate indicators (security posture, threat exposure, Sentinel health), each listing
   the evidence behind it; no single unexplained score. Includes a short summary section for founders and CTOs.
5. **Built 2026-11-05 (ADR-0022; review "Approve with fixes", all fixed; 49 tests).** `sentinel search` (structured filters, no
   free text, a pasted secret is refused) and `sentinel incident timeline <ID>` (six labelled sections built only from
   recorded data). Saved queries and "create a rule from a search" are not built. **`sentinel search`** (by fingerprint, asset, session, time range) and **`incident timeline`** (confirmed events,
   inferred links, missing evidence, alternative explanations, each labelled).
6. **Built 2026-11-06 (ADR-0023; review "Approve with fixes", all fixed; 30 tests).** `sentinel drill run` / `drill status`; opt-in
   schedule through `[drills] interval_hours` in `sentinel run`; posture shows the last drill. First real drill on
   this machine: leak detected in 0.78 s and the R1 incident opened in 0.83 s (pipeline time only, in a throwaway
   workspace). **Scheduled detection drills:** fake canary leaks pushed through the live pipeline, measuring time to
   detect and to open an incident (the section 7 metrics).
- **Exit:** reach and reached-by on real local data with observed edges; posture report generated from a real run; one
  drill run with measured time to detect; every new rule has tests; security review passed.

### v0.7d: Agent containment  [M]  (scope confirmed by the owner 2026-11-06; started)
Four ideas from the owner's ORE kernel (P:\development\ore-kernel), reimplemented: ORE is AGPL-3.0, so ideas only, no
copied code or pattern lists. Choices: egress is a host allow-list without TLS interception; the context firewall
covers prompts and data sent through tools; WASM is deferred. ORE's own gaps are not inherited (path rules never
enforced, no redirect, DNS or private-address checks, unknown manifest keys ignored, no memory or time limits, an
unsandboxed shell mode, stdout-only telemetry, no tests).
0. **Hook pin covers the policy engine.** Built 2026-11-06. The pin now hashes every `*.py` in `.claude/hooks`
   (it missed `gateway.py`, `_policy.py` and `scan_written_file.py`), and a file added or removed after the pin fails
   `verify-agent-hooks`. **Owner action:** re-pin (`uv run sentinel agentlog pin-hooks --actor Parthiban`).
1. **Agent permission manifest** (ADR-0024): a strict, owner-edited TOML policy (filesystem read, write and deny;
   network domains; execution; MCP tools; approvals; expiry; version), pinned like the hooks. It can only tighten the
   gateway. Enforced by a gateway patch the owner applies.
2. **Context firewall** (ADR-0025): one detector library (secrets, private keys, PII, internal and metadata IPs,
   injection indicators) counting per occurrence and storing no values. Used on prompts (UserPromptSubmit), on data
   sent through MCP, WebFetch and WebSearch, and by the AI assistant pack.
3. **Sandbox egress allow-list** (ADR-0026, amends ADR-0017): an internal Docker network whose only route out is a
   pinned proxy container. Allowed hosts only; DNS resolved by the proxy, with private, loopback, link-local and
   metadata addresses refused; plain-HTTP method and path rules; no TLS interception. Each refusal is an
   `egress_anomaly` event (its first real producer). Off unless `sandbox run --allow-net`.
4. **WASM backend:** deferred to v1.x. Lessons from ORE: memory and wall-clock limits as well as fuel, fail closed
   on mount errors, never create host folders for read grants.
- **Exit:** manifest enforced on the live hooks (owner applied and pinned); a prompt and an MCP call holding a fake
  key are refused; the sandbox reaches an allowed host and is refused for others and for 169.254.169.254; security
  review passed for each item.

### v0.8: Endpoint agent and central service  [L]
Detailed design happens here; direction is decided (plug-and-play on every employee system).
- Installer and enrolment (see section 5), local-first agent that syncs, central service and datastore, authentication
  and roles, per-user approvals, immutable audit log, read-only console first, then approvals in the console.
- Telemetry from developer machines (editor extensions S5, credential-file access, shell history and transcript scans)
  and CI runners; rule R3.
- From the 2026-11-05 review: the console shows the asset graph and posture; fleet-wide agent kill switch; CI runtime
  signals (workflow runs, artifact uploads, runner egress through an existing tool, not a new one); optionally
  vulnerability intelligence through `osv-scanner` or `pip-audit` (CISA KEV and EPSS feeds are new destinations and need
  an ADR; no reachability analysis).
- **Exit:** two operators and two machines on shared state; approvals attributed to individuals; restore drill passed;
  enrolment under 10 minutes.

### v0.9: Real response  [M]
- Adapters for specific actions with approval, dry run, rollback plan, audit entry and automatic verification: revoke a
  GitHub token or key, delete a Google API key, cap quota, suspend an agent credential, isolate a runner.
- From the 2026-11-05 review: dependency-aware credential rotation (replace, validate, revoke, watch); workflow rollback to
  the last approved version; health checks after rotation or rollback. Each has its own approval and rollback plan.
- Emergency pre-approved policies only where a human explicitly agreed.
- **Exit:** each adapter proven in a sandbox account; failed action leaves the incident open; drills pass.

### v1.0: Internal general availability  [M]
Everything in the definition of done (section 1): service levels, metrics, runbooks per rule, on-call and escalation,
documentation and onboarding, independent security review and penetration test of Sentinel itself.

### v1.x: To sell
Multi-tenant isolation, single sign-on, billing and licensing, compliance evidence, public API, support tooling.
From the 2026-11-05 review, each needing a data source or an ADR first:
- Identity threat detection (logins, geography, privilege changes): needs an identity provider (Entra ID, Okta) or an
  organisation audit log. Stale SSH keys and tokens are already covered (S14) and stay in v0.7c item 2.
- Data loss detection: metadata and classification only, within the signed monitoring policy. Agent outbound traffic is
  the open sandbox egress allow-list ADR.
- Policy as code (schema-validated, versioned), integrations hub (each integration is a new destination with an ADR;
  Slack or Teams alerts may come at v1.0 for on-call), compliance mapping (never claims certification), third-party and
  connected-app risk, a wider deception network (for example a decoy MCP server).
- Not planned: multi-agent AI investigation (more attack surface; v0.6 showed modest AI value).

## 5. Productization track (runs alongside the releases)

| Workstream | What | When |
|---|---|---|
| Installability | `uv`/pip package, then a signed Windows installer, then macOS and Linux; versioned releases with checksums; auto-update with rollback | v0.5 start, finish v0.8. **Started 2026-10-31 (ADR-0013):** wheel 0.5.0 with bundled schemas, `build_release.py` (clean tree, wheel checks, SHA256SUMS), `install-sentinel.ps1` (checksum before install, no downloads, `-CheckOnly`), `docs/install.md`; clean-venv install verified. Not yet: signing, hashed dependency lock, MSI, auto-update |
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
| AI provider and data rules for the assistant | v0.6 | **Decided 2026-10-31** (ADR-0014): Claude API, disguised pack only |
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
