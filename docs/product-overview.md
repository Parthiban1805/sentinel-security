# Sentinel: what we are building

Internal AI and developer security system. Status as of 2026-10-27 (v0.2, local Python CLI).

## 1. Problem statement

A Gemini API key was committed to a repository, deleted in a later commit, and left in Git history. It was
found and abused. The incident exposed gaps that are not specific to one key:

- **Signals are scattered.** Secret scanners, GitHub, CI, cloud providers, developer machines and AI agents each
  see a fragment. One event looks harmless; several related events are an attack, but nobody connects them.
- **Deleting is not fixing.** A leaked credential stays usable in history, forks and caches until it is revoked.
- **Nobody knows the impact.** There is no live map of which key reaches which system, so the blast radius of a
  leak is guesswork.
- **Closure is assumed, not proven.** Incidents get closed because someone clicked "done", not because fresh
  evidence shows the threat stopped.
- **AI agents are a new attack surface.** Coding agents run commands, read files and call tools with developer
  privileges, and can be steered by untrusted content.

Central question: *detect a problem, understand what it could affect, determine whether it is being exploited,
stop it safely, verify, and improve.*

## 2. Solution

Sentinel is a security operations workflow that connects evidence into incidents and drives each one to
**verified** containment. It is not another secret scanner and not an AI chatbot. It reuses mature tools
(gitleaks, GitHub and provider audit data) and builds the parts that are missing: asset and credential
inventory, event normalization, correlation, incident handling and verification.

```
signals -> normalized events -> correlation rules -> incident -> impact analysis
        -> approval-gated response plan -> verification evidence -> closure -> better rules and tests
```

Design principles:

1. **Rules decide, AI explains.** Detection and blocking decisions are deterministic and explainable. AI may
   summarize evidence; it never authorizes an action.
2. **Facts are separated from hypotheses.** Every incident lists what is proven, what is inferred and what is
   unknown. Similar timing alone never proves a shared attacker.
3. **Secrets never get stored.** A credential is identified only by a keyed-hash fingerprint; raw values exist
   briefly in memory and are discarded (ADR-0004).
4. **Humans approve disruptive actions.** Sentinel recommends; revoking keys, rewriting history and similar
   steps need explicit approval. In v0.2 the response adapter is a dry run.
5. **Closure needs evidence.** An incident closes as verified only when each required step has passing
   verification evidence. A failed check keeps it open; closing without proof must be explicit and is recorded.
6. **Read-only collectors, documented network use.** Sentinel only reads from a short allowlist of hosts
   (ADR-0005).

## 3. How it works, with the original incident

1. **Detect.** `sentinel scan` finds a key in Git history and registers it by fingerprint (one key = one ID,
   even if committed six times).
2. **Connect.** A provider signal for the same credential (usage far above its baseline, or any use after it
   should be dead) triggers rule **R1** and opens a critical incident.
3. **Assess impact.** The inventory shows which assets the key was confirmed to reach (blast radius), and which
   it might reach (labelled hypothesis).
4. **Respond.** The incident carries a plan from the runbook: revoke, cap quota, review usage, review related
   identities, issue a scoped replacement. Steps that change things need approval.
5. **Verify.** The human revokes the key; `verify-key` asks the provider whether it is really deleted. Anything
   less than proof leaves the incident open.
6. **Improve.** Lessons become scenario tests and rule changes.

## 4. Features and current status

Legend: **Live** = ran against real accounts. **Tested** = automated tests only. **Simulated** = needs
simulated input today. **Planned** = not built.

| Area | Feature | Status |
|---|---|---|
| Detection | Secret scan of files and full Git history, one stable ID per key, no raw values stored | Live on local repos |
| Detection | Findings registry: open, revoke pending, risk accepted (with expiry), revoked unverified, revoked verified; audit trail; verified needs evidence | Live |
| Detection | Free-text secret screen (blocks a pasted key in evidence or notes) | Tested |
| Inventory | Repo discovery, asset import, owner and approval gap checks | Live |
| Inventory | Credential-to-asset links and blast radius (confirmed vs possible access) | Tested |
| Correlation | **R1** exposed key then used | Tested (usage simulated) |
| Correlation | **R2** risky workflow change by a non-maintainer | Live on GitHub |
| Correlation | **R8** release shortly after a workflow change | Tested |
| Correlation | **R4** spend spike, **R6** suspicious login then new token or key, **R7** canary used | Tested (simulated input) |
| Incidents | Facts, hypotheses, unknowns, timeline, risk score, response plan | Live |
| Incidents | Approval gates, dry-run response adapter, verified closure | Tested end to end |
| Collectors | GitHub: workflow changes, releases, SSH keys | Live |
| Collectors | Google Cloud: per-key request volume, key metadata, `verify-key` | Tested only (not run live) |
| Operations | `sentinel run`: scan, collect, correlate, alert in one pass; failing sources isolated | Live |
| Operations | Alerts to a log file and a Windows notification (real high or critical incidents only) | Tested |
| Operations | Scheduler script (user runs it) | Provided |
| Reporting | Baseline and incident reports in Markdown (gate status, metrics, collector health) | Live |
| Safety | Guard hooks for the AI coding agent, scenario tests S0, S2 and S11 | Live |
| Safety | Pinned, checksummed CI with a lint, type and test job | Live |
| Planned | Rules R3, R5, R9; agent policy gateway and sandboxing | Planned |
| Planned | AI investigation assistant (summaries only) | Planned |
| Planned | Real response execution, central service, UI, billing data | Planned |

## 5. What is verified and what is not

- 145 automated tests pass (plus 3 recorded known gaps); lint and type checks are clean; CI is green.
- The GitHub collector and R2 ran on live data. Its first alert was a false positive caused by a rule flaw; the
  rule was fixed and a regression test added.
- A security review of the network code found two blockers (a redirect could forward the token to another host,
  and a mistyped key id could make a live key look revoked). Both were confirmed, fixed and tested.
- **Not verified:** the Google Cloud collector against a real project; the exact format of provider key ids; how
  GitHub's `since` filter treats backdated commits.

## 6. Known limits (facts from provider documentation)

- Google usage metrics arrive up to about 30 minutes late, so provider-signal detection cannot meet a 15-minute
  target. Scanner and GitHub signals can.
- Google does not expose the caller's IP or region in these metrics. "Used from a new location" is not
  observable; Sentinel uses volume above baseline and any use of a key that should be dead.
- No REST endpoint for a personal GitHub account's login history was found, so R6 sees only new SSH keys.
- Known detector gaps: the AI agent's command guard is a safety net, not a sandbox (inline interpreter calls
  bypass it); gitleaks misses keys inside JSON-escaped quotes.

## 7. Roadmap

| Phase | Focus | Gate |
|---|---|---|
| B Prevent | Stop recurrence: protections, pinned CI, first scenario tests | All repos protected. **Partly met** (no GitHub-side branch protection on the free plan) |
| C Correlate | Connect the evidence: events, rules, incidents, verified closure | Rules live, closures verified. **Largely built** (v0.1 to v0.2) |
| D Runtime and AI | Control agents live: gateway, sandboxing, egress monitoring | Agents behind a gateway, injection tests pass. **Not started** |

Next candidates: agent policy gateway (R5 and R9), AI investigation assistant, more scenario tests (S1, S7),
live Google Cloud collector after a security re-review.

## 8. Where things are

| Need | File |
|---|---|
| Project rules and conventions | `CLAUDE.md` |
| Demo and setup walkthrough | `docs/demo.md` |
| Correlation rule specs | `docs/spec/correlation-rules.md` |
| Collector research and sources | `docs/research/collectors.md` |
| Architecture decisions | `docs/adr/0001` to `0005` (0003 to 0005 still "proposed", need review) |
| Threat scenarios | `docs/scenarios/` |
| Incident runbook | `docs/runbooks/credential-exposure.md` |
| AI agent policy | `policies/agent-policy.md` |
