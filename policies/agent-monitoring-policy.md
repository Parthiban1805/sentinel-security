# AI agent activity logging: policy (APPROVED by the owner on 2026-10-31)

Applies to the tamper-evident decision log written by the Claude Code hooks (`docs/patches/agent-decision-log/`, ADR-0007).
Status: **approved as written** (owner sign-off below, 2026-10-31). In force on the owner's machine only (section 6).

## 1. Purpose (and what it is not for)
- **Purpose:** detect when an AI coding agent is steered into unsafe actions (credential reads, exfiltration, history rewrites,
  use of unapproved tools) and give the incident process trustworthy evidence.
- **Not for:** measuring developer productivity, performance reviews, or reconstructing what someone worked on.

## 2. What is recorded
| Recorded | Not recorded |
|---|---|
| A blocked action: time, tool name, stable rule id (for example BG-01), a class (for example `network_tool`) | The command text, file paths, tool arguments, prompts or model output |
| A call to an MCP tool: time, tool name (`mcp__<server>__<tool>`) | Ordinary allowed tool calls (reads, edits, normal commands) |
| A session start (heartbeat) | The content of any session |
| A hashed session id and a keyed fingerprint of the blocked target (cannot be reversed without the local key) | The raw session id or the raw target |

## 3. Where it lives and who can see it
- A file on the developer's own machine: `<project>/.sentinel/agent-decisions.jsonl`. It is not uploaded anywhere in the current
  version.
- Readable by the machine's user and by Sentinel on that machine. Agents are blocked from reading or changing it.
- When a central service exists (later release), this policy must be revised before any upload, and employees notified first.

## 4. Retention
- **Proposed: 90 days**, then rotate or delete. Keep a longer copy only for an open incident, with the owner's approval.
- Rotation must preserve the hash chain and the verification anchor. **Not implemented yet** (open item in ADR-0007); until then the
  file is kept and reviewed monthly by the owner.

## 5. Integrity
- Each entry is hash-chained; `sentinel agentlog verify` detects edits, removals, forged lines, truncation and history rewrites.
- A failed verification is a security event: `sentinel run` writes an alert and `doctor` reports it.

## 6. Rollout to other people (not yet in scope)
Before enabling on any machine other than the owner's: written notice to the employee stating section 2, an opt-in or a documented
legal basis, and an agreed contact for questions. This document is the starting point for that notice.

## 7. Review
Reviewed every 6 months or whenever the recorded fields change (a change to section 2 needs a new ADR).

## Sign-off
Owner: Parthiban  Date: 2026-10-31  Decision: [x] approved as written  [ ] approved with changes  [ ] rejected
(Approval given in the Claude Code chat in answer to a yes/no question; recorded here by Claude.)

All generated content requires human review before use.
