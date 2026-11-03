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
| A call to an MCP tool: time, tool name (`mcp__<server>__<tool>`) | The content of an allowed call: what was read, edited or run |
| **Since v0.7a (ADR-0016): every tool call** as a decision: time, tool name, decision (allow, ask or deny), rule id and class (for example `file_access`, `command`) | The command text, file path or arguments of any call, allowed or not |
| A session start (heartbeat) | The content of any session |
| A hashed session id and a keyed fingerprint of the target: a file path, or for commands the command text (cannot be reversed without the local key; someone holding the key could confirm a guessed short command) | The raw session id or the raw target |

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

**Amendment 2026-11-03 (ADR-0016, v0.7a agent gateway):** section 2 now also records every tool call as a decision. Only the
tool name, decision, rule id, class and a keyed fingerprint of the target are recorded, never the command, path or
arguments. Allowed file-tool calls (Read, Edit, Write, Grep, Glob) and "ask" decisions also become events in Sentinel's local
store, so rule R9 can tell whether the gateway saw a call on a decoy file. Approved by the owner in the Claude Code chat
("go 7a", accepting the recommendation to log allowed actions without their content). Recorded here by Claude.

All generated content requires human review before use.
