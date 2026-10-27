# ADR-0007: Tamper-evident agent decision log
Date: 2026-10-27 | Status: proposed (needs human review; hook patch not yet applied)

## Context
The Claude Code guard hooks make an allow or deny decision on every tool call and then discard it. Sentinel therefore cannot
see an agent being steered (problem: unsafe AI-agent operations), and a steered agent could hide its own activity if the record
were an ordinary editable file inside the workspace.

## Decision
- The hooks append one JSON line per **denial**, per **MCP tool call** and per **session start** to
  `<project>/.sentinel/agent-decisions.jsonl`. Ordinary allowed calls are not logged (low volume; less monitoring of developers).
- Fields: version, sequence, time, hashed session id, tool, decision, stable rule id (`BG-xx`, `PF-xx`, `MCP-01`, `SS-01`),
  target class, and a keyed fingerprint of the target (HMAC with the existing fingerprint key; omitted if no key).
  **Never stored:** the raw command, path, prompt, or tool arguments.
- Each line carries `prev` and `hash` (sha256 of prev plus the canonical entry): editing, removing or reordering a line breaks the
  chain. Appends use a lock file so parallel hooks cannot fork the chain.
- Truncating the end of the file is invisible to a chain, so `sentinel agentlog verify` stores an **anchor** (last verified
  seq and hash) in Sentinel's database. Later runs fail if the file ends earlier than the anchor, no longer contains the anchored
  entry, or was deleted. `sentinel run` verifies on every pass and writes `alerts.log` on failure; `doctor` reports the state.
- The agent cannot read, edit or shell-redirect into `.sentinel/` once the patch is applied (rules BG-14 and PF-17 plus deny
  rules), because that directory holds the credential map, the GitHub token file and the log.
- Logging can never change a decision: every logging error is swallowed, and a test proves a denial still denies when the log
  location is unwritable.
- The hook side is delivered as a patch (`docs/patches/agent-decision-log/`) because `.claude/hooks/**` and
  `.claude/settings.json` are protected files; a human applies it.

## Consequences (security, operations, cost)
- Detects tampering by the monitored agent only if the verifier runs somewhere the agent cannot rewrite: the anchor lives in the
  database, but a determined agent with full shell access outside the guard could still alter both. Real isolation is the gateway
  (later release); this raises the bar and makes silent edits detectable.
- The decision log records only what the hooks block or observe. It does not prove that no un-hooked action happened (rule R9 is a
  later release).
- Retention and rotation are not implemented yet: the file grows without bound (denials are rare). Rotation must preserve the chain
  and the anchor (open item).
- Privacy: no commands, paths or arguments are stored; a hashed session id and a keyed target fingerprint only. A monitoring
  policy for employees still needs a decision before any rollout beyond this workstation.

## Alternatives considered
- Log every allowed call: high volume and broader employee monitoring.
- Store raw commands: could contain secrets (project rule 1).
- Send decisions to a service: needs the central service (later release).
