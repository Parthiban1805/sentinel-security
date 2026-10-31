# ADR-0012: Agent visibility from the hook decision log (source, inventory, rule R5)
Date: 2026-10-31 | Status: proposed (needs human review)

## Context
ADR-0007 made the Claude Code guard hooks write a tamper-evident decision log. Until v0.3b nothing read it except
`agentlog verify`. The product plan (v0.3b) asks for agent behaviour to become events and incidents, without logging
ordinary developer activity. The monitoring policy (`policies/agent-monitoring-policy.md`) was approved by the owner on
2026-10-31: only blocked actions, MCP calls and session starts are recorded; no commands, paths, prompts or output.

## Decision
- **Source** `sentinel/sources/agent.py`, run by `sentinel run` after the `agentlog` verification:
  - reads `<home>/agent-decisions.jsonl` (local file; no network);
  - emits `agent_tool_denied` (decision `deny`, severity low) and `agent_tool_allowed` (decision `allow_mcp`, severity info,
    with the server parsed from `mcp__<server>__<tool>`); `session_start` is not an event;
  - **emits nothing from a log whose chain or anchor fails** (a tampered log is not evidence; the `agentlog` health check alerts);
  - a cursor stores the chain id (hash of its first entry), the last emitted sequence number and its hash: an archived log with a
    new chain is read from its start; a shortened or rewritten history of the same chain is refused;
  - the cursor is committed only after the events were stored (DeferredState).
- **Inventory** `sentinel/inventory/agents.py` (also `sentinel inventory agents`): one `ai_agent` asset per workspace and one
  `mcp_server` asset per server in the project's `.mcp.json`, keeping only the name, transport, host and command basename. Env
  values, headers and arguments are dropped before storage. Names with unusual characters are skipped, not stored. Approval and
  owner set by a person survive re-discovery.
- **Rules** (spec in `docs/spec/correlation-rules.md`): R5a, a single denial, is context only; R5b, at least 3 denials in one
  session within 30 minutes, opens one Medium incident per session (both values `[confirm]` on real data); R5c, an MCP call to an
  unapproved server, opens one High incident per server and is active only once at least one server is approved.
- **Verification:** the R5b step `verify_agent_hooks` (`sentinel incident verify-agent-hooks`) compares against a **pin** that a
  human records with `sentinel agentlog pin-hooks` (interactive terminal only, typed confirmation), kept in Sentinel's store, which
  the agent cannot write. It passes only when every installed hook file and the `hooks` block of `.claude/settings.json` equal the
  pin, neither settings file disables hooks, `.claude/settings.local.json` does not override them, and the log chain and anchor are
  intact with no dropped decisions. The workspace is the folder that holds the state dir, never a path the caller chooses. Ending
  the session and revoking credentials stay human steps.

## Amendments after the 2026-10-31 security review (verdict was "Block"; all fixed, tests in `test_agent_source.py`, `test_r5.py`)
- The first verifier compared the installed hooks with `docs/patches/` in the same workspace, which the agent can edit: it could make
  weakened hooks pass. Replaced by the human-made pin above.
- It checked file bytes only; a local settings file could disable or override the hooks. The settings checks above were added.
  **Owner action (protected files):** add `.claude/settings.local.json` and `docs/patches/**` to the deny list and to the
  protect-sensitive-files hook, then re-run `pin-hooks`.
- An MCP `command` written as one string kept its arguments (possibly a credential). Only the first token's basename is kept now, and
  only if it looks like a program name; transport is limited to `stdio`/`http`/`sse`; an unparsable URL is stored as `unparsable`.
- Server ids were lower-cased slugs, so `GitHub`, `github` and `git_hub` shared one approval. Ids now keep the exact name; R5c matches
  the tool name's `mcp__<approved name>__` prefix exactly (no guessing where a name with `__` ends). An approval is tied to the server's
  name, transport, host and command; any change clears it and is audited.
- A broken `.mcp.json` stopped log ingestion. Inventory now runs in its own guard after the events were read.
- R5b/R5c keys never expired, so a closed incident silenced the server or session forever, and one test event marked real events as
  test. Keys are now per episode (only events after the last closed incident count) and test and real events are grouped apart.
- Approving an MCP server or AI agent now needs an interactive terminal (an agent must not approve its own server).
- Denials without a session id share an `unknown` bucket instead of being dropped; odd session values are dropped; `agentlog reset`
  ingests pending entries before archiving and resets the cursor; `sentinel run` notes when R5c is inactive.
- **Still open:** splitting denials across child sessions to stay under the threshold (hypothesis; a per-asset threshold is a later
  option); claude.ai connectors cannot be approved through `.mcp.json` (use `inventory import`); a pin is per machine.

## Consequences (security, operations, cost)
- Privacy: matches the approved policy; events carry the hashed session id, tool name, rule id, class and keyed target fingerprint
  only. The inventory reads `.mcp.json`, which may hold credentials in `env` or `headers`; those values are parsed in memory and
  discarded, never stored or printed.
- Detection limits (facts): only actions a hook blocks and MCP calls are visible; allowed ordinary calls are not logged by design;
  user-scope MCP servers are invisible. Full visibility needs the agent gateway (v0.7, rule R9).
- Noise: the guard hooks match keywords and block harmless commands (seen in this project). That is why a single denial opens
  nothing and R5b's confidence is low. Thresholds must be tuned on real data; the log held 17 entries when this was built.
- The hooks verifier compares against the patch folder in this repository; another installation needs a signed manifest of hook
  hashes instead (endpoint agent, v0.8).
- Cost: negligible (one local file read per run).

## Alternatives considered
- Alert on every denial: rejected, alert fatigue (R5a).
- Log every allowed call to see more: rejected by the approved monitoring policy.
- Read user-scope MCP configuration to see all servers: rejected, it holds credentials (CLAUDE.md rule 2).
