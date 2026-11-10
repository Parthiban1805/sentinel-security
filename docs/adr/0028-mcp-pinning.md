# ADR-0028: MCP server pinning and rug-pull detection (v0.7e item F2)
Date: 2026-11-10 | Status: proposed (needs human review) | Amends: ADR-0012 (agent inventory), ADR-0016 (gateway)

## Context
ADR-0016 made the gateway deny MCP servers nobody approved (MCP-02). The approval was tied to the server's
name, transport, host and command name. `pinned_version` was recorded but never compared. Tool poisoning and
"rug pulls" (Invariant Labs, 2025; their mcp-scan tool pins tool definitions by hash) change what an approved
server does without changing its name: `npx -y pkg` fetches whatever version is newest at each start, an
argument or an env variable can change what runs, a URL can move. A same-named server at local or user scope
would also be launched instead of the project entry.

mcp-scan itself is not used: by default it sends tool names and descriptions to an invariantlabs.ai API, which
CLAUDE.md rule 5 does not allow, and it starts the servers to list their tools.

**Facts checked in the Claude Code documentation:**
- Hooks (2026-11-06): no hook exposes MCP tool definitions (`tools/list`); MCP tools appear in tool events as
  `mcp__<server>__<tool>`; every hook gets `session_id`; SessionStart runs when a session starts, which is also
  when Claude Code starts the project's MCP servers.
- MCP (2026-11-10): when one server name is defined in several places, the highest-precedence source is used
  whole: local scope, then project scope (the project file), then user scope. Local scope is stored in
  `~/.claude.json` and is the default of `claude mcp add`. `${VAR}` and `${VAR:-default}` expand in `command`,
  `args`, `env`, `url` and `headers`.

## Decision
- **One stdlib module** `sentinel/mcppin.py`, shipped byte-identical to the hooks as `_mcppin.py` (Python 3.10).
- **Launch hash:** HMAC-SHA256 with the fingerprint key, domain-separated (`sentinel/mcp-config/v1`), over the
  server's whole entry in the project file, env and header VALUES included: `NODE_OPTIONS`, a registry URL or a
  proxy change what runs. Only the keyed hash is stored. Rotating a literal credential in the project file
  therefore needs a re-approval; a project file should hold `${VAR}` references, not values.
- **Inventory** (`inventory agents`, `sentinel run`): stores the hash as `config_hash`, and ties the approval to
  it. Any launch change clears the approval (audited `mcp_approval_cleared`) and drops what the person reviewed
  (`pinned_version`, `reviewed`, `trusted`; the tool list stays, it only narrows). An approval made before
  pinning is kept and pinned once (audited `mcp_pin_added`); the first keyed run closes that migration
  (`mcp_pinning_enabled`). A run without the key keeps the old pin but still clears the approval on a transport,
  host or command change. Rediscovery keeps what a person set; it used to drop it. After discovery the allow-list
  is rewritten (if allow-list mode is on), so pins and cleared approvals reach the gateway at once.
- **Imports:** `inventory import` refuses `mcp_server` and `ai_agent` records (an import file is something the
  agent could write), and is a person-only command (BG-17).
- **Allow-list** (`mcp-allowlist.json`): approved entries carry `config_hash`, and when set a pinned `tools`
  list and `trusted` (read by the output guard, ADR-0027).
- **Check at session start:** `session_log.py` compares each pinned server with the project file and writes
  `mcp-drift.json` (`changed`, `missing`, `unverifiable`; `*` when the allow-list itself is unreadable), bound to
  the session (decision-log hash of its id) and the workspace. Within one session the drift can only grow: a
  second check after quietly restoring the project file does not clear a server that is already running. A
  person approving a server rewrites the result and keeps the binding, so a re-approved server is usable at once;
  with no binding yet the file is not trusted until the next session start. A failed check removes the old file
  and records SS-98; a found drift records SS-02. Written with a unique temp file, retried on Windows.
- **Gateway** (`_policy._mcp_pinned`, via `_mcppin.check`):

  | Approved server | Decision | Rule |
  |---|---|---|
  | pinned, and drifted (changed, missing, unverifiable) | deny | MCP-04 |
  | pinned, and the drift file is absent, unreadable, unbound, or for another session or workspace | deny ("not checked") | MCP-04 |
  | a pinned tool list that does not hold this tool | ask | MCP-05 |
  | otherwise | allow, recorded | MCP-01 |

- **Person-only commands** (gateway rules, matched anywhere in the command segment, so options placed before the
  action do not slip past): BG-17 now covers `mcp-allowlist off|pin-tools` and `inventory set|import`, besides
  the existing kill-switch, manifest, sandbox strict, creds and agentlog actions. BG-28 denies running a hook
  file by hand (the live hooks or their patch copies). BG-29 denies `claude mcp add|add-json|remove|...` and
  `claude config set|add|remove`: a local-scope server overrides the project entry of the same name.
- **Tool list:** `sentinel agent mcp-allowlist pin-tools <server> [--tools a,b] --actor <you>`, by a person only.
  Without `--tools` it pins the tool names the gateway let through for that server since the approval's review
  date, from the decision log, after verifying the log's hash chain.
- **Hygiene:** M1 (a package launch without an exact version, after unwrapping `cmd /c`, `sh -c` and `env`, and
  skipping options that take a value; a container image without a digest), M2 (a remote server over plain
  `http://`, host read with `urlsplit`), M3 (`${VAR}` in the command, args or URL: the pin hashes the text, not
  the value), M0 (an unreadable project file). Findings name the server only (`<project file>#<name>`).
- **Status:** `sentinel agent mcp-allowlist status` reads the file the gateway uses and exits 1 on drift, an
  unpinned entry or an unreadable file: usable in pre-commit, post-merge or CI, so drift is caught before a
  session starts.

## Consequences (security, operations, cost)
- **Security:**
  - The agent cannot use an approved server whose package version, arguments, URL or env change, until a person
    reviews and re-approves it. A removed project entry is denied too.
  - A new tool on an approved server asks first, once its tool list is pinned.
  - Fails closed: no drift file, an unreadable or foreign one, a missing key or an unreadable config all deny
    pinned servers.
  - **Not a boundary:**
    - **A changed stdio server still starts.** Claude Code launches it at session start, alongside the check;
      MCP-04 only stops the agent from calling its tools. Code in a changed package has already run by then.
      Run `mcp-allowlist status` before a session (or in pre-commit/CI) to catch it earlier.
    - A server that changes its tool DESCRIPTIONS or behaviour without changing its launch settings or tool names
      is not detected (no hook sees `tools/list`). Pin exact versions (M1) to narrow this.
    - `${VAR}` expansion (M3): a changed variable starts different code under the same hash.
    - Local- and user-scope servers are still not inventoried (`~/.claude.json` is off limits); BG-29 stops the
      agent adding them, not a person or another program.
    - Remote servers can change behind the same URL.
    - Gateway rules are patterns; a script the agent writes and runs can still do what they block.
  - **Open question:** the MCP docs describe replacing characters outside `A-Za-z0-9_-` with `_` only for
    plugin-bundled servers. If ordinary server names are normalised the same way, an approved name with a `.`
    would always be denied (fails closed). Check with `claude mcp get` before approving such a name.
- **Operations:**
  - Existing approvals keep working after the first `inventory agents` (or `sentinel run`) with the key: they are
    pinned once and written to the gateway's allow-list.
  - A first approval is usable from the next session start.
  - After a deliberate upgrade: `sentinel inventory agents`, then `sentinel inventory set mcp-<name> --approve
    --owner ... --pinned-version ...`.
  - The owner applies the gateway patch: new hook file `_mcppin.py`; `session_log.py` and `_policy.py` change.
- **Cost:** none. No network call, no new dependency.

## Alternatives considered
- **Wrapping mcp-scan:** sends tool descriptions to a third-party API by default (rule 5), and runs servers.
- **Starting each server in the sandbox to hash its `tools/list`:** catches description changes, but runs
  third-party code on every check. A v0.8 candidate, in the Docker sandbox with no network.
- **Checking the project file in the gateway on every MCP call:** reads and hashes the config on every call; the
  servers only start with the session, so the session-start check sees what actually runs.
- **Storing the launch settings instead of a hash:** they can hold credentials.
- **Leaving env values out of the hash** (the first version): rotation would not need re-approval, but an
  env-based rug pull (`NODE_OPTIONS`, a registry URL) would go unnoticed.
