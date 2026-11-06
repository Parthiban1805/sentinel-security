# ADR-0024: Agent permission manifest (v0.7d item 1)
Date: 2026-11-06 | Status: proposed (needs human review)

## Context
The agent gateway (ADR-0016) applies the same fixed rules to every session: blocked command patterns, protected paths,
the MCP allow-list. The owner wants a declarative per-agent policy, as in their ORE kernel's manifests: what the agent
may read and write, which domains it may fetch, whether it may use a shell, which MCP tools it may call, and when that
grant expires. ORE's manifests are an idea source only (AGPL-3.0; nothing copied). Their weaknesses are avoided:
unknown keys silently ignored, no deny lists, no expiry, and identity taken from the request body.

## Decision
- **Source:** `policies/agent-manifest.toml`, edited by the owner. An example is in
  `policies/agent-manifest.example.toml`. Keys:

  | Section | Keys |
  |---|---|
  | top level | `version` = 1 |
  | `[agent]` | `id`, `owner`, `expires` (optional date) |
  | `[filesystem]` | `read`, `write`, `deny`, `ask_write` globs relative to the workspace; `outside_workspace` = allow, ask or deny |
  | `[network]` | `fetch_domains` (exact host or `*.domain`; absent = no extra limit), `web_search` |
  | `[execution]` | `shell`, `deny_tools` |
  | `[mcp.servers.<name>]` | `tools` (exact tool names or `*`) |

  - Unknown keys and wrong types are refused, with the key path named.
- **Applied, never live-edited:** `sentinel agent manifest apply --actor <name>` (person at a terminal only) validates
  the TOML and writes a compiled copy to `<state dir>/agent-manifest.json`, which the agent cannot write (PF-17,
  BG-14). It records the TOML's SHA-256, the workspace path, who applied it and when, and writes an audit entry.
  - Editing the TOML has no effect until it is applied again.
  - `sentinel agent manifest status` and `sentinel doctor` (and so `sentinel posture`) report drift (the TOML
    differs from what was applied), expiry, and an unreadable compiled copy.
  - `sentinel agent manifest off` (person only) removes the compiled copy.
- **Enforcement:**
  - **Module:** the gateway patch adds `.claude/hooks/_manifest.py`, a byte-identical copy of
    `sentinel/agentmanifest.py`. It is stdlib only, and a test enforces that the two stay identical.
  - **Order:** the existing rules decide first. The manifest can only tighten: it turns allow into ask or deny, and
    ask into deny, never the reverse.
  - **No manifest:** without a compiled manifest nothing changes.
  - **Fail closed:** an unreadable or invalid compiled manifest, or an import failure of `_manifest.py`, denies
    everything but reading (MF-05). An error while evaluating a call denies it (MF-99).
  - **Expiry:** an expired manifest makes every non-read call ask (MF-04).
- **Rules** (new rule ids, `manifest_*` classes):

  | Rule | Decision | Trigger |
  |---|---|---|
  | MF-01 | deny | read target not covered by `read` |
  | MF-02 | deny | write target not covered by `write` |
  | MF-03 | deny | target matches `deny` |
  | MF-04 | ask | expired |
  | MF-05 | deny (non-read) | compiled manifest unreadable or invalid, or `_manifest.py` cannot be imported |
  | MF-06 | deny | shell disabled |
  | MF-07 | deny | fetch domain not allowed |
  | MF-08 | deny | web search disabled |
  | MF-09 | deny | MCP tool not allowed for a listed server |
  | MF-10 | deny | tool in `deny_tools` |
  | MF-11 | ask | write matches `ask_write` |
  | MF-12 | per `outside_workspace` | target outside the workspace |
  | MF-13 | deny | a network or device path that cannot be placed against the workspace |
  | MF-99 | deny | the manifest could not be evaluated for this call |
- **Globs:** `**` matches any number of folders, `*` and `?` match within one name. Matching is case-insensitive on
  Windows. Path spellings are normalised as in the gateway, and symlinks and junctions are resolved.
  - A folder target (Grep `path`, a Glob pattern's fixed prefix) is readable only when a `read` glob ending in `/**`
    covers the whole folder, because a search returns file content.
- The decision log records the rule id and class only, as for every gateway decision.

## Amendment after the 2026-11-06 security review ("Approve with fixes"; tests in `test_manifest_review.py`)
- **Gateway hardening found on the way** (both pre-dated the manifest):
  - **BG-26 and BG-27:** `cd`, `pushd` or `Set-Location` into the state folder, and any command whose working
    folder is inside it, are denied. Before, `cd .sentinel` and then `del <file>` in a later call matched no rule.
  - **BG-17** now denies every human-only Sentinel action when an agent runs it: kill switch off, `manifest apply` and
    `off`, `mcp-allowlist off`, `sandbox strict off`, `pin-hooks`, `creds set`, `inventory set`, `agentlog archive`.
    The terminal check alone can be passed by a new console (`start`, `Start-Process`).
- **Paths:**
  - `\\?\` and `\\.\` prefixes are removed before matching.
  - A UNC or other network path that cannot be placed against the workspace is denied (MF-13), never treated as
    "outside".
  - Trailing-dot and trailing-space spellings are checked too.
  - The workspace is recorded both as given and as resolved, so subst and mapped drives match.
- **Searches:**
  - A Glob pattern resolves under the tool's own `path`. A Grep `glob` only narrows `path`. A Grep `path` that is a
    file uses the file glob.
  - `{` counts as a wildcard.
  - A folder search is denied when the folder holds a path a `deny` glob names (when the glob has a fixed folder).
- **WebFetch:** only plain URLs are accepted (scheme, host made of letters, digits, `.` and `-`, an optional port).
  Userinfo, backslashes, percent-encoding and non-ASCII hosts are refused, because Python and WHATWG URL parsing
  disagree on them.
- **MCP:**
  - `mcp.unlisted = "deny"` refuses servers the manifest does not list.
  - Server keys allow letters, digits, `_` and `-` only.
  - A `command` key of any type counts as a shell call.
- **Limits on the file:** repeated `**/` is collapsed, there are at most 400 globs, and compiled globs are cached.
  Error messages show key names in a safe character set only.
- **Applying:**
  - `apply` refuses a state folder that is not a Claude Code project's `.sentinel`.
  - It records the source path, so `status` and `doctor` compare against the file that was applied.
  - It prints a summary of the rules.
  - The patch's import check now includes `_manifest`, and a restore removes it.
- **Known risk:** the agent can edit `policies/agent-manifest.toml`. Nothing changes until a person applies it, the
  apply summary is shown, and the manifest can only tighten, but a person who applies without reading could still
  accept an edited file. Protecting the TOML from agent writes is an open owner option (it is a protected-file change).
- **Not fixed:** `_manifest.py` is pinned when present but is not in the required hook list, so a pin can still be
  made before the patch is applied. Claude Code may normalise MCP server names (for example `.` to `_`); keys must
  match the normalised name.

## Consequences (security, operations, cost)
- **Security:**
  - The manifest narrows what a steered agent can touch.
  - It cannot widen anything: the protected paths, blocked commands and kill switch stay in force.
  - **Identity is the workspace's single Claude Code agent.** The hook input gives no reliable per-agent identity, so
    one manifest covers the workspace. Sub-agents are not told apart.
- **Limits:**
  - A `deny` glob on files inside a folder does not stop a search of the whole folder. Content search still respects
    `.gitignore`, and the protected-path rules still apply.
  - Shell commands are not path-checked by the manifest. Use `shell = false`, or the sandbox, for that.
- **Operations:** a wrong manifest can block the agent's own work. `sentinel agent manifest off` (person only) and
  the kill switch are the recovery paths.
- **Cost:** none. No network call, dependency or schema change.

## Alternatives considered
- **Editing `_policy.py` rules per project:** not declarative, and every change needs a hook patch.
- **The gateway reading the TOML directly:** then the agent could edit its own policy. The compiled copy in the state
  directory avoids that.
- **Per-sub-agent manifests:** no trustworthy identity in the hook input yet. Revisit when one exists.
