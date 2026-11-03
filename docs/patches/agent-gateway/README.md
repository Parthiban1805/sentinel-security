# Patch: agent gateway (v0.7a, ADR-0016)

Replaces the separate guard hooks with **one gateway hook for every Claude Code tool call**. The owner applies it, because
`.claude/` is protected from the agent.

## What changes
- **One hook, `gateway.py` (matcher `*`), backed by `_policy.py`, decides every call:**
  - **Deny:** exit 2, with the reason shown to Claude.
  - **Ask:** you confirm in a permission prompt.
  - **Allow:** silent, so your normal permission rules still apply. The gateway never auto-approves.
- **Every call is recorded** in the tamper-evident log (ADR-0007): tool name, decision, rule id, class and a keyed
  fingerprint of the target. Never the command, path or arguments. Monitoring policy section 2 is amended for this.
- **New rules:**
  - **BG-15 (ask):** inline interpreter code such as `python -c`, `python -`, `node -e` or `pwsh -Command`.
  - **BG-16 (deny):** encoded PowerShell.
  - **BG-17 (deny):** turning the kill switch off from an agent.
  - **KS-01 (deny):** the kill switch is on, so only reading is allowed.
  - **MCP-02 / MCP-03 (deny):** an unapproved MCP server, or an unreadable allow-list.
- `bash_guard.py`, `protect_sensitive_files.py` and `mcp_log.py` become thin wrappers around the gateway.
- **Settings:**
  - The three PreToolUse entries become one (`*` -> `gateway.py`).
  - New deny rules: writing `.claude/settings.json`, `.claude/hooks/**` and `.claude/settings.local.json`.

## Apply
```
docs\patches\agent-gateway\apply-patch.bat
```
The script:
- backs up the current hooks and settings to `.claude/backup-before-gateway`,
- copies the files in,
- checks that the settings are valid JSON and that the gateway imports,
- restores the backup if any of that fails.

Then:
1. Start a new conversation.
2. Run the guard tests.
3. Pin the hooks.
4. Do the kill-switch drill.

The script prints each command.

## Known limits (ADR-0016, including the security review amendment)
- **BG-15 only covers inline code.** A script written to a file and then run is not inspected. v0.7b (sandbox) is the fix.
- **The gateway only sees Claude Code tool calls,** not the processes they start. Rule R9 (decoy touched with no
  matching decision) is the detection for that gap.
- **The kill switch only stops new tool calls.** Background shells or scripts already running keep going; stop them by
  hand.
- **The kill switch is per project.** It lives in this project's `.sentinel` folder, so run `kill-switch on` from the
  project folder. The command warns otherwise.
- **The MCP allow-list trusts the server name.** The pinned version is recorded but not checked.
- **If the hook itself fails** (Python missing, a timeout), Claude Code lets the call through. Run the guard tests after
  any Python change.
- **Not every network route is covered:** `git clone` and DNS lookups, for example.
