# Patch: agent gateway (v0.7a, ADR-0016)

Replaces the separate guard hooks with **one gateway hook for every Claude Code tool call**. The owner applies it, because
`.claude/` is protected from the agent.

## v0.7d update 2: context firewall (ADR-0025)
- **New files:** `_firewall.py` (a byte-identical copy of `sentinel/contextfirewall.py`) and `prompt_guard.py`.
- **New hook:** `settings.merged.json` adds a `UserPromptSubmit` hook running `prompt_guard.py`. It blocks a prompt
  that holds a known credential format or a private key (FW-10). The text still stays in Claude Code's local
  transcript.
- **Gateway:** a third layer after the built-in rules and the manifest checks WebFetch, WebSearch and MCP inputs.
  - **Deny:** a known credential (FW-01) and the cloud-metadata address (FW-02).
  - **Ask:** guesses, emails, card numbers and internal addresses (FW-03).
  - **Fail closed:** an error denies these tools (FW-99).
- **After applying:** start a new conversation, run `uv run pytest -q tests/scenarios/test_s11_agent_policy_hooks.py`,
  and re-pin (`uv run sentinel agentlog pin-hooks --actor <you>`): there are two new hook files.

## v0.7d update: agent permission manifest (ADR-0024)
- **New file `_manifest.py`:** a byte-identical copy of `sentinel/agentmanifest.py`, and a test keeps them
  identical. `apply-patch.bat` now installs it.
- **`_policy.decide`** first applies the built-in rules (unchanged, now `_base_decide`). The applied manifest
  (`.sentinel/agent-manifest.json`) can then only tighten the result: allow becomes ask or deny, ask becomes deny.
- **No manifest applied:** nothing changes.
- **Unreadable manifest:** only reading is allowed (MF-05).
- **After applying the patch:**
  1. Start a new conversation.
  2. Run `uv run pytest -q tests/scenarios/test_s11_agent_policy_hooks.py`.
  3. Re-pin: `uv run sentinel agentlog pin-hooks --actor <you>`. The pin now covers every hook file, including
     `_manifest.py`, `_policy.py` and `gateway.py`.
- **To use a manifest:** copy `policies/agent-manifest.example.toml` to `policies/agent-manifest.toml`, edit it, then
  run `uv run sentinel agent manifest apply --actor <you>` in a terminal.

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
