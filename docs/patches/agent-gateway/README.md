# Patch: agent gateway (v0.7a, ADR-0016)

Replaces the separate guard hooks with **one gateway hook for every Claude Code tool call**. The owner applies it, because
`.claude/` is protected from the agent.

## v0.7f update: networked sandbox asks (ADR-0026)
- **Gateway only (`_policy.py`):** `sentinel sandbox run --allow-net ...` asks first (BG-30). A networked sandbox
  can send data to every host in `[sandbox.egress]`, so a person confirms each run the agent starts. Without
  `--allow-net` nothing changes.
- **After applying:** start a new conversation, run `uv run pytest -q tests/sentinel/test_sandbox_egress.py`, and
  re-pin the hooks (`uv run sentinel agentlog pin-hooks --actor <you>`; no new files, `_policy.py` changed).

## v0.7e live drill: checked 2026-11-10
Read output was redacted (OG-01) and the TF-01 prompt appeared; the decision log verified. Events are under
`uv run sentinel search --source agent_hook --since 1d` after `uv run sentinel run --no-scan`; R13 only fires when a
data-leaving call is refused after a redaction (an ask that is declined is not a refusal).

## v0.7e update 2: MCP pinning (ADR-0028)
- **New file:** `_mcppin.py` (a byte-identical copy of `sentinel/mcppin.py`).
- **`session_log.py`:** at session start it also compares each pinned MCP server with `.mcp.json` and writes
  `.sentinel/mcp-drift.json`.
- **Gateway:** an approved server whose launch settings changed, went missing or could not be checked is denied
  (MCP-04), and so is every pinned server when the drift file is missing or unreadable. With a pinned tool list,
  a new tool asks first (MCP-05). `mcp-allowlist pin-tools` joins the person-only commands (BG-17).
- **After applying:** run `uv run sentinel inventory agents` once (existing approvals are pinned, not cleared),
  start a new conversation, run `uv run pytest -q tests/sentinel/test_mcp_pinning.py`, re-pin the hooks (one new
  file), and check `uv run sentinel agent mcp-allowlist status`.

## v0.7e update: output guard and trifecta gate (ADR-0027)
- **New files:** `_taint.py` (a byte-identical copy of `sentinel/sessiontaint.py`) and `output_guard.py`.
- **New hook:** `settings.merged.json` adds a second `PostToolUse` entry (Read, Bash, Grep, WebFetch, WebSearch,
  MCP tools) running `output_guard.py`. It replaces a known-format credential or private key in the output with
  `[REDACTED:<kind>:<sha256[:8]>]` before Claude sees it (OG-01), and marks the session: untrusted content read,
  credential seen.
- **Gateway:** a fourth tighten-only layer asks before WebFetch, WebSearch or an MCP call in a session with both
  marks (TF-01); an unreadable state asks too (TF-99). TF-01 wins a tie with an earlier ask and carries its reason.
- **State:** marker files in `.sentinel/agent-sessions/` (no content, no raw session id).
- **After applying:** start a new conversation, run
  `uv run pytest -q tests/scenarios/test_s11_agent_policy_hooks.py tests/sentinel/test_output_guard.py`, re-pin
  (`uv run sentinel agentlog pin-hooks --actor <you>`: two new hook files), then the live drill:
  1. Read a harness-generated canary file: Claude must see `[REDACTED:...]`, not the value.
  2. Run a WebSearch, then a WebFetch: the TF-01 prompt must appear.
  3. `uv run sentinel agentlog verify`, then `uv run sentinel run --no-scan` and
     `uv run sentinel search --source agent_hook --since 1d`.
  If step 1 shows the value, Claude Code ignored `updatedToolOutput` for that tool: report it (ADR-0027).

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
