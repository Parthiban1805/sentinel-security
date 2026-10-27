# Claude Code hooks: verified facts (2026-10-27)

Source: https://code.claude.com/docs/en/hooks (official; fetched 2026-10-27). Only the first ~100k characters of the page
were read; items marked "not seen" were in the truncated part.

| Item | Status | Detail |
|---|---|---|
| Common stdin fields | **confirmed** | `session_id`, `prompt_id`, `transcript_path`, `cwd`, `scratchpad_dir`, `permission_mode`, `effort`, `hook_event_name`; PreToolUse adds `tool_name`, `tool_input`, `tool_use_id` |
| MCP tool names | **confirmed** | `mcp__<server>__<tool>`; plugin servers `mcp__plugin_<plugin>_<server>__<tool>` |
| Matcher semantics | **confirmed** | Only letters, digits, `_`, `-`, space, `,`, `\|` means exact names; any other character makes it an unanchored JavaScript regex. So `mcp__.*` is a regex matching every MCP tool. `mcp__memory` alone matches nothing. |
| SessionStart | **confirmed** | Matchers `startup`, `resume`, `clear`, `compact`, `fork`; command hooks supported |
| SessionStart JSON example | not seen | Shape follows the general three-level structure (event, matcher group, handler) |
| Exit code 2 | **confirmed** | Blocks the tool call; stderr is the reason; JSON `permissionDecision` cannot override it |
| `CLAUDE_PROJECT_DIR` | **confirmed** | Project root where the session started |

Implications for Sentinel:
- A per-session identity can be derived from `session_id` (hashed; the raw id is not stored).
- One `mcp__.*` PreToolUse hook sees every MCP call, including its server name.
- A `SessionStart` hook can write a heartbeat entry so a silent gap in logging is detectable.
- The docs recommend the exec form (`command` plus `args`) for hooks that use path placeholders; the patch files keep the
  shell form used by `.claude/settings.json` today. Review this when applying.
