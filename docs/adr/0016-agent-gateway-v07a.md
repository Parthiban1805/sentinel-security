hub # ADR-0016: Agent gateway, part a: policy engine, decisions for every call, kill switch, MCP allow-list, R9
Date: 2026-11-03 | Status: accepted (owner, 2026-11-03: "go 7a", accepting the four recommendations)

## Context
Roadmap v0.7 asks for a gateway in front of AI agent tool calls. The exit gate has three parts: every in-scope agent action has
a decision; the two recorded hook-bypass tests turn green; and a kill-switch drill passes. The bypass tests are
`python -c "...urlopen(...)"` (network) and `python -c "print(open('.env').read())"` (secret read). A keyword guard cannot
see inside inline code, and only a real sandbox fully closes that gap. The owner split v0.7 in two:
- **7a (this ADR):** a policy engine with no new infrastructure.
- **7b (later):** a sandbox (container or VM with an outgoing-traffic allow-list). It needs a technology choice.

Claude Code hook facts this design relies on (official hooks documentation, read 2026-11-03):
- A PreToolUse hook may return `permissionDecision` `allow`, `deny`, `ask` or `defer`.
- `ask` prompts the user, and in `-p` runs the call is denied.
- When hooks disagree, `deny` > `defer` > `ask` > `allow`.
- A matcher of `*` matches every tool.
- **`allow` skips the user's permission prompt.** The gateway therefore never returns `allow`: for calls it has no
  objection to it stays silent, so the user's normal permission rules still apply.

## Decision
1. **One gateway hook for every tool call** (`docs/patches/agent-gateway/gateway.py`, matcher `*`), backed by a
   standard-library policy engine (`_policy.py`). The old `bash_guard.py`, `protect_sensitive_files.py` and `mcp_log.py`
   become thin wrappers, so existing references keep working. The rules are the existing BG and PF rules plus:
   - **BG-15 inline code (ask):** an interpreter running code given on the command line or on standard input, for
     example `python -c`, `python -`, `node -e`, `ruby -e`, `perl -e`, `php -r`, `pwsh -Command`. This makes the two
     bypass tests green. It narrows the gap but does not close it: code written to a file and then run is not caught,
     which is what 7b is for.
   - **BG-16 encoded command (deny):** PowerShell `-EncodedCommand` and its short forms. Hidden code has no review path.
   - **BG-17 gateway control (deny):** turning the kill switch off from an agent.
   - **KS-01 kill switch (deny):** when `<home>/agent-kill-switch` exists, every tool except read-only ones (Read, Grep,
     Glob, LS) is refused. The read-only tools still pass the file rules.
   - **MCP-02 and MCP-03 (deny):** a call to an MCP server not in `<home>/mcp-allowlist.json` (allow-list mode), or an
     allow-list file that cannot be read (fail closed). With no allow-list file, MCP calls are allowed and recorded,
     as before.
2. **A decision for every call.** Every call is written to the existing tamper-evident log (ADR-0007) as `allow`,
   `allow_mcp`, `ask` or `deny`, with tool name, rule id, class and a keyed fingerprint of the target. Never the
   command, path or arguments. Monitoring policy section 2 is amended accordingly (owner approval 2026-11-03).
   File targets are normalised (absolute, forward slashes, lower case on Windows) so that one file always gets the
   same fingerprint.
3. **Kill switch.**
   - `sentinel agent kill-switch on` works for anyone, including an agent.
   - `off` needs a human at an interactive terminal, and the gateway also denies it from an agent (BG-17).
   - `status` shows whether it is on.
4. **MCP allow-list with owner, pinned version and review date.** Approving an MCP server
   (`inventory set mcp-<name> --approve`, already human-only) now requires `--owner` and `--pinned-version`. Sentinel
   writes `<home>/mcp-allowlist.json` listing the approved servers with owner, pinned version and review date, and
   deletes it when none are approved. The agent cannot write there (state directory rules).
5. **R9: sensitive access with no matching gateway decision.**
   - **Trigger:** a decoy (ADR-0009) is touched, including a plain read, while an agent session is active on the same
     machine (any gateway decision within the window), and no gateway decision has the decoy's path fingerprint.
   - **Meaning:** something outside the gateway touched the decoy: a script the agent ran, or another process.
   - **Rating:** severity high, confidence medium. A backup job or scanner at the same moment is named as an innocent
     explanation.
   - **Window:** 30 minutes before the decoy event [confirm], because the canary check runs every 15
     minutes and its event time is the check time.
   - **Data:** canary events now carry the decoy path's fingerprint, and the agent-log source now emits
     `agent_tool_allowed` events for allowed file-tool calls and for `ask` decisions, so the rule can join them.
6. **Injection suite.** S11 tests feed injection-style commands (fetch and run, exfiltrate, read secrets, disable
   the guard, encoded payloads) through the gateway and require deny or ask. The CI test job already runs every test on
   each push, so no new workflow or action pin is needed.
7. **Hooks stay owner-applied.** The patch lives in `docs/patches/agent-gateway/`, and the owner runs
   `apply-patch.bat`. Tests run against the patch files. They also run against the live hooks once the gateway is
   installed there.

## Consequences (security, operations, cost)
- **More prompts:** inline interpreter code now asks the user. That includes legitimate one-liners.
- **More log entries:** every tool call is recorded (minimal fields, no content), and allowed file-tool calls become
  events in the store. The volume is a few hundred per working day.
- **Still possible in 7a:** running code saved to a file, a process outside Claude Code, and R9's joins, which depend
  on decoys having been planted. 7b and v0.8 address these.
- A hook that crashes must not open a hole. Errors in the policy engine deny the call (fail closed), except malformed
  input, which never breaks a session (as before).
- No network, no new dependency, no cost.

## Security review amendment (2026-11-03, before the first commit)
An independent read-only review found that the first version did less than this ADR claimed. These are fixed and tested
(`tests/scenarios/test_s11_agent_policy_hooks.py`, `tests/sentinel/test_gateway.py`):
- **BG-15 matched only literal spellings.** `.venv\Scripts\python.exe -c`, `python -Ic`, `python -X utf8 -c`, quoted
  flags, line continuations, code piped or redirected into an interpreter, `python -m timeit`, `node -pe`,
  `ruby -rnet/http -e`, `deno eval`, PowerShell positional commands and `/enc` or en-dash prefixes all passed. BG-15 is now an
  argument parser per interpreter family (Python, Node/Bun/Deno, Ruby/Perl/PHP, PowerShell), not a regex.
- **File rules ignored links and Windows aliases.** They now also check the resolved path (symlinks, junctions, short
  names), trailing dots and spaces, and NTFS alternate data streams (PF-21). Grep's `glob` is checked. New protected
  files:
  - `~/.claude.json`: no reads, no writes; it can hold MCP tokens.
  - `.mcp.json`: no writes.
  - Python startup files (`*.pth`, `sitecustomize.py`): no writes.
  - `.claude/backup*`: no writes.
  `.claude.json` and `.mcp.json` are also in the settings deny list.
- **No Bash rule protected the gateway itself.**
  - BG-20 denies writes to `.claude` hooks or settings, `.mcp.json` and backups by any write verb or redirection.
  - BG-14 now covers many more delete, rename and link commands for `.sentinel` and `~/.claude.json`.
  - BG-22 denies `git clean -x`.
- **More network and secret-read commands:**
  - Denied: `iwr`, `irm`, `Invoke-WebRequest`, `certutil`, `bitsadmin`, piping into `iex`, and copying `.env` or reading
    it with `sed`, `awk`, `Get-Content` and similar.
  - Ask: package runners (`npx`, `uvx`, `uv run --with`) as BG-18, link creation as BG-19, and fake terminals
    (`winpty`, `script -c`) as BG-21.
- **Any tool with a `command` field** (for example a PowerShell tool) gets the command rules, not only `Bash`.
- **R9 could be silenced:** a denied call or a listing on the decoy counted as coverage. Now only an *allowed* call
  by a tool that reads or writes content counts. A denied call on the decoy followed by a touch raises confidence to
  high.
- **MCP allow-list:**
  - Unapproving the last server deleted the file, which allowed every server. Allow-list mode now stays on (an
    empty list blocks all); only `sentinel agent mcp-allowlist off`, human-only, returns to record-only.
  - A wrong-typed allow-list fails closed.
  - Server names are parsed the same way everywhere (everything before the last `__`), so a server named `github__x`
    cannot pass as `github`. The trade-off: a legitimate tool whose own name contains `__` is blocked and alerted
    (R5c changed to match).
  - Any change to an MCP server or AI agent in the inventory now needs a human.
- **Kill switch in the wrong folder:** turning it on from another folder wrote a file the gateway never reads. `on`
  now prints the absolute path, states that it applies to this project only, and warns when the folder is not a
  Claude Code project's `.sentinel`.
- **Installer and hooks:**
  - The hooks run under `python -I` (isolated: no user site, no `PYTHON*` variables).
  - The installer runs its checks in isolated Python from the Windows folder, not the repo. It makes a new
    timestamped backup each run and checks every copy.
  - The gateway answers first and logs after, so a slow log lock cannot delay a block.

**Known limits, accepted for 7a (documented, not fixed):**
- A script written to a file and then run.
- Processes that tools start, including background shells already running when the kill switch is turned on. The
  runbook step is to stop them.
- Network access through tools not on the list (for example `git clone`, DNS lookups).
- The MCP allow-list trusts the server **name**; the pinned version is recorded but not checked.
- If the hook itself fails (Python missing, a timeout), Claude Code lets the call through.
- The installer finds `python` on PATH.
- The "human at a terminal" check can be imitated; BG-21 asks about the known tools for that.
- Symlink resolution is tested only where the machine allows creating links.

## Alternatives considered
- **Return `allow` for clean calls.** Rejected: it would silently skip the user's permission prompts.
- **Deny inline code outright.** Rejected by the owner in favour of `ask`, to keep ordinary work possible.
- **A gateway process that every tool call goes through (a proxy).** Larger, and it adds nothing over hooks until 7b
  adds a sandbox.
- **Log full commands for better forensics.** Rejected: the monitoring policy forbids it.
