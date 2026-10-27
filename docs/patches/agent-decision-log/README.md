# Patch: tamper-evident agent decision log

**A human applies this.** `.claude/hooks/**` and `.claude/settings.json` are protected files that the agent may not edit.
Everything here is tested (`tests/sentinel/test_hook_patches.py`); it is not active until you copy it in.

## What it does
- Every hook **denial** is recorded in `<project>/.sentinel/agent-decisions.jsonl` with a stable rule id (BG-01..14, PF-01..17),
  the tool, a class, a keyed fingerprint of the target and a hashed session id. The raw command, path and arguments are
  **never** stored. Allowed ordinary calls are not logged (low volume, less monitoring of developers).
- MCP calls (`mcp__<server>__<tool>`) are recorded as `allow_mcp`; a `SessionStart` heartbeat records that logging was on.
- Each line is hash-chained to the previous one. `sentinel agentlog verify` detects edited, removed or reordered lines, and
  a truncated tail (it keeps an anchor in Sentinel's database, outside the file).
- New protections: the agent cannot read, edit or shell-redirect into `.sentinel/` (BG-14, PF-17, and the deny rules below).
  That directory holds the credential map, the GitHub token file and the log itself.
- Logging never changes a decision: if it fails, a deny is still a deny.

## Apply in one step
Double-click `apply-patch.bat` in this folder, or run `docs\patches\agent-decision-log\apply-patch.bat` from the repo root.
It backs up your current hooks and settings to `.claude\backup-before-decision-log\`, copies the five hook files and the
merged settings, validates the JSON (and restores the backup if invalid), and prints what to do next.

## Apply by hand (about 3 minutes)
1. Copy these files into `.claude/hooks/`, overwriting the two existing ones:
   `_decision_log.py`, `bash_guard.py`, `protect_sensitive_files.py`, `mcp_log.py`, `session_log.py`.
2. Settings, easiest way: copy the ready-made merged file over the current one:
   `copy /Y docs\patches\agent-decision-log\settings.merged.json .claude\settings.json`
   It is the current settings plus exactly two hook entries and three deny rules (checked by script; nothing removed).
   Alternatively merge `settings-additions.json` by hand (remove its `_comment` key).
3. Restart Claude Code so the settings load.
4. Check it: ask Claude to run a harmless blocked command (for example one that uses a network download tool); then run
   `uv run sentinel agentlog verify`. It should report entries and `chain OK`.
5. `uv run sentinel doctor` now includes an agent-log check.

## Updates to the patch (re-run `apply-patch.bat` after pulling them)
- 2026-10-27: a decision that cannot be chained (another hook holds the lock for more than 5 s, or a write fails) is no longer
  dropped silently: it leaves a one-line note in `.sentinel/agent-decisions.dropped`, and `sentinel agentlog verify`, `doctor` and
  `sentinel run` report the count. `SENTINEL_LOG_LOCK_WAIT` (seconds) tunes the wait.
- Tests that run the real hooks now use a throwaway state dir. Before this fix every `pytest` run wrote about 50 fake denials into
  the real log. To archive an already-polluted log, run in an interactive terminal:
  `uv run sentinel agentlog reset --reason "polluted by test runs"` and type RESET. The old log is kept as
  `agent-decisions.<time>.archive.jsonl`; the command refuses to run without a terminal, so an agent cannot use it.

## Roll back
Restore the two original hook files from Git (`git checkout -- .claude/hooks`) and remove the added settings entries.

## Facts to know
- Verified against the official hooks documentation (`docs/research/agent-hooks.md`): `session_id`, MCP naming, the
  `mcp__.*` matcher and `SessionStart` all exist as used here.
- The guard is still a keyword matcher, not a sandbox (inline interpreter calls bypass it). Denials can include harmless text
  that merely contains a keyword, so a single denial is context, not an incident (rule R5 design).
- Tail truncation is only detected after the first `sentinel agentlog verify` has stored an anchor. Run it regularly
  (`sentinel run` does it when the log exists).
