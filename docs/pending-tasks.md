# Pending tasks (owner actions)

Things only the owner can do or decide. Everything else is built, tested and pushed. Last updated 2026-10-27.
Mark an item done by deleting it or moving it to "Done".

## 1. Collect a few days of real agent-log data (unlocks v0.3b)
**Why:** v0.3b raises alerts when an AI agent is steered into unsafe actions. The guard hooks are keyword-based and produce harmless
denials (this project saw them for words like "curl" and "SSH" inside ordinary text), so alert thresholds must come from real use.
**Do:**
1. Work in Claude Code as usual for 3 to 7 days.
2. Start at least one NEW conversation (writes the first "session started" entry; the log was archived on 2026-10-27).
3. Then run and send me the output of:
   ```
   uv run sentinel agentlog verify
   uv run sentinel doctor
   ```
4. If `doctor` still says "no decision log yet" after a new session: re-run `docs\patches\agent-decision-log\apply-patch.bat`, start another session.

## 2. GitHub token: Administration read
**Status: done.** Token replaced on 2026-10-31 after the old one was rejected (HTTP 401): fine-grained, one repository, read-only
Administration, Contents, Metadata and Git SSH keys, expires 2027-01-29 (set a reminder). `doctor` clean, `audit` reaches GitHub.
Result: `sentinel audit` still reports `SS0` (secret-scanning settings not visible) and `BP1` (no branch protection). Both are most likely the
free plan for private repositories (hypothesis; GitHub does not say so). Nothing further is needed unless you upgrade the plan or move the repo.

## 3. Decide on Google Cloud (R1 on real usage data)
**Choose one:** install `gcloud` and enable it, or say "drop Google" and I will mark it out of scope.
**Gain:** rule R1 ("leaked key, then used") on real data, the `verify-key` check, and the spend-spike rule R4. This is the origin-incident chain.
**Cost:** about 15 minutes; a Google account that can read monitoring data and list API keys; the collector has never run on real Google data
(expect surprises; I will re-run the security review first). Limits either way: usage data is up to about 30 minutes late and has no caller IP.
**Steps if yes:**
1. Install the Google Cloud CLI from Google's official download page; open a new Command Prompt.
2. `gcloud auth application-default login` (Sentinel accepts only this credential type).
3. Find the project ID that owns your Gemini keys (Google Cloud console).
4. `uv run sentinel init --force --gcp-project <project-id>` (keeps a `.bak` of the config).
5. `uv run sentinel run` and send me the status lines.

## 4. Monitoring policy sign-off
File: `policies/agent-monitoring-policy.md` (one page, status "proposed").
Defaults: log only blocked actions, MCP calls and session starts (no commands, paths or prompts); stays on this machine; 90-day retention;
notice to employees before any rollout to other people.
**Status: done.** Approved as written by Parthiban on 2026-10-31 (recorded in the policy file).

## 5. Review decisions and the old alert
**ADRs** (`docs/adr/`), all "proposed". Accept by changing the `Status:` line to `accepted`, or tell me and I will:
| ADR | Decision | Trade-off to challenge |
|---|---|---|
| 0003 | CLI plus library, SQLite state | Single machine until the service release |
| 0004 | Keyed-hash credential fingerprints; gitleaks runs unredacted in-process | Real values briefly in memory |
| 0005 | Read-only collectors on four fixed hosts, plus the GitHub audit endpoints | New outbound traffic |
| 0006 | Valid schema `$id`, version in the path | None, it fixes a bug |
| 0007 | Tamper-evident agent log (hash chain plus anchor) | An agent with full shell access could alter file and database; the gateway release adds real isolation |
| 0008 | Probes contact only hosts you list and confirm you own | Relies on the confirmation being honest |
| 0009 | Self-built decoys: copy, tamper, read tripwires | Cannot detect use at a provider |

**Old false-positive incident `INC-63C56A65`** (rule flaw, fixed). Review the flagged commit, then close it:
```
git show 5910c92 --stat
git show 5910c92 -- .github/workflows
uv run sentinel incident verify INC-63C56A65 review_workflow_diff --actor <your-name> --evidence "reviewed 5910c92: my own first commit, pinned gitleaks download; false positive"
uv run sentinel incident close INC-63C56A65 --actor <your-name>
```
It should only add the secret-scan workflow with the pinned gitleaks download. If anything looks unfamiliar, do not close it; tell me.

## 6. Choose the places outside Git to scan (S2, v0.5)
**Status: skipped for now** (owner choice, 2026-10-31). Nothing outside Git is scanned. Pick this up any time.
**Why:** keys also end up in CI logs, build output, agent transcripts and history files. Sentinel scans none of these unless you list them
(ADR-0011), because they can hold personal data.
**Do:** decide, per path, whether Sentinel may read it. Then add absolute paths to `sentinel.toml`:
```
[scan]
extra_paths = ["P:/ci-logs", "P:/builds/output"]
```
Then run `uv run sentinel run` and send me the status lines (`scan-extra:<name>`). Avoid listing key stores (SSH keys, cloud CLI config):
Sentinel would fingerprint real keys there. Drive roots and your whole home folder are refused.

## 7. Agent visibility (v0.3b): two owner actions
1. **Protect two more paths** (they are protected files, so you apply this): add `.claude/settings.local.json` and
   `docs/patches/**` to the `deny` list in `.claude/settings.json` and to the protect-sensitive-files hook. Reason: an agent that can
   write a local settings file could switch the hooks off (ADR-0012, review amendment).
2. **Pin the reviewed hooks** in an interactive terminal, after the step above:
   ```
   uv run sentinel agentlog pin-hooks --actor Parthiban
   ```
   Type PIN to confirm. Repeat whenever you change the hooks or the `hooks` block of `.claude/settings.json` on purpose.
Then approve the MCP servers you trust: `uv run sentinel inventory agents`, and for each one
`uv run sentinel inventory set mcp-<name> --actor Parthiban --approve` (interactive terminal).

## 8. AI assistant (v0.6): DONE 2026-11-03
Run 4: mean 4.55, 0 made-up claims, 0 injection followed. Gate met, and the owner's spot-check of case 09 was ok.

**Still useful later (not blocking):**
- For real incidents, use `provider = "anthropic"` with an Anthropic key, plus a scored eval run for Claude. NVIDIA's trial is
  for simulated incidents only, and that is enforced in code.
- Optionally delete the old eval folders (`.sentinel-eval`, `.sentinel-eval2`, `.sentinel-eval3`). They are git-ignored.

### History of item 8 (kept for reference)
**Status 2026-11-03:** built and committed. **Gate pending one re-run.** On the owner's spot-check, run 3 case 09 counts as made
up (gate NOT MET, by one sentence). The cause was Sentinel's own R7 wording ("Decoys have no legitimate use"), which is now
reworded: the decoy has no planned use, but automated processes can still touch one. **Next:**
```
uv run sentinel ai eval-build --dir .sentinel-eval4
uv run sentinel ai eval-run --dir .sentinel-eval4
```
Type `y` once. Then tell me: the independent reviewer scores it, and you spot-check case 09 and any others it flags.
- Runs (`.sentinel-eval*/scoring.csv`, simulated incidents, NVIDIA provider):
  - Run 1: mean 4.05, 1 made-up claim.
  - Run 2: mean 4.15, 2 made-up claims.
  - Run 3: mean 4.55, 0 injection followed. This run is after the structural change: the model no longer writes facts.
    The reviewer found 0 made-up claims; the owner's spot-check counted 1 (case 09).
- Done: packages pinned; NVIDIA key re-created and stored; ADR-0014 and ADR-0015 accepted; NVIDIA trial terms read; `.emv` removed.
- **Your spot-check (the plan's gate says "scored by a human").** Read `.sentinel-eval3/ai-summaries/` for cases 01, 03, 09, 12
  and 19. Case 09 is the one to judge. Its assessment says the decoy use "by definition indicates unauthorized interaction".
  Reviewers 1 and 2 counted that kind of sentence as made up; reviewer 3 did not, because the record says "Decoys have no
  legitimate use". If you count it as made up, the gate is not met.
- **NVIDIA is for simulated incidents only** (trial terms: testing only, content may be used to improve NVIDIA models, no
  confidential data). This is enforced in code. Real incidents need `provider = "anthropic"` with an Anthropic key (console,
  Sentinel-only workspace, USD 20 monthly limit, then `uv run sentinel ai set-key --provider anthropic`), or a paid NVIDIA
  subscription and a new ADR.
- After the eval: set `daily_calls` back to 30 in `sentinel.toml`.
- Then say "commit".

## Housekeeping (anytime)
- Delete `probe-test/` and `.claude/backup-before-decision-log/` if they still exist.
- A scheduled run every 15 minutes: `powershell -File scripts\schedule-sentinel.ps1` (creates a scheduled task; read the script first).
- A stale `SENTINEL_GITHUB_TOKEN` in the Windows environment can shadow the saved token file (`doctor` warns); remove it with
  `reg delete HKCU\Environment /v SENTINEL_GITHUB_TOKEN /f` if it is not the token you want.

## Suggested order
1. Close `INC-63C56A65` (5 minutes). 2. Reply with your policy sign-off and the Google decision. 3. Read the ADRs. 4. Use Claude for a few days, then send the log summary.
