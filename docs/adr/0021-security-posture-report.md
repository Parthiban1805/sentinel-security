# ADR-0021: Security posture report (v0.7c item 4)
Date: 2026-11-05 | Status: proposed (needs human review)

## Context
Sentinel produces incidents, but nothing says how the whole organisation stands. The 2026-11-05 feature review asked for
a posture view that does **not** combine everything into one unexplained score and that shows the evidence behind each
indicator. The product plan also wants a short view for founders and CTOs. The data already exists (inventory,
credentials, GitHub audit snapshots, hygiene checks, incidents, run health, `doctor`).

## Decision
- **`sentinel posture`** prints three separate indicators. There is **no overall score**:
  1. **Security posture:** is the configuration sound? Asset ownership, approval and monitoring; repository hygiene;
     GitHub branch and secret-scanning protection; credential expiry, rotation and ownership; MCP approval and pinned hooks.
  2. **Threat exposure:** what risk exists now? Open incidents by severity, stale incidents, failed verification,
     incidents closed without verification, live leaked credentials, expired risk acceptances, credentials aliased to a
     live leak or found in several places.
  3. **Operational health:** is Sentinel itself working? Time of the last run, per-collector errors and warnings, and
     the `doctor` checks.
- **Each indicator** has a status (`good`, `review`, `attention`, `unknown`), a one-line reason list, and its
  **evidence**: every area that was measured, with a count, a severity and up to 10 references (asset ids, credential
  fingerprints, incident ids; never names, paths of file contents, or values).
- **Status is a fixed rule, not a learned value:** any measured area with a finding of severity high is `attention`;
  otherwise any finding of lower severity is `review`; otherwise `good`; `unknown` when nothing could be measured.
  Items marked `info` (such as the advisory agent-session score) never change a status.
- **Unmeasured is not good.** An area that cannot be measured (no hygiene scan path, no GitHub audit snapshot, no
  credentials known, no run recorded) is listed under `not_measured` with the reason, and `good` is reported only for
  areas that were measured. Each indicator states how many of its areas were measured.
- **Live, not historical.** `config_drift` events stay in the store after the problem is fixed, so posture never counts
  them. It uses the current inventory, `credentials.review`, the latest GitHub audit snapshot per watched repository, a
  hygiene scan run at report time (`--no-hygiene` skips it), the incident store and the last run's health.
- **Founder/CTO summary:** three plain lines (one per indicator) with the top reasons. It is the same data, shortened,
  never a separate calculation.
- `--json` for machines. `--check` exits **2** if any indicator is `attention` and **3** if nothing at all could be
  measured; 1 stays the generic error code, so a script can tell "needs attention" from "crashed". Without `--check`
  the exit code is 0. `--stale-run-hours` (default 6, `[confirm]`) sets how old the last run may be.
- **No new network call, dependency, setting or schema.** The module is pure over its inputs; the CLI gathers the
  hygiene results and `doctor` checks (read-only local checks).

## Amendment after the 2026-11-05 security review ("Approve with fixes"; all fixed, tests in `test_posture*.py`)
The review's main point was that the report must never say `good` for something it did not measure.
- **Hygiene:** a scan that covered no repository is "not measured", and every skipped repository is listed. A failed
  `git ls-files` (unsafe-directory rule, corrupt repository) is now an **error** in `hygiene` itself, not an empty
  list, so `sentinel hygiene` and `sentinel run` no longer read it as clean either.
- **GitHub audit:** counted only when the snapshot is readable, less than 72 hours old, and the repository settings
  could be read (`GP0` is not measured). Each unaudited, stale or unreadable repository is listed.
- **Credentials:** counted only when a current, non-deleted credential or a fresh SSH key list exists.
- **Threat exposure:** incidents need a recorded run or an existing incident; leaked credentials need a run or a stored
  finding. A stale run (or one where every collector failed) caps the status at `unknown` unless a real finding
  exists, and the reason is shown.
- **Malformed stored documents:** each indicator is built in its own guard. A bad document makes that one indicator
  `unknown` and names the exception type only; the other two still render. An unreadable, naive-time or future run
  time is a finding. An unknown collector state counts as a warning.
- **Risk acceptances:** parsed as times; one with no readable expiry counts as expired, never as active.
- **Agent hooks:** the report says only that a pin is recorded, and lists "drift not compared with the pin" as not
  measured (`incident verify-agent-hooks` does the comparison).
- **Read-only:** a missing state directory is an error and nothing is created, so a mistyped `--home` leaves no files.
- **Founder summary** states partial coverage ("good (partial: 2 of 5 areas measured)").
- **Names:** references can include repository folder names and collector names (for example `scan:<folder>`), as
  `sentinel run` health already does. They are never screened for credential shapes, only for characters.
- **Known limits:** findings and canary data carry no test flag, so a simulated finding counts as a live leak; the
  `doctor` checks read the GitHub token file in memory as they always have (nothing is printed).

## Consequences (security, operations, cost)
- **Security:** the report holds ids and counts only. It reads no credential store and no file content (hygiene already
  works from Git metadata and workflow text). A posture report is still a map of weaknesses, so treat its output as
  sensitive and do not post it publicly.
- **Honesty:**
  - `good` means "measured and clean" for that indicator's measured areas, not "secure". The coverage line says how
    much was measured.
  - Derived assets (workflows, scan locations) are not counted as unowned, because Sentinel creates them itself.
  - The status bands are untuned. Severity comes from the check that produced the finding.
- **Operations:** a hygiene scan reads Git metadata of each configured repository, so the command takes a few seconds
  per repository; use `--no-hygiene` for a quick look.
- **Cost:** none.

## Alternatives considered
- **One score:** rejected. It would hide which area is weak and cannot be explained line by line.
- **Counting stored `config_drift` events:** rejected. They include problems that were fixed long ago.
- **A web dashboard now:** the console arrives with v0.8. This command is the data source it will show.
