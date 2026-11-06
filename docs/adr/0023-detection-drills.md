# ADR-0023: Detection drills (v0.7c item 6)
Date: 2026-11-06 | Status: proposed (needs human review)

## Context
`sentinel coverage` proves each rule's logic on simulated events, but nothing measures whether the real pipeline
(Git, gitleaks, findings, correlation, incidents) still works end to end, or how long it takes. Section 7 of the
product plan sets targets such as "time to detect a leaked secret under 15 minutes", and the 2026-11-05 review asked
for continuous attack simulation. A drill must never put a real-looking secret anywhere real (rules 1 and 3) and must
not fill the live store with simulated findings and incidents.

## Decision
- **`sentinel drill run [--scenario leaked-key|agent-sequence] [--json] [--no-record]`** and
  **`sentinel drill status`**.
- **`leaked-key`:** in a throwaway folder, it creates a Git repository and commits a fake Google-shaped key generated
  at runtime. It then runs the real gitleaks scan (history mode) with a throwaway fingerprint key and ingests the
  finding into a throwaway store, marked as test data. It adds a simulated provider-usage event for that credential
  and runs the real correlation and incident code. **Pass** = exactly one new credential found, a `secret_exposure`
  event, an R1 incident, and the fake value absent from everything in the drill store. Needs `git` and `gitleaks`.
- **`agent-sequence`:** the simulated R12 events (sensitive read, then outbound attempt) run through the real
  correlation into a throwaway store. **Pass** = one R12 incident.
- **Timing:** each stage is timed with a monotonic clock. `time_to_detect_s` covers commit to finding stored;
  `time_to_incident_s` covers commit to incident opened. These are **pipeline times only**. They exclude the wait until
  the next scheduled `sentinel run` (up to the run interval) and, for real provider usage, the provider's reporting
  delay (about 30 minutes for Google).
- **What reaches the live store:** only the result (scenario, time, pass or fail, stage timings, rule, fixed check
  names, and the error type). It goes into snapshot `drills:history` (last 20 runs). The fake value, its fingerprint
  and the throwaway workspace never leave the drill; the workspace is deleted afterwards.
- **Scheduling:** `[drills] interval_hours` in `sentinel.toml` (default 0 = off). When set, `sentinel run` runs a
  drill (`[drills] scenario`, default `leaked-key`) once the last one is older than the interval, in its own health
  guard (`drill`), after the collectors. A failed drill is a `warn:` in run health.
- **Posture:** operational health gains a fourth area, "detection drill": not measured if none is recorded, high if
  the last drill failed, medium if it is older than 7 days.
- Exit codes: 0 passed, 2 failed, 1 for an error in the command itself.

## Amendment after the 2026-11-06 security review ("Approve with fixes"; all fixed, tests in `test_drills_review.py`)
- **Git runs isolated** from the user: no global or system config (`GIT_CONFIG_GLOBAL` set to the null device,
  `GIT_CONFIG_NOSYSTEM`), an empty hooks folder, an empty template, `--no-verify`, no signing, no fsmonitor, and
  `HOME` set to the throwaway folder. A user hook (for example a hosted-scanner hook) can therefore never see or send
  the fake key, and a global pre-commit scanner cannot make the drill fail falsely. Tested with a hostile global
  config.
- **No inherited `GIT_*` variables,** in the drill and now in **every** gitleaks scan: `GIT_DIR` or `GIT_WORK_TREE`
  could otherwise point git at a real repository.
- **Cleanup is verified:** a workspace that could not be removed fails the drill ("workspace not removed"). The file
  carries a marker line saying it is a drill fake, and the value is removed from the working file right after the
  commit, so only Git history holds it.
- **Honest timings:** no time to detect is reported when nothing was detected.
- **A fuller leak check:** every store table, keys included, for the whole value, its random part and every
  12-character slice of it.
- **Timeouts:** git calls 15 s, the drill's gitleaks scan 60 s, so a stuck drill delays `sentinel run` by at most a
  few minutes. Every exception is kept as its type only.
- **Snapshots:** a future or unreadable drill time is due (it cannot silence the schedule) and is shown as not
  measured in posture; only a real `True` counts as a pass; `drill status` survives wrong types.
- **Posture** names the drilled scenario; an `agent-sequence` drill does not count for the secret-leak path.
- `drill run` checks the state directory before the drill runs. Recording is not locked (two drills recorded at the
  same instant can lose one entry; accepted).

## Consequences (security, operations, cost)
- **Security:** the fake key is created at runtime and lives only in a temporary folder and store that are deleted.
  The drill checks its own containment: if the fake value ever appears in the drill store, the drill fails with
  "leak". Nothing is sent over the network (the provider usage is simulated).
- **Honesty:** a passing drill shows the pipeline works on this machine now, with a fake key. It does not show that a
  real provider would report real usage, or how fast. The R1 part uses simulated usage.
- **Operations:** a `leaked-key` drill takes a few seconds (one gitleaks run) and writes to the system temp folder.
- **Cost:** none.

## Alternatives considered
- **Drilling in the live store:** would mix simulated findings and incidents with real ones (findings carry no test
  flag). Rejected.
- **Planting a fake key in a real repository:** realistic, but it would sit in real history and real scans. Rejected.
- **A hosted canary service:** measures provider-side detection, which this cannot. It is a later option (v1.x).
