# ADR-0020: Agent session risk score and rule R12 (v0.7c item 3)
Date: 2026-11-05 | Status: proposed (needs human review)

## Context
Sentinel records every agent-gateway decision (ADR-0016) and has R5b (three or more blocked actions in one session)
and R5c (an MCP server nobody approved). Neither looks at *what* was attempted, in what order. The 2026-11-05 feature
review asked for agent behaviour intelligence: a session risk score and sequence detection. It also asked for baselines
of "normal" behaviour, but the real log holds six entries (all denials, four sessions, no allowed calls), so there is
nothing to learn from yet. This ADR covers only what can be done honestly with the data that exists.

## Decision
- **A session risk score,** `sentinel/correlation/session_risk.py`. A pure function over the gateway events of one
  session. Fixed weights, no learned values, no I/O, deterministic:

  | Event | Points |
  |---|---|
  | denied sensitive-access attempt (credential, env, history, key or cloud-credential files, state dir) | 2 |
  | denied outbound attempt (network tool, remote access, pipe to shell, cloud CLI) | 2 |
  | any other denial | 1 |
  | an `ask` decision | 1 |
  | a call to an unapproved MCP server (allowlist mode only) | 2 |
  | the R12 sequence below | 3 |

  Levels: low 0-2, elevated 3-5, high 6 and above. Each point has a reason line that holds rule ids and classes
  only. A class that is not listed counts as "other", so a new hook rule is never silently ignored.
- **The score is advisory.** It never blocks, approves or closes anything (principle 1: rules decide, AI explains,
  and a score decides nothing). It is shown in the incident record of R5b and R12 and by `sentinel agent sessions`
  (`--json`, `--include-test`).
- **Rule R12** (spec in `docs/spec/correlation-rules.md`): a sensitive access attempt, followed within 15 minutes
  by an outbound attempt in the same session. One incident per session episode; severity floor high, confidence
  low. Same-instant events never pair, because their order is unknown.
- **What counts as an attempt:** a call the gateway denied or asked about, or a call to an unapproved MCP server.
  Plain allowed calls are not logged as attempts, so they never count.
- **Shared definitions:** the class sets, the sequence finder and the MCP-name parser live in one module used by the
  rule and the score, so they cannot drift apart. The MCP name parser moved there from `rules.py`, unchanged.
- **Small fix found on the way:** R5b keyed sessionless events as `unknown@<asset>`. The `@` broke closed-episode
  matching (the key is split on its first `@`). Both R5b and R12 now use `unknown-<asset>`. The incident id comes
  from the key, so an existing sessionless R5b incident would be reported again under a new id. **Checked on
  2026-11-05: the real store has no R5b or R12 incidents and no sessionless agent events**, so nothing is orphaned.
  A test covers the new key and its closed-episode lookup.
- **No new network call, dependency, setting or schema change.** `r12_window` is a `Config` default
  (`[confirm]`), like the other windows.

## Amendment after the 2026-11-05 security review ("Approve with fixes"; all fixed, tests in `test_r12.py`)
- **Linear cost:** the sequence search was quadratic (an agent looping on denials could stall `sentinel run`). Each
  event is now parsed and classified once and the partner is found by bisection, O(n log n). A test runs 50,000
  events in one session.
- **Malformed events never raise:** a missing or non-mapping `attributes`, or an unreadable `time`, is skipped.
- **Bounded output:** reasons are aggregated per kind of attempt with a count and capped at 20 lines. Rule ids and
  classes copied from event attributes are limited to a safe character set and 40 characters.
- **`agent sessions`** keeps test and real events apart, says "no refused or questioned attempts logged" for a
  session with no points, and states that points have no time limit and that allowed calls are mostly not logged.

## Consequences (security, operations, cost)
- **Security:**
  - Events hold a hashed session id, a tool name, a rule id, a class and a keyed fingerprint, never a command or a
    path (monitoring policy, approved 2026-10-31). The score and R12 add no new data.
  - R12 shows attempts that the gateway refused or questioned. It does **not** show that any data left the machine,
    and the incident says so.
- **Accuracy:**
  - The classes come from keyword rules in the hooks, which also block harmless commands. Both rules state that
    explanation as a hypothesis.
  - Without a baseline, an unusual-but-legitimate session scores like a hostile one. That is why the score is
    advisory only.
  - Calls the gateway allows without asking are mostly not logged, so a sequence that stays inside allowed calls is
    invisible.
- **Observed on the real log (2026-11-05):** one session scores "high" (6 points) from three blocked commands
  spread over three days (a search containing "ssh", a cloud CLI call the owner had asked for, and a state-folder
  touch). R12 correctly did not fire, because the attempts were days apart. This shows the limit of a score that
  adds up a whole session: **points have no time limit, so a long session drifts upward on keyword noise.** The score
  is therefore advisory, and the output lists the span and every reason. A time-bounded or decaying score is the
  obvious next change, but it needs real data to set the bound, so it is not guessed here.
- **Ways to evade R12 (inferred, not tested against a real adversary):**
  - slow-walking beyond the 15-minute window;
  - splitting the steps across sessions (a new session id per step, or sub-agents with their own ids);
  - using a class that is in neither set, which counts as "other";
  - staying inside calls the gateway allows and does not log;
  - a pair within the same second, because the order is then unknown;
  - an unapproved MCP server before any server has been approved (allowlist mode is off).
- **Operations:** the window and the weights are untuned. Tune them on real logs once there are a few weeks of data.
- **Cost:** none.

## Alternatives considered
- **Behaviour baselines per agent:** the right long-term answer, but the real log has too few entries to learn
  anything. Revisit after weeks of data; it needs its own ADR.
- **A learned or weighted-by-model score:** rejected. It cannot be explained line by line.
- **Raising R5b's severity for sensitive classes instead of a new rule:** mixes "many attempts" with "an ordered
  sequence". They are different signals with different false-positive causes.
