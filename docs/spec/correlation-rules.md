# Correlation rules

Deterministic, explainable. AI summarizes; it never makes blocking decisions.

| ID | Condition | Result | Scenarios |
|---|---|---|---|
| R1 | Secret found in commit/file, then provider usage from new IP or region | Critical | S0, S2, S3 |
| R2 | Workflow change adds network calls or secret refs, by actor outside usual maintainers | High | S8, S10 |
| R3 | New dependency installed, then same machine/runner accesses credential files or unexpected egress | High | S7 |
| R4 | API spend above X times the 7-day baseline [confirm X] | High; quota cap if pre-approved | S0 |
| R5 | Agent calls tool outside allowlist or touches secrets it does not normally use (built as R5a/R5b/R5c, see below) | Medium (R5b) / High (R5c) | S11, S12 |
| R6 | GitHub login from new location, then new token or SSH key within 1 hour | Critical | S4, S6 |
| R7 | Any canary credential or decoy resource used | Critical | All |
| R8 | Deployment workflow changed shortly before off-pattern release | High | S10 |
| R9 | Sensitive access with no matching gateway decision | High | S11, S13 |

New rules: use the spec format in `.claude/skills/correlation-rule-authoring/SKILL.md`.

## Implemented in v0.1 (`sentinel/correlation/rules.py`, tests in `tests/sentinel/test_rules.py`)

### R1: exposed credential, then used
- **Inputs:** `secret_exposure` and `credential_usage_anomaly` events carrying `credential_ref`.
- **Join key:** `credential_ref` (keyed-hash fingerprint, ADR-0004). Provider events must be mapped to the
  same ref by the collector (a human can match a console key with `sentinel fingerprint`).
- **Window:** none upper bound. Any usage at or after the first exposure counts, because a leaked key stays
  usable until revoked. Usage before the exposure time does not match (near miss). Suppressed once the finding is
  `revoked_verified`.
- **Output:** one incident per credential; severity floor critical; confidence high only if all events are high.
- **Facts vs hypothesis:** matching ref and ordering are facts. That the user of the key obtained it from the
  exposure is a hypothesis; timing alone never proves a shared attacker.
- **False positives:** the legitimate owner using their own key from a new location. **Known gaps:** no real
  provider collector yet; usage events are simulated.

### R4: spend spike
- **Inputs:** `spend_anomaly` with `attributes.multiple_of_baseline`. **Threshold:** X = 3.0 `[confirm]`, configurable.
- **Output:** High incident (score bands may raise it). **Gaps:** baseline computation belongs to the collector.

### R6: anomalous login, then new token/SSH key
- **Inputs:** `login_anomaly` then `token_created` or `ssh_key_added` with the same `identity_ref`.
- **Window:** 1 hour, 0 <= delta <= 1h. **Output:** Critical; confidence medium. Hypothesis: stolen session.

### R7: canary triggered
- **Inputs:** `canary_triggered` events. Real events come from `sentinel canary` (ADR-0009) with `attributes.reason`; an event with
  no reason (the simulated chain, or a future hosted-canary source reporting actual use) is treated as use of the decoy.
- **Condition and output, by reason:**
  | reason | meaning | incident | severity floor | confidence |
  |---|---|---|---|---|
  | `copied` | the decoy's value was found at another location by the secret scan | yes | critical | high |
  | `modified`, `removed` | the decoy file changed or vanished | yes | high | medium |
  | `read` | the file's access time moved | **no** (event only) | n/a | low |
  | none (use) | the decoy was used | yes | critical | high |
- **Why `read` never opens an incident:** antivirus and desktop indexers read files, and Windows can delay or disable access-time
  updates. It is recorded for investigation but is not an alert. Not seeing a read proves nothing.
- **Hypothesis labelling:** a copy proves the decoy value moved, not who moved it or why. **Not detectable:** use of the decoy at a provider
  (needs a live provider key or a hosted canary service).

## Implemented in v0.2 (real GitHub signals; tests in `tests/sentinel/test_collectors.py`)

### R2: risky workflow change by a non-maintainer
- **Inputs:** `workflow_changed` with attributes `adds_network`, `adds_secret_ref` (computed from ADDED diff
  lines only; the diff is never stored) and `actor_is_maintainer` (actor committed to the repo in the 90 days
  before the change). **Output:** High, confidence medium.
- **False positives:** new legitimate contributors. **Gaps:** obfuscated network calls; actions referenced
  by `uses:` are not inspected (S8 needs action-ref pinning checks).

### R8: workflow change shortly before a release
- **Inputs:** `workflow_changed` then `release_published` on the same repo asset. **Window:** 0 to 24h `[confirm]`.
- **Output:** High floor, confidence low (most such releases are normal); a provenance review is the required step.

## Implemented in v0.5 (verification watch; tests in `tests/sentinel/test_r11.py`)

### R11: a credential is used AFTER it was verified revoked
- **Why:** "verified" is a claim. If the provider still reports use after the revocation was verified, the revocation did not take effect
  (a different key was revoked, a second copy exists, or propagation is delayed). Without this rule Sentinel went quiet about a key once
  it was marked `revoked_verified` (R1 deliberately stops firing).
- **Inputs:** `credential_usage_anomaly` events with a `credential_ref` whose finding has `status = revoked_verified` and a recorded
  `verified_at`. **Join key:** `credential_ref`. **Window:** none upper bound; only events strictly AFTER `verified_at` count, so older usage
  (the original abuse) never matches.
- **Output:** one Critical incident per credential. Confidence high when the collector flagged `use_of_dead_key` (it already knew the key
  should be dead), otherwise medium. Facts: the verification time and the later usage. **Hypothesis (not proven):** the revocation was not
  effective. Plan: re-check the provider state (investigate), revoke again (approval), review usage (investigate), find other copies (investigate).
- **False positives:** clock skew between the provider and this machine; late-arriving provider data for hours before the revocation (Google data
  is up to ~30 minutes late, so events are compared by their own time, not arrival time). **Known gaps:** needs `verified_at`, which findings
  verified before v0.5 do not have (they are never matched, to avoid guessing).

## Implemented in v0.4 (exposure probes; tests in `tests/sentinel/test_probes.py`)

### R10: a sensitive path is served by our own host (S1, S15)
- **Inputs:** `exposed_service` events from `sentinel probe` (`attributes.path`, `probe`, `signature`, `status`, `base_url`).
- **Join key:** one incident per host asset and path. No time window: an exposure persists until fixed.
- **Condition:** a probe saw HTTP 200/206 for a fixed sensitive path AND the first bytes matched that file's SHAPE (env file, git
  config, SQL dump, archive, key...). A catch-all page that returns 200 for everything does not match, because shapes are tested.
- **Output:** severity floor taken from the probe (critical = secrets likely inside; high = source or data; medium = information
  leak), confidence high that the file is served, **unknown whether anything was fetched or used** (hypothesis: the contents may
  already be in an attacker's hands; credential use is rule R1's evidence).
- **Automatic verification:** the step `verify_path_closed` re-probes the exact path; it passes only on a definitive answer without
  the file (404/403/410 or a 200 that no longer matches). A network error proves nothing and fails the step.
- **False positives:** a deliberately public sample file that happens to look like an env file. **Known gaps:** fixed path list;
  only the first 512 bytes are inspected; hosts behind authentication or a WAF that hides the path from the probe are not seen.

## Implemented in v0.3b (agent visibility; tests in `tests/sentinel/test_r5.py`, ADR-0012)

Source: `sentinel/sources/agent.py` turns the tamper-evident hook log (ADR-0007) into events. It refuses to emit anything
from a log whose chain or anchor fails (the `agentlog` health check raises the alert instead). The log holds no command text,
paths, prompts or arguments (policy `policies/agent-monitoring-policy.md`, approved 2026-10-31): only time, a hashed session
id, the tool name, a stable rule id, a class and a keyed target fingerprint.

| Hook decision | Event | Severity |
|---|---|---|
| `deny` (a guard hook blocked a call) | `agent_tool_denied` | low |
| `allow_mcp` (an MCP tool was called) | `agent_tool_allowed`, with `attributes.mcp_server` parsed from `mcp__<server>__<tool>` | info |
| `session_start` (heartbeat) | none (proves logging was on; counted, not an event) | |

### R5a: a single blocked action (context only, NO incident)
- **Why no incident:** the guard hooks match keywords, so harmless commands are blocked too (this project's own sessions were
  blocked for the word "ssh" inside a search pattern and for a cloud CLI command the owner had asked for). One block says little.
- **Effect:** the event is stored and counts toward R5b; it appears in the incident record if R5b fires.

### R5b: repeated blocked actions in one agent session (S11)
- **Inputs:** `agent_tool_denied` (`attributes.session`, `rule`, `target_class`, `tool`). **Join key:** `attributes.session` (a hash of
  the session id; the raw id is never stored).
- **Window:** `r5b_window` = 30 minutes `[confirm]`; **count:** `r5b_count` = 3 `[confirm]`. Justification: a steered agent tends to
  retry a blocked goal several times in quick succession; isolated keyword hits are spread out. Both values are configurable and must
  be tuned on real log data (product plan, v0.3b).
- **Condition:** at least `r5b_count` denials in the same session whose times fit inside one `r5b_window`.
  Pseudocode: `for session: sort denials by time; if any i with t[i + count - 1] - t[i] <= window: match`.
- **Output:** ONE incident per session (dedup key `R5b:<session>`), however many denials follow, so a steered agent raises one incident,
  not a flood. Severity floor medium, confidence low. **Facts:** the number of denials, the time span, the rule ids and classes hit.
  **Hypothesis (not proven):** the agent may have been steered by untrusted input (prompt injection) or may be pursuing an unsafe goal;
  repeated keyword false positives are an equally plausible explanation until the session's inputs are reviewed.
- **Response plan:** review the session's untrusted inputs (investigate), end the session and revoke any credential it held (approval),
  confirm the hooks and the log are intact (investigate; verification evidence: installed hooks unchanged, chain intact, credential
  actually revoked or session ended, never "no more denials").
- **False positives:** a human repeatedly asking the agent for something the guard blocks (as happened in this project). **Known gaps:**
  only actions that a hook blocks are visible; allowed ordinary calls are deliberately not logged; a gateway (v0.7) is needed for full
  visibility (rule R9).

### R5c: an MCP tool call to a server that is not approved (S12)
- **Inputs:** `agent_tool_allowed` with `attributes.mcp_server`; `Context.approved_mcp_servers` from `mcp_server` assets with
  `approved = true`. **Join key:** the server name. **Window:** none (a single call is enough).
- **Allowlist mode:** R5c is active only once at least one `mcp_server` asset has been approved (`inventory set <id> --approve`). Before
  that, every call would match, which is noise rather than detection.
- **Matching (after the 2026-10-31 review):** a call counts as approved only if its tool name starts with `mcp__<exact approved
  name>__`; names are never lower-cased or slugged, so a look-alike name never inherits an approval. Changing an approved server's
  transport, host or command clears its approval.
- **Episodes (R5b and R5c):** the key is `<base>@<first event time>`; once an incident for a base is closed, only later events count,
  so a closed incident never silences later activity. Test events are grouped apart from real ones (`<base>:test`).
- **Output:** ONE incident per server episode (dedup key `R5c:<server>@<time>`). Severity floor high, confidence medium. **Fact:** the agent called a tool
  of a server that nobody approved. **Hypothesis:** the server may be untrusted or impersonating a trusted one; it may also simply be a
  server the owner forgot to approve.
- **Response plan:** review the server (owner, source, version) and approve it or remove it (approval), review what the agent sent to it
  (investigate), rotate anything it could read (approval).
- **Known gaps:** servers configured at user scope are invisible to the inventory (that configuration holds credentials and is off
  limits), so they always count as "not approved" until the owner registers them by hand; claude.ai connectors appear as servers too.

### Data-source limits (facts, `docs/research/collectors.md`)
- R1 with Google data: usage = per-key request volume above max(3x 7-day hourly mean, floor), or any use of a
  key whose finding is revoked/verified. Google gives no caller IP/region; data is up to ~30 min late.
- R6 cannot see logins for personal GitHub accounts (no security-log API found); only `ssh_key_added` is collected.

All rules are pure functions, deterministic and order independent. Events with `is_test: true` produce test
incidents that are counted in metrics only.

## Specified in v0.7c (agent session risk; tests in `tests/sentinel/test_r12.py`, ADR-0020)

### Session risk score (a function, not a rule)
- **Inputs:** the `agent_tool_denied` / `agent_tool_allowed` events of ONE session (`attributes.session`), with
  `decision`, `rule`, `target_class` and `mcp_server`.
- **Output:** `{level, points, reasons}`. Fixed weights, no learned values, deterministic. Levels: `low` (0-2),
  `elevated` (3-5), `high` (6 and above). Every point has a reason line, so the score can always be explained.
- **Weights:** a denial of a sensitive-read class (credential, env, history, key or cloud-credential files)
  = 2; a denial of an outbound class (network tool, remote access, pipe to shell, cloud CLI) = 2; any other
  denial = 1; a call to an unapproved MCP server (allowlist mode only) = 2; an `ask` decision = 1; the R12
  sequence below = 3. A class not listed counts as "other".
- **Use:** shown in the incident record and `sentinel agent sessions`. It never blocks anything and never
  authorizes anything (principle 1). Severity, confidence and urgency stay separate fields.

### R12: a sensitive read attempt, then an outbound attempt, in one agent session (S11)
- **Inputs:** `agent_tool_denied` and `agent_tool_allowed` from `agent_hook`. **Join key:** `attributes.session`.
- **Window:** `r12_window` = 15 minutes `[confirm]` from the sensitive attempt to the outbound one.
- **Sensitive-read classes:** `credential_read`, `env_dump`, `shell_history`, `env_file`, `key_file`, `ssh_key`,
  `ssh_dir`, `cloud_credentials`, `credential_store`, `secrets_dir`, `credential_json`, `state_dir`,
  `state_dir_access`.
- **Outbound classes:** `network_tool`, `remote_access`, `pipe_to_shell`, `cloud_cli`, or an `agent_tool_allowed`
  MCP call to a server that is not approved (allowlist mode).
- **Condition:** a sensitive attempt (denied, or asked) followed by an outbound attempt in the same session within
  the window. Pseudocode: `for each sensitive s: if any outbound o with 0 < t(o) - t(s) <= window: match`.
- **Output:** ONE incident per session episode (dedup key `R12:<session>@<time>`). Severity floor high,
  confidence low. **Facts:** which classes were attempted and the order. **Hypotheses (not proven):** the agent may
  have been steered to collect and send out sensitive data; it may equally be a person running legitimate commands
  that the keyword guard blocks. Both attempts were refused or confirmed by the gateway, so no data leaving is
  shown by this rule.
- **Not a match:** outbound before sensitive; outside the window; different sessions; an allowed outbound call that
  is not an MCP call (the gateway does not log plain allowed calls); test events are grouped apart.
- **Response plan:** review the session's untrusted inputs; end the session and rotate anything it could read
  (approval); verify the hooks are unchanged and the log chain is intact.
- **Known gaps:** only gateway decisions are visible; there is no baseline of normal behaviour (the real log holds
  too few entries, see the product plan), so unusual-but-legitimate work cannot be told apart yet. Evasion routes
  (slow-walking, splitting across sessions, unlisted classes, unlogged allowed calls, same-second pairs) are listed
  in ADR-0020. The score has no time limit on its points.

## Implemented in v0.7e item F1 (output guard and trifecta gate; tests in `tests/sentinel/test_r13.py`, ADR-0027)

### R13: a data-leaving call after untrusted content and a seen credential, in one agent session (S11)
- **Inputs:** `agent_tool_allowed` from `agent_hook`: the gateway's `ask` with rule `TF-01` (class `trifecta`),
  and the output guard's records `OG-01` (`output_redacted`), `OG-02` (`output_tainted`), `OG-10` and `OG-11`
  (`taint`). **Join key:** `attributes.session`.
- **Window:** none. The session's legs never expire within the session, so the gate itself carries the condition:
  the gateway asks only when the session has read untrusted content (U) AND seen a credential (S).
- **Condition:** at least one `TF-01` in the session episode. `TF-99` (the state could not be read) is not a match.
- **Output:** ONE incident per session episode (dedup key `R13:<session>@<time of the first TF-01>`). Severity
  floor high, confidence medium (the legs and the attempt are recorded facts). **Facts:** the data-leaving tools,
  how many calls were questioned, which guard rules marked the session; whether the person allowed the call is not
  recorded. **Hypotheses (not proven):** untrusted content steered the agent to send the credential out (indirect
  prompt injection); equally plausible, legitimate research after output that happened to hold a key.
- **Not a match:** guard events without a `TF-01`; a `TF-01` in another session; test events are grouped apart; a
  closed incident never silences a later episode.
- **Score:** `trifecta` is an outbound class (so R12 can pair it with an earlier sensitive attempt), and a session
  with a `TF-01` gets +3 once (`POINTS_TRIFECTA`).
- **Response plan:** review what the session read and what the call would have sent; rotate the seen credential
  by fingerprint (approval); end the session (approval, optional); verify the hooks and the log chain.
- **Known gaps:** see ADR-0027. The legs are coarse (per session, not per value as in CaMeL); a trusted MCP server
  must be marked by a person; PII alone does not set leg S; a credential that the guard did not recognise sets
  nothing.

## Implemented in v0.7a (agent gateway; tests in `tests/sentinel/test_gateway.py`, ADR-0016)

### R9: a decoy touched during an agent session, with no gateway decision for it (S11, S13)
- **Inputs:**
  - `canary_triggered` events that carry `attributes.location_fp`. That is the decoy path's fingerprint, computed with
    the same key and normalisation as the gateway; `canaries.check` adds it when the key exists.
  - Agent-gateway events (`agent_tool_allowed` and `agent_tool_denied` from `agent_hook`) with `attributes.target_fp`.
- **Window:** gateway decisions in the `r9_lookback` (30 minutes [confirm]) BEFORE the decoy event. The look-back covers
  the 15-minute canary check interval, because the event time is the check time, not the access time.
- **Match:** at least one gateway decision in the window (an agent session was active), and none of them has the decoy's
  fingerprint. The gateway did not see a call on that file, so something outside it touched the decoy.
- **Not a match:**
  - no agent activity in the window (R7 alone covers decoys),
  - a decision that covers the decoy (the gateway saw it),
  - agent activity only after the decoy event,
  - a decoy event without a fingerprint.
- **Rating:**
  - Severity high, confidence medium.
  - Hypotheses: a program started in the session touched it outside the gateway, or a backup job or scanner did. Timing
    alone does not decide which.
- **Response:** review the agent session and identify the process (both required); the kill switch is optional and
  needs approval.
