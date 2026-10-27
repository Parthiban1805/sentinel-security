# Correlation rules

Deterministic, explainable. AI summarizes; it never makes blocking decisions.

| ID | Condition | Result | Scenarios |
|---|---|---|---|
| R1 | Secret found in commit/file, then provider usage from new IP or region | Critical | S0, S2, S3 |
| R2 | Workflow change adds network calls or secret refs, by actor outside usual maintainers | High | S8, S10 |
| R3 | New dependency installed, then same machine/runner accesses credential files or unexpected egress | High | S7 |
| R4 | API spend above X times the 7-day baseline [confirm X] | High; quota cap if pre-approved | S0 |
| R5 | Agent calls tool outside allowlist or touches secrets it does not normally use | High | S11, S12 |
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

### R7: canary used
- **Inputs:** any `canary_triggered`. **Output:** Critical, confidence high (decoys have no legitimate use).

All rules are pure functions, deterministic and order independent. Events with `is_test: true` produce test
incidents that are counted in metrics only.
