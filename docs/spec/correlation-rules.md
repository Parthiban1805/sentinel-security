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
