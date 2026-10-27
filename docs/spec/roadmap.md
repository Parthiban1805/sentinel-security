# Roadmap, gates and targets

| Phase | Focus | Deliverables | Gate (exit criteria) |
|---|---|---|---|
| B Prevent | Stop recurrence | Hooks + push protection, branch/workflow rules, agent policy in native settings, dependency checks, first continuous tests, first recovery drill | All repos protected; Priority 1 tests pass |
| C Correlate (current) | Connect the evidence | Event + asset schema, rules R1-R9, blast-radius graph, incident workflow, approval gates, verified closure | R1-R9 live; closures verified |
| D Runtime and AI | Control agents live | Agent gateway, sandboxed tool runs, egress monitoring, endpoint/server telemetry, scoped automation, injection test suite | Agents behind gateway; injection tests pass |

## Severity targets [confirm]
| Severity | Example | Acknowledge | Contain |
|---|---|---|---|
| Critical | Leaked key in active abuse; canary triggered | 15 min | 1 hour |
| High | Leaked key, no abuse seen | 1 hour | 24 hours |
| Medium | Repo missing branch protection | 1 business day | 1 week |
| Low | Outdated non-exploitable dependency | Next sprint | Next sprint |

## Metrics
Live secrets (target 0); static long-lived credentials (falling); keys with owner/scope/quota/expiry (100%);
repos with push+branch protection (100%); unowned assets (0); MTTD leaked secret (<15 min);
MTTC critical (<1 h); scenario detection rate (100% for P1); agent actions via policy (100%);
false positive rate (<20%); recovery drills per quarter (>=1 per type).
