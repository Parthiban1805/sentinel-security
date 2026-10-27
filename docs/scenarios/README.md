# Threat scenario catalogue

Priority 1 = MVP. Each scenario becomes a continuous test (`TEMPLATE.md`).

| ID | Scenario | Signal chain | Priority |
|---|---|---|---|
| S0 | Secret in Git history abused (origin incident) | Secret in commit -> provider usage from unknown source | 1 |
| S1 | `.env`/`.git` served publicly by Nginx | Sensitive path reachable -> key used externally | 1 |
| S2 | Secrets outside Git (shell history, CI logs, image layers, artifacts, agent transcripts/config) | Secret in non-repo location -> usage anomaly | 1 |
| S3 | Key pasted in public gist/issue/forum | External leak alert -> usage anomaly | 2 |
| S4 | Stolen session cookie bypasses 2FA | New-location login without 2FA -> new token/SSH key | 1 |
| S5 | Malicious VS Code extension | New extension -> credential access -> outbound | 2 |
| S6 | Stolen GitHub PAT | Token from new IP -> bulk clone/settings change | 1 |
| S7 | Malicious/typosquatted package | New dependency -> install script -> credential access/egress | 1 |
| S8 | Compromised third-party Action | Action ref changed -> secrets accessed -> egress | 2 |
| S9 | Fork PR workflow exposes secrets | Untrusted trigger with secret access | 2 |
| S10 | Workflow modified to ship poisoned release | Workflow change by unusual actor -> off-pattern release | 2 |
| S11 | Prompt injection makes agent leak data | Untrusted content read -> action outside policy | 1 |
| S12 | Malicious/overprivileged MCP server | New MCP server -> broad file/network request | 2 |
| S13 | Agent pushes/merges without review | Agent identity pushes to protected branch/self-approves | 2 |
| S14 | Stale SSH key / former member access | Login with unapproved key | 2 |
| S15 | Exposed/unencrypted DB backup | Backup reachable or unusual download | 3 |

## Fake credential policy
Generated at runtime by the test harness; never committed. If a fixture file is unavoidable, mark the
line `sentinel:allow-fake-secret` and add a narrow `.gitleaks.toml` allowlist entry with the reason.
