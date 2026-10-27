# Runbook: credential exposure (S0, S2, S3)

1. **Detect:** finding from gitleaks, GitHub secret scanning, provider notice or canary.
2. **Triage (agent may help):** provider, owner, first exposure date, public or private, fingerprint.
   Severity High; Critical if usage anomalies or canary.
3. **Contain (human):** revoke/delete the key in the provider console. Emergency pre-approved if the key
   is confirmed in public history. Cap quotas/budget if available.
4. **Assess misuse (human + agent):** provider usage and billing for the exposure window; GitHub security
   log, sessions, tokens, SSH/deploy keys, OAuth apps for related compromise.
5. **Replace:** new key with minimal scope, quota, expiry, stored in a secret store, never in repo.
6. **Clean (approval-required):** history rewrite with git filter-repo on a backup clone, force push,
   ask collaborators to re-clone. Forks/caches may persist; revocation is the real fix.
7. **Verify:** old key fails auth (tested by human) or provider shows deleted; history scan clean;
   replacement scoped. Otherwise mark `verified: false`.
8. **Improve:** add/update a scenario test that would have caught this; record lessons.
