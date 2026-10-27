---
name: incident-response
description: Use when an alert, canary trigger, leaked credential, suspicious login, workflow change or agent policy violation needs investigation or a response plan. Produces a structured investigation record, timeline and approval-gated response plan following the project runbook. Trigger for /incident or any "we may be compromised" situation.
---

# Incident response

Follow `docs/runbooks/credential-exposure.md` for credential cases; this skill is the general method.

## Principles
- Separate **facts** (with evidence reference) from **hypotheses** (labelled). Timing alone is not proof.
- Prefer containment that is reversible. Disruptive actions need explicit human approval.
- Never ask the user to paste secrets, tokens or full logs containing them.
- An incident closes only with verification evidence.

## Steps
1. **Open the record** in `reports/incidents/INC-YYYYMMDD-NN.md` (git-ignored) using the template below.
2. **Severity** from the table in `docs/spec/roadmap.md` (Critical/High/Medium/Low) plus separate
   confidence (low/medium/high) and urgency.
3. **Answer the seven questions:** what happened + evidence; when it began; affected credentials,
   identities, repos, machines, services; what they can reach (blast radius); evidence of misuse;
   unknowns; safest next action.
4. **Timeline:** ordered UTC events, each with source and evidence reference.
5. **Response plan:** list actions in classes: automatic, emergency pre-approved, approval-required,
   investigate-first. For each approval-required action write the exact step for a human.
6. **Verification checklist:** credential revoked + replacement scoped and stored safely; sessions
   and identities contained; history reviewed; systems inspected/restored; original route now
   blocked by a tested control.
7. **Post-incident:** add or update a scenario test in `docs/scenarios/` that would have caught it.

## Record template
```markdown
# INC-YYYYMMDD-NN: <short title>
Severity: | Confidence: | Status: open | Owner: | Approver:
## Facts (with evidence refs)
## Hypotheses
## Timeline (UTC)
## Affected assets and blast radius
## Response plan (by class)
## Approvals (who, when, what)
## Verification evidence
## Lessons and new/updated tests
```
