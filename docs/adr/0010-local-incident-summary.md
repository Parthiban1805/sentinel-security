# ADR-0010: Local, summary-only incident assistant (no AI model, no network)
Date: 2026-10-27 | Status: accepted

## Context
Roadmap v0.6 asks for an assistant that explains an incident. Three choices had to be made: whether it calls an
outside AI service (a network call, which needs a documented destination under project rule 5), which fields it may
see, and whether it may propose response actions.

## Decision
1. **Local only.** `sentinel incident summary <ID>` renders a plain template from the stored incident. It makes no
   network call and uses no AI model. Its output is a template, not generated analysis.
2. **Allow-listed input.** Only the fields in `sentinel/incidents/summary.py` `ALLOWED` are read. Close notes,
   evidence text, actor and approver names, and free-text verification evidence are never copied into the summary.
3. **Summary only.** It states facts, hypotheses (labelled as hypotheses), unknowns, the timeline and the step
   states. It does not draft or suggest actions beyond listing which required steps lack a passing verification.
4. **Output guard.** The rendered text is scanned with the same credential heuristic as free-text input. If it looks
   secret, the command refuses to print it.

## Consequences (security, operations, cost)
- No data leaves the machine, so no new outside destination and no cost.
- The summary is less fluent than a language model would produce. That is accepted for the first version.
- Adding an AI service later needs a new ADR, a README for its network destination, and a review of the allow-list.
  The allow-list would be the first control to reuse.
- The output guard is a heuristic. It can miss exotic formats; the allow-list is the main control.

## Alternatives considered
- **Call the Claude API with incident data.** Better prose, but data leaves the machine and needs a documented
  destination and a data-handling review. Deferred until the local version has been used and judged.
- **Draft response steps for approval.** Useful, but it moves from explanation into action suggestion, which adds
  approval-policy questions. Deferred until summaries are trusted.
