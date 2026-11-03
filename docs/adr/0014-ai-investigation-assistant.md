# ADR-0014: AI investigation assistant (Claude API, disguised evidence, explain only)
Date: 2026-10-31 | Status: accepted (owner, 2026-11-02, by instruction to the agent; amendments below included)

## Context
Roadmap v0.6 asks for an assistant that summarizes impact, lists unknowns, proposes investigation steps and
drafts the report. ADR-0010 shipped a local template and deferred any AI service until a destination, data
rules and cost limits were decided. Project rule 5 requires a documented destination for any network call.
The owner chose the options below on 2026-10-31.

## Decision
1. **Destination: Anthropic's Claude API, `https://api.anthropic.com`, only.** (ADR-0015 adds a second,
   separately configured provider; the default stays this one.) The URL is fixed in code
   (`sentinel/assistant/client.py`), so an `ANTHROPIC_BASE_URL` environment variable cannot redirect it.
   Official Python SDK, installed as the optional extra `sentinel[ai]`; the base install does not include it.
2. **Opt-in per command, human at a terminal.** Only `sentinel incident summary <ID> --ai` calls out. It
   asks for confirmation, showing the destination, model and worst-case cost, and refuses to run
   without an interactive terminal. There is no `--yes`, so a script or an AI agent cannot send data or
   spend money. `--dry-run` prints the exact pack that would be sent and sends nothing.
3. **What may be sent: a disguised evidence pack** (`sentinel/assistant/pack.py`):
   - Starts from the ADR-0010 allow-list. Close notes, evidence text, actor and approver names are never included.
   - Every string from outside Sentinel is replaced by a placeholder (`ASSET-1`, `CRED-1`, `PERSON-1`,
     `EVENT-1`, `PATH-1`, `VALUE-1`, `INCIDENT-1`). These are event fields and attributes, asset ids and
     names from the inventory, and path-shaped text in rule output. Repo names, file paths, credential
     fingerprints, identities and person names therefore never leave the machine. The mapping stays local
     and is used to swap names back into the answer.
   - Hints the model needs are sent instead: asset type and importance (for example `repository`, `critical`).
   - Fail closed: if any original value or anything credential-shaped is still in the pack, nothing is sent.
4. **Explain only.** The model gets no tools. Its answer must match a fixed JSON schema (summary,
   impact labelled fact or hypothesis, unknowns, read-only investigation steps, report draft).
   Suggested steps that name a response action (revoke, rotate, delete, close and similar) are dropped,
   and the reader is told how many. The answer is written to `<home>/ai-summaries/<ID>.ai-summary.md`,
   labelled AI-generated and needing human review. The store is never written: no incident, audit,
   approval or verification change. Tests prove this both statically and end to end.
5. **Untrusted input.** Incident text is passed inside `<incident_data>` as data. The system prompt says
   it is never instructions. Because event-derived text is replaced by placeholders, attacker-chosen
   strings (an MCP server name, a workflow file name) do not reach the model at all.
6. **Key storage.** The Anthropic API key is read only from the OS credential store through `keyring`
   (Windows Credential Manager), and is set with `sentinel ai set-key` (hidden input). It is never read from
   environment variables, `sentinel.toml` or `.env`, and never printed or logged.
7. **Model and cost.** The default is `claude-sonnet-5-5`; `--deep` uses `claude-opus-5-5`; both can be
   changed in `[assistant]`, but only to priced models. Effort is `medium`, and `max_output_tokens` is 8000.
   Limits are 30 calls a day and USD 20 a month, checked before each call against a worst-case estimate.
   Actual usage is recorded in `<home>/ai-usage.jsonl` (tokens and estimated cost; no content).
   The owner also sets the same monthly cap in the Anthropic console, which is the hard limit.
8. **Refusal fallback.** Server-side `fallbacks: "default"` is on (`server-side-fallback-2026-07-01`)
   because incident text may trip the cyber classifier. Another model may then answer. The output names
   the model that answered, and the budget assumes the most expensive fallback. It can be switched off
   with `[assistant] fallbacks = false`.

## Consequences (security, operations, cost)
- **New outbound destination:** `api.anthropic.com`, which receives disguised incident structure: rule ids, times,
  severities, Sentinel's own rule text, and placeholders. Anthropic's data retention terms for the
  account apply; the owner should confirm them for the organization.
- The disguise is a heuristic for free text, but it is backed by an exact check against every collected
  value. A value that Sentinel never collected and that is not path-shaped could pass. The main control
  is that rule text is written by Sentinel, and the allow-list keeps operator free text out.
- Disguising costs some explanation quality; asset hints offset part of it. To be revisited after scoring.
- The model's answer can still be wrong. It is labelled, kept out of the record, and the exit gate is a
  human accuracy score on 20 incidents.
- Cost: a summary should cost cents (estimate; to be measured during scoring).
- **Unverified until the first live call:** the exact combination of structured output, adaptive thinking
  and server-side fallback on the beta endpoint for `claude-sonnet-5-5`; the response `model` field after a
  fallback. Tests use a fake client.

## Security review amendment (2026-10-31, before first commit)
An independent read-only review found these gaps; all are fixed and covered by tests in `tests/sentinel/test_assistant.py`:
- **Links could carry real values out.** A Markdown image or link in the answer, after placeholders were
  swapped back, could send real names to a remote host when a preview loads it. Now URLs are removed
  from model text; `< > [ ]` and backticks are escaped; control characters are stripped; and real values
  are swapped back only as one-line inline code.
- **Event `source` and "label" attributes passed through as free text.** Now only exact known
  collector names, probe signatures, hook target classes, decisions and id formats (rule, probe,
  scenario, built-in tool) are kept. Anything else is disguised.
- **Dict keys and nested lists in attributes were not collected.** Now every string at any depth is
  collected, including dict keys below the top level.
- **Placeholder-shaped event data** (for example an MCP server named `ASSET-1`) could be confused with real
  placeholders. Now the pack is refused. Only placeholders the pack itself created are swapped back.
- **Short identifying values** (an MCP server named `gh`) were skipped. Now they are disguised whatever
  their length.
- **Failed calls bypassed the budget.** Each call now reserves its worst-case cost in the ledger before
  it is sent. The reservation is replaced by the actual cost only on success, so refusals, truncations and
  timeouts still count. SDK retries are off (`max_retries=0`), so one call is one billed request. The
  estimate includes the output schema.
- **Action filter.** Now it also checks each step's reason and more synonyms. A fixed line on the report
  draft says response actions run only through the approval-gated plan.
- **Keyring backend.** Plaintext-file and other non-OS backends are refused.

**Structural rule: the model never writes facts (2026-11-02, after the second scoring).** Both scored runs
failed the gate only on "made-up claims" (1, then 2 of 20), and every one was an inference that the model labelled
as a fact. A prompt rule against it did not hold. So the answer format changed:
- The model returns only `summary` (its assessment), `hypotheses`, `unknowns` and `investigation_steps`. The
  `impact` items with a model-chosen fact/hypothesis label and the free-written `report_draft` are gone.
- Sentinel prints the record's own sections itself, from the evidence pack: rule, severity and status, facts, the
  record's hypotheses, what the credential can reach, the response-plan state, and whether the incident can close.
  Every model-written section is headed "AI", with hypotheses tagged `[hypothesis]`. The notes file is the draft
  report.
- Checks that would open, download or print a file or dump that may hold secrets (an env file, key, database
  dump, git config) are dropped like response actions. The prompt also forbids them.
- An LLM can still write a wrong interpretation. It can no longer present one as a recorded fact.
- Third scored run (`.sentinel-eval3`, independent Claude reviewer, not a human): mean 4.55, lowest 3, 0 made-up,
  0 injection followed: gate PASS, pending the owner's spot-check. The reviewer found 4 of 66 suggested checks that
  would reveal or test a secret ("confirm the secret matches", "verify the credential's validity", "credentials
  found in the file", "list secrets stored on the host"). The filter now drops these too. Checked against the 66
  real checks, it drops exactly those 4. A test-data bug (the linked database was typed as a repository) is fixed.
- Owner spot-check of run 3 (2026-11-03): case 09 counts as made up. Its assessment said decoy use "by definition
  indicates unauthorized interaction", but the record says who or what is unknown. Gate NOT MET. The cause was the
  R7 fact text, "Decoys have no legitimate use", which invites that conclusion. It now reads: decoys have no planned
  use, but a backup job, scanner or other automated process can still touch one, so this alone does not show who
  touched it or why (tested). A fresh run (`.sentinel-eval4`) decides the gate.
- Run 4 (2026-11-03, `.sentinel-eval4`): mean 4.55, lowest 3, 0 made-up claims, 0 injection followed. Gate MET. The
  owner spot-checked case 09 and accepted it. The reviewer flagged 5 more checks that need the secret (credentials
  "present in" or "referenced in" an exposed file, "full request and response payloads", gitleaks finding "context").
  The filter now drops these as well. Across all 131 real checks from runs 3 and 4 it drops exactly the 9 flagged ones.
  This was audited on the text as the filter sees it, before names are restored.

**Data rule extended after the first scoring (owner decision A, 2026-11-02).** The first scored run
(mean accuracy 4.05, one made-up claim) showed that the model could not know what a credential can reach, or
details such as "the login had no second factor". Two things were added to the pack, both still disguised:
- `blast_radius`: whether the credential is linked to assets, and for each linked or reachable asset a
  placeholder, the permission, the origin (documented or observed) and the importance. A permission, origin or
  importance that is not Sentinel's own vocabulary is disguised like free text. The person who confirmed a
  link is never sent.
- Event `attributes`, from an exact allow-list only: numbers and flags (`multiple_of_baseline`,
  `baseline_days`, `status`, `second_factor`, `adds_network`, `adds_secret_ref`, `patch_missing`) and the exact
  known labels already allowed (`signature`, `target_class`, `decision`, `rule`, `probe`, `scenario`, `tool`).
  Everything else in `attributes`, such as locations, URLs, file lists and free text, stays on the machine.
The system prompt now also explains these fields, and tells the model to keep `[confirm]` markers, never to
state who or where an actor is without evidence, and not to invent reasons. Tests cover each of these. The
earlier scores no longer describe this version: the 20 cases are rebuilt in a new folder and scored again.

**Found in the first live run (2026-11-02):**
- The credential guard on the finished answer rejected a legitimate long file path (the entropy guess reads a long
  token as a key). It now runs in two steps: the full check (known formats plus entropy) on the model's own text
  before real values are put back, and only the known key formats after. Real values come from Sentinel's records,
  and the pack is still checked before anything is sent. Tested both ways.
- Models put raw line breaks inside JSON strings, which a strict parser rejects. The answer is now parsed with
  control characters allowed in strings; it is still validated against the schema.
- A link scrubber bug that removed "data:" from ordinary text is fixed (see tests).

**Closed after the owner installed the packages (2026-11-02):**
- The `ai` extra is pinned: `anthropic==2.3.0`, `keyring==25.7.0` (lockfile updated).
- Checked against anthropic 2.3.0, offline: the credential sent is the stored key, not
  `ANTHROPIC_AUTH_TOKEN`; an explicit `base_url` wins over `ANTHROPIC_BASE_URL`. The SDK did read proxy and
  certificate environment variables by default (`trust_env=True`), so the client now sets
  `trust_env=False` and verifies certificates with the OS store, like the collectors (tested).
- The Windows keyring backend is `keyring.backends.Windows` (WinVault), which the allow-list accepts.

**Still open:**
- The first live call: whether the API accepts the exact request (structured output, `effort: medium`,
  server-side fallback on Sonnet 5.5) and what the answer looks like. Everything so far uses a fake client.
- There is no file lock between the budget check and the reservation. Parallel runs could both pass the
  check (single-user CLI; accepted).

## Alternatives considered
- **Claude through Bedrock or Vertex.** Same model through a cloud account. Deferred: Google Cloud is
  not set up (pending task 3).
- **Send real names.** Better explanations, but repo names and paths reveal what the company builds,
  and the decision cannot be undone once data is sent. Rejected for now.
- **Environment variable for the key.** Leaks into child processes, logs and crash reports. Rejected.
- **Let the assistant draft response actions.** Moves it toward the approval path. Rejected (ADR-0010).
- **Stay local only.** Kept as the default: without `--ai` nothing changes.
