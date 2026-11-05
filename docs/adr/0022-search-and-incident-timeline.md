# ADR-0022: Structured search and incident timeline (v0.7c item 5)
Date: 2026-11-05 | Status: proposed (needs human review)

## Context
Everything Sentinel knows sits in one SQLite store, but an investigator can only read it through fixed reports. The
2026-11-05 feature review asked for a hunting workspace ("which assets and incidents touch this credential
fingerprint in the last 30 days?") and for an evidence-based incident reconstruction that separates what is confirmed
from what is inferred or suspected. The existing incident record already holds facts, hypotheses, unknowns, a plan and
a blast radius, and every lifecycle action is audited.

## Decision
- **`sentinel search`** (read-only, `--json`, `--limit`, `--include-test`) with structured filters only:
  `--credential <fingerprint>`, `--asset`, `--session`, `--type` (event type), `--source`, `--since`, `--until`
  (ISO date or time, or relative `7d`, `12h`, `30m`). At least one filter is required. Filters combine with AND.
  - **Searched:** events, incidents, findings, assets, human-confirmed credential links, and audit entries. Each result
    carries its kind, time and a few safe fields (ids, types, severities, statuses). A filter that does not apply to a
    kind excludes that kind (for example `--session` returns events and the incidents built from them, nothing else).
  - **No free-text search.** Notes and evidence text are not searched or shown, so the command cannot be used to dig
    secrets or personal text out of the store.
  - **A value that looks like a credential is refused** (rule 1): the error tells the user to use the fingerprint.
  - **Newest first,** counts per kind before the limit, and a `truncated` flag.
  - **Saved queries and "create a rule from a search"** are not built. They need an editor for rules and their own ADR.
  - **"Which machines"** cannot be answered yet: there is one machine until the v0.8 service. The command searches
    assets and sessions, and the output says so.
- **`incident timeline <ID>`** (`--json`) rebuilds one incident from recorded data only, in labelled sections:
  1. **Confirmed (timed):** the incident's events, the credential's first and last sighting and status, links a person
     confirmed, and every lifecycle action from the audit trail with its actor.
  2. **Stated by the rule:** the facts the rule printed from the matched events.
  3. **Inferred:** relationships Sentinel derived, such as assets the credential could reach through recorded edges. Each
     is labelled a hypothesis of access.
  4. **Suspected:** the hypotheses recorded on the incident, "not proven".
  5. **Alternative explanations:** fixed text per rule, written from the rule specs.
  6. **Missing evidence:** the incident's unknowns, required steps not yet verified, failed verifications, and
     "closed without verification".
- No AI model is involved (it does not change `incident summary`). The timeline never changes any state.

## Amendment after the 2026-11-05 security review ("Approve with fixes"; all fixed, tests in
`test_search_timeline_review.py`)
- **AND semantics:** related assets are added to a credential search only when the credential is the sole filter
  (besides time). With `--asset`, `--session`, `--type` or `--source` the expansion would return assets that do not
  meet the other filter.
- **Test data:** audit rows of simulated incidents are hidden unless `--include-test`. Findings and links carry no test
  flag, which stays a known limit.
- **Credential-shaped text is withheld** in both commands (`[withheld: looks like a credential]`). Rule facts quote
  event attributes an attacker can choose, such as an MCP server name or a workflow file name. Only known credential
  formats are used for this, so ids and fingerprints are never withheld.
- **Filter values:** spaces are no longer accepted. A known-format key split by `:`, `-`, `/` or `.` is refused. The
  entropy guess runs on each separator-delimited part, because ids such as `wf-repo-<name>-<hash>` would otherwise
  read as one long random token.
- An unknown incident id that looks like a key is not echoed. Timeline times are normalised to UTC before sorting, and
  an unreadable time leaves the line untimed. Documents of the wrong shape are skipped, never raised on.
- **Known limits:** non-ASCII look-alike characters are kept (only control, escape and format characters are
  replaced); opening the store may create SQLite's `-wal`/`-shm` side files, as every Sentinel command does.

## Consequences (security, operations, cost)
- **Security:** output holds ids, fingerprints, types and statuses. Audit `evidence` and `detail` text and finding
  notes are **not** printed. Control characters and over-long values are removed from every printed field.
  A search result set is a map of the organisation: treat it as sensitive.
- **Honesty:** a search is only as complete as what Sentinel stored. An empty result means "nothing recorded", not
  "nothing happened". The alternative explanations are generic per rule and may not fit a specific incident.
- **Operations:** a search scans the store in memory. That is fine for one machine; the v0.8 datastore will need
  indexes.
- **Cost:** none. No network call, dependency, setting or schema change.

## Alternatives considered
- **SQL or a query language:** powerful but turns the CLI into a way to read anything. Structured filters are enough
  for the questions in the plan.
- **Free-text search:** rejected for the reason above.
- **AI-written timelines:** rejected. The point is that every line traces to a recorded fact.
