# ADR-0019: Credential lifecycle checks (v0.7c item 2)
Date: 2026-11-05 | Status: proposed (needs human review)

## Context
Sentinel tracks leaked credentials (findings) and has some credential assets: Google API keys from the GCP collector,
with creation and deletion times, plus any `github_token` or `service_account` asset that was imported. GitHub SSH key
ids and creation times sit in a collector snapshot. Nothing says when a credential expires, when it was last rotated,
whether it is still used, or whether the same leaked value sits in several places. The 2026-11-05 review asked for
lifecycle management. Rotation itself is a response action (v0.9). This ADR covers only knowing the state.

## Decision
- **No new store or schema.** Lifecycle facts are string attributes on the credential asset (types `api_key`,
  `github_token`, `service_account`):

  | Attribute | Set by |
  |---|---|
  | `created` | producer (Google `createTime`) or a person |
  | `expires` | a person |
  | `last_used` | a person |
  | `rotated_at` | a person |
  | `rotate_every_days` | a person |

  People set them with `sentinel creds set <asset> --actor <name>`. That goes through `update_asset`, so every value
  is validated, screened for credential shapes and audited. Dates must be ISO dates or date-times. No producer writes
  `last_used` yet; GitHub and Google usage per key needs its own source.
- **SSH keys** come from the existing `github:user_keys` snapshot (id and `created_at` only). They have no asset and
  no owner field, so only the age and rotation checks apply.
- **Checks** (deterministic, rule-based):

  | Check | Meaning | Severity |
  |---|---|---|
  | C1 | expired: `expires` is in the past | high |
  | C2 | expires within `expiry_warn_days` (default 14) | medium |
  | C3 | rotation overdue: `rotated_at`, else `created`, plus `rotate_every_days` (default `rotate_days`, 90) is in the past | medium |
  | C4 | no owner | low |
  | C5 | unused: `last_used` is older than `unused_days` (default 90); a candidate for deletion | low |
  | C6 | a person aliased the key to a leaked credential that may still work (`findings.LIVE_STATUSES`) | high |
  | C9 | one leaked credential found in two or more assets (findings with locations in several assets) | medium |

  - Deleted keys (`attributes.deleted`) are listed as deleted and never checked.
  - A field that is not known is listed as **unknown**, never treated as fine. A key with no expiry and no
    creation or rotation date says "rotation cannot be checked".
- **Events:** each problem becomes a `config_drift` event (`source: credentials`) with a deterministic id
  (`creds:<ref>:<check>`), so re-runs never duplicate it. No correlation rule reacts to `config_drift`, so these
  never open incidents. `sentinel run` records them; `sentinel creds --record` records them on demand.
- **Settings:** `[credentials] rotate_days`, `expiry_warn_days`, `unused_days` in `sentinel.toml` (owner-edited).

## Amendment after the 2026-11-05 security review ("Approve with fixes"; all fixed, tests in `test_credentials.py`)
- **Re-syncs keep people's facts:** the GCP collector now merges attributes, so a re-sync no longer wipes the
  lifecycle facts a person recorded.
- **`creds set` needs a person** at an interactive terminal. These values decide what is reported as fine, so an
  agent must not set them for itself.
- **Date limits:**
  - `rotated_at` and `last_used` cannot be in the future (one day of clock skew allowed). Stored future dates are
    reported as unknown.
  - Dates outside 1990..2100 are unknown, which also prevents an overflow crash.
  - All dates are normalised to UTC.
- **Output screening:** names and owners from unscreened sources (a Google `displayName`, an imported owner) are
  withheld in output when they look like a credential.
- **States:** a credential is shown as `unknown (n)`, never `ok`, when facts are missing. SSH keys list owner and
  last use as unknown, and a key list older than 2 days is marked stale.
- **Recurrences are recorded:** event ids include the triggering value (expiry date, due date, alias, or a hash of
  the asset set for C9).
- **Deleted keys:**
  - A Google key deleted less than 30 days ago is still checked for C6 and shown as "restorable until". The 30-day
    undelete window is a **hypothesis**, not checked against Google's documentation.
  - A `deleted` attribute that is not a date is reported as unknown, and the key is checked as live.
- **Run order:** `sentinel run` checks credentials after all collectors, so this run's data is used.
- **Exit code:** `sentinel creds` exits 1 for "problems found" and for errors. Scripts cannot tell these apart
  (documented in the help text).
- **Known limit:** findings carry no `is_test` flag, so C6 and C9 events from test material are not marked as test
  data.

## Consequences (security, operations, cost)
- **Security:** no secret value is involved. Only asset ids, SSH key ids, dates and owner names are stored.
  - `creds set` and `inventory set` screen owner and dates.
  - `inventory import` and the Google `displayName` are not screened at storage, so output withholds them when they
    look like a credential.
- **Operations:**
  - Most values are typed by a person until provider sources exist, so a wrong date gives a wrong answer. The report
    shows who set it (audit trail) and labels unknowns.
  - C3 on Google keys works from `createTime` alone, so it runs as soon as the collector runs.
- **Cost:** none.

## Alternatives considered
- **A separate lifecycle table:** cleaner, but a second place for asset facts before v0.8 decides the datastore.
- **Opening incidents for expired credentials:** too noisy. These are hygiene, not compromise. C6 is already covered
  by R1/R11 incidents when usage is seen.
- **Automatic rotation now:** that is a disruptive action (rule 4) and belongs with the v0.9 adapters.
