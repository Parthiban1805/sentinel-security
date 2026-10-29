# ADR-0011: Opt-in scan locations outside Git
Date: 2026-10-28 | Status: proposed (needs human review)

## Context
Scenario S2: a key lands where Git scanning never looks (CI logs, build output, agent transcripts, shell
history). Sentinel scanned only Git repositories listed in `[scan] paths`. The scanner already handles any
folder, so the missing parts were a way to say which places to watch, a record of them in the inventory, and
honest limits. These places can hold personal data and other people's secrets, so nothing may be scanned by
default.

## Decision
- New config list `[scan] extra_paths`. **Empty by default.** Each entry is a folder or a single file and
  must be an absolute path without `..`. After links are resolved, a drive root, the home folder and any
  folder that contains the home folder are refused ("too broad"), so a typo cannot widen the scan to a disk
  or a profile. Known credential-store folders (`.ssh`, `.aws`, `.gnupg`, `.azure`, `.kube`, `.docker`,
  `gcloud`) are refused too, unless the owner sets `[scan] allow_credential_stores = true`. The same checks
  run again when a location is scanned, so settings built in code cannot skip them. Error messages carry the
  final name only, never the full path.
- A listed path that is itself a symlink is refused (list the real path). Symlinks inside a listed folder are
  not followed, because they could lead outside the listed scope.
- Before scanning, Sentinel counts what it cannot read: unreadable files or folders, symlinks, and JSON files
  over the 20 MB decoding limit. Any gap turns the run's health entry into `warn:` with the counts instead of
  a plain `ok`. The health entry is keyed by the location's asset id (name plus path hash), so two folders with
  the same name cannot hide each other's errors.
- `sentinel run` scans each entry in gitleaks `dir` mode only. No Git history, no hygiene or dependency
  checks. A single file reports its own file name; JSON and JSONL files are decoded in memory first (the S2
  fix from v0.3a).
- Each entry becomes an inventory asset of the new type `scan_location` (`loc-<name>-<12-hex path hash>`),
  unowned and unapproved until a person assigns an owner. An id that already exists for a different path is
  refused, not reused. The schema enum gains one value (additive, still v1).
- Findings use the existing registry: a keyed fingerprint, the file name relative to the location, and a line
  number. **No matched text, no file content and no full path is stored in findings or events.** The asset
  records the absolute path the owner configured.
- A path that is missing or unreadable is a collector health error. It is never treated as "clean".
- `incident verify-rescan` accepts these assets. Evidence says the result covers the scanned scope only. If
  any file could not be read, the result is INCONCLUSIVE and recorded as a failed verification: "absent" would
  prove nothing about files that were not scanned.
- No network calls. Nothing here writes outside the state directory.

## Consequences (security, operations, cost)
- Sentinel will read whatever the owner lists. Credential stores are refused unless the owner explicitly
  allows them, because Sentinel would fingerprint real keys there. The example config lists none, and the
  agent guard hooks still stop an AI agent from reading those places.
- **Unverified (fact):** whether the installed gitleaks follows symlinks or reports permission errors itself.
  Sentinel does not rely on either: it skips symlinks in its own JSON pass and counts unreadable files before
  scanning. Real symlink creation needs a privilege on Windows, so the symlink behaviour is covered by tests
  that simulate a link, not by a real one.
- Working-tree exclusions apply (`dist`, `build`, `target`, `node_modules`, virtual environments, `.sentinel`).
  A secret kept in one of those folders inside a location is not found. The re-scan evidence says so.
- Files over 20 MB are skipped for JSON decoding. Plain-text scanning by gitleaks has its own limits.
- A transcript or history file that is rewritten often can cause the same credential to be seen again with a
  new line number; the registry de-duplicates by fingerprint, so no new event is created.
- Cost: one gitleaks run per location per `sentinel run`. Large log folders can be slow (300 s timeout, then a
  health error).
- Not covered: rotating or archived files in other folders, remote logs, other machines (needs the endpoint
  agent, v0.8).

## Alternatives considered
- Scan well-known locations automatically: rejected. Reading history and transcripts by default is a privacy
  decision (see `policies/agent-monitoring-policy.md`) that the owner must make per path.
- Watch for new files with a file-system hook: deferred. Polling with `sentinel run` is enough for now.
- Store matched snippets for easier triage: rejected. It would copy secrets into the store (ADR-0004).
