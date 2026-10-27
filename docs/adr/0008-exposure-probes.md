# ADR-0008: Exposure probes contact owner-confirmed hosts
Date: 2026-10-27 | Status: proposed (needs human review)

## Context
Scenarios S1 (a sensitive path such as `.env` or `.git` is served by our own web server) and S15 (a database backup is reachable)
can only be detected by asking the host. Project rule 5 forbids network calls from Sentinel unless the destination is documented in
the module README and an ADR. Unlike the collectors (ADR-0005, four fixed hosts), the destinations here are the owner's own hosts,
so they cannot be on a fixed allowlist. A careless implementation would be a scanner that can be pointed at anyone.

## Decision
- **Destinations:** only hosts listed under `[[probes.hosts]]` in the (git-ignored) config with `confirm_ownership = true`, or passed to
  `sentinel probe --url ... --i-own-this`. Without the confirmation, nothing is contacted (tested: zero requests are made). No
  discovery, no crawling, no hostname generation.
- **Requests:** GET only, a fixed list of at most 25 paths (`sentinel/probes.py: PROBES`), a pause between requests (default 0.25 s),
  8 s timeout, a header `Range: bytes=0-511`, and a User-Agent that says it is an owner-run probe. Redirects are never followed.
  A host that answers nothing is abandoned after 3 unanswered requests in a row.
- **Target policy:** https only, unless the owner sets `allow_http = true` for that host (for example a staging box). Credentials,
  paths, queries and fragments in the target are refused; link-local addresses (cloud metadata, 169.254.0.0/16) are refused.
- **Content handling:** at most 512 bytes are read, only to test the file's *shape* (env file lines, git config section, SQL dump
  tokens, archive magic bytes, key header). The bytes are discarded immediately and are never stored, logged or printed. Events carry
  the path, the shape name, the HTTP status and a severity. Tests serve files containing a fake key and assert it appears nowhere.
- **Cadence:** `sentinel run` probes each configured host at most once per `interval_hours` (default 24).
- **Output:** `exposed_service` events (deterministic ids, so re-runs do not duplicate), a `server` asset per host (unowned until
  assigned), and rule R10 (`docs/spec/correlation-rules.md`). Fixed exposures are reported as cleared only when the host answered; silence
  proves nothing.
- **Verification:** the incident step `verify_path_closed` re-probes the exact path and passes only on a definitive answer without the
  file. A network error fails the step.

## Consequences (security, operations, cost)
- Security: Sentinel now sends requests to hosts chosen by the owner. The confirmation flag and the refusal to run without it are the
  control; they rely on the owner being honest. The probe list and shape tests keep the traffic small, identifiable and non-intrusive.
- A found `.env` means its contents transited Sentinel's memory for the shape test. Nothing is retained, but the owner must still treat
  the credentials inside as exposed and rotate them (the incident plan says so).
- Detection gaps: fixed paths only; only the first 512 bytes; hosts behind authentication or a WAF that hides the path are not seen;
  a catch-all site is protected from false positives by the shape test, not by a baseline request.
- Operations: one sweep is about 22 requests per host per day. Cost: none.

## Alternatives considered
- Scan any host given on the command line without confirmation: simpler, but one wrong paste scans a third party.
- Read and fingerprint the exposed file's secrets so R1 could join them to provider usage: more powerful, but stores derived secret
  material from a third party's file and widens the blast radius; deferred.
- Use an external scanning service: sends our host list and findings to a third party.
