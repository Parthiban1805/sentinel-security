# ADR-0009: Self-built canary decoys (copy, tamper and read tripwires)
Date: 2026-10-27 | Status: proposed (needs human review)

## Context
Rule R7 ("a decoy credential or resource was used") had only simulated inputs. The owner chose a self-built canary first, with a hosted
canary service as a possible later addition. A self-built decoy has no server of its own to notice use, so the design must say plainly what
it can and cannot detect.

## Decision
- A **decoy** is a small text file (default `.env.backup`; also `credentials.bak`, `secrets.old.env`, `gemini-key-old.txt`) holding a
  provider-shaped **fake** credential (Google-key or GitHub-token shape), generated at runtime. The value is written once and discarded;
  only its keyed fingerprint (ADR-0004) is stored, with the path, size, modification and access times.
- Decoys inside a Git work tree are added to that repository's local `.git/info/exclude`, so `git add .` cannot commit them.
- **What is detected:**
  | signal | how | strength | opens an incident? |
  |---|---|---|---|
  | COPIED | the secret scan finds the decoy's fingerprint at any location other than its own planted file, or in Git history | strong | yes, critical |
  | MODIFIED, REMOVED | size or modification time changed, or the file is gone | medium | yes, high |
  | READ | last-access time moved | weak | **no** (event only, low confidence) |
- **What is not detected:** use of the decoy at a provider. That needs a real provider key in a monitored project or a hosted canary service
  (later, with its own network ADR).
- Decoys are never "live credential" findings: the scan filter removes decoy fingerprints before the findings registry sees them, so a decoy
  can never trigger R1 or the revoke list. A decoy at its own location is expected; elsewhere it is a COPIED event.
- The tripwire pass uses `stat()` only. Reading a decoy to check it would move its access time and create the signal it is looking for.
- At planting, a probe tests whether a read moves the access time promptly on that volume ("immediate") or not ("unverified"). When it is
  unverified, a missing READ signal proves nothing. Antivirus and desktop indexers also read files, which is why READ never pages anyone.
- `sentinel run` runs the tripwire pass and filters scans; `sentinel canary plant|list|check|disarm` manage decoys. The decoy files are
  tamper evidence for the decoy only: an attacker who deletes both the decoy and Sentinel's database is out of scope here.

## Consequences (security, operations, cost)
- Security: decoy values are fake, random and never stored, but they ARE provider-shaped, so the pre-commit hook and CI scans would flag a
  committed decoy. That is intended (a committed decoy is a COPIED event). Plant decoys outside tracked files or let the local exclude handle it.
- Detection is strongest for the scenario that matters here: a staged or leaked copy (S0, S2, S3 patterns). It is weak for local reads.
- Operations: one stat call per decoy per run; one extra probe file (removed immediately) per planting.
- Cost: none. A hosted canary service remains an option for provider-side use detection.

## Alternatives considered
- Hosted canary tokens: instant provider-side alerts, but a third party and a new outbound destination.
- A permissionless real Google key in a canary project: detects real use, but needs Google live (not set up) and the 30-minute data delay.
- Read the decoy and compare a hash: simpler, but reading moves the access time and breaks the read tripwire.
