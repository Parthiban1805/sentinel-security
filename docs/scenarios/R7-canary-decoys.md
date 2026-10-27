# R7: Canary decoys (copied, tampered with, read)

- **Threat:** an intruder or a careless process finds and stages a credential file. A decoy that nothing legitimate uses turns that into a high-confidence signal.
- **Priority:** 1 (R7 applies to every scenario)
- **Preconditions:** throwaway folders; fake random values; real gitleaks; no network.
- **Simulated events (ordered):**
  1. Plant a decoy; run the tripwire pass (no signals).
  2. Copy the decoy's content to another folder; scan that folder (a COPIED event, a critical R7 incident).
  3. Edit or delete the decoy (MODIFIED or REMOVED events, a high R7 incident).
  4. Move the access time (a READ event, low confidence, no incident).
  5. Commit the decoy into another repo and delete it (still found in Git history: COPIED).
- **Expected detections:** rule R7 for copied, modified, removed or used; READ is an event only.
- **Expected incident:** critical for copied or used; high for tampering; none for read.
- **Expected response class:** investigate-first (find the source), then approval-required for revoking anything the intruder could reach.
- **Pass criteria:** (`tests/sentinel/test_canaries.py`, 24 tests; live demo run on 2026-10-27)
  - [x] A decoy at its own location is never a finding or an event; a copy anywhere else, or in Git history, is a critical COPIED event
  - [x] Decoys never enter the live-credential findings registry or the revoke list
  - [x] Tamper and removal are detected once each; READ is recorded at low confidence and never opens an incident
  - [x] The tripwire pass never reads the decoys (no self-inflicted READ signals)
  - [x] The decoy value appears in no stored state, event, incident or output (only the decoy file holds it)
  - [x] Inside a Git work tree a decoy cannot be committed by `git add .`; unsafe names, overwriting and bad directories are refused
  - [x] The access-time probe reports honestly ("immediate" on this volume; "unverified" where it does not move)
  - [ ] Use of a decoy AT A PROVIDER: **not detectable** with a self-built decoy (needs a live provider key or a hosted canary service)
- **Known limits (facts):** antivirus and indexers can cause READ signals; Windows can delay or disable access-time updates; an attacker who
  removes both the decoy and Sentinel's state is not caught; decoys only help where an intruder would look (name and location matter).
- **Cleanup:** `sentinel canary disarm <id> --delete-file`; temp dirs removed by pytest.
