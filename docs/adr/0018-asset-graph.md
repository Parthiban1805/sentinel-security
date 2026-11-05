# ADR-0018: Asset graph with observed edges (v0.7c)
Date: 2026-11-05 | Status: proposed (needs human review)

## Context
Blast radius (`sentinel/inventory/blast.py`) walks `access_edges` from assets a person linked to a credential. Almost no
edges exist, because only a person typing them (or an import) creates them, so most incidents say "reach unknown". The
v0.5 item "automatic blast-radius edges" was never built. The 2026-11-05 feature review put an attack graph first, and
v0.8 will design the central datastore, so the graph model has to be fixed before then.

## Decision
- **No new store.** The graph is the existing asset records: nodes are assets, edges are `access_edges`. The asset
  schema stays `sentinel/v1`. One optional edge field is added, `source` (which producer made the edge). That is
  additive, so ADR-0006 does not require a v2.
- **Two kinds of edge, always labelled:**
  - `documented`: a person recorded it (`inventory edge`, screened and audited).
  - `observed`: Sentinel derived it from data it already reads.

  Every edge, and every path built from edges, is a hypothesis of access until investigated. Reports say "could reach",
  never "reached".
- **Producers own their edges.** A producer replaces only edges that have `origin: observed` and its own `source` on
  the asset it refreshes. Documented edges and other producers' edges are never touched. An edge to an asset that is not
  in the inventory is skipped and counted, never invented.
- **First producers (offline, no new network calls):**
  - `mcp_config`: ai_agent -> mcp_server (`can_call`), from the servers `inventory agents` already registers.
  - `workflow_files`: repository -> ci_workflow (`runs_workflow`), from `.github/workflows/*.yml` and `*.yaml` in
    repositories with a local path.
    - The workflow asset keeps the *names* of secrets it references (`secrets.NAME`, `secrets['NAME']`), never values.
      Names must match `^[A-Za-z0-9_]{1,100}$` and pass the credential-shape screen, or they are dropped and counted.
    - `secrets: inherit` and whole-object use such as `toJSON(secrets)` set `uses_all_secrets` and importance high. **An
      empty `secret_refs` list does not mean the workflow has no secret access** (environments, OIDC and
      organisation secrets are not visible here).
    - The workflow id is a readable slug plus a SHA-256 prefix of the exact repository id and file name, so similar
      names never share an asset. An existing asset with that id but a different type, repository or file is
      never overwritten (counted as a collision).
- **Safety limits for producers** (an agent can write workflow files and `.mcp.json`; added after the 2026-11-05
  review):
  - Expressions are found with plain string search, and the regexes run only on bodies of at most 2,000 characters,
    so scan time is linear in the file size.
    - The innermost `${{` before each `}}` is used, so an unclosed opener cannot hide a later reference.
    - Oversize bodies are counted and warned ("secret references may be missing").
    - `secrets: inherit` is matched on the stripped start of each line, so padding cannot hide it.
  - At most 1 MB per file is read (by reading, not `stat`). At most 200 files per repository are read; listing
    stops one file past the cap, with a warning.
  - A workflow's approval is cleared, with an audit entry, when its content changes (a SHA-256 prefix of the file is
    stored for change detection only), the same rule as MCP servers.
  - The workflows folder and every file must resolve inside the repository. This catches symlinks and Windows
    junctions in any path component. A file whose name looks like a credential is skipped.
  - Anything skipped is counted and shown as a `warn:` in run health, never silently dropped.
  - **Limits:**
    - Hard links cannot be detected.
    - Two scan paths with the same folder name share one `graph:<name>` health line (the same is true of `scan:` and
      `hygiene:`).
    - There is no runner-level test of the `warn:` line yet.
- **Later producers** need their own amendment: token -> repositories (`GET /user/repos`, same host as ADR-0005, but a
  new endpoint) and Google key -> allowed APIs (key restrictions, already read by the GCP collector).
- **Queries:**
  - `reach(asset)`: forward walk, i.e. what could this reach if it were compromised.
  - `reached_by(asset)`: reverse walk, i.e. what can reach this.

  `reached_by` also lists the credentials linked to an asset (they are not assets, so they have type `credential`
  and no importance). Asking what reaches a credential is refused with a clear message.

  Both walk breadth-first with a depth limit (default 6) and are safe on cycles. Each result carries its path, depth,
  importance and a `basis` label for **the path shown** (the first shortest path; documented edges are preferred): `documented` (every edge on the path documented), `observed` (every edge observed) or
  `mixed`. Results are deterministic (sorted).
- `blast_radius()` and its incident record shape stay unchanged for now (the AI pack and reports depend on them).
  Incidents gain observed edges automatically because blast radius already walks `access_edges`.

## Consequences (security, operations, cost)
- **Security:**
  - The graph is a map of what reaches what, so it makes the store a more valuable target. It holds no secret values,
    only asset ids and secret names. Store protection is the existing open item (encryption and ACLs in section 5 of
    the product plan).
  - Secret names can hint at what exists (for example `GEMINI_API_KEY`). That is accepted, as GitHub shows the same
    names to repository readers.
- **Operations:**
  - A workflow that is deleted keeps its asset, but loses its edge on the next refresh.
  - Observed edges written before this ADR have no `source`, so no producer owns them and they are never removed
    automatically. None existed in the store when this was written.
- **Accuracy:** an observed edge is only as good as its source. `can_call` means "configured", not "called". The edge
  to a workflow does not show which environments or branches can trigger it.
- **Cost:** none (local files only).

## Alternatives considered
- **A graph database or a separate edge table:** more flexible, but a second store to secure and migrate before v0.8
  decides the datastore. Rejected for now. The v0.8 design may move edges into their own table behind the same functions.
- **Inferring edges with an AI model:** violates principle 1 (rules decide). Rejected.
- **Parsing workflows with a YAML library:** better structure, but a new dependency for name extraction. Text
  search for expressions is enough, and hygiene already reads workflows as text.
