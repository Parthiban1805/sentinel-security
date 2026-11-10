# ADR-0029: zizmor for GitHub Actions workflow audits (v0.7e item F3)
Date: 2026-11-06 | Status: proposed (needs human review) | Extends: the v0.4 hygiene checks (W1-W6)

## Context
Scenarios S8-S10 (CI supply chain) are covered by Sentinel's hygiene checks W1-W6. They are regex checks over
workflow text: they find unpinned actions, `pull_request_target`, missing or `write-all` permissions and untrusted
context in `run:` blocks, but they do not parse YAML. They miss credential persistence (`actions/checkout`
leaving the token in `.git/config`, which an uploaded artifact can then leak), cache poisoning, impostor commits,
per-job permission scope and much more. The 2025 `tj-actions/changed-files` compromise (CVE-2025-30066) leaked CI
secrets into public logs: the same class of exposure as Sentinel's origin incident.

CLAUDE.md says to reuse mature tools rather than write new scanners. **zizmor** (github.com/zizmorcore/zizmor,
MIT) is a widely used static analyser for GitHub Actions.

**Facts checked in the zizmor docs on 2026-11-06** (docs.zizmor.sh/usage):
- `--offline` (or `ZIZMOR_OFFLINE`): no Internet access, no remote repositories, online audits skipped.
- **zizmor goes online by itself** when `GH_TOKEN`, `GITHUB_TOKEN` or `ZIZMOR_GITHUB_TOKEN` is set.
- `--format=json` (json-v1): a flat array of findings with `ident`, `desc`, `url`, `determinations` (severity
  Informational/Low/Medium/High, confidence, persona), `locations` (symbolic key and route; concrete position,
  0-based row, and `feature`, the matching workflow text) and `ignored`.
- Exit codes: 0 no findings; 1 audit error; 2 argument error; 3 no inputs; 11-14 findings by highest severity.
- Accepts a local directory.
- Latest release on PyPI: 1.32.0 (2026-11-02). **Pinned: 1.31.1 (2026-10-15)**, the newest release at least two
  weeks old.

## Decision
- **Wrapper** `sentinel/scanners/zizmor.py`, like the gitleaks wrapper:
  - runs `zizmor --offline --format=json <repo>`, with no shell, a 300-second timeout, `ZIZMOR_OFFLINE=true`, and
    the three token variables **removed** from the child's environment;
  - exit codes 0 and 11-14 succeed; 3 means nothing to audit; anything else is an error whose message never
    contains the tool's output;
  - keeps only the audit name (checked against `[a-z0-9-]{1,40}`, else `unknown`), a severity (Informational maps
    to low), a repo-relative path (a path outside the repo keeps its file name only) and a 1-based line. The
    `feature` text and the annotation are **dropped**: a workflow line can hold a secret.
- **Hygiene:** `scan_repo` adds `ZZ-<audit>` findings (one per audit and file, at the highest severity, with up to
  ten line numbers) as `config_drift` events, like W1-W6. A zizmor finding whose regex equivalent already fired on
  the same file is not repeated (unpinned-uses W1, dangerous-triggers W2/W3, excessive-permissions W4/W5,
  template-injection W6). The regex checks always run, so nothing is lost when zizmor is absent or disagrees.
- **Failure is visible:** a failed run adds one `ZZ-error` finding ("CI checks are regex-only for this run").
  `doctor` warns when zizmor is missing or is not the reviewed version.
- **Optional tool,** found on PATH like gitleaks; not a Python dependency. Ignore entries work as for other checks
  (`ZZ-artipacked:*`).

## Consequences (security, operations, cost)
- **Security:** YAML-aware workflow audits, including credential persistence, which ties CI back to credential
  exposure. No network call: offline mode plus token stripping (CLAUDE.md rule 5). No workflow text is stored.
- **Not verified yet:** zizmor is not installed on the development machine. The parser is tested against a fixture
  built from the documented json-v1 shape, and one test runs the real tool only where it is installed. **Install
  1.31.1 and run `pytest tests/sentinel/test_zizmor.py` before relying on it.**
- **Operations:** install with `pipx install zizmor==1.31.1` or `uv tool install zizmor==1.31.1` (a person does
  this; Sentinel does not install tools). New `ZZ-*` findings appear in `sentinel hygiene` and `sentinel run`.
- **Cost:** none beyond the tool's run time.

## Alternatives considered
- **Extending the regex checks:** every new audit would be another fragile regex; zizmor already parses YAML and
  is maintained.
- **actionlint:** mostly syntax and correctness, fewer security audits.
- **Semgrep rules:** broader, but heavier, and its rule registry is fetched online by default.
- **OpenSSF Scorecard:** scores a repository via the GitHub API (network, token); a different job.
