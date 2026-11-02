# Sentinel security workspace (Claude Code setup)

Claude Code configuration and project scaffolding for the Internal AI & Developer Security System.

## Contents
```
CLAUDE.md                     Project memory: rules, conventions, where things are
.claude/settings.json         Permissions (allow/ask/deny) + hook wiring
.claude/hooks/                Guard hooks: sensitive files, risky bash, secret scan after edits
.claude/skills/               6 project skills (SKILL.md each)
.claude/agents/               security-reviewer, scenario-tester subagents
.claude/commands/             /new-scenario /new-rule /security-review /incident
.mcp.json                     Empty MCP allowlist (add servers only after review)
docs/spec/                    Roadmap, correlation rules; put the full spec export here
docs/schemas/                 Event and asset JSON schemas
docs/scenarios/               Scenario catalogue S0-S15 + test case template
docs/runbooks/                Credential exposure runbook
docs/adr/                     Architecture decision records
policies/agent-policy.md      AI agent security policy (13 rules)
.gitleaks.toml                Gitleaks config
.pre-commit-config.yaml       Pre-commit secret scanning
.github/workflows/            Secret scan workflow
```

## Install Sentinel on another machine
See [docs/install.md](docs/install.md): a versioned wheel verified against `SHA256SUMS` and installed with
`scripts/install-sentinel.ps1` (ADR-0013). Releases are built with `uv run python scripts/build_release.py`.

## Setup (developing Sentinel itself)
1. Copy this folder into your repo root (or start a new repo with it).
2. Install tools: Python 3.11+, `pip install pre-commit ruff mypy pytest`, and gitleaks
   (https://github.com/gitleaks/gitleaks#installing).
3. `pre-commit install` so commits are scanned locally.
4. Export the team design doc as Markdown to `docs/spec/design-spec.md`.
5. Make hooks executable on Linux/macOS: `chmod +x .claude/hooks/*.py`.
   On Windows, if `python3` is not on PATH, change `python3` to `python` (or `py`) in
   `.claude/settings.json`.
6. In GitHub repo settings, enable secret scanning and push protection, and protect `main`.
7. Start Claude Code in the repo and run `/permissions` to confirm the rules loaded.

## Verify the guards work (safe tests)
- Ask Claude Code to read `.env` -> should be blocked.
- Ask it to run `curl https://example.com` -> should be blocked.
- Ask it to run `git push` -> should prompt for approval.
Permission rules and hooks are layered on purpose: past Claude Code releases have had permission
bugs, so the hooks enforce the same boundaries independently. Re-test after Claude Code upgrades.

## Important
- Check current Claude Code docs for settings/hook syntax: https://docs.claude.com/en/docs/claude-code/settings
- Pin `actions/checkout` and other actions to verified full commit SHAs before relying on CI.
