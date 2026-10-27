---
description: Security review of current changes before commit
---

Run `git diff` and `git status`, then delegate a review of the changed files to the security-reviewer
subagent. Also run `gitleaks protect --staged --redact` if anything is staged. Summarize blockers first.
