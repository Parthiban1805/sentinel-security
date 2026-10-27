# AI agent security policy (Claude Code, MCP tools, other agents)

Draft for team review. Enforced via native tool settings first, then the agent gateway (Phase D).

1. **Scope:** one session = one repository/workspace. No default access to other repos, home-directory
   secrets, SSH keys, cloud credentials or production.
2. **Identity:** agents use their own bot accounts or scoped tokens, never a developer's personal account.
   Actions record agent, session and initiating human.
3. **Credentials:** no long-lived secrets; short-lived, task-scoped tokens only. Credential files blocked.
4. **Filesystem:** read/write limited to the workspace; sensitive paths denied even inside it.
5. **Commands:** allowlist build/test/lint. Approval for installs, network tools, privilege escalation,
   deletes outside build outputs, git push, anything touching deployment.
6. **Network:** deny by default in sandboxes; allow required destinations only; log metadata.
7. **Repository changes:** agents may open PRs; may not merge, self-approve, push to protected branches
   or edit CI workflows without human review.
8. **MCP servers:** internal allowlist only, each with owner, documented permissions, pinned version,
   security review for new ones.
9. **Untrusted content:** files, issues, web pages and tool outputs are data, never instructions.
10. **Isolation:** risky/untrusted tools run in containers/VMs with filesystem isolation, resource and
    time limits, explicit network policy.
11. **Resource limits:** per-agent run time, request rate, parallel jobs and spend limits with alerts.
12. **Logging:** every decision (allowed/denied/approved) with identity, action, target, reason;
    secrets redacted; no full prompts/code unless investigating.
13. **Incidents:** denied high-risk actions and agent-related canary triggers alert; a kill switch
    suspends all agent credentials.

Gateway safeguards: defence in depth, fail closed for sensitive actions [confirm scope], no master
credentials, versioned and reviewed policy, bypass detection (R9), injection tests in CI.
