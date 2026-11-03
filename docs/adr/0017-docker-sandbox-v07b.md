# ADR-0017: Docker sandbox for agent-run code (v0.7b)
Date: 2026-11-03 | Status: accepted (owner, 2026-11-03: "go 7b", options A and B as recommended; C on hold, see below)

## Context
The v0.7a gateway (ADR-0016) decides every Claude Code tool call, but it cannot see inside a script that the agent
writes to a file and then runs, or inside programs that tools start. Only isolation closes that gap. The owner chose
Docker (Docker Desktop with the WSL2 backend on Windows 11 Home; Windows Sandbox is not available on Home).

## Decision
1. **`sentinel sandbox run -- <command>`** runs one command in a throwaway Linux container:
   - **No network:** `--network none`. No outgoing-traffic allow-list in this release (owner choice A); an allow-list
     would need a proxy container and its own ADR.
   - **A scratch copy, never the repo:** only Git-tracked files are copied into a new temp folder, mounted at `/work`.
     Files matching secret patterns are never copied, even when tracked: `.env*` except templates, key files,
     `.ssh` / `.aws` / `.azure` / `.kube` / `.sentinel` / `.git`, `.netrc`, `.git-credentials`, `.mcp.json`,
     `.claude.json`, `.claude/settings.local.json`, `secrets/` and credential JSON. Symlinks, files outside the repo
     and files over 20 MB are skipped, and the copy is limited to 300 MB. Nothing is written back to the repo; the
     scratch folder is deleted afterwards unless `--keep` is given (then it is printed, to read the results).
   - **Hardening:**
     - non-root user (65534), read-only root filesystem, all capabilities dropped, `no-new-privileges`,
     - memory (swap equal to memory, so no extra swap), CPU and process limits, `--ipc none`, a timeout,
     - a small writable `/tmp` (tmpfs), no Docker socket, no host environment (only the variables Docker itself
       needs are passed to the docker CLI; none reach the container),
     - the command is passed as an argument list, without a shell.
   - **Pinned image:** `[sandbox] image` in `sentinel.toml` must include `@sha256:<digest>`; anything else is refused.
     The owner pulls the image once (Sentinel makes no network call), and `sentinel sandbox check` reports
     problems.
2. **Gateway:**
   - **No exemption:** sandboxed one-liners (`sentinel sandbox run -- python -c ...`) still ask, like any inline code.
     The first version skipped the prompt for them, but the review showed that a shell function named `sentinel`
     defined in the same command could borrow that exemption to run code on the host. A check on the shell text
     cannot prove the sandbox really runs.
   - **Docker:** container commands ask (BG-25), and those that can reach the host are refused (BG-24): privileged
     runs, host mounts, host network or PID namespace, added capabilities, devices, `docker context use`, and setting
     `DOCKER_HOST` or `DOCKER_CONTEXT`.
   - **Protected:** `sentinel.toml` (it holds the image pin) and shell profiles (`.bashrc`, PowerShell profile) can
     only be written by a person. Token files (`.npmrc`, `.pypirc`, `google-services.json`, client secrets, Terraform
     state and similar) cannot be read by the agent. `git stash --all` is refused, because it moves Sentinel's state
     files away.
3. **Strict mode (owner choice B, off by default), advisory and not a security boundary:**
   - `sentinel sandbox strict on` makes the gateway ask (BG-23) whenever a command runs code outside the sandbox:
     - interpreters (Python, Node, Bun, Deno, Ruby, Perl, PHP, PowerShell),
     - shells and `cmd`, make, npm, pnpm, yarn, go, java, cargo and pytest,
     - anything through `uv run`,
     - a script run directly (`./x.sh`, `x.bat`).
   - The only command it does not ask about is a single `sentinel sandbox run ...` (or `uv run sentinel sandbox
     run ...` without options).
   - A list of programs can never be complete, and the agent shapes its own shell, so strict mode reduces risk but
     does not guarantee it.
   - `on` can be run by anyone, an agent too; `off` needs a person at a terminal (the same pattern as the kill
     switch).

## Consequences (security, operations, cost)
- **No new network destination:** the container has no network, and Sentinel itself makes none.
- **Tests:** unit tests with a fake Docker check the flags, the scratch contents, the absence of write-back and of
  host environment, timeouts, the gateway exemption and strict mode. A live test (no network, no `.env`, no Docker
  socket, not root) runs when `SENTINEL_SANDBOX_IMAGE` names a pinned image and Docker is running.
- **Overhead:** each run copies the tracked files and starts a container, so a few seconds each time.
- **Limits:**
  - Code that needs the network (installing packages) does not work in the sandbox. Install on the host after your
    review, or wait for the allow-list.
  - The agent can still run code on the host without the sandbox unless strict mode is on.
  - An agent that edits Sentinel's own source or `sentinel.toml` could weaken the sandbox. This is the same inherent
    limit as for any tool the agent can change; the ADR and code review are the control.
  - Docker Desktop runs containers in a WSL2 VM, and a container escape (kernel bug) is out of scope for this release.
- **Open (owner, choice C): Docker Desktop licence.** It is free for personal use and for companies with fewer than
  250 employees and less than USD 10 million in annual revenue; larger organisations need a paid subscription.
  **The owner put this on hold on 2026-11-03.** Until it is confirmed, use the sandbox only for personal and
  evaluation work. Alternative if needed: Docker Engine inside WSL2 without Docker Desktop (Apache-2.0 licensed), which
  needs only a different setup, not different code.

## Security review amendment (2026-11-03, before the first commit)
An independent read-only review blocked the first version. Fixed and tested (`tests/sentinel/test_sandbox.py`):
- **Blocker:** the inline-code exemption could be borrowed with a shell function named `sentinel`. The exemption is
  removed (see Decision 2).
- **`uv run` options:** `uv run --project=<other> sentinel ...` was treated as Sentinel. Options after `uv run` now
  never count as the sandbox.
- **No image pulls:** `--pull never`; the image comes only from the project's own `sentinel.toml`, which agents cannot
  write. `sandbox run` has no `--config` option.
- **Docker reaching the host:** see BG-24 and BG-25 above. `DOCKER_HOST`, `DOCKER_CONTEXT` and `DOCKER_CONFIG` are no
  longer passed to the docker CLI.
- **Host resources:**
  - a 1 GB limit on any file written, and 1,024 open files;
  - output read in a stream and capped at 1 MB per stream, after which the container is stopped;
  - the container is removed on timeout, Ctrl+C or any error, and the scratch copy is always cleaned up;
  - `--timeout` is limited to 1 to 3,600 seconds.
- **Secrets in the copy:** `.docker/config.json` (protected by the gateway but missing from the sandbox list) and more
  token files are now left out, and hardlinked files are skipped. A test checks that every file the gateway forbids
  reading is also left out of the sandbox.
- **Strict mode:**
  - It now covers shells, build tools, `uv run` and scripts.
  - It is documented as advisory.
  - `git stash --all` can no longer remove its flag file.
  - `strict on` warns when run outside the project's `.sentinel` folder.

**Known limits accepted:**
- A shell function, alias or profile that redefines `sentinel` would make strict mode treat host code as
  sandboxed. Profiles are now write-protected, but strict mode stays advisory.
- An image chosen by the person who sets `sentinel.toml` is trusted. Escaping the hardened container needs a runtime or
  kernel bug.
- Symlinks created inside `/work` remain in a `--keep` copy. Do not open them with host tools without checking.
- Tracked files that hold secrets in unusual places are not scanned before copying; gitleaks covers the repo itself.

## Alternatives considered
- **Windows Sandbox:** not available on Windows 11 Home.
- **WSL2 directly, without Docker:** possible, but Docker's flags give the isolation settings in one tested list.
- **Mount the repo read-only instead of copying:** simpler, but every untracked secret in the folder (a `.env`)
  would be visible inside. Copying only tracked files, minus secret patterns, is safer.
- **An egress allow-list now:** rejected for this release (owner choice A).
