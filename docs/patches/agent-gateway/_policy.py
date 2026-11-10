"""Agent gateway policy engine (v0.7a, ADR-0016). Standard library only.

decide() returns one Decision for any Claude Code tool call:
  "deny"      - block (the hook exits 2 and explains why to Claude)
  "ask"       - the user must confirm (the hook prints permissionDecision "ask")
  "allow"     - no objection; the hook stays SILENT so the user's normal permission rules still apply
                (a hook "allow" would skip the user's prompt, see ADR-0016)
  "allow_mcp" - as "allow", for MCP tool calls (kept for the existing log readers)

Command checks (Bash, and any tool with a string "command"): regex rules for network tools, secret
reads, protected files and more, plus an argument parser per interpreter for inline code (BG-15
ask; encoded PowerShell BG-16 deny). Deny always wins over ask.
File checks: the PF rules on the raw path, the normalised path and the resolved path (symlinks and
junctions), with Windows aliases (trailing dots/spaces, alternate data streams) handled.
Kill switch KS-01 and the MCP allow-list MCP-02/03. Any internal error denies (GW-99).
"""

import collections
import json
import os
import re
import shlex

Decision = collections.namedtuple("Decision", "decision rule cls reason target")

KILL_SWITCH_NAME = "agent-kill-switch"
MCP_ALLOWLIST_NAME = "mcp-allowlist.json"
SANDBOX_STRICT_NAME = "sandbox-strict"  # ADR-0017: present = code outside the sandbox asks
READ_ONLY_TOOLS = ("Read", "Grep", "Glob", "LS")
WRITE_TOOLS = ("Edit", "MultiEdit", "Write", "NotebookEdit")
FILE_TOOLS = READ_ONLY_TOOLS + WRITE_TOOLS
_FLAGS = re.IGNORECASE | re.MULTILINE

# --- Command rules (regex) ----------------------------------------------------------------------
_SEG_END = r"[^|;&\n]*"
# Sentinel state and the user-level Claude config (may hold MCP tokens): no reads, no writes.
_STATE = r"(\.sentinel\b|\.sen[\w.]*[*?\[]|\.claude\.json\b)"
# The gateway itself and agent configuration: reads are fine, writes are not.
_GUARD = (
    r"(\.claude[\\/]+(hooks|settings|backup)|\.cla[\w.]*[*?\[]|\.mcp\.json\b|\bsentinel\.toml\b"
    r"|\.(bashrc|bash_profile|bash_login|profile|zshrc)\b|\bprofile\.ps1\b)"
)
_READ_VERB_NAMES = (
    "cat|type|more|less|head|tail|get-content|gc|grep|rg|sed|awk|sort|uniq|findstr"
    "|select-string|sls|strings|xxd|base64|bat|nl|od"
)
_READ_VERBS = r"\b(" + _READ_VERB_NAMES + r")\b"
_WRITE_VERBS = (
    r"(\b(cp|copy|copy-item|cpi|xcopy|robocopy|mv|move|move-item|mi|rm|del|erase|rd|rmdir"
    r"|remove-item|ri|ren|rename|rename-item|rni|set-content|sc|add-content|ac|out-file|tee|dd"
    r"|truncate|unlink|icacls|attrib|takeown|mklink|ln|new-item|ni|chmod|chown|install)\b"
    r"|\bsed\s+-[a-z]*i|\bperl\s+-[a-z]*i|>)"
)
_CREDENTIAL_PATHS = (
    r"(\.env\b(?!\.example)|\.en[\[*?]|\.e\*|\.ssh|\.aws|\.kube|gcloud|\.netrc|\.git-credentials"
    r"|\.pem\b|\.key\b|id_rsa|id_ed25519)"
)

# (id, class, pattern, decision, reason). Evaluated per command; any deny beats any ask.
BASH_RULES = [
    ("BG-01", "network_tool",
     r"\b(curl|wget|nc|ncat|netcat|socat|telnet|iwr|irm|invoke-webrequest|invoke-restmethod"
     r"|certutil|bitsadmin|start-bitstransfer)\b|net\.webclient|system\.net\.http",
     "deny", "network transfer tools are not allowed; ask the user"),
    ("BG-02", "remote_access", r"\b(ssh|scp|sftp|rsync)\b", "deny",
     "remote access/copy is not allowed from the agent"),
    ("BG-03", "env_dump", r"(^|[;&|]\s*)(printenv|env|set|export\s+-p)\s*($|[;&|])", "deny",
     "dumping environment variables can expose secrets"),
    ("BG-04", "credential_read",
     r"\b(" + _READ_VERB_NAMES + r"|cp|copy|copy-item|xcopy|robocopy|mv|move|move-item)\b"
     + _SEG_END + _CREDENTIAL_PATHS,
     "deny", "reading or copying credential files is not allowed"),
    ("BG-05", "shell_history", r"(^|[;&|]\s*)history\b", "deny", "shell history may contain secrets"),
    ("BG-06", "force_push", r"git\s+push\b.*(--force|\s-f\b|--force-with-lease)", "deny",
     "force push requires human approval"),
    ("BG-07", "history_rewrite", r"git\s+(filter-repo|filter-branch)|\bbfg\b", "deny",
     "rewriting Git history requires human approval; propose the exact command to the user"),
    ("BG-08", "global_git_config", r"git\s+config\s+--global", "deny",
     "changing global git config is not allowed"),
    ("BG-09", "destructive_delete", r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|~|\$HOME)(\s|$)", "deny",
     "destructive delete of root or home"),
    ("BG-10", "privilege_escalation", r"\bsudo\b|(^|[;&|]\s*)su\s", "deny",
     "privilege escalation is not allowed"),
    ("BG-11", "cloud_cli",
     r"(^|[;&|]\s*)(aws|gcloud|az|kubectl|heroku|vercel|netlify)\b|terraform\s+apply", "deny",
     "cloud/deploy CLIs are run by the user after approval"),
    ("BG-12", "world_writable", r"chmod\s+(-R\s+)?777", "deny",
     "world-writable permissions are not allowed"),
    ("BG-13", "pipe_to_shell", r"\|\s*(sh|bash|zsh|pwsh|powershell|cmd|iex|invoke-expression)\b",
     "deny", "piping into a shell is not allowed"),
    ("BG-14", "state_dir_access",
     r"(" + _READ_VERBS + r"|" + _WRITE_VERBS + r")" + _SEG_END + _STATE
     + r"|" + _STATE + _SEG_END + _WRITE_VERBS,
     "deny", "Sentinel's state and Claude's user config are protected; use the sentinel CLI"),
    ("BG-20", "guard_write",
     _WRITE_VERBS + _SEG_END + _GUARD + r"|" + _GUARD + _SEG_END + _WRITE_VERBS,
     "deny", "the agent gateway, its settings and MCP config are changed by a person, not an agent"),
    ("BG-22", "clean_ignored",
     r"\bgit\s+clean\b" + _SEG_END + r"\s-[a-zA-Z]*[xX]"
     r"|\bgit\s+stash\b" + _SEG_END + r"(\s-[a-zA-Z]*a\b|\s--all\b)", "deny",
     "git clean -x / git stash --all remove ignored files, including Sentinel's state"),
    # Docker can mount the host or run privileged; the sandbox is the reviewed way to use it.
    ("BG-24", "container_host_access",
     r"\b(docker|podman|nerdctl)(\.exe)?\b" + _SEG_END
     + r"(--privileged|\s-v\s|\s-v[=:/\\A-Za-z]|--volume|--mount|docker\.sock|--pid[= ]host"
     r"|--net(work)?[= ]host|--cap-add|--security-opt|--device|--userns[= ]host)"
     r"|\bdocker\s+context\s+(use|create|update)\b|\b(DOCKER_HOST|DOCKER_CONTEXT)\s*=", "deny",
     "this Docker command can reach the host; use sentinel sandbox run instead"),
    ("BG-25", "container_cli", r"(^|[;&|(]\s*)(docker|podman|nerdctl)(\.exe)?\b", "ask",
     "runs a container command; the sandbox is the reviewed way to run code in Docker"),
    # Every human-only Sentinel action. The CLI also checks for a terminal, but a new console
    # (start, Start-Process) has one, so the agent must not run these at all.
    # Options may come before the action (`mcp-allowlist --actor x off`), so the action is matched
    # anywhere later in the same command segment (security review 2026-11-10).
    ("BG-17", "gateway_control",
     r"\bkill-switch\b" + _SEG_END + r"\boff\b"
     r"|\bmanifest\b" + _SEG_END + r"\b(off|apply)\b"
     r"|\bmcp-allowlist\b" + _SEG_END + r"\b(off|pin-tools)\b"
     r"|\bsandbox\b" + _SEG_END + r"\bstrict\b" + _SEG_END + r"\boff\b"
     r"|\bpin-hooks\b|\bcreds\b" + _SEG_END + r"\bset\b|\binventory\b" + _SEG_END + r"\b(set|import)\b"
     r"|\bagentlog\b" + _SEG_END + r"\barchive\b", "deny",
     "this Sentinel action is a person's decision; ask the user to run it in their own terminal"),
    # The hooks run only from Claude Code: re-running session_log.py by hand could rewrite the MCP
    # launch check mid-session (ADR-0028).
    # Matches running a hook file (live, or the patch copy, which acts on the same state folder),
    # not reading it or a test file such as test_output_guard.py.
    ("BG-28", "hook_run",
     r"\b(python[\d.]*|pythonw|py|uv)(\.exe)?\b" + _SEG_END
     + r"(\.claude[\\/]+hooks[\\/]+[\w.-]+\.py\b|(^|[\s\"'\\/=])(bash_guard|prompt_guard|"
     r"output_guard|protect_sensitive_files|scan_written_file|session_log|mcp_log|gateway|"
     r"_mcppin|_taint|_policy|_firewall|_manifest|_decision_log)\.py\b)", "deny",
     "the guard hooks run only from Claude Code"),
    # A local-scope MCP server overrides the project's .mcp.json entry of the same name, outside
    # Sentinel's view (~/.claude.json). Adding or changing servers is a person's decision.
    ("BG-29", "agent_config",
     r"\bclaude\b" + _SEG_END + r"\bmcp\b" + _SEG_END
     + r"\b(add|add-json|add-from-claude-desktop|remove|reset-project-choices)\b"
     r"|\bclaude\b" + _SEG_END + r"\bconfig\b" + _SEG_END + r"\b(set|add|remove)\b", "deny",
     "adding or changing MCP servers or Claude Code settings is a person's decision"),
    ("BG-26", "state_dir_access",
     r"\b(cd|pushd|chdir|set-location|sl|push-location)\b" + _SEG_END + _STATE, "deny",
     "Sentinel's state folder is protected; use the sentinel CLI"),
    ("BG-18", "package_run",
     r"\b(npx|uvx|bunx|pnpx)\b|\bpipx\s+run\b|\b(npm|pnpm)\s+(exec|dlx)\b|\byarn\s+dlx\b"
     r"|\buv\s+(run|tool\s+run)\b" + _SEG_END + r"--with\b",
     "ask", "downloads and runs a package"),
    ("BG-19", "link_create",
     r"\bmklink\b|(^|[;&|]\s*)ln\s|\bjunction(\.exe)?\b"
     r"|new-item\b" + _SEG_END + r"-itemtype\s+[\"']?(symboliclink|junction|hardlink)",
     "ask", "creates a link, which can make a protected file look like an ordinary one"),
    ("BG-21", "fake_terminal", r"\bwinpty\b|\bscript\s+-[a-z]*c", "ask",
     "runs a command under a fake terminal, which can pass human-only checks"),
    ("BG-15", "inline_code", r"\b(iex|invoke-expression)\b", "ask",
     "evaluates a string as PowerShell code"),
]  # fmt: skip

# --- Inline code: one small argument parser per interpreter family --------------------------------
_PY = re.compile(r"(python[0-9.]*w?|py|pypy[0-9.]*)")
_NODE = re.compile(r"(node|nodejs|bun|deno)")
_RUBY_PERL = re.compile(r"(ruby|perl)")
_PHP = re.compile(r"php[0-9.]*")
_PS = re.compile(r"(pwsh|powershell)")
_PY_CODE_MODULES = ("timeit", "code", "pdb", "trace", "cprofile", "profile", "runpy")
_PS_DASHES = "-/–—―"  # PowerShell accepts these as the parameter prefix
_PS_TAKES_VALUE = (
    "executionpolicy", "ep", "ex", "exec", "windowstyle", "w", "workingdirectory", "wd",
    "configurationname", "settingsfile", "custompipename", "outputformat", "of",
    "inputformat", "if", "version", "v",
)  # fmt: skip
_ASK = Decision("ask", "BG-15", "inline_code", "runs inline code that the guard cannot inspect", "")


def _segments(command):
    """(text, piped) per simple command: split on unquoted ; & | newline (&&, || too)."""
    out, buf, quote, piped, i = [], [], "", False, 0
    while i < len(command):
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch in ";&|\n":
            double = command[i : i + 2] in ("&&", "||")
            out.append(("".join(buf), piped))
            piped = ch == "|" and not double
            buf = []
            i += 2 if double else 1
            continue
        else:
            buf.append(ch)
        i += 1
    out.append(("".join(buf), piped))
    return out


def _tokens(segment):
    try:
        lexer = shlex.shlex(segment, posix=False)
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:  # unbalanced quotes
        return segment.split()


def _bare(token):
    return token.strip("\"'`")


def _program(token):
    name = re.split(r"[\\/]", _bare(token))[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _python(args, piped):
    j, script, stdin = 0, False, False
    while j < len(args):
        a = args[j]
        if a.startswith("<"):
            stdin = True
            break
        if a == "-":
            return _ASK
        if a == "--":
            script = j + 1 < len(args)
            break
        if a.startswith("--"):
            j += 1
            continue
        if a.startswith("-") and len(a) > 1:
            cluster, consume_next, k = a[1:], False, 0
            while k < len(cluster):
                ch = cluster[k]
                if ch == "c":
                    return _ASK
                if ch == "m":
                    module = cluster[k + 1 :] or (_bare(args[j + 1]) if j + 1 < len(args) else "")
                    if module.split(".")[0].lower() in _PY_CODE_MODULES:
                        return _ASK
                    return None  # an installed module, not inline code
                if ch in "WXQ":
                    consume_next = k + 1 == len(cluster)
                    break
                k += 1
            j += 2 if consume_next else 1
            continue
        script = True
        break
    return _ASK if not script and (stdin or piped) else None


def _node(name, args, piped):
    if name in ("deno", "bun") and args and args[0].lower() == "eval":
        return _ASK
    j, script, stdin = 0, False, False
    while j < len(args):
        a = args[j]
        nxt = args[j + 1] if j + 1 < len(args) else ""
        if a.startswith("<"):
            stdin = True
            break
        if a in ("-", "-e", "--eval", "-p", "--print") or a.startswith(("--eval=", "--print=")):
            return _ASK
        if re.fullmatch(r"-[a-zA-Z]+", a) and ("e" in a[1:] or "p" in a[1:]):
            return _ASK
        if a in ("--import", "--require", "-r", "--loader", "--experimental-loader"):
            if "data:" in nxt:
                return _ASK
            j += 2
            continue
        if "data:" in a:
            return _ASK
        if a.startswith("-"):
            j += 1
            continue
        if a.lower() == "run" and name == "deno":
            j += 1
            continue
        if a.lower().startswith(("http:", "https:")):
            return _ASK  # runs code fetched from the network
        script = True
        break
    return _ASK if not script and (stdin or piped) else None


def _ruby_perl_php(name, args, piped):
    j, script, stdin = 0, False, False
    while j < len(args):
        a = args[j]
        if a.startswith("<"):
            stdin = True
            break
        if a == "-":
            return _ASK
        if name.startswith("php"):
            if re.fullmatch(r"-[a-zA-Z]*r", a):
                return _ASK
        elif re.fullmatch(r"-[a-zA-Z]*[eE]", a):
            return _ASK
        if a.startswith("-"):
            j += 1
            continue
        script = True
        break
    return _ASK if not script and (stdin or piped) else None


def _powershell(args, piped):
    j = 0
    while j < len(args):
        a = args[j]
        if a.startswith("<"):
            return _ASK
        if a[:1] not in _PS_DASHES or len(a) == 1:
            if a == "-" or not a.lower().endswith(".ps1"):
                return _ASK  # a positional argument is run as a command (-Command)
            return None
        name = a.lstrip(_PS_DASHES).lower()
        if re.fullmatch(r"e|ec|en|enc|enco\w*|encodedcommand|encodeda\w*", name):
            return Decision(
                "deny", "BG-16", "encoded_command",
                "encoded PowerShell commands hide what they do and are not allowed", "",
            )  # fmt: skip
        if re.fullmatch(r"c|co|com\w*", name):
            return _ASK
        if name in ("f", "file"):
            return None
        j += 2 if name in _PS_TAKES_VALUE else 1
    return _ASK if piped else None


def _segment_tokens(command):
    """(tokens, piped) per simple command, with line continuations and glued empty quotes removed."""
    command = re.sub(r"(\\|\^|`)\r?\n", " ", command)  # line continuations: bash, cmd, PowerShell
    for segment, piped in _segments(command):
        # A shell glues empty quotes to the neighbouring word: python ""-c, py""thon -c.
        segment = re.sub(r"(?<=\S)(\"\"|'')|(\"\"|'')(?=\S)", "", segment)
        yield _tokens(segment), piped


def _launched(tokens):
    """Index of the program a segment runs, skipping a leading `uv run` WITHOUT options (options
    such as --project could pick another project's programs)."""
    if len(tokens) >= 2 and _program(tokens[0]) == "uv" and _bare(tokens[1]).lower() == "run":
        return 2
    return 0


def _sandboxed(tokens):
    """`sentinel sandbox run ...` or `uv run sentinel sandbox run ...` (ADR-0017), used only by
    strict mode. Only the bare command name counts: a path like ./sentinel could be a program the
    agent wrote. Not a security boundary: a shell function or alias named sentinel in the agent's
    shell would also match (ADR-0017, security review)."""
    j = _launched(tokens)
    if len(tokens) < j + 3 or _bare(tokens[j]).lower() not in ("sentinel", "sentinel.exe"):
        return False
    return [_bare(t).lower() for t in tokens[j + 1 : j + 3]] == ["sandbox", "run"]


_CODE_RUNNERS = (
    _PY, _NODE, _RUBY_PERL, _PHP, _PS,
    re.compile(r"pytest|bash|sh|zsh|dash|cmd|make|npm|pnpm|yarn|go|java|cscript|wscript|cargo"),
)  # fmt: skip
_SCRIPT = re.compile(r".+\.(py|pyw|js|mjs|cjs|ts|sh|bash|bat|cmd|ps1|rb|pl|php)", re.IGNORECASE)


def _runs_code(tokens):
    """Strict mode's test for 'this runs code'. Advisory (ADR-0017): a list is never complete."""
    if any(any(p.fullmatch(_program(t)) for p in _CODE_RUNNERS) for t in tokens):
        return True
    j = _launched(tokens)
    if j == 2 and len(tokens) > 2:
        return True  # uv run <anything> runs a program from the project environment
    return bool(tokens) and bool(_SCRIPT.fullmatch(_bare(tokens[0])))


def _inline(command):
    """The strongest inline-code finding in a command: deny (encoded) > ask > None.
    No exemption for the sandbox: a shell-level name check cannot prove the sandbox really runs
    (security review 2026-11-03), so sandboxed one-liners ask like any other inline code."""
    found = None
    for tokens, piped in _segment_tokens(command):
        for i, token in enumerate(tokens):
            name = _program(token)
            args = [_bare(t) for t in tokens[i + 1 :]]
            if _PY.fullmatch(name):
                result = _python(args, piped)
            elif _NODE.fullmatch(name):
                result = _node(name, args, piped)
            elif _RUBY_PERL.fullmatch(name) or _PHP.fullmatch(name):
                result = _ruby_perl_php(name, args, piped)
            elif _PS.fullmatch(name):
                result = _powershell(args, piped)
            else:
                continue
            if result is not None and result.decision == "deny":
                return result
            found = found or result
            break  # the first interpreter in a segment owns its arguments
    return found


def _strict(command, home):
    """Sandbox strict mode (ADR-0017): code run OUTSIDE the sandbox needs the user's confirmation."""
    if not home or not _present(os.path.join(home, SANDBOX_STRICT_NAME)):
        return None
    segments = list(_segment_tokens(command))
    if len(segments) == 1 and _sandboxed(segments[0][0]):
        return None  # exactly one command, and it is the sandbox
    for tokens, _piped in segments:
        if _runs_code(tokens):
            return Decision(
                "ask", "BG-23", "unsandboxed_code",
                "runs code outside the sandbox while sandbox strict mode is on "
                "(use: sentinel sandbox run -- <command>)",
                command,
            )  # fmt: skip
    return None


def _command(command, home=""):
    deny, ask = None, None
    for rule_id, cls, pattern, decision, reason in BASH_RULES:
        if re.search(pattern, command, flags=_FLAGS):
            hit = Decision(decision, rule_id, cls, reason, command)
            if decision == "deny":
                deny = deny or hit
            else:
                ask = ask or hit
    if deny:
        return deny
    inline = _inline(command)
    if inline is not None:
        return inline._replace(target=command)
    if ask:
        return ask
    strict = _strict(command, home)
    if strict is not None:
        return strict
    return Decision("allow", "GW-00", "command", "", command)


# --- File tools ----------------------------------------------------------------------------------
ALLOWED_TEMPLATES = (".env.example", ".env.sample", ".env.template")
# (id, class, pattern, scope): "all" = no reads or writes, "write" = reading is fine.
FILE_RULES = [
    ("PF-01", "env_file", r"(^|/)\.env($|\.)", "all"),
    ("PF-02", "key_file", r"\.(pem|key|p12|pfx|jks|keystore)$", "all"),
    ("PF-03", "ssh_key", r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$", "all"),
    ("PF-04", "ssh_dir", r"(^|/)\.ssh(/|$)", "all"),
    ("PF-05", "cloud_credentials", r"(^|/)\.aws(/|$)", "all"),
    ("PF-06", "cloud_credentials", r"(^|/)\.azure(/|$)", "all"),
    ("PF-07", "cloud_credentials", r"(^|/)\.kube(/|$)", "all"),
    ("PF-08", "cloud_credentials", r"(^|/)\.config/gcloud(/|$)", "all"),
    ("PF-09", "cloud_credentials", r"(^|/)\.docker/config\.json$", "all"),
    ("PF-10", "credential_store", r"(^|/)\.netrc$", "all"),
    ("PF-11", "credential_store", r"(^|/)\.git-credentials$", "all"),
    ("PF-12", "secrets_dir", r"(^|/)secrets(/|$)", "all"),
    ("PF-13", "credential_json", r"credentials[^/]*\.json$", "all"),
    ("PF-14", "credential_json", r"service[-_]?account[^/]*\.json$", "all"),
    ("PF-15", "guard_config", r"(^|/)\.claude/(hooks/|backup)", "write"),
    ("PF-16", "guard_config", r"(^|/)\.claude/settings(\.local)?\.json$", "write"),
    ("PF-17", "state_dir", r"(^|/)\.sentinel(/|$)", "all"),
    ("PF-18", "mcp_config", r"(^|/)\.mcp\.json$", "write"),
    ("PF-19", "user_agent_config", r"(^|/)\.claude\.json$", "all"),
    ("PF-20", "python_startup", r"\.pth$|(^|/)(site|user)customize\.py$", "write"),
    (
        "PF-22",
        "token_file",
        r"(^|/)\.(npmrc|pypirc|vault-token|htpasswd|envrc)$|\.(ppk|p8|tfstate|tfvars)$"
        r"|client_secret[^/]*\.json$|(^|/)google-services\.json$|(^|/)\.gnupg(/|$)"
        r"|(^|/)kubeconfig[^/]*$",
        "all",
    ),
    (
        "PF-23",
        "agent_config",
        r"(^|/)sentinel\.toml$|(^|/)\.(bashrc|bash_profile|bash_login|profile|zshrc)$"
        r"|(^|/)(microsoft\.powershell_)?profile\.ps1$",
        "write",
    ),
]


def normalize_path(path, cwd=""):
    """One spelling per file, so the same file always gets the same fingerprint (R9 join):
    absolute, forward slashes, lower case on Windows. Mirrors sentinel.agentgate.normalize_path."""
    text = os.path.expanduser(str(path))
    if not os.path.isabs(text):
        text = os.path.join(cwd or os.getcwd(), text)
    text = os.path.normpath(text).replace("\\", "/")
    return text.lower() if os.name == "nt" else text


def _windows_trimmed(text):
    """Win32 drops trailing dots and spaces from each path part: '.env ' opens '.env'."""
    return "/".join(part.rstrip(" .") or part for part in text.split("/"))


def _has_stream(text):
    """An NTFS alternate data stream (file::$DATA, file:stream) after the drive letter."""
    rest = re.sub(r"^([a-zA-Z]:|//[?.]/[a-zA-Z]:)", "", text)
    return ":" in rest


def _file_targets(tool, tool_input):
    # Every tool may name a file in file_path, notebook_path or path (the old hook read all three
    # for every tool; a Grep with file_path slipped past an earlier version of this function).
    # glob is a path filter for Grep; for Glob the pattern itself is the path.
    keys = ("file_path", "notebook_path", "path", "glob")
    if tool == "Glob":
        keys = (*keys, "pattern")
    return [
        str(tool_input[k]) for k in keys if isinstance(tool_input.get(k), str) and tool_input[k]
    ]


def _file_check(tool, raw, cwd):
    norm = os.path.expanduser(raw).replace("\\", "/")
    target = normalize_path(raw, cwd)
    real = normalize_path(os.path.realpath(target), cwd)  # symlinks, junctions, short names
    spellings = {norm, target, real, _windows_trimmed(norm), _windows_trimmed(target)}
    if os.name == "nt" and any(_has_stream(s) for s in (norm, target)):
        return Decision("deny", "PF-21", "alternate_stream",
                        "%s on an alternate data stream is blocked" % tool, target)  # fmt: skip
    if norm.endswith(ALLOWED_TEMPLATES) and real.endswith(ALLOWED_TEMPLATES):
        return None
    flags = re.IGNORECASE if os.name == "nt" else 0
    for rule_id, cls, pattern, scope in FILE_RULES:
        if any(re.search(pattern, s, flags=flags) for s in spellings):
            if scope == "write" and tool not in WRITE_TOOLS:
                continue
            return Decision(
                "deny", rule_id, cls,
                "%s on a sensitive path is blocked; ask the user, or refer to the secret by "
                "fingerprint only" % tool,
                target,
            )  # fmt: skip
    return None


def _file(tool, tool_input, cwd):
    targets = _file_targets(tool, tool_input)
    for raw in targets:
        hit = _file_check(tool, raw, cwd)
        if hit is not None:
            return hit
    first = normalize_path(targets[0], cwd) if targets else ""
    return Decision("allow", "GW-00", "file_access", "", first)


# --- MCP and kill switch -------------------------------------------------------------------------
def _present(path):
    """True if the file exists. Anything other than 'not found' counts as present (fail closed)."""
    try:
        os.stat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return True


def mcp_server_of(tool):
    """mcp__<server>__<tool> -> <server>. Everything before the LAST '__', as Sentinel's log reader
    does, so both sides name the same server (a server called 'a__b' is not 'a')."""
    rest = tool[len("mcp__") :]
    return rest.rsplit("__", 1)[0] if "__" in rest else ""


def _mcp(tool, home, data=None):
    server = mcp_server_of(tool)
    path = os.path.join(home, MCP_ALLOWLIST_NAME)
    if not _present(path):
        return Decision("allow_mcp", "MCP-01", "mcp_tool", "", "")  # never enabled: record only
    try:
        with open(path, encoding="utf-8") as handle:
            servers = json.load(handle).get("servers")
        if not isinstance(servers, dict):
            raise ValueError("servers must be an object")
    except Exception:  # noqa: BLE001 - an unreadable allow-list must not open the door
        return Decision("deny", "MCP-03", "mcp_tool", "the MCP allow-list cannot be read", "")
    if server and server in servers:
        return _mcp_pinned(tool, server, servers[server], home, data or {})
    return Decision(
        "deny", "MCP-02", "mcp_tool",
        "MCP server '%s' is not approved (a person runs: sentinel inventory set mcp-<name> "
        "--approve --owner ... --pinned-version ...)" % server,
        "",
    )  # fmt: skip


MCP_DRIFT_NAME = "mcp-drift.json"


def _mcp_pinned(tool, server, entry, home, data):
    """An approved server (ADR-0028). With a pinned launch hash: a server whose `.mcp.json`
    settings changed, went missing or could not be checked at session start is denied (MCP-04),
    and so is every pinned server when the drift file is absent, unreadable, or bound to another
    session or workspace (fail closed). With a pinned tool list: a tool not on it asks first
    (MCP-05), the visible sign of a rug pull."""
    if not isinstance(entry, dict):
        return Decision("allow_mcp", "MCP-01", "mcp_tool", "", "")
    if entry.get("config_hash"):
        try:
            import _mcppin

            reason = _mcppin.check(home, server, str(data.get("session_id") or ""),
                                   os.environ.get("CLAUDE_PROJECT_DIR", ""))  # fmt: skip
        except Exception:  # noqa: BLE001 - not checked this session: do not trust the pin
            reason = "not checked"
        if reason:
            return Decision(
                "deny", "MCP-04", "mcp_drift",
                "MCP server '%s' does not match its approved launch settings (%s); a person "
                "reviews it and runs: sentinel inventory agents, then sentinel inventory set "
                "mcp-<name> --approve ..." % (server, reason),
                "",
            )  # fmt: skip
    tools = entry.get("tools")
    name = tool.rsplit("__", 1)[-1]
    if isinstance(tools, list) and tools and name not in tools:
        return Decision(
            "ask", "MCP-05", "mcp_new_tool",
            "MCP server '%s' offers a tool that was not there when it was pinned (%s): check it "
            "before allowing it" % (server, name[:64]),
            "",
        )  # fmt: skip
    return Decision("allow_mcp", "MCP-01", "mcp_tool", "", "")


MANIFEST_NAME = "agent-manifest.json"
_RANK = {"allow": 0, "allow_mcp": 0, "ask": 1, "deny": 2}


def decide(data, home):
    """The decision for one hook payload (dict). Never raises: any internal error denies.

    Four layers, each of which can only tighten (allow -> ask or deny, ask -> deny): the
    built-in rules, the agent manifest (ADR-0024), the context firewall (ADR-0025), the
    session trifecta gate (ADR-0027)."""
    base = _base_decide(data, home)
    if base.decision == "deny":
        return base
    after = _with_manifest(data, home, base)
    if after.decision == "deny":
        return after
    after = _with_firewall(data, after)
    if after.decision == "deny":
        return after
    return _with_taint(data, home, after)


def _tighter(current, verdict):
    if verdict is None or _RANK[verdict[0]] <= _RANK.get(current.decision, 0):
        return current
    return Decision(verdict[0], verdict[1], verdict[2], verdict[3], current.target)


def _with_firewall(data, current):
    """Data leaving the machine through WebFetch, WebSearch or an MCP tool (ADR-0025). For those
    tools an error denies (fail closed); other tools are not affected."""
    tool = str(data.get("tool_name") or "")
    if tool not in ("WebFetch", "WebSearch") and not tool.startswith("mcp__"):
        return current
    try:
        import _firewall

        tool_input = data.get("tool_input") if isinstance(data.get("tool_input"), dict) else {}
        return _tighter(current, _firewall.decide_tool(tool, tool_input))
    except Exception:  # noqa: BLE001 - fail closed for data that would leave the machine
        return Decision("deny", "FW-99", "firewall_error",
                        "the context firewall could not check this call", "")  # fmt: skip


def _leaves_machine(tool):
    return tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__")


def _with_taint(data, home, current):
    """The trifecta gate (ADR-0027): a data-leaving call in a session that has read untrusted
    content AND seen private data asks first (TF-01). The output guard sets the two legs. A state
    that cannot be read asks too (TF-99): this layer asks, it never opens or hard-closes.

    TF-01 wins a tie with an earlier ask (FW-03, a manifest ask) and carries its reason along: the
    log keeps one rule per call, and rule R13 must see the attempt (security review 2026-11-06).
    A deny never reaches this layer."""
    tool = str(data.get("tool_name") or "")
    if not _leaves_machine(tool):
        return current
    try:
        import _taint

        if not _taint.tainted(home, str(data.get("session_id") or "")):
            return current
    except Exception:  # noqa: BLE001
        return _tighter(current, ("ask", "TF-99", "trifecta_error",
                                  "Sentinel could not check this session's taint state"))  # fmt: skip
    reason = ("this session has read untrusted content and seen a credential; this %s call could "
              "send it out. Check what it sends before allowing it" % tool)  # fmt: skip
    if current.decision == "ask" and current.reason:
        reason += "; also: " + current.reason
    return Decision("ask", "TF-01", "trifecta", reason, current.target)


def _with_manifest(data, home, base):
    if not _present(os.path.join(home, MANIFEST_NAME)):
        return base
    tool = str(data.get("tool_name") or "")
    try:
        import _manifest

        manifest = _manifest.load_compiled(home)
    except Exception:  # noqa: BLE001 - a manifest that cannot be read must not open the door
        if tool in READ_ONLY_TOOLS:
            return base
        return Decision("deny", "MF-05", "manifest_error",
                        "the agent manifest cannot be read; only reading is allowed", "")  # fmt: skip
    if manifest is None:
        return base
    try:
        tool_input = data.get("tool_input") if isinstance(data.get("tool_input"), dict) else {}
        extra = _manifest.check(manifest, tool, tool_input, str(data.get("cwd") or ""))
    except Exception:  # noqa: BLE001 - fail closed
        return Decision("deny", "MF-99", "manifest_error",
                        "the agent manifest could not be evaluated", "")  # fmt: skip
    return _tighter(base, extra)


def _base_decide(data, home):
    """The built-in rules for one hook payload. Never raises: any internal error denies."""
    try:
        tool = str(data.get("tool_name") or "")
        tool_input = data.get("tool_input")
        if tool_input is None:
            tool_input = {}
        if not isinstance(tool_input, dict):
            raise TypeError("tool_input must be an object")
        cwd = str(data.get("cwd") or "")
        if _present(os.path.join(home, KILL_SWITCH_NAME)) and tool not in READ_ONLY_TOOLS:
            return Decision(
                "deny", "KS-01", "kill_switch",
                "the agent kill switch is on: only reading is allowed until a person turns it off",
                "",
            )  # fmt: skip
        if tool.startswith("mcp__"):
            return _mcp(tool, home, data)
        if tool in FILE_TOOLS:
            return _file(tool, tool_input, cwd)
        command = tool_input.get("command")
        if tool == "Bash" or "command" in tool_input:  # Bash, PowerShell and any other shell tool
            state = normalize_path(home).rstrip("/")
            where = normalize_path(cwd) if cwd else ""
            if where and (where == state or where.startswith(state + "/")):
                # `cd .sentinel` in an earlier call, then `del x`: the folder is the target.
                return Decision("deny", "BG-27", "state_dir_access",
                                "commands may not run inside Sentinel's state folder", "")  # fmt: skip
            text = command if isinstance(command, str) else ""
            return _command(text, home) if text else Decision("allow", "GW-00", "command", "", "")
        return Decision("allow", "GW-00", "tool_call", "", "")
    except Exception:  # noqa: BLE001 - fail closed
        return Decision(
            "deny", "GW-99", "gateway_error", "the gateway could not evaluate this call", ""
        )
