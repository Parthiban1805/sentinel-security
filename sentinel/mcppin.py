"""MCP server pinning and rug-pull detection (v0.7e F2, ADR-0028). Stdlib only.

This file is ALSO the gateway's `.claude/hooks/_mcppin.py` (a byte-identical copy shipped by the
gateway patch; a test keeps them identical). It must import nothing from `sentinel` and run on
the first `python` on PATH, which can be 3.10.

An approval used to cover a server NAME. Tool poisoning and "rug pulls" (Invariant Labs, 2025;
mcp-scan) change what an approved server does without changing its name: a new package version,
other arguments, another URL, an env variable such as NODE_OPTIONS or a registry URL. Here an
approval is tied to a keyed hash of the server's whole entry in the project's `.mcp.json`:

- `config_hash`: HMAC-SHA256 (the fingerprint key, domain-separated) over the entire entry, env and
  header VALUES included. Values are never stored; only the keyed hash is. Rotating a literal
  credential in `.mcp.json` therefore needs a re-approval (a project file should hold `${VAR}`
  references, not values).
- `drift`: for every allow-list entry with a `config_hash`, whether the server is unchanged,
  `changed`, `missing` from `.mcp.json`, or `unverifiable`. The SessionStart hook writes it to
  `<home>/mcp-drift.json`, bound to the session and the workspace; within a session it can only
  grow. The gateway denies a drifted server, and every pinned server when the file is absent,
  unreadable or bound to another session or workspace (MCP-04).
- `launch_findings`: hygiene M1 (launched without a fixed version), M2 (a remote server over plain
  http), M3 (the launch depends on `${VAR}` expansion, which the hash cannot see). Server names
  only, never arguments.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit

MCP_CONFIG = ".mcp.json"
ALLOWLIST_NAME = "mcp-allowlist.json"
DRIFT_NAME = "mcp-drift.json"
KEY_NAME = "fingerprint.key"
ALL = "*"  # a drift entry that covers every pinned server (the check itself failed)
NOT_CHECKED = "not checked"
_DOMAIN = b"sentinel/mcp-config/v1\x00"  # the fingerprint key also hashes credentials
_KEY_BYTES = 32
_HASH = re.compile(r"[0-9a-f]{32}")
_SAFE_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


# --- the pin -----------------------------------------------------------------------------------
def canonical(config: Any) -> str:
    """The whole server entry, keys sorted. Never stored: it can hold credentials."""
    return json.dumps(config, sort_keys=True, separators=(",", ":"), default=str)


def config_hash(config: Any, key: bytes) -> str:
    data = _DOMAIN + canonical(config).encode("utf-8", "surrogatepass")
    return hmac.new(key, data, hashlib.sha256).hexdigest()[:32]


def session_key(session_id: str) -> str:
    """The decision log's session hash; "" when there is no id."""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16] if session_id else ""


def same_place(a: str, b: str) -> bool:
    def norm(path: str) -> str:
        return os.path.normcase(os.path.realpath(path))

    return bool(a) and bool(b) and norm(a) == norm(b)


def read_key(home: str) -> bytes | None:
    try:
        with open(os.path.join(home, KEY_NAME), "rb") as handle:
            key = handle.read()
    except OSError:
        return None
    return key if len(key) == _KEY_BYTES else None


def load_servers(workspace: str) -> dict[str, Any]:
    """`mcpServers` from `<workspace>/.mcp.json`; {} if there is no file. Raises ValueError if it
    cannot be read."""
    path = os.path.join(workspace, MCP_CONFIG)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        raise ValueError(f"{MCP_CONFIG} is not readable JSON") from None
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    return servers if isinstance(servers, dict) else {}


def pinned(home: str) -> dict[str, str]:
    """Allow-list entries with a config hash: name -> hash ("" if the hash is malformed, which
    makes the server unverifiable). {} when allow-list mode is off. Raises ValueError if the
    allow-list exists but cannot be read."""
    path = os.path.join(home, ALLOWLIST_NAME)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            servers = json.load(handle).get("servers")
    except (OSError, UnicodeDecodeError, ValueError, AttributeError, RecursionError):
        raise ValueError("the MCP allow-list is not readable") from None
    if not isinstance(servers, dict):
        raise ValueError("the MCP allow-list has no servers object")
    out: dict[str, str] = {}
    for name, entry in servers.items():
        if isinstance(entry, dict) and entry.get("config_hash"):
            value = entry["config_hash"]
            out[str(name)] = value if isinstance(value, str) and _HASH.fullmatch(value) else ""
    return out


def drift(home: str, workspace: str) -> dict[str, str]:
    """name -> "changed" | "missing" | "unverifiable" for each pinned server that does not match
    `.mcp.json` now; {ALL: "unverifiable"} if the pins themselves cannot be read."""
    try:
        pins = pinned(home)
    except ValueError:
        return {ALL: "unverifiable"}
    if not pins:
        return {}
    key = read_key(home)
    try:
        current = load_servers(workspace)
    except ValueError:
        current = None
    if key is None or current is None:
        return dict.fromkeys(pins, "unverifiable")
    out: dict[str, str] = {}
    for name, expected in pins.items():
        if not expected:
            out[name] = "unverifiable"
        elif name not in current:
            out[name] = "missing"
        elif not hmac.compare_digest(config_hash(current[name], key), expected):
            out[name] = "changed"
    return out


def read_drift(home: str) -> dict[str, Any] | None:
    """The drift file, or None if it is absent or unreadable."""
    try:
        with open(os.path.join(home, DRIFT_NAME), encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
        return None
    return data


def _replace(tmp: str, path: str) -> None:
    """os.replace, retried: on Windows it fails while another process has the file open."""
    for attempt in range(5):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.05 * (attempt + 1))


def write_drift(home: str, workspace: str, session_id: str | None = None) -> dict[str, str]:
    """Compute the drift and write `<home>/mcp-drift.json`, bound to a session and workspace.

    `session_id` given (the SessionStart hook): the file is bound to that session; a second write
    for the SAME session keeps every drift already found (it can add, never clear), so re-running
    the check after quietly restoring `.mcp.json` does not clear a server that is already running.
    `session_id` None (a person at the terminal, after an approval): the existing binding is kept
    and the result replaces it, so a re-approved server is usable at once. With no binding yet the
    file stays unbound, and the gateway treats it as not checked until the next session start."""
    found = drift(home, workspace)
    old = read_drift(home)
    if session_id is None:
        bound_session = str((old or {}).get("session", ""))
        bound_workspace = str((old or {}).get("workspace", "")) or workspace
        servers = found
    else:
        bound_session, bound_workspace = session_key(session_id), workspace
        servers = dict(found)
        if old and old.get("session") == bound_session and bound_session:
            for name, reason in old["servers"].items():
                servers.setdefault(str(name), str(reason))
    os.makedirs(home, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".mcp-drift-", suffix=".tmp", dir=home)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(
                {"session": bound_session, "workspace": os.path.abspath(bound_workspace),
                 "servers": servers},
                handle,
                sort_keys=True,
            )  # fmt: skip
        _replace(tmp, os.path.join(home, DRIFT_NAME))
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return servers


def check(home: str, server: str, session_id: str, workspace: str) -> str:
    """For the gateway: why a pinned server must not be used now, or "" if it may. Fails closed:
    no file, an unreadable one, or one bound to another session or workspace is NOT_CHECKED.
    `workspace` "" skips the workspace comparison (the hook did not say)."""
    data = read_drift(home)
    if data is None:
        return NOT_CHECKED
    if not session_id or data.get("session") != session_key(session_id):
        return NOT_CHECKED
    if workspace and not same_place(str(data.get("workspace", "")), workspace):
        return NOT_CHECKED
    servers = data["servers"]
    return str(servers.get(server) or servers.get(ALL) or "")


# --- hygiene: how a server is launched (M1, M2, M3) ------------------------------------------
_EXACT_NPM = re.compile(r"@\d+\.\d+\.\d+([-+][\w.]+)?$")  # pkg@1.2.3, @scope/pkg@1.2.3-rc.1
_VALUE_FLAGS = frozenset({
    "-e", "--env", "--env-file", "--name", "--platform", "-p", "--package", "--from", "--with",
    "--python", "--directory", "--network", "-v", "--volume", "--user", "-u", "--entrypoint",
    "-w", "--workdir", "--label", "-l", "--cache", "--registry",
})  # fmt: skip
_SUBCOMMANDS = frozenset({"run", "dlx", "exec", "x", "tool", "--"})
_NODE = frozenset({"npx", "bunx", "pnpm", "yarn", "npm", "bun"})
_PYTHON = frozenset({"uvx", "pipx", "uv"})
_CONTAINER = frozenset({"docker", "podman", "nerdctl"})


def _program(word: str) -> str:
    name = os.path.basename(word.replace("\\", "/")).lower()
    return name[:-4] if name.endswith((".exe", ".cmd", ".bat")) else name


def _words(config: dict[str, Any]) -> list[str]:
    command = config.get("command")
    words = command.split() if isinstance(command, str) else []
    args = config.get("args")
    if isinstance(args, list):
        words += [str(a) for a in args]
    # Unwrap launchers that only start another program: cmd /c npx ..., sh -c "npx ...",
    # env A=1 npx ...
    for _ in range(4):
        if not words:
            break
        head = _program(words[0])
        if head == "cmd" and len(words) > 2 and words[1].lower() in ("/c", "/k"):
            words = words[2:]
        elif head in ("sh", "bash", "zsh", "pwsh", "powershell") and "-c" in words[1:3]:
            i = words.index("-c")
            words = " ".join(words[i + 1 :]).strip("'\"").split()
        elif head == "env":
            words = [w for w in words[1:] if "=" not in w or w.startswith("-")]
            words = [w for w in words if not w.startswith("-")]
        else:
            break
    return words


def _package(words: list[str]) -> str:
    """The first argument after the launcher that is not an option, an option's value or a
    subcommand (the package or image)."""
    skip = False
    for word in words[1:]:
        if skip:
            skip = False
            continue
        if word in _SUBCOMMANDS:
            continue
        if word.startswith("-"):
            skip = word in _VALUE_FLAGS  # "-e KEY" takes the next word; "--env=KEY" does not
            continue
        return word
    return ""


def unpinned_launch(config: Any) -> bool:
    """M1: a package launcher without an exact version, or a container image without a digest.
    Each start can then fetch different code."""
    if not isinstance(config, dict):
        return False
    words = _words(config)
    if not words:
        return False
    launcher = _program(words[0])
    if launcher == "uv" and "tool" not in words[1:3]:
        return False  # `uv run script.py` runs a local file
    if launcher in ("npm", "pnpm", "yarn", "bun") and not ({"exec", "x", "dlx"} & set(words[1:3])):
        return False  # `npm run`, `yarn start`: the project's own scripts
    spec = _package(words)
    if not spec:
        return False
    if launcher in _NODE:
        return not _EXACT_NPM.search(spec)
    if launcher in _PYTHON:
        return "==" not in spec and not _EXACT_NPM.search(spec)
    if launcher in _CONTAINER:
        return "@sha256:" not in spec
    return False


def plain_http(config: Any) -> bool:
    """M2: a remote server reached over plain http (not localhost)."""
    if not isinstance(config, dict) or not isinstance(config.get("url"), str):
        return False
    try:
        parts = urlsplit(config["url"].strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return True  # unparsable: report it
    return parts.scheme.lower() == "http" and host not in _LOCAL_HOSTS


def expands_variables(config: Any) -> bool:
    """M3: `${VAR}` in what starts or addresses the server. The pin hashes the text, so a change
    of the variable's value starts different code with the same hash."""
    if not isinstance(config, dict):
        return False
    parts = [config.get("command"), config.get("url")]
    if isinstance(config.get("args"), list):
        parts += config["args"]
    return any(isinstance(p, str) and "${" in p for p in parts)


def launch_findings(workspace: str) -> list[tuple[str, str]]:
    """(check, server label) for M1, M2 and M3. Unusual names get a numbered label."""
    out: list[tuple[str, str]] = []
    unnamed = 0
    for name, config in sorted(load_servers(workspace).items(), key=lambda kv: str(kv[0])):
        if isinstance(name, str) and _SAFE_NAME.fullmatch(name):
            label = name
        else:
            unnamed += 1
            label = f"(unnamed-{unnamed})"
        for check_id, test in (("M1", unpinned_launch), ("M2", plain_http),
                               ("M3", expands_variables)):  # fmt: skip
            if test(config):
                out.append((check_id, label))
    return out
