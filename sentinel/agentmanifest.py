"""Agent permission manifest (v0.7d item 1, ADR-0024). Stdlib only.

This file is ALSO the gateway's `.claude/hooks/_manifest.py` (a byte-identical copy shipped by the
gateway patch; a test keeps them identical). It must therefore import nothing from `sentinel`,
and `tomllib` is imported only where TOML is parsed (Sentinel side, when a person applies it).

The manifest can only TIGHTEN the gateway: `check` returns a deny or ask decision, or None.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
from datetime import UTC, date, datetime
from typing import Any

COMPILED_NAME = "agent-manifest.json"
READ_TOOLS = ("Read", "Grep", "Glob", "LS")
WRITE_TOOLS = ("Edit", "MultiEdit", "Write", "NotebookEdit")
OUTSIDE = ("allow", "ask", "deny")
MAX_GLOBS = 400
Verdict = tuple[str, str, str, str]  # decision, rule, class, reason

# key -> (type, required). Unknown keys are refused everywhere.
_TOP: dict[str, tuple[type, bool]] = {
    "version": (int, True),
    "agent": (dict, True),
    "filesystem": (dict, False),
    "network": (dict, False),
    "execution": (dict, False),
    "mcp": (dict, False),
}
_SECTIONS: dict[str, dict[str, tuple[type, bool]]] = {
    "agent": {"id": (str, True), "owner": (str, True), "expires": (str, False)},
    "filesystem": {
        "read": (list, False),
        "write": (list, False),
        "deny": (list, False),
        "ask_write": (list, False),
        "outside_workspace": (str, False),
    },
    "network": {"fetch_domains": (list, False), "web_search": (bool, False)},
    "execution": {"shell": (bool, False), "deny_tools": (list, False)},
    "mcp": {"servers": (dict, False), "unlisted": (str, False)},
}
_COMPILED_META = {
    "source_sha256": str,
    "source_path": str,
    "workspace": str,
    "workspace_real": str,
    "applied_by": str,
    "applied_at": str,
}
_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_SERVER = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_LABEL = r"[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?"
_DOMAIN = re.compile(r"^(\*\.)?" + _LABEL + r"(\." + _LABEL + r")+$")
# Only plain URLs: no userinfo, no backslash, no percent or non-ASCII host (WHATWG and Python's
# urlsplit disagree on those, and the fetch tool may follow the WHATWG reading).
_URL = re.compile(r"^https?://([A-Za-z0-9.\-]+)(:\d{1,5})?(/[^\\]*)?$")


class ManifestError(ValueError):
    """The manifest is invalid; the message names the key, never a value from a file."""


def _key(text: Any) -> str:
    """A key name from the file, shown in an error: safe characters only, capped."""
    return re.sub(r"[^A-Za-z0-9_.\-]", "?", str(text))[:40]


# --- validation ----------------------------------------------------------------------------
def _strings(
    path: str, value: Any, *, pattern: re.Pattern[str] | None = None, limit: int = 200
) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ManifestError(f"{path} must be a list of non-empty strings")
    if len(value) > limit:
        raise ManifestError(f"{path} has more than {limit} entries")
    for v in value:
        if len(v) > 300 or (pattern is not None and not pattern.fullmatch(v)):
            raise ManifestError(f"{path} holds an invalid entry")
    return list(value)


def _glob_list(path: str, value: Any) -> list[str]:
    items = []
    for item in _strings(path, value):
        item = re.sub(r"(\*\*/)+", "**/", item.replace("\\", "/"))  # no nested ** backtracking
        if item.startswith("/") or re.match(r"^[A-Za-z]:", item) or ".." in item.split("/"):
            raise ManifestError(f"{path} must hold workspace-relative globs without '..'")
        items.append(item)
    return items


def _check_keys(where: str, body: dict[str, Any], spec: dict[str, tuple[type, bool]]) -> None:
    prefix = where + "." if where else ""
    for key in body:
        if key not in spec:
            raise ManifestError(f"unknown key: {prefix}{_key(key)}")
    for key, (kind, required) in spec.items():
        if key not in body:
            if required:
                raise ManifestError(f"missing key: {prefix}{key}")
            continue
        value = body[key]
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            raise ManifestError(f"{prefix}{key} has the wrong type")


def validate(data: Any, *, compiled: bool = False) -> dict[str, Any]:
    """Check every key and type; return a normalised copy. Refuses unknown keys."""
    if not isinstance(data, dict):
        raise ManifestError("the manifest must be a table")
    top = dict(_TOP)
    if compiled:
        top.update({k: (t, True) for k, t in _COMPILED_META.items()})
    _check_keys("", data, top)
    if data["version"] != 1:
        raise ManifestError("version must be 1")
    out: dict[str, Any] = {"version": 1}
    for section, spec in _SECTIONS.items():
        body = data.get(section, {})
        _check_keys(section, body, spec)
        out[section] = dict(body)
    agent = out["agent"]
    for key in ("id", "owner"):
        if not _NAME.fullmatch(agent[key]):
            raise ManifestError(f"agent.{key} must be 1-64 letters, digits, '.', '_' or '-'")
    if "expires" in agent and parse_day(agent["expires"]) is None:
        raise ManifestError("agent.expires must be a date (YYYY-MM-DD)")
    fs = out["filesystem"]
    total = 0
    for key in ("read", "write", "deny", "ask_write"):
        if key in fs:
            fs[key] = _glob_list("filesystem." + key, fs[key])
            total += len(fs[key])
    if total > MAX_GLOBS:
        raise ManifestError(f"filesystem holds more than {MAX_GLOBS} globs")
    if fs.get("outside_workspace", "allow") not in OUTSIDE:
        raise ManifestError("filesystem.outside_workspace must be allow, ask or deny")
    net = out["network"]
    if "fetch_domains" in net:
        domains = [d.lower() for d in _strings("network.fetch_domains", net["fetch_domains"])]
        if not all(_DOMAIN.fullmatch(d) for d in domains):
            raise ManifestError("network.fetch_domains holds an invalid domain")
        net["fetch_domains"] = domains
    ex = out["execution"]
    if "deny_tools" in ex:
        ex["deny_tools"] = _strings("execution.deny_tools", ex["deny_tools"], pattern=_NAME)
    mcp = out["mcp"]
    if mcp.get("unlisted", "allow") not in ("allow", "deny"):
        raise ManifestError("mcp.unlisted must be allow or deny")
    clean: dict[str, dict[str, list[str]]] = {}
    for name, body in mcp.get("servers", {}).items():
        if not _SERVER.fullmatch(name) or not isinstance(body, dict) or set(body) - {"tools"}:
            raise ManifestError(
                "mcp.servers entries must be [mcp.servers.<name>] (letters, digits, '_', '-') "
                "with only 'tools'"
            )
        clean[name] = {"tools": _strings(f"mcp.servers.{name}.tools", body.get("tools", []))}
    out["mcp"] = {"servers": clean, "unlisted": mcp.get("unlisted", "allow")}
    if compiled:
        for key in _COMPILED_META:
            out[key] = data[key]
    return out


def parse_day(text: Any) -> date | None:
    try:
        return date.fromisoformat(text) if isinstance(text, str) and len(text) == 10 else None
    except ValueError:
        return None


# --- Sentinel side: compile what a person applies -----------------------------------------
def compile_manifest(
    source: bytes,
    workspace: str,
    actor: str,
    now: datetime,
    *,
    source_path: str = "",
    workspace_real: str = "",
) -> dict[str, Any]:
    """TOML bytes -> the compiled dict the gateway reads. Raises ManifestError."""
    import tomllib  # only here: the hook never parses TOML

    try:
        data = tomllib.loads(source.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"the manifest is not valid TOML ({type(exc).__name__})") from None
    compiled = validate(data)
    compiled.update(
        source_sha256=hashlib.sha256(source).hexdigest(),
        source_path=source_path,
        workspace=normalize_path(workspace),
        workspace_real=normalize_path(workspace_real or workspace),
        applied_by=actor,
        applied_at=now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    return compiled


# --- path and glob helpers (same normalisation as the gateway, plus device prefixes) --------
def normalize_path(path: str, cwd: str = "") -> str:
    text = os.path.expanduser(str(path)).replace("\\", "/")
    low = text.lower()
    if low.startswith("//?/unc/"):
        text = "//" + text[8:]
    elif low.startswith(("//?/", "//./")):
        text = text[4:]
    if not os.path.isabs(text):
        text = os.path.join(cwd or os.getcwd(), text)
    text = os.path.normpath(text).replace("\\", "/")
    return text.lower() if os.name == "nt" else text


def _trimmed(text: str) -> str:
    """Win32 drops trailing dots and spaces from each path part: 'deploy./x' opens 'deploy/x'."""
    return "/".join(part.rstrip(" .") or part for part in text.split("/"))


def _relative(target: str, workspaces: tuple[str, ...]) -> str | None:
    """Workspace-relative posix path, '' for the workspace itself, None if outside all of them."""
    for workspace in workspaces:
        if target == workspace:
            return ""
        prefix = workspace.rstrip("/") + "/"
        if target.startswith(prefix):
            return target[len(prefix) :]
    return None


@functools.lru_cache(maxsize=1024)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """`**` any number of folders, `*` / `?` within one name."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    flags = re.IGNORECASE if os.name == "nt" else 0
    return re.compile("^" + "".join(out) + "$", flags)


def _matches(rel: str, patterns: list[str]) -> bool:
    return any(_glob_regex(p).match(rel) for p in patterns)


def _covers_folder(rel: str, patterns: list[str]) -> bool:
    """A folder is readable as a whole only when a `<base>/**` (or `**`) pattern covers it."""
    parts = rel.split("/") if rel else []
    for p in patterns:
        if p == "**":
            return True
        if not p.endswith("/**"):
            continue
        base = _glob_regex(p[:-3])
        if any(base.match("/".join(parts[:n])) for n in range(1, len(parts) + 1)):
            return True
    return False


def _static_prefix(pattern: str) -> str:
    parts = []
    for part in pattern.replace("\\", "/").split("/"):
        if any(c in part for c in "*?[{"):
            break
        parts.append(part)
    return "/".join(parts)


def _holds_denied(rel: str, deny: list[str]) -> bool:
    """A folder search would return files a deny glob names (when the glob has a fixed folder)."""
    for p in deny:
        prefix = _static_prefix(p)
        if prefix and (rel == "" or prefix == rel or prefix.startswith(rel + "/")):
            return True
    return False


def _targets(tool: str, tool_input: dict[str, Any], cwd: str) -> list[tuple[str, bool]]:
    """(absolute normalised path, is_folder) for every path a file tool names. A Glob pattern is
    resolved under the tool's `path` (or the working folder); a Grep `glob` only narrows `path`."""
    searches = tool in ("Grep", "Glob", "LS")
    out: list[tuple[str, bool]] = []
    base = cwd
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            target = normalize_path(value, cwd)
            folder = searches and key == "path" and not os.path.isfile(target)
            out.append((target, folder))
            if key == "path":
                base = target
    if tool == "Glob":
        pattern = tool_input.get("pattern")
        if isinstance(pattern, str) and pattern:
            out.append((normalize_path(_static_prefix(pattern) or ".", base), True))
    if searches and not out:
        out.append((normalize_path(".", cwd), True))  # no path: the working folder
    return out


def _domain_allowed(host: str, domains: list[str]) -> bool:
    host = host.lower()
    for d in domains:
        if d.startswith("*."):
            if host.endswith(d[1:]) and host != d[2:]:
                return True
        elif host == d:
            return True
    return False


# --- the decision --------------------------------------------------------------------------
def _file_rules(
    manifest: dict[str, Any], tool: str, tool_input: dict[str, Any], cwd: str
) -> list[Verdict]:
    fs = manifest.get("filesystem", {})
    workspaces = (manifest["workspace"], manifest["workspace_real"])
    deny = fs.get("deny", [])
    writing = tool in WRITE_TOOLS
    results: list[Verdict] = []
    for target, folder in _targets(tool, tool_input, cwd):
        real = normalize_path(os.path.realpath(target), cwd)
        for spelling in sorted({target, real, _trimmed(target), _trimmed(real)}):
            rel = _relative(spelling, workspaces)
            if rel is None:
                if spelling.startswith("//"):
                    reason = "a network or device path cannot be placed against the manifest"
                    results.append(("deny", "MF-13", "manifest_device_path", reason))
                    continue
                mode = fs.get("outside_workspace", "allow")
                if mode != "allow":
                    reason = f"{tool} outside the workspace is not allowed by the agent manifest"
                    results.append((mode, "MF-12", "manifest_outside", reason))
                continue
            if _matches(rel, deny) or (folder and _holds_denied(rel, deny)):
                results.append(("deny", "MF-03", "manifest_deny", "the agent manifest denies it"))
            elif writing:
                if "write" in fs and not _matches(rel, fs["write"]):
                    reason = "the agent manifest does not allow writing here"
                    results.append(("deny", "MF-02", "manifest_write", reason))
                elif _matches(rel, fs.get("ask_write", [])):
                    reason = "the agent manifest asks before writing here"
                    results.append(("ask", "MF-11", "manifest_ask_write", reason))
            elif "read" in fs:
                ok = _covers_folder(rel, fs["read"]) if folder else _matches(rel, fs["read"])
                if not ok:
                    reason = "the agent manifest does not allow reading here"
                    results.append(("deny", "MF-01", "manifest_read", reason))
    return results


def _fetch_host(url: Any) -> str | None:
    match = _URL.fullmatch(url) if isinstance(url, str) else None
    return match.group(1).lower().rstrip(".") if match else None


def _other_rules(manifest: dict[str, Any], tool: str, tool_input: dict[str, Any]) -> list[Verdict]:
    results: list[Verdict] = []
    if tool.startswith("mcp__"):
        server, _, name = tool[len("mcp__") :].rpartition("__")
        mcp = manifest.get("mcp", {})
        servers = mcp.get("servers", {})
        if server in servers:
            tools = servers[server]["tools"]
            if "*" not in tools and name not in tools:
                reason = "the agent manifest does not allow this MCP tool"
                results.append(("deny", "MF-09", "manifest_mcp", reason))
        elif mcp.get("unlisted") == "deny":
            reason = "the agent manifest does not list this MCP server"
            results.append(("deny", "MF-09", "manifest_mcp", reason))
    elif tool == "WebFetch":
        domains = manifest.get("network", {}).get("fetch_domains")
        if domains is not None:
            host = _fetch_host(tool_input.get("url"))
            if not host or not _domain_allowed(host, domains):
                reason = "the agent manifest does not allow fetching this URL"
                results.append(("deny", "MF-07", "manifest_fetch", reason))
    elif tool == "WebSearch":
        if manifest.get("network", {}).get("web_search") is False:
            results.append(("deny", "MF-08", "manifest_search", "the agent manifest disables it"))
    elif tool == "Bash" or "command" in tool_input:
        if manifest.get("execution", {}).get("shell") is False:
            reason = "the agent manifest disables shell commands"
            results.append(("deny", "MF-06", "manifest_shell", reason))
    return results


def check(
    manifest: dict[str, Any],
    tool: str,
    tool_input: dict[str, Any],
    cwd: str,
    now: datetime | None = None,
) -> Verdict | None:
    """Extra restriction for one tool call: (decision, rule, class, reason) or None."""
    now = now or datetime.now(UTC)
    results: list[Verdict] = []
    if tool in manifest.get("execution", {}).get("deny_tools", []):
        results.append(("deny", "MF-10", "manifest_tool", f"the agent manifest denies {tool}"))
    expires = parse_day(manifest.get("agent", {}).get("expires"))
    if expires is not None and now.date() > expires and tool not in READ_TOOLS:
        reason = f"the agent manifest expired on {expires.isoformat()}"
        results.append(("ask", "MF-04", "manifest_expired", reason))
    if tool in READ_TOOLS or tool in WRITE_TOOLS:
        results += _file_rules(manifest, tool, tool_input, cwd)
    else:
        results += _other_rules(manifest, tool, tool_input)
    for wanted in ("deny", "ask"):
        for r in results:
            if r[0] == wanted:
                return r
    return None


def load_compiled(home: str) -> dict[str, Any] | None:
    """The compiled manifest, None if absent. Raises ManifestError if present but invalid."""
    path = os.path.join(home, COMPILED_NAME)
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise ManifestError("the compiled agent manifest cannot be read") from None
    return validate(data, compiled=True)
