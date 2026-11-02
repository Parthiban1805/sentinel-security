"""Evidence pack: the only incident data that may leave the machine (ADR-0014).

Three layers, each fail-closed:
1. Allow-list: start from `summary.view` (ADR-0010). Close notes, evidence text, actor and approver
   names never enter the pack.
2. Disguise: every string that came from outside Sentinel (event fields and attributes, asset ids
   and names from the inventory) is replaced by a placeholder such as ASSET-1, CRED-1, PERSON-1,
   EVENT-1, PATH-1 or VALUE-1. This also removes attacker-controlled text (an MCP server name, a
   workflow file name) before a model reads it. The mapping stays on this machine.
3. Leak check: if any original value, or anything credential-shaped, is still in the pack, building
   it fails. Nothing is sent.
"""

import json
import re
from dataclasses import dataclass
from typing import Any

from sentinel import probes
from sentinel.incidents import summary
from sentinel.redaction import looks_like_secret

# Values Sentinel itself produces. Only these exact values (or exact id formats) are sent as they
# are; every other string from an event is disguised. An unknown value is safe, just less telling.
KNOWN_SOURCES = frozenset(
    {
        "agent_hook",
        "canary",
        "dependencies",
        "exposure_probe",
        "github_api",
        "github_audit",
        "gitleaks",
        "hygiene",
        "provider_usage",
    }
)
KNOWN_SIGNATURES = frozenset(p.signature for p in probes.PROBES)
KNOWN_TARGET_CLASSES = frozenset(
    {
        "cloud_credentials",
        "credential_store",
        "credential_json",
        "credential_file",
        "guard_config",
        "state_dir_access",
        "ssh_key",
        "ssh_dir",
        "shell_history",
        "secrets_dir",
        "remote_access",
        "privilege_escalation",
        "pipe_to_shell",
        "network_tool",
        "mcp_tool",
        "key_file",
        "history_rewrite",
        "global_git_config",
        "force_push",
        "env_file",
        "env_dump",
        "world_writable",
    }
)
_SAFE_ATTR: dict[str, Any] = {
    "signature": KNOWN_SIGNATURES,
    "target_class": KNOWN_TARGET_CLASSES,
    "decision": frozenset({"deny", "allow_mcp"}),
    "rule": re.compile(r"[A-Z]{2,5}-\d{2,3}"),
    "probe": re.compile(r"X\d{2}"),
    "scenario": re.compile(r"S\d{1,2}"),
    "tool": re.compile(r"[A-Z][A-Za-z]{1,30}"),  # built-in tool names (Bash, Read); not mcp__*
}
# Keys whose values identify something: disguised however short they are.
_IDENTIFYING = re.compile(r"(asset_id|mcp_server|server|session|name|repo|host|url|user|owner)$")
_EVENT_SAFE_KEYS = frozenset(
    {"time", "event_type", "severity", "confidence", "verified", "is_test"}
)
# A path: starts with a separator, drive or ~, or has two separators, or one plus a file extension.
_PATH = re.compile(
    r"(?<![\w-])(?:"
    r"(?:[A-Za-z]:|~)?[\\/][\w.\-~]+(?:[\\/][\w.\-~]*)*"
    r"|[\w.\-~]+[\\/][\w.\-~]+[\\/][\w.\-~/\\]*"
    r"|[\w\-~]+[\\/][\w\-~]*\.[A-Za-z0-9]{1,8}"
    r")"
)
PLACEHOLDER = re.compile(r"\b(?:ASSET|CRED|PERSON|EVENT|PATH|VALUE|INCIDENT)-\d+\b")
MIN_LEN = 3  # shorter free values are not disguised (no identity; they would match ordinary words)


class PackLeakError(ValueError):
    """The pack still contains an original value or something credential-shaped."""


@dataclass(frozen=True)
class Pack:
    payload: dict[str, Any]  # what is sent
    mapping: dict[str, str]  # placeholder -> original (never sent)

    def to_json(self) -> str:
        return json.dumps(self.payload, indent=2, sort_keys=True)


class _Disguiser:
    def __init__(self) -> None:
        self.by_value: dict[str, str] = {}
        self.counts: dict[str, int] = {}
        self.forged = False  # an outside value already looks like a placeholder

    def add(self, value: object, kind: str, *, identifying: bool = False) -> None:
        if not isinstance(value, str) or not value:
            return
        if PLACEHOLDER.search(value):
            self.forged = True
            return
        if len(value) < MIN_LEN and not identifying and kind in ("VALUE", "PATH"):
            return
        if value not in self.by_value:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            self.by_value[value] = f"{kind}-{self.counts[kind]}"

    def sub(self, text: str) -> str:
        # One pass over all values (longest first), so an inserted placeholder is never rewritten.
        values = sorted(self.by_value, key=lambda v: (-len(v), v))
        if values:
            pattern = re.compile(
                r"(?<![\w-])(?:" + "|".join(re.escape(v) for v in values) + r")(?![\w-])"
            )
            text = pattern.sub(lambda m: self.by_value[m.group(0)], text)
        return _PATH.sub(self._path, text)

    def _path(self, m: re.Match[str]) -> str:
        path = m.group(0).rstrip(".")  # a sentence's full stop is not part of the path
        tail = m.group(0)[len(path) :]
        self.add(path, "PATH")
        return self.by_value.get(path, path) + tail

    def mapping(self) -> dict[str, str]:
        return {p: v for v, p in self.by_value.items()}


def _bounded(value: str) -> re.Pattern[str]:
    return re.compile(r"(?<![\w-])" + re.escape(value) + r"(?![\w-])")


def _collect_event(d: _Disguiser, event: dict[str, Any]) -> None:
    d.add(event.get("event_id"), "EVENT", identifying=True)
    d.add(event.get("asset_id"), "ASSET", identifying=True)
    d.add(event.get("credential_ref"), "CRED", identifying=True)
    d.add(event.get("identity_ref"), "PERSON", identifying=True)
    if event.get("source") not in KNOWN_SOURCES:
        d.add(event.get("source"), "VALUE", identifying=True)
    for key, value in event.items():
        if key not in _EVENT_SAFE_KEYS and key not in ("attributes", "source"):
            _collect_any(d, key, value)
    _collect_any(d, "attributes", event.get("attributes") or {}, top=True)


_FIELD_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")


def _collect_any(d: _Disguiser, key: str, value: Any, *, top: bool = False) -> None:
    """Every string anywhere below `value`, dict keys included, except exact known labels.
    Top-level attribute names that look like field names (snake_case) are kept: disguising them
    would rewrite ordinary words such as "path" or "session" in Sentinel's own rule text."""
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                _collect_any(d, key, k)
                _collect_any(d, key, v)
                continue
            if not (top and _FIELD_NAME.fullmatch(k)):
                d.add(k, "VALUE")
            if not _is_safe_attr(k, v):
                _collect_any(d, k, v)
    elif isinstance(value, list | tuple | set | frozenset):
        for item in value:
            _collect_any(d, key, item)
    elif isinstance(value, str):
        if _PATH.fullmatch(value):
            d.add(value, "PATH", identifying=True)
        elif key.endswith("asset_id"):
            d.add(value, "ASSET", identifying=True)
        else:
            d.add(value, "VALUE", identifying=bool(_IDENTIFYING.search(key)))


def _is_safe_attr(key: str, value: object) -> bool:
    if isinstance(value, bool | int | float) or value is None:
        return True  # numbers and booleans carry no identity
    if not isinstance(value, str):
        return False
    allowed = _SAFE_ATTR.get(key)
    if isinstance(allowed, re.Pattern):
        return bool(allowed.fullmatch(value))
    return allowed is not None and value in allowed


def _walk(obj: Any, fn: Any) -> Any:
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_walk(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: _walk(v, fn) for k, v in obj.items()}
    return obj


def _strings(obj: Any) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, list):
        return [s for x in obj for s in _strings(x)]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    return []


def build(
    incident: dict[str, Any],
    events: list[dict[str, Any]],
    assets: list[dict[str, Any]],
) -> Pack:
    """Build the disguised pack for one incident. `events` are the stored events (only those in the
    incident timeline are used); `assets` is the inventory (for names and importance hints)."""
    view = summary.view(incident)
    wanted = {t["event_id"] for t in view["timeline"]}
    involved = [e for e in events if e.get("event_id") in wanted]

    d = _Disguiser()
    d.add(view["id"], "INCIDENT", identifying=True)
    d.add(view["asset_id"], "ASSET", identifying=True)
    d.add(view["cred_ref"], "CRED", identifying=True)
    d.add(view["identity_ref"], "PERSON", identifying=True)
    for t in view["timeline"]:
        d.add(t["event_id"], "EVENT", identifying=True)
        d.add(t["asset_id"], "ASSET", identifying=True)
        if t["source"] not in KNOWN_SOURCES:
            d.add(t["source"], "VALUE", identifying=True)
    for e in involved:
        _collect_event(d, e)
    for a in assets:  # inventory: ids and names (repo folders, paths) are identifying
        d.add(a.get("asset_id"), "ASSET", identifying=True)
        d.add(a.get("name"), "VALUE", identifying=True)

    body = {
        "incident": "INCIDENT-1",
        "rule_id": view["rule_id"],
        "title": view["title"],
        "status": view["status"],
        "severity": view["severity"],
        "confidence": view["confidence"],
        "urgency": view["urgency"],
        "created": view["created"],
        "first_event_time": view["first_event_time"],
        "is_test": view["is_test"],
        "credential": view["cred_ref"],
        "identity": view["identity_ref"],
        "asset": view["asset_id"],
        "facts": view["facts"],
        "hypotheses": view["hypotheses"],
        "unknowns": view["unknowns"],
        "timeline": [
            {k: t[k] for k in ("time", "event_type", "source", "asset_id")}
            for t in view["timeline"]
        ],
        "response_plan": [
            {
                "step": s["step"],
                "required_for_close": s["required_for_close"],
                "state": s["state"],
                "verified": any(v["verified"] for v in s["verifications"]),
            }
            for s in view["response_plan"]
        ],
    }
    payload = _walk(body, d.sub)
    by_id = {a.get("asset_id"): a for a in assets}
    payload["asset_hints"] = {
        d.by_value[aid]: {
            "type": a.get("asset_type"),
            "importance": a.get("importance"),
        }
        for aid, a in sorted(by_id.items(), key=lambda kv: str(kv[0]))
        if isinstance(aid, str) and aid in d.by_value and _used(d.by_value[aid], payload)
    }
    _check(payload, d)
    return Pack(payload=payload, mapping=d.mapping())


def _used(placeholder: str, payload: dict[str, Any]) -> bool:
    return any(placeholder in s for s in _strings(payload))


def _check(payload: dict[str, Any], d: _Disguiser) -> None:
    if d.forged:
        raise PackLeakError(
            "event data contains placeholder-shaped text (possible spoofing); nothing was sent"
        )
    strings = _strings(payload)  # raw strings: JSON escaping would hide backslash paths
    if any(looks_like_secret(s) for s in strings):
        raise PackLeakError("evidence pack looks like it contains a credential; nothing was sent")
    for value in d.by_value:
        if any(_bounded(value).search(s) for s in strings):
            raise PackLeakError(
                f"evidence pack still contains an identifying value ({d.by_value[value]}); "
                "nothing was sent"
            )
