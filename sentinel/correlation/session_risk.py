"""Agent session risk: shared definitions for rule R12 and the advisory session score (ADR-0020).

Pure functions over agent-gateway events (`agent_tool_denied`, `agent_tool_allowed`). Fixed weights,
no learned values, no I/O. The score is advisory: it never blocks or approves anything
(principle 1).
Events carry only a hashed session id, a tool name, a rule id, a class and a keyed target
fingerprint, so nothing here can hold a command, a path or a secret.

Robustness (security review 2026-11-05): an agent can generate thousands of denials, so every
search here is O(n log n); malformed events are skipped, never raised on; and text copied into
reasons is capped and limited to a safe character set.
"""

import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from sentinel.correlation.model import Context

Event = dict[str, Any]

# Classes written by the gateway hooks (`.claude/hooks/_policy.py`). A class that is not listed
# counts as "other" (one point), so a new hook rule is never silently ignored.
SENSITIVE_CLASSES = frozenset(
    {
        "credential_read",
        "env_dump",
        "shell_history",
        "env_file",
        "key_file",
        "ssh_key",
        "ssh_dir",
        "cloud_credentials",
        "credential_store",
        "secrets_dir",
        "credential_json",
        "state_dir",
        "state_dir_access",
    }
)
# firewall_*: the gateway refused a tool call that would send a credential or reach a metadata
# address (ADR-0025): an outbound attempt.
OUTBOUND_CLASSES = frozenset(
    {
        "network_tool",
        "remote_access",
        "pipe_to_shell",
        "cloud_cli",
        "firewall_secret",
        "firewall_metadata",
        # TF-01 (ADR-0027): a data-leaving call in a session that read untrusted content and saw
        # a credential. The gateway asked; it is an outbound attempt.
        "trifecta",
    }
)
TRIFECTA_RULE = "TF-01"

POINTS_SENSITIVE = 2
POINTS_OUTBOUND = 2
POINTS_OTHER_DENIAL = 1
POINTS_ASK = 1
POINTS_UNAPPROVED_MCP = 2
POINTS_SEQUENCE = 3
POINTS_TRIFECTA = 3  # once per session (ADR-0027, rule R13)
LEVELS = ((2, "low"), (5, "elevated"))  # up to and including; above the last is "high"
MAX_REASON_LINES = 20  # the rest is summarised ("and N more")
_SAFE_TEXT = re.compile(r"[^A-Za-z0-9_.\-]")


def attrs_of(event: Event) -> dict[str, Any]:
    """The event's attributes, or {} if absent or not a mapping (never raises)."""
    attrs = event.get("attributes")
    return attrs if isinstance(attrs, dict) else {}


def safe_text(value: Any, limit: int = 40) -> str:
    """Rule ids and classes come from event attributes, so they are capped and reduced to a safe
    character set before they reach an incident record or a terminal."""
    return _SAFE_TEXT.sub("?", str(value))[:limit]


def ts(event: Event) -> datetime:
    return datetime.fromisoformat(event["time"].replace("Z", "+00:00"))


def _try_ts(event: Event) -> datetime | None:
    try:
        return ts(event)
    except (KeyError, AttributeError, ValueError, TypeError):
        return None


def approved_prefix(tool: str, approved: frozenset[str]) -> bool:
    """Exact server name: everything before the LAST '__', parsed the same way as the gateway
    (security review 2026-11-03: a server named 'github__x' is not the approved 'github')."""
    rest = tool[len("mcp__") :]
    return "__" in rest and rest.rsplit("__", 1)[0] in approved


def is_unapproved_mcp(event: Event, approved: frozenset[str]) -> bool:
    """An MCP tool call to a server nobody approved (allowlist mode only: some server approved)."""
    attrs = attrs_of(event)
    tool = str(attrs.get("tool", ""))
    return (
        bool(approved)
        and event.get("event_type") == "agent_tool_allowed"
        and attrs.get("decision") == "allow_mcp"
        and tool.startswith("mcp__")
        and not approved_prefix(tool, approved)
    )


def attempt_kind(event: Event, approved: frozenset[str]) -> str | None:
    """Classify one gateway event for R12: "sensitive", "outbound", "other", or None (no attempt).

    An attempt is a call the gateway denied or asked about, or an unapproved MCP call. A plain
    allowed call is not logged by the gateway as an attempt, so it never counts."""
    attrs = attrs_of(event)
    if is_unapproved_mcp(event, approved):
        return "outbound"
    decision = attrs.get("decision")
    kind = event.get("event_type")
    refused = kind == "agent_tool_denied" and decision == "deny"
    asked = kind == "agent_tool_allowed" and decision == "ask"
    if not (refused or asked):
        return None
    cls = str(attrs.get("target_class", ""))
    if cls in SENSITIVE_CLASSES:
        return "sensitive"
    if cls in OUTBOUND_CLASSES:
        return "outbound"
    return "other"


def is_trifecta_gate(event: Event) -> bool:
    """The gateway asked before a data-leaving call in a tainted session (TF-01, ADR-0027)."""
    attrs = attrs_of(event)
    return (
        event.get("source") == "agent_hook"
        and event.get("event_type") == "agent_tool_allowed"
        and attrs.get("decision") == "ask"
        and attrs.get("rule") == TRIFECTA_RULE
    )


def ordered(events: Iterable[Event]) -> list[Event]:
    """Events sorted by time then id. An event whose time cannot be read is left out."""
    stamped = [(t, e) for e in events if (t := _try_ts(e)) is not None]
    stamped.sort(key=lambda pair: (pair[0], str(pair[1].get("event_id", ""))))
    return [e for _, e in stamped]


def find_sequence(
    events: Iterable[Event], approved: frozenset[str], window: timedelta
) -> tuple[Event, Event] | None:
    """The earliest (sensitive attempt, outbound attempt) pair in the same session where the
    outbound one comes strictly later and within `window`. Same-instant events have no known
    order, so they never pair. Callers pass the events of ONE session.

    O(n log n): each event is parsed and classified once, and for every sensitive attempt the first
    strictly later outbound attempt is found by bisection (if that one is outside the window, all
    later ones are too)."""
    seq = ordered(events)
    times = [ts(e) for e in seq]
    outbound = [
        (t, e) for t, e in zip(times, seq, strict=True) if attempt_kind(e, approved) == "outbound"
    ]
    out_times = [t for t, _ in outbound]
    for t, e in zip(times, seq, strict=True):
        if attempt_kind(e, approved) != "sensitive":
            continue
        i = bisect_right(out_times, t)
        if i < len(outbound) and out_times[i] - t <= window:
            return e, outbound[i][1]
    return None


def _reason(event: Event, kind: str) -> tuple[int, str]:
    attrs = attrs_of(event)
    cls, rule = safe_text(attrs.get("target_class", "?")), safe_text(attrs.get("rule", "?"))
    if kind == "mcp":
        return POINTS_UNAPPROVED_MCP, "call to an MCP server that is not approved"
    if attrs.get("decision") == "ask":
        return POINTS_ASK, f"the gateway asked about a call ({rule}, {cls})"
    if kind == "sensitive":
        return POINTS_SENSITIVE, f"blocked: sensitive access attempt ({rule}, {cls})"
    if kind == "outbound":
        return POINTS_OUTBOUND, f"blocked: outbound attempt ({rule}, {cls})"
    return POINTS_OTHER_DENIAL, f"blocked: other action ({rule}, {cls})"


def session_risk(events: Iterable[Event], ctx: Context) -> dict[str, Any]:
    """Advisory score for ONE session: {level, points, reasons}. Every point has a reason.

    Fixed weights (see `docs/spec/correlation-rules.md`): sensitive denial 2, outbound denial 2,
    other denial 1, an `ask` 1, an unapproved MCP call 2, and 3 for the R12 sequence. Levels:
    low (0-2), elevated (3-5), high (6+). Reasons hold rule ids and classes only, one line per
    kind of attempt with a count, at most MAX_REASON_LINES lines.

    Points have NO time limit: a long session drifts upward on keyword noise (ADR-0020)."""
    approved = ctx.approved_mcp_servers
    seq = ordered(events)
    counts: Counter[tuple[int, str]] = Counter()
    first_seen: dict[tuple[int, str], int] = {}
    points = 0
    for i, e in enumerate(seq):
        if is_unapproved_mcp(e, approved):
            gained, why = _reason(e, "mcp")
        else:
            kind = attempt_kind(e, approved)
            if kind is None:
                continue
            gained, why = _reason(e, kind)
        points += gained
        counts[(gained, why)] += 1
        first_seen.setdefault((gained, why), i)
    reasons = []
    for (gained, why), n in sorted(counts.items(), key=lambda kv: first_seen[kv[0]]):
        reasons.append(f"+{gained * n} {why}" + ("" if n == 1 else f" (x{n})"))
    if find_sequence(seq, approved, ctx.config.r12_window) is not None:
        points += POINTS_SEQUENCE
        reasons.append(
            f"+{POINTS_SEQUENCE} sequence: a sensitive access attempt, then an outbound attempt, "
            "in this session (rule R12)"
        )
    if any(is_trifecta_gate(e) for e in seq):
        points += POINTS_TRIFECTA
        reasons.append(
            f"+{POINTS_TRIFECTA} trifecta: untrusted content read and a credential seen in this "
            "session, then a data-leaving call (rule R13)"
        )
    if len(reasons) > MAX_REASON_LINES:
        extra = len(reasons) - MAX_REASON_LINES
        reasons = [*reasons[:MAX_REASON_LINES], f"and {extra} more kind(s) of attempt"]
    level = next((name for limit, name in LEVELS if points <= limit), "high")
    return {"level": level, "points": points, "reasons": reasons}
