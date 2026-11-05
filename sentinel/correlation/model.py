"""Rule inputs and outputs."""

from dataclasses import dataclass, field
from datetime import timedelta


@dataclass(frozen=True)
class Config:
    spend_multiple: float = 3.0  # R4 threshold X [confirm]
    r6_window: timedelta = timedelta(hours=1)
    r8_window: timedelta = timedelta(hours=24)  # [confirm]
    r5b_count: int = 3  # denials in one agent session [confirm on real log data]
    r5b_window: timedelta = timedelta(minutes=30)  # [confirm on real log data]
    # R9: gateway decisions this long BEFORE a decoy event count as "an agent session was active".
    # Covers the 15-minute canary check interval (the event time is the check time). [confirm]
    r9_lookback: timedelta = timedelta(minutes=30)
    # R12: a sensitive access attempt, then an outbound attempt, in one agent session. [confirm]
    r12_window: timedelta = timedelta(minutes=15)


@dataclass(frozen=True)
class Context:
    """Facts the pure rules may use (loaded by the caller; rules do no I/O)."""

    revoked_verified: frozenset[str] = frozenset()
    # cred_ref -> UTC time ("...Z") the revocation was verified; used by R11.
    revoked_verified_at: dict[str, str] = field(default_factory=dict)
    # Exact names of MCP servers a person approved; R5c is active only when this is non-empty.
    approved_mcp_servers: frozenset[str] = frozenset()
    # Episode base key (incident key before '@') -> time its latest incident was CLOSED, so a
    # closed incident never silences later activity (R5b, R5c).
    closed_episodes: dict[str, str] = field(default_factory=dict)
    config: Config = field(default_factory=Config)


@dataclass(frozen=True)
class Match:
    rule_id: str
    key: str  # dedup key: one incident per key
    title: str
    severity_floor: str
    confidence: str
    facts: tuple[str, ...]
    hypotheses: tuple[str, ...]
    event_ids: tuple[str, ...]
    asset_id: str
    first_time: str
    last_time: str
    is_test: bool
    cred_ref: str | None = None
    identity_ref: str | None = None
