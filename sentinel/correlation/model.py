"""Rule inputs and outputs."""

from dataclasses import dataclass, field
from datetime import timedelta


@dataclass(frozen=True)
class Config:
    spend_multiple: float = 3.0  # R4 threshold X [confirm]
    r6_window: timedelta = timedelta(hours=1)
    r8_window: timedelta = timedelta(hours=24)  # [confirm]


@dataclass(frozen=True)
class Context:
    """Facts the pure rules may use (loaded by the caller; rules do no I/O)."""

    revoked_verified: frozenset[str] = frozenset()
    # cred_ref -> UTC time ("...Z") the revocation was verified; used by R11.
    revoked_verified_at: dict[str, str] = field(default_factory=dict)
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
