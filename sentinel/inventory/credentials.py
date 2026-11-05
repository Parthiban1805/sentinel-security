"""Credential lifecycle checks C1-C9 (v0.7c item 2, ADR-0019).

Knowing the state only: expiry, age, rotation, owner, use, exposure and duplicates. Rotation and
revocation are response actions (v0.9) and need human approval. Unknown is reported as unknown,
never as fine. No secret value is involved: asset ids, key ids and dates only.
"""

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sentinel.config import MAX_ROTATE_DAYS
from sentinel.config import CredentialPolicy as Policy
from sentinel.events.schema import format_time, make_event
from sentinel.findings import LIVE_STATUSES
from sentinel.inventory.assets import update_asset
from sentinel.redaction import looks_like_secret
from sentinel.sources.gcp import alias_key
from sentinel.store.db import Store

CREDENTIAL_TYPES = ("api_key", "github_token", "service_account")
SSH_SNAPSHOT = "github:user_keys"
MIN_YEAR, MAX_YEAR = 1990, 2100  # outside this a date is a typo, and far years overflow
CLOCK_SKEW = timedelta(days=1)  # a "past" date may be this far ahead (time zones, clocks)
RESTORE_WINDOW = timedelta(days=30)  # Google undelete window (hypothesis: not checked live)
SNAPSHOT_STALE = timedelta(days=2)
WITHHELD = "[withheld: looks like a credential]"
__all__ = ["Policy", "review", "duplicates", "to_events", "set_lifecycle", "report_json"]

CHECK_TEXT = {
    "C1": "expired",
    "C2": "expires soon",
    "C3": "rotation overdue",
    "C4": "no owner",
    "C5": "unused for a long time (candidate for deletion)",
    "C6": "aliased to a leaked credential that may still work",
    "C9": "the same leaked credential is in several assets",
}


@dataclass(frozen=True)
class Problem:
    check: str
    severity: str
    detail: str
    state: str = ""  # the value that triggered it: part of the event id, so a recurrence counts


@dataclass
class CredentialView:
    ref: str  # asset id, or github-ssh-<id> for an SSH key
    kind: str  # asset type, or ssh_key
    name: str  # never printed in text; in JSON only if it passes the credential screen
    owner: str | None
    created: str | None
    expires: str | None
    last_used: str | None
    rotated_at: str | None
    age_days: int | None
    rotate_due: str | None  # UTC date (YYYY-MM-DD), or None when it cannot be worked out
    deleted: bool = False
    exposed_as: str | None = None  # cred_ref of a live leaked credential a person aliased
    problems: list[Problem] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)

    @property
    def state(self) -> str:
        if self.deleted:
            return "deleted"
        if self.problems:
            return f"{len(self.problems)} problem(s)"
        return f"unknown ({len(self.unknown)})" if self.unknown else "ok"


@dataclass(frozen=True)
class Duplicate:
    ref: str  # cred_ref
    status: str
    assets: list[str]


# parsing -------------------------------------------------------------------------
def parse_when(value: Any) -> datetime | None:
    """ISO date or date-time -> UTC datetime; anything else, or a year outside MIN_YEAR..MAX_YEAR,
    -> None (unknown)."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        if len(text) == 10:
            parsed = datetime.combine(date.fromisoformat(text), datetime.min.time(), UTC)
        else:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return parsed if MIN_YEAR <= parsed.year <= MAX_YEAR else None


def utc_date(value: Any) -> str | None:
    parsed = parse_when(value)
    return parsed.date().isoformat() if parsed else None


def _days(value: Any) -> int | None:
    try:
        days = int(str(value))
    except (TypeError, ValueError):
        return None
    return days if 1 <= days <= MAX_ROTATE_DAYS else None


def _past(view: CredentialView, label: str, value: Any, now: datetime) -> datetime | None:
    """A date that must lie in the past. Unparsable or in the future -> unknown, never fine."""
    if value in (None, ""):
        return None
    parsed = parse_when(value)
    if parsed is None:
        view.unknown.append(f"{label} not a valid date")
    elif parsed > now + CLOCK_SKEW:
        view.unknown.append(f"{label} is in the future")
        return None
    return parsed


# review --------------------------------------------------------------------------
def _check(view: CredentialView, now: datetime, policy: Policy, every_raw: Any) -> None:
    created = _past(view, "creation date", view.created, now)
    last_used = _past(view, "last use", view.last_used, now)
    rotated = _past(view, "rotation date", view.rotated_at, now)
    expires = parse_when(view.expires)
    if created:
        view.age_days = max((now - created).days, 0)
    if expires is None:
        view.unknown.append("expiry" if not view.expires else "expiry not a valid date")
    elif expires <= now:
        day = expires.date().isoformat()
        view.problems.append(Problem("C1", "high", f"expired on {day}", day))
    elif expires <= now + timedelta(days=policy.expiry_warn_days):
        day = expires.date().isoformat()
        view.problems.append(Problem("C2", "medium", f"expires on {day}", day))
    every = _days(every_raw)
    if every_raw not in (None, "") and every is None:
        view.unknown.append("rotate_every_days invalid (policy default used)")
    basis = rotated or created
    if basis is None:
        view.unknown.append("rotation cannot be checked")
    else:
        due = (basis + timedelta(days=every or policy.rotate_days)).date().isoformat()
        view.rotate_due = due
        if due <= now.date().isoformat():
            source = "last rotation" if rotated else "creation"
            view.problems.append(Problem("C3", "medium", f"due {due} (from {source})", due))
    if view.kind == "ssh_key":
        view.unknown.extend(["owner (not recorded for SSH keys)", "last use"])
        return
    if not view.owner:
        view.problems.append(Problem("C4", "low", "no owner recorded"))
    if last_used is None:
        if not view.last_used:
            view.unknown.append("last use")
    elif last_used <= now - timedelta(days=policy.unused_days):
        day = last_used.date().isoformat()
        view.problems.append(Problem("C5", "low", f"last used {day}", day))


def _exposure(store: Store, view: CredentialView, attrs: dict[str, Any]) -> None:
    project, uid = attrs.get("project"), attrs.get("uid")
    if not (project and uid):
        return
    alias = store.get_doc("aliases", alias_key(str(project), str(uid)))
    finding = store.get_doc("findings", alias["cred_ref"]) if alias else None
    if finding and finding.get("status") in LIVE_STATUSES:
        view.exposed_as = finding["cred_ref"]
        detail = f"aliased to {finding['cred_ref']} ({finding['status']})"
        view.problems.append(Problem("C6", "high", detail, finding["cred_ref"]))


def review(store: Store, now: datetime, policy: Policy) -> list[CredentialView]:
    """Every credential asset and every snapshotted SSH key, checked. Sorted by ref."""
    views: list[CredentialView] = []
    for asset in store.assets():
        if asset["asset_type"] not in CREDENTIAL_TYPES:
            continue
        attrs = asset.get("attributes") or {}
        view = CredentialView(
            ref=asset["asset_id"],
            kind=asset["asset_type"],
            name=asset["name"],
            owner=asset.get("owner"),
            created=attrs.get("created"),
            expires=attrs.get("expires"),
            last_used=attrs.get("last_used"),
            rotated_at=attrs.get("rotated_at"),
            age_days=None,
            rotate_due=None,
        )
        deleted_raw = attrs.get("deleted")
        deleted_at = parse_when(deleted_raw)
        if deleted_raw and deleted_at is None:
            view.unknown.append("deleted flag is not a valid date (checked as live)")
        if deleted_at is not None:
            view.deleted = True
            if now - deleted_at < RESTORE_WINDOW:
                # Hypothesis: Google allows undelete for about 30 days, so exposure still matters.
                restorable = (deleted_at + RESTORE_WINDOW).date().isoformat()
                view.unknown.append(f"restorable until {restorable} (hypothesis)")
                _exposure(store, view, attrs)
            views.append(view)
            continue
        _check(view, now, policy, attrs.get("rotate_every_days"))
        _exposure(store, view, attrs)
        views.append(view)
    snapshot = store.get_doc("snapshots", SSH_SNAPSHOT) or {}
    taken = parse_when(snapshot.get("time"))
    for key_id, created in sorted((snapshot.get("ids") or {}).items()):
        view = CredentialView(
            ref=f"github-ssh-{key_id}",
            kind="ssh_key",
            name=f"GitHub SSH key {key_id}",
            owner=None,
            created=created or None,
            expires=None,
            last_used=None,
            rotated_at=None,
            age_days=None,
            rotate_due=None,
        )
        _check(view, now, policy, None)
        view.unknown = [u for u in view.unknown if u != "expiry"]  # SSH keys do not expire
        if taken is None or now - taken > SNAPSHOT_STALE:
            when = taken.date().isoformat() if taken else "unknown time"
            view.unknown.append(f"key list is stale (from {when})")
        views.append(view)
    views.sort(key=lambda v: v.ref)
    return views


def duplicates(store: Store) -> list[Duplicate]:
    """C9: a leaked credential (still possibly live) found in two or more assets."""
    out = []
    for doc in store.docs("findings"):
        if doc.get("status") not in LIVE_STATUSES:
            continue
        assets = sorted({loc["asset_id"] for loc in doc.get("locations") or []})
        if len(assets) > 1:
            out.append(Duplicate(doc["cred_ref"], doc["status"], assets))
    return sorted(out, key=lambda d: d.ref)


def to_events(
    views: list[CredentialView], dups: list[Duplicate], now: datetime
) -> list[dict[str, Any]]:
    """One `config_drift` event per problem. The id holds the triggering value, so a re-run is
    deduplicated but a recurrence (re-expiry, rotation overdue again, a new asset) is recorded.
    Limit: findings carry no `is_test` flag, so these events are never marked as test data."""
    events = []
    for view in views:
        asset_id = "gh-account" if view.kind == "ssh_key" else view.ref
        for p in view.problems:
            events.append(
                make_event(
                    event_type="config_drift",
                    source="credentials",
                    asset_id=asset_id,
                    time=now,
                    severity=p.severity,
                    confidence="high",
                    evidence_ref=f"credentials/{view.ref}/{p.check}",
                    event_id=f"creds:{view.ref}:{p.check}:{p.state}",
                    attributes={"check": p.check, "credential": view.ref, "detail": p.detail},
                )
            )
    for d in dups:
        assets_hash = hashlib.sha256("\0".join(d.assets).encode()).hexdigest()[:12]
        events.append(
            make_event(
                event_type="config_drift",
                source="credentials",
                asset_id=d.assets[0],
                time=now,
                severity="medium",
                confidence="high",
                evidence_ref=f"finding/{d.ref}",
                event_id=f"creds:{d.ref}:C9:{assets_hash}",
                credential_ref=d.ref,
                attributes={"check": "C9", "assets": d.assets, "detail": CHECK_TEXT["C9"]},
            )
        )
    return events


# setting values ------------------------------------------------------------------
def _date_text(name: str, value: str | None, now: datetime, *, past: bool) -> str | None:
    if value is None:
        return None
    parsed = parse_when(value)
    if parsed is None:
        raise ValueError(
            f"{name} must be an ISO date (YYYY-MM-DD) or date-time between {MIN_YEAR} and "
            f"{MAX_YEAR}"
        )
    if past and parsed > now + CLOCK_SKEW:
        raise ValueError(f"{name} cannot be in the future")
    return value.strip()


def set_lifecycle(
    store: Store,
    asset_id: str,
    *,
    actor: str,
    now: datetime,
    expires: str | None = None,
    last_used: str | None = None,
    rotated_at: str | None = None,
    rotate_every_days: int | None = None,
) -> dict[str, Any]:
    """A person records lifecycle facts on a credential asset (validated, screened, audited).
    The CLI requires an interactive terminal: these values decide what is reported as fine."""
    asset = next((a for a in store.assets() if a["asset_id"] == asset_id), None)
    if asset is None:
        raise KeyError(f"unknown asset: {asset_id}")
    if asset["asset_type"] not in CREDENTIAL_TYPES:
        raise ValueError(f"{asset_id} is not a credential asset ({', '.join(CREDENTIAL_TYPES)})")
    values = {
        "expires": _date_text("expires", expires, now, past=False),
        "last_used": _date_text("last_used", last_used, now, past=True),
        "rotated_at": _date_text("rotated_at", rotated_at, now, past=True),
    }
    if rotate_every_days is not None:
        if _days(rotate_every_days) is None:
            raise ValueError(f"rotate_every_days must be between 1 and {MAX_ROTATE_DAYS}")
        values["rotate_every_days"] = str(rotate_every_days)
    attributes = {k: v for k, v in values.items() if v is not None}
    if not attributes:
        raise ValueError(
            "nothing to set (use --expires, --last-used, --rotated-at, --rotate-every)"
        )
    return update_asset(store, asset_id, actor=actor, now=now, attributes=attributes)


def shown(text: str | None) -> str | None:
    """Text from an unscreened source (a Google displayName, an imported owner) for output."""
    return WITHHELD if text and looks_like_secret(text) else text


def report_json(
    views: list[CredentialView], dups: list[Duplicate], now: datetime
) -> dict[str, Any]:
    """Names (a Google key's displayName is stored unscreened) are withheld if they look like a
    credential; owner is screened when a person sets it."""
    credentials = []
    for v in views:
        item: dict[str, Any] = asdict(v)
        item["state"] = v.state
        item["name"] = shown(v.name)
        item["owner"] = shown(v.owner)
        credentials.append(item)
    return {
        "time": format_time(now),
        "credentials": credentials,
        "duplicates": [asdict(d) for d in dups],
        "counts": {
            "problems": sum(len(v.problems) for v in views) + len(dups),
            "with_unknowns": sum(1 for v in views if v.unknown and not v.problems),
        },
    }
