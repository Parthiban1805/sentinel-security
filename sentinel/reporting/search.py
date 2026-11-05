"""Structured search over the store (v0.7c item 5, ADR-0022). Read-only.

Filters: credential fingerprint, asset, session, event type, source, time range. At least one is
required and they combine with AND; a filter that does not apply to a kind of record excludes that
kind. There is NO free-text search and notes or evidence text is never read or shown, so this cannot
be used to dig secrets out of the store. A filter value that looks like a credential is refused and
never echoed. Output holds ids, fingerprints, types, statuses and times only.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sentinel.events.schema import format_time
from sentinel.inventory.credentials import parse_when
from sentinel.redaction import has_secret_pattern, looks_like_secret
from sentinel.store.db import Store

MAX_LIMIT = 1000
MAX_VALUE = 200
_VALUE = re.compile(r"^[A-Za-z0-9_.:/\-]{1,200}$")
_SEPARATORS = re.compile(r"[:/.\-_]")
WITHHELD = "[withheld: looks like a credential]"
_RELATIVE = re.compile(r"^(\d{1,7})([dhm])$")
_MAX_RELATIVE = {"d": 3650, "h": 87600, "m": 5_256_000}
NOTE = (
    "An empty result means nothing is recorded, not that nothing happened. The search covers this "
    "machine's store only: there are no other machines until the v0.8 service. Treat the "
    "results as sensitive: they map your systems."
)
_AUDIT_FIELDS = ("action", "actor", "incident", "step", "passed", "verified", "rule", "severity")


@dataclass(frozen=True)
class Query:
    credential: str | None = None
    asset: str | None = None
    session: str | None = None
    event_type: str | None = None
    source: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    include_test: bool = False
    limit: int = 100


def parse_time(text: str, now: datetime) -> datetime:
    """An ISO date or time, or a relative `7d` / `12h` / `30m` (at least 1, at most 10 years)."""
    match = _RELATIVE.fullmatch(text.strip())
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        if not 1 <= amount <= _MAX_RELATIVE[unit]:
            raise ValueError(
                f"a relative time must be between 1{unit} and {_MAX_RELATIVE[unit]}{unit}"
            )
        delta = {
            "d": timedelta(days=amount),
            "h": timedelta(hours=amount),
            "m": timedelta(minutes=amount),
        }
        return now - delta[unit]
    parsed = parse_when(text.strip())
    if parsed is None:
        raise ValueError("time must be an ISO date or time (2026-11-01) or relative (7d, 12h, 30m)")
    return parsed


def _clean(value: Any, limit: int = 120) -> str:
    """Printable text: control, escape and format characters are replaced and the length is capped.
    Non-ASCII letters are kept, so look-alike names are not caught. Text in a known credential
    format is withheld (ids and fingerprints are never in such a format)."""
    text = "".join(c if c.isprintable() and c != "\x1b" else "?" for c in str(value))[:limit]
    return WITHHELD if has_secret_pattern(text) else text


def _check(name: str, value: str | None) -> None:
    if value is None:
        return
    # A known-format key split by separators is still that key. Only the known formats are
    # applied to the joined value: the entropy guess would also flag ids that end in a hash.
    # The entropy guess runs per separator-delimited part: a random secret is one long part, while
    # ids such as `wf-repo-<name>-<hash>` are many short parts and would otherwise be refused.
    joined = _SEPARATORS.sub("", value)
    parts = [p for p in _SEPARATORS.split(value) if p]
    suspicious = has_secret_pattern(value) or has_secret_pattern(joined)
    if suspicious or any(looks_like_secret(p) for p in parts):  # first; never echoed
        raise ValueError(
            f"--{name} looks like a credential value, which Sentinel never searches for or stores; "
            "use its fingerprint (`sentinel fingerprint`)"
        )
    if not _VALUE.fullmatch(value):
        raise ValueError(
            f"--{name} must be 1 to {MAX_VALUE} letters, digits or . _ : / - characters"
        )


def _when(value: Any) -> datetime | None:
    return parse_when(value) if isinstance(value, str) else None


def _shown(value: Any) -> str:
    parsed = _when(value)
    return format_time(parsed) if parsed else ""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any) -> set[str]:
    return {value} if isinstance(value, str) and value else set()


def _record(
    kind: str,
    rid: Any,
    time: Any,
    fields: dict[str, Any],
    match: dict[str, set[str]],
    span: tuple[datetime, datetime] | None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "id": _clean(rid),
        "time": _shown(time),
        "fields": {
            k: _clean(v) if isinstance(v, str) else v for k, v in fields.items() if v is not None
        },
        "_m": match,
        "_span": span,
    }


def _span(first: Any, last: Any) -> tuple[datetime, datetime] | None:
    a, b = _when(first), _when(last)
    if a and b:
        return (min(a, b), max(a, b))
    one = a or b
    return (one, one) if one else None


def _collect(store: Store, q: Query) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    session_of: dict[str, str] = {}
    for e in store.events():
        attrs = _dict(e.get("attributes"))
        session = attrs.get("session") if isinstance(attrs.get("session"), str) else ""
        if session:
            session_of[str(e.get("event_id"))] = session
        if e.get("is_test") and not q.include_test:
            continue
        out.append(
            _record(
                "event",
                e.get("event_id"),
                e.get("time"),
                {
                    "event_type": e.get("event_type"),
                    "source": e.get("source"),
                    "asset_id": e.get("asset_id"),
                    "severity": e.get("severity"),
                    "credential_ref": e.get("credential_ref"),
                    "session": session or None,
                    "is_test": bool(e.get("is_test")),
                },
                {
                    "credential": _strings(e.get("credential_ref")),
                    "asset": _strings(e.get("asset_id")),
                    "session": _strings(session),
                    "event_type": _strings(e.get("event_type")),
                    "source": _strings(e.get("source")),
                },
                _span(e.get("time"), e.get("time")),
            )
        )
    test_incidents: set[str] = set()
    for d in store.docs("incidents"):
        if not isinstance(d, dict):
            continue
        if d.get("is_test"):
            test_incidents.add(str(d.get("id")))
            if not q.include_test:
                continue
        rows = _list(d.get("timeline"))
        sessions = {
            session_of[r["event_id"]]
            for r in rows
            if isinstance(r, dict)
            and isinstance(r.get("event_id"), str)
            and r["event_id"] in session_of
        }
        out.append(
            _record(
                "incident",
                d.get("id"),
                d.get("created"),
                {k: d.get(k) for k in ("rule_id", "severity", "status", "cred_ref", "asset_id")},
                {
                    "credential": _strings(d.get("cred_ref")),
                    "asset": _strings(d.get("asset_id")),
                    "session": sessions,
                },
                _span(d.get("created"), d.get("created")),
            )
        )
    for d in store.docs("findings"):
        if not isinstance(d, dict):
            continue
        locations = _list(d.get("locations"))
        assets = sorted(
            {
                x["asset_id"]
                for x in locations
                if isinstance(x, dict) and isinstance(x.get("asset_id"), str)
            }
        )
        out.append(
            _record(
                "finding",
                d.get("cred_ref"),
                d.get("last_seen"),
                {
                    "status": d.get("status"),
                    "first_seen": _shown(d.get("first_seen")) or None,
                    "assets": assets,
                    "location_count": len(locations),  # never the file or line
                },
                {"credential": _strings(d.get("cred_ref")), "asset": set(assets)},
                _span(d.get("first_seen"), d.get("last_seen")),
            )
        )
    for a in store.assets():
        out.append(
            _record(
                "asset",
                a.get("asset_id"),
                a.get("last_seen"),
                {
                    "asset_type": a.get("asset_type"),
                    "importance": a.get("importance"),
                    "approved": a.get("approved"),
                },
                {"asset": _strings(a.get("asset_id"))},
                _span(a.get("last_seen"), a.get("last_seen")),
            )
        )
    for d in store.docs("links"):
        if not isinstance(d, dict):
            continue
        out.append(
            _record(
                "link",
                f"{d.get('cred_ref')}|{d.get('asset_id')}",
                d.get("time"),
                {"permission": d.get("permission")},
                {"credential": _strings(d.get("cred_ref")), "asset": _strings(d.get("asset_id"))},
                _span(d.get("time"), d.get("time")),
            )
        )
    for n, (time, entry) in enumerate(store.audit_rows()):
        if not isinstance(entry, dict):
            continue
        if not q.include_test and str(entry.get("incident")) in test_incidents:
            continue  # the lifecycle actions of a simulated incident are test data too
        asset = entry.get("asset_id") or entry.get("asset")
        out.append(
            _record(
                "audit",
                f"audit-{n}",
                time,
                {k: entry.get(k) for k in _AUDIT_FIELDS},  # never evidence, detail or notes
                {"credential": _strings(entry.get("cred_ref")), "asset": _strings(asset)},
                _span(time, time),
            )
        )
    return out


def _matches(rec: dict[str, Any], q: Query) -> bool:
    for name in ("credential", "asset", "session", "event_type", "source"):
        wanted = getattr(q, name)
        if wanted is not None and wanted not in rec["_m"].get(name, set()):
            return False
    if q.since is not None or q.until is not None:
        span = rec["_span"]
        if span is None:
            return False
        if q.since is not None and span[1] < q.since:
            return False
        if q.until is not None and span[0] > q.until:
            return False
    return True


def run(store: Store, q: Query, now: datetime) -> dict[str, Any]:
    """The matching records, newest first, with counts per kind before the limit."""
    filters = (q.credential, q.asset, q.session, q.event_type, q.source, q.since, q.until)
    if all(f is None for f in filters):
        raise ValueError("give at least one filter (--credential, --asset, --session, --type, ...)")
    for name in ("credential", "asset", "session", "event_type", "source"):
        _check(name, getattr(q, name))
    if not 1 <= q.limit <= MAX_LIMIT:
        raise ValueError(f"--limit must be between 1 and {MAX_LIMIT}")
    records = _collect(store, q)
    hits = [r for r in records if _matches(r, q)]
    others = (q.asset, q.session, q.event_type, q.source)
    if q.credential is not None and all(f is None for f in others):
        # Only when the credential is the sole filter (besides time): with any other filter the
        # expansion would return assets that do not satisfy it. The assets the credential is
        # tied to: linked by a person, found in, or seen in an event.
        related = {
            a
            for r in hits
            if r["kind"] in ("link", "finding", "incident", "event")
            for a in (r["_m"].get("asset") or set())
        }
        have = {(r["kind"], r["id"]) for r in hits}
        for r in records:
            if r["kind"] == "asset" and r["id"] in related and ("asset", r["id"]) not in have:
                relaxed = Query(since=q.since, until=q.until)
                if _matches(r, relaxed):
                    hits.append(
                        {**r, "fields": {**r["fields"], "via": "related to the credential"}}
                    )
    hits.sort(key=lambda r: (r["time"], r["kind"], r["id"]), reverse=True)
    counts: dict[str, int] = {}
    for r in hits:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
    shown = [{k: v for k, v in r.items() if not k.startswith("_")} for r in hits[: q.limit]]
    return {
        "query": {
            "credential": q.credential,
            "asset": q.asset,
            "session": q.session,
            "event_type": q.event_type,
            "source": q.source,
            "since": format_time(q.since) if q.since else None,
            "until": format_time(q.until) if q.until else None,
            "include_test": q.include_test,
        },
        "note": NOTE,
        "counts": dict(sorted(counts.items())),
        "truncated": len(hits) > q.limit,
        "results": shown,
    }


def format_result(result: dict[str, Any]) -> str:
    total = sum(result["counts"].values())
    lines = [f"{total} record(s): " + ", ".join(f"{n} {k}" for k, n in result["counts"].items())]
    for r in result["results"]:
        details = " ".join(f"{k}={v}" for k, v in r["fields"].items() if v not in ("", [], None))
        lines.append(f"{r['time'] or '-':<21} {r['kind']:<9} {r['id']}  {details}")
    if result["truncated"]:
        lines.append(
            f"(showing {len(result['results'])} of {total}; use --limit or narrow the filters)"
        )
    lines.append(result["note"])
    return "\n".join(lines) + "\n"
