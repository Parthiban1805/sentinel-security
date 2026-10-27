"""Exposure probes (scenarios S1, S15): is a sensitive file served by one of OUR hosts?

Network safety (ADR-0008, project rule 5):
- Only hosts the owner listed in the config with `confirm_ownership = true` (or passed with
  --i-own-this) are ever contacted. There is no discovery and no crawling.
- GET only, at most ~25 fixed paths per host, a pause between requests, short timeouts,
  redirects are never followed, cloud-metadata addresses are refused.
- Only the first 512 bytes are read, and only to test the file's SHAPE (an env file, a git config,
  a SQL dump, a zip...). The bytes are discarded immediately: never stored, logged or printed.
- A match is evidence of exposure, not of misuse: whether anything inside was already fetched or
  used is unknown (a hypothesis to investigate).
"""

import ipaddress
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from sentinel.events.schema import format_time, make_event
from sentinel.sources.http import _NoRedirect, tls_context
from sentinel.store.db import Store

MAX_BYTES = 512
MAX_SILENT = 3  # give up on a host after this many unanswered requests in a row
USER_AGENT = "sentinel-exposure-probe/0.4 (run by the host owner)"


class ProbeError(ValueError):
    """Invalid or unsafe probe target (message never contains response content)."""


# file-shape signatures (each sees at most MAX_BYTES; none stores or returns content) -----------
def _text(body: bytes) -> str:
    return body.decode("utf-8", errors="ignore")


def _env_like(body: bytes) -> bool:
    text = _text(body)
    if "<html" in text.lower()[:300] or "<!doctype" in text.lower()[:300]:
        return False
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    head = lines[:4]
    return bool(head) and all(
        re.match(r"^(export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=", ln) for ln in head
    )


def _git_config(body: bytes) -> bool:
    return b"[core]" in body


def _git_head(body: bytes) -> bool:
    return body.startswith(b"ref: refs/") or bool(re.match(rb"^[0-9a-f]{40}\s*$", body[:42]))


def _sql_dump(body: bytes) -> bool:
    return any(
        t in body
        for t in (
            b"CREATE TABLE",
            b"INSERT INTO",
            b"-- MySQL dump",
            b"PostgreSQL database dump",
            b"DROP TABLE IF EXISTS",
        )
    )


def _zip(body: bytes) -> bool:
    return body.startswith(b"PK\x03\x04")


def _gzip(body: bytes) -> bool:
    return body.startswith(b"\x1f\x8b")


def _sqlite(body: bytes) -> bool:
    return body.startswith(b"SQLite format 3\x00")


def _aws_credentials(body: bytes) -> bool:
    low = body.lower()
    return b"aws_access_key_id" in low or (b"[default]" in low and b"aws_" in low)


def _npmrc(body: bytes) -> bool:
    return b"_authtoken" in body.lower()


_PEM_START = b"-----BEGIN "  # split so no complete key header sits in the source
_PEM_KIND = b"PRIVATE KEY-----"


def _private_key(body: bytes) -> bool:
    return _PEM_START in body and _PEM_KIND in body


def _ds_store(body: bytes) -> bool:
    return b"Bud1" in body[:16]


def _apache_status(body: bytes) -> bool:
    return b"Apache Server Status" in body


def _phpinfo(body: bytes) -> bool:
    return b"phpinfo()" in body or b"PHP Version" in body


@dataclass(frozen=True)
class Probe:
    id: str
    path: str
    severity: str  # critical = secrets likely inside; high = source/data; medium = information leak
    signature: str  # name of the shape that matched (never the content)
    check: Callable[[bytes], bool]
    scenario: str  # S1 (sensitive path) or S15 (backup)


PROBES: tuple[Probe, ...] = (
    Probe("X01", "/.env", "critical", "env file", _env_like, "S1"),
    Probe("X02", "/.env.production", "critical", "env file", _env_like, "S1"),
    Probe("X03", "/.env.local", "critical", "env file", _env_like, "S1"),
    Probe("X04", "/.env.backup", "critical", "env file", _env_like, "S1"),
    Probe("X05", "/.git/config", "high", "git config", _git_config, "S1"),
    Probe("X06", "/.git/HEAD", "high", "git HEAD", _git_head, "S1"),
    Probe("X07", "/.aws/credentials", "critical", "cloud credentials file", _aws_credentials, "S1"),
    Probe("X08", "/.npmrc", "critical", "package registry token file", _npmrc, "S1"),
    Probe("X09", "/id_rsa", "critical", "private key", _private_key, "S1"),
    Probe("X10", "/.ssh/id_rsa", "critical", "private key", _private_key, "S1"),
    Probe("X11", "/backup.sql", "high", "SQL dump", _sql_dump, "S15"),
    Probe("X12", "/dump.sql", "high", "SQL dump", _sql_dump, "S15"),
    Probe("X13", "/database.sql", "high", "SQL dump", _sql_dump, "S15"),
    Probe("X14", "/db.sql", "high", "SQL dump", _sql_dump, "S15"),
    Probe("X15", "/backup.zip", "high", "zip archive", _zip, "S15"),
    Probe("X16", "/site.zip", "high", "zip archive", _zip, "S15"),
    Probe("X17", "/backup.tar.gz", "high", "gzip archive", _gzip, "S15"),
    Probe("X18", "/db.sqlite", "high", "SQLite database", _sqlite, "S15"),
    Probe("X19", "/database.sqlite", "high", "SQLite database", _sqlite, "S15"),
    Probe("X20", "/.DS_Store", "medium", "directory listing file", _ds_store, "S1"),
    Probe("X21", "/server-status", "medium", "server status page", _apache_status, "S1"),
    Probe("X22", "/phpinfo.php", "medium", "phpinfo page", _phpinfo, "S1"),
)
PROBE_BY_ID = {p.id: p for p in PROBES}


# target validation -----------------------------------------------------------------------------
def normalize_target(url: str, *, allow_http: bool = False) -> str:
    """Return the base URL (scheme://host[:port]) or raise ProbeError."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("https", "http"):
        raise ProbeError("target must start with https:// (or http:// with allow_http)")
    if parts.scheme == "http" and not allow_http:
        raise ProbeError("plain http targets need allow_http = true (traffic is not encrypted)")
    if not parts.hostname:
        raise ProbeError("target has no host name")
    if parts.username or parts.password:
        raise ProbeError("credentials in the URL are not allowed")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ProbeError("target must be a bare host (no path, query or fragment)")
    try:
        _ = parts.port  # raises ValueError for an invalid port
    except ValueError as exc:
        raise ProbeError("invalid port") from exc
    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError:
        address = None
    if address is not None and address.is_link_local:
        raise ProbeError("link-local addresses (cloud metadata) are refused")
    return f"{parts.scheme}://{parts.netloc}"


def host_label(base_url: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", urlsplit(base_url).netloc.lower()).strip("-")


def asset_id_for_host(base_url: str) -> str:
    return "host-" + host_label(base_url)


# fetching --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Fetch:
    status: int | None  # None = no HTTP answer (error)
    body: bytes  # at most MAX_BYTES; discarded by callers after the signature test
    error: str | None = None  # exception TYPE name only


FetchFn = Callable[[str], Fetch]


def make_fetcher(allow_http: bool, timeout: float = 8.0) -> FetchFn:
    handlers: list[Any] = [_NoRedirect]
    handlers.append(urllib.request.HTTPSHandler(context=tls_context()))
    opener = urllib.request.build_opener(*handlers)

    def fetch(url: str) -> Fetch:
        request = urllib.request.Request(  # noqa: S310 (scheme validated by normalize_target)
            url,
            headers={"User-Agent": USER_AGENT, "Range": f"bytes=0-{MAX_BYTES - 1}"},
            method="GET",
        )
        try:
            with opener.open(request, timeout=timeout) as resp:
                return Fetch(resp.status, resp.read(MAX_BYTES))
        except urllib.error.HTTPError as exc:
            return Fetch(exc.code, b"")  # 3xx/4xx/5xx: never follow, never read the body
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return Fetch(None, b"", type(exc).__name__)

    return fetch


@dataclass(frozen=True)
class Exposure:
    probe: str
    path: str
    severity: str
    signature: str
    scenario: str
    status: int


def evaluate(probe: Probe, result: Fetch) -> str:
    """'exposed', 'clear' (a definitive answer without the file) or 'inconclusive' (no answer)."""
    if result.status is None:
        return "inconclusive"
    if result.status in (200, 206) and probe.check(result.body):
        return "exposed"
    return "clear"


def probe_host(
    base_url: str, fetch: FetchFn, *, pause: float = 0.25, only: tuple[str, ...] | None = None
) -> tuple[list[Exposure], bool]:
    """Probe one host. Returns (exposures, reachable). Content is never kept."""
    exposures: list[Exposure] = []
    reachable = False
    silent = 0  # consecutive requests with no HTTP answer
    probes = [p for p in PROBES if only is None or p.id in only]
    for index, probe in enumerate(probes):
        if index and pause:
            time.sleep(pause)
        result = fetch(base_url + probe.path)
        reachable = reachable or result.status is not None
        silent = 0 if result.status is not None else silent + 1
        if not reachable and silent >= MAX_SILENT:
            break  # a host that answers nothing is down or filtered: do not hammer it
        if evaluate(probe, result) == "exposed":
            exposures.append(
                Exposure(
                    probe.id,
                    probe.path,
                    probe.severity,
                    probe.signature,
                    probe.scenario,
                    result.status or 0,
                )
            )
    return exposures, reachable


# state, events ---------------------------------------------------------------------------------
def snapshot_key(base_url: str) -> str:
    return f"probes:{host_label(base_url)}"


def due(store: Store, base_url: str, now: datetime, interval_hours: int) -> bool:
    previous = store.get_doc("snapshots", snapshot_key(base_url))
    if previous is None or interval_hours <= 0:
        return True
    last = datetime.fromisoformat(previous["time"].replace("Z", "+00:00"))
    return (now - last).total_seconds() >= interval_hours * 3600


def collect(
    store: Store, base_url: str, now: datetime, fetch: FetchFn, *, pause: float = 0.25
) -> tuple[list[dict[str, Any]], list[str], bool, dict[str, Any]]:
    """Probe a host. Returns (events, cleared paths, reachable, new snapshot). The caller stores the
    events, then saves the snapshot (state advances only after the events were stored)."""
    asset = asset_id_for_host(base_url)
    if not any(a["asset_id"] == asset for a in store.assets()):
        store.upsert_asset(
            {
                "asset_id": asset,
                "asset_type": "server",
                "name": urlsplit(base_url).netloc,
                "owner": None,
                "importance": "medium",
                "monitoring": "partial",
                "approved": False,
                "last_seen": format_time(now),
                "attributes": {"base_url": base_url},
            }
        )
    exposures, reachable = probe_host(base_url, fetch, pause=pause)
    previous = store.get_doc("snapshots", snapshot_key(base_url))
    events = [
        make_event(
            event_type="exposed_service",
            source="exposure_probe",
            asset_id=asset,
            time=now,
            severity=e.severity,
            confidence="high",
            evidence_ref=f"probe/{host_label(base_url)}{e.path}",
            event_id=f"probe:{host_label(base_url)}:{e.probe}",
            attributes={
                "base_url": base_url,
                "path": e.path,
                "probe": e.probe,
                "signature": e.signature,
                "scenario": e.scenario,
                "status": e.status,
            },
        )
        for e in exposures
    ]
    now_paths = sorted(e.path for e in exposures)
    # Paths that were exposed and now answer definitively are "cleared"; a host that did not
    # answer at all proves nothing, so its previous exposures are carried over.
    cleared = sorted(set(previous["exposed"]) - set(now_paths)) if previous and reachable else []
    exposed_state = now_paths if reachable or previous is None else previous["exposed"]
    return events, cleared, reachable, {"exposed": exposed_state, "time": format_time(now)}


def reprobe(base_url: str, path: str, fetch: FetchFn) -> tuple[str, int | None]:
    """Fresh check of ONE path (used to verify a fix). Returns (state, http status)."""
    probe = next((p for p in PROBES if p.path == path), None)
    if probe is None:
        raise ProbeError(f"unknown probe path: {path}")
    result = fetch(base_url + path)
    return evaluate(probe, result), result.status
