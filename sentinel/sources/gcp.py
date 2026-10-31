"""Google Cloud collector (read-only).

Destinations: monitoring.googleapis.com, apikeys.googleapis.com, oauth2.googleapis.com (token
refresh by google-auth). See ADR-0005 and docs/research/collectors.md.

Emits:
- credential_usage_anomaly: per-key request volume above max(multiple * 7-day hourly mean, floor),
  or ANY use of a key whose finding is revoked/verified (a key that should be dead).
- spend_anomaly: project request volume spike (a labelled proxy for spend; no billing data).
Google does not expose caller IP/region, and data is up to ~30 minutes late (documented).
Never fetches key strings (HttpClient refuses any path containing "keyString").
"""

import os
from datetime import datetime, timedelta
from typing import Any, Protocol
from urllib.parse import quote, urlencode

from sentinel.config import PROJECT_ID
from sentinel.events.schema import format_time, make_event
from sentinel.sources.base import DeferredState
from sentinel.sources.http import HttpClient, HttpError
from sentinel.store.db import Store

MONITORING = "https://monitoring.googleapis.com/v3"
APIKEYS = "https://apikeys.googleapis.com/v2"
# Requested on every token refresh, so the access token is narrowed to these (read-only) scopes.
# monitoring.read is needed in addition: Cloud Monitoring answered 403 to a token carrying only
# cloud-platform.read-only on the first live run (2026-10-31), while API Keys accepted it.
READ_ONLY_SCOPES = (
    "https://www.googleapis.com/auth/cloud-platform.read-only",
    "https://www.googleapis.com/auth/monitoring.read",
)
_HISTORY_HOURS = 7 * 24
_MIN_HISTORY = 24
_MAX_PAGES = 50  # a repeated or endless nextPageToken must not loop forever


class TokenProvider(Protocol):
    def token(self) -> str: ...


class AdcTokenProvider:
    """Application Default Credentials (created by the user with gcloud; never by Sentinel).

    google-auth makes its own HTTPS calls (via requests), outside HttpClient's allowlist, so only
    the narrowest credential type is accepted: `authorized_user` (gcloud auth
    application-default login), which refreshes via oauth2.googleapis.com. Service-account keys
    (long-lived private key) and external_account (can read arbitrary local files / call STS)
    are refused (fail closed).
    """

    def __init__(self, creds: Any = None) -> None:
        import google.auth
        import google.auth.transport.requests

        if creds is None:
            # Never probe the cloud metadata server (169.254.169.254): it is not a documented
            # destination (CLAUDE.md rule 5) and this tool only runs on workstations.
            os.environ["NO_GCE_CHECK"] = "True"
            # google-auth sends these scopes with each refresh (google/oauth2/credentials.py,
            # checked in google-auth 2.36.0), so the token is narrowed to read-only scopes.
            # HttpClient (GET only, host allowlist) is a second, independent limit (ADR-0005).
            creds, _ = google.auth.default(scopes=list(READ_ONLY_SCOPES))  # type: ignore[no-untyped-call]
        self.check_credentials(creds)
        self._creds = creds
        self._request = google.auth.transport.requests.Request()  # type: ignore[no-untyped-call]

    @property
    def quota_project(self) -> str | None:
        """Quota project recorded by gcloud in the credential (validated; None if absent)."""
        value = getattr(self._creds, "quota_project_id", None)
        return value if isinstance(value, str) and PROJECT_ID.fullmatch(value) else None

    @staticmethod
    def check_credentials(creds: Any) -> None:
        from google.oauth2 import credentials as user_credentials

        if not isinstance(creds, user_credentials.Credentials):
            raise ValueError(
                "ADC must be an authorized_user credential (run `gcloud auth application-default "
                f"login`); refusing credential type {type(creds).__name__}"
            )

    def token(self) -> str:
        if not self._creds.valid:
            self._creds.refresh(self._request)
        return str(self._creds.token)


def normalize_credential_id(value: str) -> str:
    """'apikey:<uid>' and '<uid>' map to the same key (the exact Google format is unconfirmed)."""
    return value.split(":", 1)[1] if value.startswith("apikey:") else value


def alias_key(project: str, credential_id: str) -> str:
    return f"gcp:{project}:{normalize_credential_id(credential_id)}"


def detect(
    points: list[tuple[str, int]], history: list[int], multiple: float, floor: int
) -> tuple[list[tuple[str, int, float, str]], list[int]]:
    """Pure: return (anomalies as (time, count, mean, reason), updated history).

    Points must be sorted. Once 24 hours are learned, anomalous hours are NOT added to the
    history, so a spike or a slow ramp cannot raise the baseline and hide later abuse. During
    warm-up (fewer than 24 hours of history) a count above floor * multiple is flagged, but every
    warm-up hour IS learned: otherwise a key that is normally busy would never finish warm-up and
    would be flagged every hour forever. So warm-up flags are bounded to the first 24 hours.
    """
    anomalies: list[tuple[str, int, float, str]] = []
    hist = list(history)
    for when, count in points:
        mean = sum(hist) / len(hist) if hist else 0.0
        if len(hist) >= _MIN_HISTORY:
            if count > max(multiple * mean, floor):
                anomalies.append((when, count, mean, "volume_above_baseline"))
                continue
        elif count > floor * multiple:
            anomalies.append((when, count, mean, "warmup_volume_above_floor"))
        hist.append(count)
        hist = hist[-_HISTORY_HOURS:]
    return anomalies, hist


def learn_only(
    points: list[tuple[str, int]], history: list[int]
) -> tuple[list[tuple[str, int, float, str]], list[int]]:
    """First contact: add every hour to the baseline and flag nothing."""
    return [], (list(history) + [count for _when, count in points])[-_HISTORY_HOURS:]


class GcpCollector(DeferredState):
    name = "gcp"

    def __init__(self, client: HttpClient, tokens: TokenProvider) -> None:
        super().__init__()
        self._client = client
        self._tokens = tokens
        self.notes: list[str] = []  # facts for the operator (e.g. "first run: baseline only")

    def _get(self, url: str, project: str) -> dict[str, Any]:
        # User credentials need a quota project on some Google APIs (API Keys in particular),
        # sent as x-goog-user-project. Use the one from the gcloud login, else the project read.
        quota = getattr(self._tokens, "quota_project", None) or project
        headers = {"Authorization": f"Bearer {self._tokens.token()}", "x-goog-user-project": quota}
        data = self._client.get(url, headers).json()
        if not isinstance(data, dict):  # an empty or odd body is not "no keys" or "no usage"
            raise HttpError("unexpected response shape from Google (not a JSON object)")
        return data

    def _pages(self, url: str, project: str, params: dict[str, str], field: str) -> list[Any]:
        items: list[Any] = []
        token, seen = "", set()
        for _ in range(_MAX_PAGES):
            query = dict(params, pageToken=token) if token else params
            page = self._get(f"{url}?{urlencode(query)}", project)
            items.extend(page.get(field, []))
            token = str(page.get("nextPageToken", ""))
            if not token:
                return items
            if token in seen:
                raise HttpError("Google returned a repeated page token; stopping")
            seen.add(token)
        raise HttpError(f"more than {_MAX_PAGES} pages from Google; stopping")

    # API key metadata ------------------------------------------------------------------
    def list_keys(self, project: str) -> list[dict[str, Any]]:
        return self._pages(
            f"{APIKEYS}/projects/{quote(project)}/locations/global/keys",
            project,
            {"showDeleted": "true", "pageSize": "300"},
            "keys",
        )

    def sync_key_assets(self, store: Store, project: str, now: datetime) -> int:
        count = 0
        for key in self.list_keys(project):
            uid = key.get("uid", "")
            if not uid:
                continue
            existing = {a["asset_id"]: a for a in store.assets()}.get(f"gcp-key-{uid}")
            store.upsert_asset(
                {
                    "asset_id": f"gcp-key-{uid}",
                    "asset_type": "api_key",
                    "name": key.get("displayName") or uid,
                    "owner": existing.get("owner") if existing else None,
                    "importance": existing.get("importance", "high") if existing else "high",
                    "monitoring": "partial",
                    "recovery_method": "delete and reissue in Google Cloud console",
                    "approved": bool(existing and existing.get("approved")),
                    "last_seen": format_time(now),
                    "attributes": {
                        "project": project,
                        "uid": uid,
                        "created": key.get("createTime"),
                        "deleted": key.get("deleteTime"),
                        "restricted": bool(key.get("restrictions")),
                    },
                }
            )
            count += 1
        return count

    def key_status(self, project: str, uid: str) -> dict[str, Any]:
        """Fresh evidence for verification: is the key gone or deleted?"""
        for key in self.list_keys(project):
            if key.get("uid") == uid:
                return {
                    "found": True,
                    "deleted": bool(key.get("deleteTime")),
                    "deleteTime": key.get("deleteTime"),
                }
        return {"found": False, "deleted": None, "deleteTime": None}  # unknown, never proof

    # usage ----------------------------------------------------------------------------
    def _series(
        self, project: str, start: str, end: str, group_by: str | None
    ) -> list[dict[str, Any]]:
        params = {
            "filter": 'metric.type="serviceruntime.googleapis.com/api/request_count" '
            'AND resource.type="consumed_api"',
            "interval.startTime": start,
            "interval.endTime": end,
            "aggregation.alignmentPeriod": "3600s",
            "aggregation.perSeriesAligner": "ALIGN_SUM",
            "aggregation.crossSeriesReducer": "REDUCE_SUM",
        }
        if group_by:
            params["aggregation.groupByFields"] = group_by
        return self._pages(
            f"{MONITORING}/projects/{quote(project)}/timeSeries", project, params, "timeSeries"
        )

    @staticmethod
    def _points(ts: dict[str, Any]) -> list[tuple[str, int]]:
        try:
            pts = []
            for p in ts.get("points", []):
                when = str(p["interval"]["endTime"])
                datetime.fromisoformat(when.replace("Z", "+00:00"))  # validate early
                pts.append((when, int(p["value"].get("int64Value", 0))))
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            # fixed text: never echo the response values into health or logs
            raise ValueError("malformed Monitoring data point from Google") from exc
        return sorted(pts)

    def collect_usage(
        self,
        store: Store,
        project: str,
        now: datetime,
        *,
        lookback: timedelta,
        multiple: float,
        floor: int,
        spend_multiple: float,
    ) -> list[dict[str, Any]]:
        cursor_key = f"gcp:{project}"
        cursor = store.get_doc("cursors", cursor_key)
        # Data is visible up to ~30 min late: only read complete hours (end = now - 1h) and
        # overlap the previous window by 2h. Baselines skip points already seen ("last").
        end_dt = now - timedelta(hours=1)
        # First contact: the lookback is LEARNED as the baseline and raises no volume alerts.
        # Without this, normal busy use would look like an "anomaly" (no baseline yet) and open
        # incidents for days of ordinary traffic. Limit (stated): abuse already running before
        # the first run is learned as normal; use of a key verified as revoked still alerts.
        first_run = cursor is None
        if cursor:
            since = datetime.fromisoformat(cursor["since"].replace("Z", "+00:00"))
            start = format_time(since - timedelta(hours=2))
        else:
            start = format_time(now - lookback)
        end = format_time(end_dt)
        dead = {d["cred_ref"] for d in store.docs("findings") if d["status"] == "revoked_verified"}
        events: list[dict[str, Any]] = []
        unlabeled = learned_hours = 0

        for ts in self._series(project, start, end, "resource.labels.credential_id"):
            raw_id = (ts.get("resource", {}).get("labels", {}) or {}).get("credential_id", "")
            if not raw_id:
                unlabeled += 1
                continue
            uid = normalize_credential_id(raw_id)
            alias = store.get_doc("aliases", alias_key(project, raw_id))
            cred = alias["cred_ref"] if alias else None
            base_key = f"gcp:{project}:cred:{uid}"
            base = store.get_doc("baselines", base_key) or {"history": [], "last": ""}
            points = [p for p in self._points(ts) if p[0] > base["last"]]
            if first_run:
                anomalies, history = learn_only(points, base["history"])
                learned_hours = max(learned_hours, len(points))
            else:
                anomalies, history = detect(points, base["history"], multiple, floor)
            hits = list(anomalies)
            if cred in dead:
                hits += [(t, c, 0.0, "use_of_dead_key") for t, c in points if c > 0]
            for when, count, mean, reason in hits:
                events.append(
                    make_event(
                        event_type="credential_usage_anomaly",
                        source="provider_usage",
                        asset_id=f"gcp-{project}",
                        time=datetime.fromisoformat(when.replace("Z", "+00:00")),
                        severity="high",
                        # warm-up has no learned baseline yet: a weaker signal
                        confidence="low" if reason == "warmup_volume_above_floor" else "medium",
                        evidence_ref=f"gcp/{project}/request_count/{uid}/{when}",
                        event_id=f"gcp:{project}:{uid}:{when}:{reason}",
                        credential_ref=cred,
                        attributes={
                            "provider_key_uid": uid,
                            "requests_in_hour": count,
                            "baseline_hourly_mean": round(mean, 2),
                            "reason": reason,
                            "mapped": cred is not None,
                        },
                    )
                )
            if points:
                self.defer("baselines", base_key, {"history": history, "last": points[-1][0]})

        for ts in self._series(project, start, end, None):
            base_key = f"gcp:{project}:project"
            base = store.get_doc("baselines", base_key) or {"history": [], "last": ""}
            points = [p for p in self._points(ts) if p[0] > base["last"]]
            if first_run:
                anomalies, history = learn_only(points, base["history"])
                learned_hours = max(learned_hours, len(points))
            else:
                anomalies, history = detect(points, base["history"], spend_multiple, floor)
            for when, count, mean, _reason in anomalies:
                events.append(
                    make_event(
                        event_type="spend_anomaly",
                        source="provider_usage",
                        asset_id=f"gcp-{project}",
                        time=datetime.fromisoformat(when.replace("Z", "+00:00")),
                        severity="medium",
                        confidence="low",
                        evidence_ref=f"gcp/{project}/request_count/project/{when}",
                        event_id=f"gcp:{project}:project:{when}",
                        attributes={
                            "multiple_of_baseline": round(count / mean, 2) if mean else 0.0,
                            "baseline_days": 7,
                            "proxy": "request volume (no billing data)",
                        },
                    )
                )
            if points:
                self.defer("baselines", base_key, {"history": history, "last": points[-1][0]})
        self.defer("cursors", cursor_key, {"since": end})
        if first_run:
            self.notes.append(
                f"gcp:{project}: first run, learned {learned_hours} hour(s) of usage as the "
                "baseline; volume alerts start from the next run"
            )
        if unlabeled:
            self.notes.append(
                f"gcp:{project}: {unlabeled} usage series had no API key id; per-key detection "
                "(R1, R11) cannot see that traffic (Google label format unconfirmed)"
            )
        return events
