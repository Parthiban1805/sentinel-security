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

from datetime import datetime, timedelta
from typing import Any, Protocol
from urllib.parse import quote, urlencode

from sentinel.events.schema import format_time, make_event
from sentinel.sources.base import DeferredState
from sentinel.sources.http import HttpClient
from sentinel.store.db import Store

MONITORING = "https://monitoring.googleapis.com/v3"
APIKEYS = "https://apikeys.googleapis.com/v2"
READ_ONLY_SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"
_HISTORY_HOURS = 7 * 24
_MIN_HISTORY = 24


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
            creds, _ = google.auth.default(scopes=[READ_ONLY_SCOPE])  # type: ignore[no-untyped-call]
        self.check_credentials(creds)
        self._creds = creds
        self._request = google.auth.transport.requests.Request()  # type: ignore[no-untyped-call]

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

    Points must be sorted. Anomalous hours are NOT added to the history, so a spike or a slow
    ramp cannot raise the baseline and hide later abuse. During warm-up (fewer than 24 hours of
    history) only a count above floor * multiple is flagged, so a stolen new key cannot hide.
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
            continue
        hist.append(count)
        hist = hist[-_HISTORY_HOURS:]
    return anomalies, hist


class GcpCollector(DeferredState):
    name = "gcp"

    def __init__(self, client: HttpClient, tokens: TokenProvider) -> None:
        super().__init__()
        self._client = client
        self._tokens = tokens

    def _get(self, url: str) -> Any:
        return (
            self._client.get(url, {"Authorization": f"Bearer {self._tokens.token()}"}).json() or {}
        )

    # API key metadata ------------------------------------------------------------------
    def list_keys(self, project: str) -> list[dict[str, Any]]:
        keys: list[dict[str, Any]] = []
        token = ""
        while True:
            params = {"showDeleted": "true", "pageSize": "300"}
            if token:
                params["pageToken"] = token
            page = self._get(
                f"{APIKEYS}/projects/{quote(project)}/locations/global/keys?{urlencode(params)}"
            )
            keys.extend(page.get("keys", []))
            token = page.get("nextPageToken", "")
            if not token:
                return keys

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
        return {"found": False, "deleted": True, "deleteTime": None}

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
        series: list[dict[str, Any]] = []
        token = ""
        while True:
            query = dict(params, pageToken=token) if token else params
            page = self._get(
                f"{MONITORING}/projects/{quote(project)}/timeSeries?{urlencode(query)}"
            )
            series.extend(page.get("timeSeries", []))
            token = page.get("nextPageToken", "")
            if not token:
                return series

    @staticmethod
    def _points(ts: dict[str, Any]) -> list[tuple[str, int]]:
        pts = [
            (p["interval"]["endTime"], int(p["value"].get("int64Value", 0)))
            for p in ts.get("points", [])
        ]
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
        if cursor:
            since = datetime.fromisoformat(cursor["since"].replace("Z", "+00:00"))
            start = format_time(since - timedelta(hours=2))
        else:
            start = format_time(now - lookback)
        end = format_time(end_dt)
        dead = {d["cred_ref"] for d in store.docs("findings") if d["status"] == "revoked_verified"}
        events: list[dict[str, Any]] = []

        for ts in self._series(project, start, end, "resource.labels.credential_id"):
            raw_id = (ts.get("resource", {}).get("labels", {}) or {}).get("credential_id", "")
            if not raw_id:
                continue
            uid = normalize_credential_id(raw_id)
            alias = store.get_doc("aliases", alias_key(project, raw_id))
            cred = alias["cred_ref"] if alias else None
            base_key = f"gcp:{project}:cred:{uid}"
            base = store.get_doc("baselines", base_key) or {"history": [], "last": ""}
            points = [p for p in self._points(ts) if p[0] > base["last"]]
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
                        confidence="medium",
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
        return events
