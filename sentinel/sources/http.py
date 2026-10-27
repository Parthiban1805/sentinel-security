"""Minimal HTTPS client for collectors (ADR-0005).

Enforced here, not by convention: HTTPS only, host allowlist, method allowlist, a path denylist
(never fetch raw API key strings), timeouts and bounded retries. Error messages carry the status,
host and path only: never query strings, headers, tokens or response bodies.
"""

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

ALLOWED_HOSTS = frozenset(
    {
        "api.github.com",
        "monitoring.googleapis.com",
        "apikeys.googleapis.com",
        "oauth2.googleapis.com",
    }
)
# Covers both the RPC name (":getKeyString") and the REST path ("/keys/{id}/keyString").
_DENY_PATH_PARTS = ("keystring",)
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


class HttpError(RuntimeError):
    """Request refused or failed (no secrets in the message)."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8")) if self.body else None


class Transport(Protocol):
    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
    ) -> Response: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would forward Authorization to the new location."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_MAX_BODY = 10 * 1024 * 1024
_OPENER = urllib.request.build_opener(_NoRedirect)


class UrllibTransport:
    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
    ) -> Response:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310
        try:
            with _OPENER.open(request, timeout=timeout) as resp:
                data = resp.read(_MAX_BODY + 1)
                if len(data) > _MAX_BODY:
                    raise HttpError(f"response too large from {urlsplit(url).hostname}")
                return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, data)
        except urllib.error.HTTPError as exc:
            return Response(exc.code, {k.lower(): v for k, v in exc.headers.items()}, b"")
        except (urllib.error.URLError, TimeoutError) as exc:
            raise HttpError(f"network error contacting {urlsplit(url).hostname}") from exc


def check_url(url: str, method: str = "GET") -> None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise HttpError("only https is allowed")
    if parts.hostname not in ALLOWED_HOSTS:
        raise HttpError(f"host not in ADR-0005 allowlist: {parts.hostname}")
    try:
        port = parts.port
    except ValueError as exc:
        raise HttpError("invalid port") from exc
    if port not in (None, 443):
        raise HttpError("only the default HTTPS port is allowed")
    path = parts.path
    for _ in range(5):  # servers decode percent-escapes: check the decoded form too
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if ".." in path.split("/"):
        raise HttpError("path traversal is not allowed")
    if any(p in path.lower() for p in _DENY_PATH_PARTS):
        raise HttpError("fetching raw key strings is forbidden")
    if method not in ("GET", "POST"):
        raise HttpError(f"method not allowed: {method}")
    if method == "POST" and parts.hostname != "oauth2.googleapis.com":
        raise HttpError("POST is only allowed for OAuth token refresh")


class HttpClient:
    def __init__(
        self,
        transport: Transport | None = None,
        *,
        timeout: float = 20.0,
        retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._transport = transport or UrllibTransport()
        self._timeout = timeout
        self._retries = retries
        self._sleep = sleep

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        check_url(url, "GET")
        where = f"{urlsplit(url).hostname}{urlsplit(url).path}"
        for attempt in range(self._retries + 1):
            resp = self._transport.send("GET", url, dict(headers or {}), None, self._timeout)
            if resp.status in _RETRY_STATUS and attempt < self._retries:
                self._sleep(min(2**attempt, 30))
                continue
            if resp.status >= 300:  # includes redirects, which are never followed
                raise HttpError(f"HTTP {resp.status} from {where}", resp.status)
            return resp
        raise HttpError(f"retries exhausted for {where}")  # pragma: no cover
