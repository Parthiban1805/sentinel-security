"""Minimal HTTPS client for collectors (ADR-0005).

Enforced here, not by convention: HTTPS only, host allowlist, method allowlist, a path denylist
(never fetch raw API key strings), timeouts and bounded retries. Error messages carry the status,
host and path only: never query strings, headers, tokens or response bodies.
"""

import json
import ssl
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
    """Request refused or failed (no secrets in the message).

    `hint` is a small fixed vocabulary derived from the error body (never the body itself):
    "plan_limit", "no_permission", "not_protected" or None."""

    def __init__(self, message: str, status: int | None = None, hint: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.hint = hint


def error_hint(body: bytes) -> str | None:
    """Classify a GitHub or Google error body into a fixed label (the text is never kept or shown).

    Google reasons are checked before the generic PERMISSION_DENIED that usually comes with them."""
    text = body[:2048].decode("utf-8", errors="ignore").lower()
    if "upgrade to github pro" in text or "make this repository public" in text:
        return "plan_limit"
    if "resource not accessible" in text:
        return "no_permission"
    if "branch not protected" in text:
        return "not_protected"
    if "service_disabled" in text:
        return "api_disabled"
    if "access_token_scope_insufficient" in text or "insufficient authentication scopes" in text:
        return "scope_insufficient"
    if "user_project_denied" in text or "quota project" in text:
        return "quota_project"
    if "rate_limit_exceeded" in text or "ratelimitexceeded" in text:
        return "rate_limited"
    if "or the resource may not exist" in text:
        return "denied_or_missing"  # Google's wording when it will not say which of the two
    if "permission_denied" in text:
        return "no_permission"
    return None


# What to do next, per hint (fixed text; shown in health instead of the provider's message).
HINT_ADVICE = {
    "api_disabled": "the API is not enabled on this project (enable it in the Cloud console)",
    "scope_insufficient": "the login does not grant this access (re-run the gcloud login)",
    "quota_project": "no usable quota project (run `gcloud auth application-default "
    "set-quota-project <project-id>`)",
    "rate_limited": "rate limited by the provider (try again later)",
    "no_permission": "this account lacks a permission or role for this call",
    "denied_or_missing": "permission denied, or the requested resource does not exist "
    "(Google does not say which)",
}


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


def tls_context() -> ssl.SSLContext:
    """TLS context that verifies certificates (never disabled).

    Uses the operating system's verifier (truststore): on Windows it completes certificate chains
    and trusts roots installed by a VPN/security tool, which Python's bundled OpenSSL path cannot
    ("unable to get issuer certificate"). Falls back to the default verifying context.
    """
    try:
        import truststore

        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except ImportError:  # pragma: no cover
        return ssl.create_default_context()


_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=tls_context())
)


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
            try:
                error_body = exc.read(2048)  # only to classify the error; never kept or shown
            except OSError:
                error_body = b""
            return Response(exc.code, {k.lower(): v for k, v in exc.headers.items()}, error_body)
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
                hint = error_hint(resp.body)
                if resp.status == 401:
                    note = " (the token was rejected: expired, revoked or wrong)"
                elif hint in HINT_ADVICE and "googleapis.com" in where:
                    note = f" ({HINT_ADVICE[hint]})"
                else:
                    note = ""
                raise HttpError(f"HTTP {resp.status} from {where}{note}", resp.status, hint)
            return resp
        raise HttpError(f"retries exhausted for {where}")  # pragma: no cover
