"""The one outbound connection of the assistant: api.anthropic.com (ADR-0014, README.md here).

- Destination pinned in code (an ANTHROPIC_BASE_URL environment variable cannot redirect it).
- API key read only from the OS credential store (Windows Credential Manager via `keyring`); never
  from environment variables or files, never printed.
- No tools are offered to the model: it can only return text in the fixed output schema.
- The SDK and keyring are optional (`sentinel[ai]`); they are imported only when used.
"""

import getpass
from dataclasses import dataclass
from typing import Any

from sentinel.assistant.prompt import OUTPUT_SCHEMA, SYSTEM
from sentinel.sources.http import tls_context

BASE_URL = "https://api.anthropic.com"
KEYRING_SERVICE = "sentinel-assistant"
KEYRING_USER = "anthropic-api-key"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
TIMEOUT_S = 120.0
# Windows Credential Manager, macOS Keychain, Linux Secret Service. Not plaintext-file backends
# (keyrings.alt), not the null/fail backends, not a chainer that could fall back to a file.
OS_KEYRING_BACKENDS = (
    "keyring.backends.Windows",
    "keyring.backends.macOS",
    "keyring.backends.SecretService",
    "keyring.backends.libsecret",
)


class AssistantError(ValueError):
    """The assistant could not produce an answer (missing key, refusal, truncation, API error)."""


@dataclass(frozen=True)
class Reply:
    text: str
    model: str  # the model that answered (may be a refusal-fallback model)
    input_tokens: int
    output_tokens: int


def _keyring() -> Any:
    try:
        import keyring
    except ImportError:
        raise AssistantError(
            "the AI assistant is not installed; install the optional extra: sentinel[ai]"
        ) from None
    backend = type(keyring.get_keyring()).__module__
    if not backend.startswith(OS_KEYRING_BACKENDS):
        raise AssistantError(
            f"keyring backend {backend!r} is not an OS credential store; refusing to use it "
            "(check PYTHON_KEYRING_BACKEND and keyringrc.cfg)"
        )
    return keyring


def set_key() -> None:
    """Ask for the key without echoing it and store it in the OS credential store."""
    value = getpass.getpass("Anthropic API key (input hidden): ").strip()
    if not value:
        raise AssistantError("no key entered; nothing stored")
    _keyring().set_password(KEYRING_SERVICE, KEYRING_USER, value)


def delete_key() -> None:
    _keyring().delete_password(KEYRING_SERVICE, KEYRING_USER)


def has_key() -> bool:
    return bool(_keyring().get_password(KEYRING_SERVICE, KEYRING_USER))


def make_client() -> Any:
    key = _keyring().get_password(KEYRING_SERVICE, KEYRING_USER)
    if not key:
        raise AssistantError("no Anthropic API key stored; run: sentinel ai set-key")
    try:
        import anthropic
    except ImportError:
        raise AssistantError(
            "the AI assistant is not installed; install the optional extra: sentinel[ai]"
        ) from None
    # No automatic retries: one confirmed call is one billed request, matching the reservation.
    # trust_env=False: proxy and certificate environment variables (HTTPS_PROXY, SSL_CERT_FILE)
    # cannot reroute the key and the pack; certificates are verified by the OS store, as for the
    # collectors. Checked against anthropic 2.3.0: the key (not ANTHROPIC_AUTH_TOKEN) is the
    # credential sent, and an explicit base_url wins over ANTHROPIC_BASE_URL.
    return anthropic.Anthropic(
        api_key=key,
        base_url=BASE_URL,
        timeout=TIMEOUT_S,
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(trust_env=False, verify=tls_context()),
    )


def request(model: str, user: str, max_tokens: int, *, fallbacks: bool) -> dict[str, Any]:
    """The exact request body (also used by tests to prove there are no tools)."""
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": SYSTEM,
        "messages": [{"role": "user", "content": user}],
        "output_config": {
            "effort": "medium",
            "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA},
        },
    }
    if fallbacks:
        body["betas"] = [FALLBACK_BETA]
        body["fallbacks"] = "default"
    return body


def call(client: Any, body: dict[str, Any]) -> Reply:
    """Send one request. Errors never include request content."""
    try:
        if "betas" in body:
            response = client.beta.messages.create(**body)
        else:
            response = client.messages.create(**body)
    except Exception as exc:  # SDK errors: report the class and status only, never the body
        status = getattr(exc, "status_code", None)
        detail = f" (HTTP {status})" if status else ""
        raise AssistantError(f"Anthropic API call failed: {type(exc).__name__}{detail}") from None
    if response.stop_reason == "refusal":
        raise AssistantError("the model declined to answer (refusal); nothing was written")
    if response.stop_reason == "max_tokens":
        raise AssistantError("the answer was cut off (max_tokens); raise max_output_tokens")
    text = next((b.text for b in response.content if getattr(b, "type", "") == "text"), None)
    if text is None:
        raise AssistantError("the answer had no text block")
    return Reply(
        text=text,
        model=str(response.model),
        input_tokens=int(response.usage.input_tokens),
        output_tokens=int(response.usage.output_tokens),
    )
