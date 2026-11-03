"""Second provider: NVIDIA's hosted OpenAI-compatible API (ADR-0015, README.md here).

The same rules as the Claude path:
- Destination fixed in code: https://integrate.api.nvidia.com/v1, HTTPS only, no redirects.
  Proxy and certificate environment variables are ignored; certificates are verified with the OS
  store, as for the collectors.
- Key only from the OS credential store (service "sentinel-assistant", entry "nvidia-api-key").
- No tools are offered. The answer must pass the same JSON schema as the Claude path; this API is
  asked for JSON in the prompt but does not enforce it, so a malformed answer is refused.
- Standard library only (urllib): no extra package.

Unverified until the first live call: that the endpoint accepts `chat_template_kwargs`, the exact
token usage fields, and how the model formats its JSON.
"""

import json
import re
import urllib.error
import urllib.request
from typing import Any

from sentinel.assistant.client import AssistantError, Reply, get_key
from sentinel.assistant.prompt import OUTPUT_SCHEMA, SYSTEM
from sentinel.sources.http import _NoRedirect, tls_context

BASE_URL = "https://integrate.api.nvidia.com/v1"
ENDPOINT = BASE_URL + "/chat/completions"
DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{2,79}")
KEY_FORMAT = re.compile(r"[\x21-\x7e]{8,512}")  # printable, no spaces or newlines (header safety)
TIMEOUT_S = 300.0  # a very large model can be slow
MAX_BODY = 10 * 1024 * 1024
TEMPERATURE = 0.2  # steady, repeatable structured answers (not the 1.0 of NVIDIA's chat sample)
TOP_P = 0.95
BILLING_NOTE = (
    "Cost is shown as $0 because the owner states this NVIDIA API is free (not verified by "
    "Sentinel). NVIDIA may still limit requests or credits; its portal shows the real use."
)
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL)


class NvidiaApi:
    """Holds the key privately; it never appears in repr, errors or logs."""

    def __init__(self, key: str) -> None:
        self._key = key
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),  # no proxy variables
            _NoRedirect,  # never forward Authorization to another location
            urllib.request.HTTPSHandler(context=tls_context()),
        )

    def __repr__(self) -> str:
        return "NvidiaApi(key=<hidden>)"

    def post(self, body: dict[str, Any]) -> tuple[int, bytes]:
        request = urllib.request.Request(  # noqa: S310  (URL is the fixed HTTPS constant above)
            ENDPOINT,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self._key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with self._opener.open(request, timeout=TIMEOUT_S) as resp:
                raw = resp.read(MAX_BODY + 1)
                status = int(resp.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code), b""  # the body is never read or shown
        except OSError as exc:  # URLError, timeouts, connection resets
            # Only the kind of failure is shown (for example TimeoutError, ConnectionResetError,
            # SSLCertVerificationError), never a message that could carry request content.
            kind = type(getattr(exc, "reason", exc)).__name__
            raise AssistantError(
                f"network error contacting integrate.api.nvidia.com ({kind})"
            ) from None
        if len(raw) > MAX_BODY:
            raise AssistantError("NVIDIA API answer is too large")
        return status, raw


def make_client() -> NvidiaApi:
    key = get_key("nvidia")
    if not key:
        raise AssistantError("no NVIDIA API key stored; run: sentinel ai set-key --provider nvidia")
    if not KEY_FORMAT.fullmatch(key):
        raise AssistantError("the stored NVIDIA key has an unexpected format; store it again")
    return NvidiaApi(key)


def request(model: str, user: str, max_tokens: int, *, fallbacks: bool = False) -> dict[str, Any]:
    """The exact request body. `fallbacks` is a Claude-only feature and is ignored here."""
    if not MODEL_PATTERN.fullmatch(model):
        raise AssistantError("invalid NVIDIA model id")
    system = (
        SYSTEM
        + "\n\nReturn ONLY one JSON object, with no text before or after it, that matches this "
        + "JSON Schema:\n"
        + json.dumps(OUTPUT_SCHEMA)
    )
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": TEMPERATURE,
        "top_p": TOP_P,
        "max_tokens": max_tokens,
        "stream": False,
        # Reasoning off: the thinking text would count against max_tokens and is not needed for a
        # schema-checked summary. Unverified against this endpoint (see module docstring).
        "chat_template_kwargs": {"enable_thinking": False},
    }


def extract_json(text: str) -> str:
    """The JSON object inside a model answer: drops <think> blocks and Markdown fences."""
    text = _THINK.sub("", text).strip()
    start, end = text.find("{"), text.rfind("}")
    return text[start : end + 1] if 0 <= start < end else text


def call(api: Any, body: dict[str, Any]) -> Reply:
    """Send one request. Errors carry the status only, never request or response content."""
    status, raw = api.post(body)
    if status != 200:
        raise AssistantError(f"NVIDIA API call failed (HTTP {status})")
    try:
        data = json.loads(raw)
        choice = data["choices"][0]
        text = choice["message"]["content"]
        finish = choice.get("finish_reason")
        usage = data["usage"]
        tokens_in, tokens_out = int(usage["prompt_tokens"]), int(usage["completion_tokens"])
        model = str(data.get("model") or body["model"])
    except (ValueError, KeyError, IndexError, TypeError):
        raise AssistantError("NVIDIA API answer has an unexpected shape") from None
    if finish == "length":
        raise AssistantError("the answer was cut off (max_tokens); raise max_output_tokens")
    if finish == "content_filter":
        raise AssistantError("the model declined to answer (content filter); nothing was written")
    if not isinstance(text, str) or not text.strip():
        raise AssistantError("the answer had no text")
    return Reply(
        text=extract_json(text), model=model, input_tokens=tokens_in, output_tokens=tokens_out
    )
