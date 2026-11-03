"""NVIDIA provider (ADR-0015): request shape, answer handling, key safety, pinned destination,
and an end-to-end run with a fake API. No test touches the network."""

import json
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_assistant import CRED, REPO, SETTINGS, T0, _snapshot, answer, r1_store

from sentinel import config
from sentinel.assistant import budget, client, explain, nvidia, prompt
from sentinel.assistant.client import AssistantError
from sentinel.sources.http import _NoRedirect

NV = replace(
    SETTINGS, provider="nvidia", model=nvidia.DEFAULT_MODEL, deep_model=nvidia.DEFAULT_MODEL
)
FAKE_KEY = "FAKE-NVIDIA-KEY-MARKER-0123456789"  # obviously fake, built in the test


def _reply(content: str, *, finish: str = "stop", usage: bool = True) -> bytes:
    data: dict[str, Any] = {
        "model": nvidia.DEFAULT_MODEL,
        "choices": [{"message": {"content": content}, "finish_reason": finish}],
    }
    if usage:
        data["usage"] = {"prompt_tokens": 1500, "completion_tokens": 700}
    return json.dumps(data).encode()


class FakeApi:
    def __init__(self, status: int = 200, raw: bytes | None = None) -> None:
        self.status, self.raw = status, raw if raw is not None else _reply(answer())
        self.bodies: list[dict[str, Any]] = []

    def post(self, body: dict[str, Any]) -> tuple[int, bytes]:
        self.bodies.append(body)
        return self.status, self.raw


# --- request ----------------------------------------------------------------------------------
def test_request_has_no_tools_carries_the_schema_and_no_key() -> None:
    body = nvidia.request(nvidia.DEFAULT_MODEL, "user text", 8000)
    assert "tools" not in body and "tool_choice" not in body and body["stream"] is False
    system = body["messages"][0]["content"]
    assert system.startswith(prompt.SYSTEM) and json.dumps(prompt.OUTPUT_SCHEMA) in system
    assert body["messages"][1] == {"role": "user", "content": "user text"}
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert FAKE_KEY not in json.dumps(body)


@pytest.mark.parametrize("bad", ["", "a", "bad model", "x" * 200, "../etc", "m\nx"])
def test_request_refuses_an_invalid_model_id(bad: str) -> None:
    with pytest.raises(AssistantError, match="invalid"):
        nvidia.request(bad, "u", 1000)


# --- answer -----------------------------------------------------------------------------------
def test_call_returns_text_model_and_usage() -> None:
    r = nvidia.call(FakeApi(), nvidia.request(nvidia.DEFAULT_MODEL, "u", 1000))
    assert json.loads(r.text)["summary"] and r.model == nvidia.DEFAULT_MODEL
    assert (r.input_tokens, r.output_tokens) == (1500, 700)


@pytest.mark.parametrize(
    "wrapped",
    [
        "```json\n{J}\n```",
        "<think>let me reason about {not json}</think>\n{J}",
        "Here is the JSON:\n{J}\nHope this helps.",
    ],
)
def test_json_is_extracted_from_fences_think_blocks_and_chatter(wrapped: str) -> None:
    api = FakeApi(raw=_reply(wrapped.replace("{J}", answer())))
    r = nvidia.call(api, nvidia.request(nvidia.DEFAULT_MODEL, "u", 1000))
    assert json.loads(r.text)["unknowns"] == ["Who called the API."]


@pytest.mark.parametrize(
    ("api", "message"),
    [
        (FakeApi(status=401), r"HTTP 401"),
        (FakeApi(status=429), r"HTTP 429"),
        (FakeApi(raw=_reply("x", finish="length")), "cut off"),
        (FakeApi(raw=_reply("x", finish="content_filter")), "declined"),
        (FakeApi(raw=_reply("   ")), "no text"),
        (FakeApi(raw=_reply("x", usage=False)), "unexpected shape"),
        (FakeApi(raw=b"not json"), "unexpected shape"),
        (FakeApi(raw=b'{"choices": []}'), "unexpected shape"),
    ],
)
def test_call_failures_are_reported_without_content(api: FakeApi, message: str) -> None:
    with pytest.raises(AssistantError, match=message) as exc:
        nvidia.call(api, nvidia.request(nvidia.DEFAULT_MODEL, "u", 1000))
    assert "summary" not in str(exc.value) and FAKE_KEY not in str(exc.value)


# --- key and destination ----------------------------------------------------------------------
def test_the_key_is_hidden_and_header_injection_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    assert FAKE_KEY not in repr(nvidia.NvidiaApi(FAKE_KEY))
    monkeypatch.setattr(nvidia, "get_key", lambda provider: FAKE_KEY + "\nX-Evil: 1")
    with pytest.raises(AssistantError, match="unexpected format"):
        nvidia.make_client()
    monkeypatch.setattr(nvidia, "get_key", lambda provider: None)
    with pytest.raises(AssistantError, match="set-key --provider nvidia"):
        nvidia.make_client()


def test_destination_is_fixed_https_with_no_redirects_or_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert nvidia.ENDPOINT == "https://integrate.api.nvidia.com/v1/chat/completions"
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("https_proxy", "http://proxy.invalid:3128")
    opener = nvidia.NvidiaApi(FAKE_KEY)._opener
    # urllib's default opener would add a ProxyHandler built from the environment; ours has none.
    assert not any(isinstance(h, urllib.request.ProxyHandler) for h in opener.handlers)
    default = urllib.request.build_opener()
    assert any(isinstance(h, urllib.request.ProxyHandler) for h in default.handlers)  # contrast
    assert any(isinstance(h, _NoRedirect) for h in opener.handlers)


def test_keys_are_stored_per_provider() -> None:
    assert client.KEYRING_USERS["nvidia"] != client.KEYRING_USERS["anthropic"]
    with pytest.raises(AssistantError, match="unknown provider"):
        client.get_key("other")


# --- config -----------------------------------------------------------------------------------
def test_config_provider_defaults_and_validation(tmp_path: Path) -> None:
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text('[assistant]\nprovider = "nvidia"\n', encoding="utf-8")
    s = config.load(cfg).assistant
    assert s.provider == "nvidia" and s.model == nvidia.DEFAULT_MODEL
    assert config.load(tmp_path / "missing.toml").assistant.provider == "anthropic"
    for text, match in (
        ('[assistant]\nprovider = "other"\n', "provider must be one of"),
        ('[assistant]\nprovider = "nvidia"\nmodel = "bad model"\n', "valid NVIDIA model"),
        ('[assistant]\nmodel = "nvidia/some-model"\n', "model must be one of"),  # claude provider
    ):
        cfg.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError, match=match):
            config.load(cfg)


# --- end to end -------------------------------------------------------------------------------
def test_end_to_end_with_nvidia_is_disguised_labelled_and_changes_no_state(
    tmp_path: Path,
) -> None:
    store, incident = r1_store(tmp_path)
    before = _snapshot(store)
    asked: list[str] = []
    api = FakeApi()
    result = explain.run(
        store,
        tmp_path,
        incident["id"],
        NV,
        T0,
        confirm=lambda q: asked.append(q) or True,
        make_client=lambda: api,
    )
    assert result is not None
    assert "integrate.api.nvidia.com" in asked[0] and nvidia.DEFAULT_MODEL in asked[0]
    sent = json.dumps(api.bodies[0])
    assert CRED not in sent and REPO not in sent and incident["id"] not in sent
    assert "AI-generated" in result.text and nvidia.DEFAULT_MODEL in result.text
    assert "owner states" in result.text and "$0.0000" in result.text  # free: stated, not proven
    assert CRED in result.text  # real names are restored locally, as inline code
    assert _snapshot(store) == before
    calls, usd = budget.spent(tmp_path, T0)
    assert calls == 1 and usd == 0.0  # counted as a call, no dollars


def test_nvidia_failure_still_counts_against_the_budget(tmp_path: Path) -> None:
    store, incident = r1_store(tmp_path)
    with pytest.raises(AssistantError, match="HTTP 500"):
        explain.run(
            store,
            tmp_path,
            incident["id"],
            NV,
            T0,
            confirm=lambda q: True,
            make_client=lambda: FakeApi(status=500),
        )
    assert budget.spent(tmp_path, T0)[0] == 1
    assert not (tmp_path / explain.OUT_DIR).exists()


def test_price_rules_for_nvidia_models() -> None:
    free = budget.worst_case(nvidia.DEFAULT_MODEL, 100_000, 8000, fallback=False)
    assert free == 0.0  # the owner-stated free model
    other = budget.worst_case("nvidia/other-model", 100_000, 8000, fallback=False)
    assert other > 0  # any other model keeps the highest-tier assumption
    assert budget.worst_case("claude-sonnet-5-5", 100_000, 8000) > 0  # Claude unchanged


def test_backend_dispatch() -> None:
    assert explain.backend(NV) is nvidia
    assert explain.backend(SETTINGS) is client


@pytest.mark.parametrize(
    ("raised", "kind"),
    [
        (TimeoutError("took too long"), "TimeoutError"),
        (ConnectionResetError("peer reset"), "ConnectionResetError"),
        (urllib.error.URLError(OSError("no route")), "OSError"),
    ],
)
def test_network_errors_name_the_kind_but_never_the_message(raised: OSError, kind: str) -> None:
    class Boom:
        def open(self, *args: Any, **kwargs: Any) -> Any:
            raise raised

    api = nvidia.NvidiaApi(FAKE_KEY)
    api._opener = Boom()  # type: ignore[assignment]
    with pytest.raises(AssistantError, match="network error") as exc:
        api.post({"model": nvidia.DEFAULT_MODEL})
    assert kind in str(exc.value)
    assert "took too long" not in str(exc.value) and FAKE_KEY not in str(exc.value)


def test_nvidia_refuses_real_incidents_and_sends_nothing(tmp_path: Path) -> None:
    """NVIDIA trial terms: testing only, content may train NVIDIA models, no confidential data."""
    from sentinel.incidents import lifecycle
    from sentinel.simulation import scenarios
    from sentinel.store.db import Store

    store = Store(tmp_path / "s.db")
    for e in scenarios.exposure(CRED, REPO, T0) + scenarios.provider_usage(CRED, "gcp-x", T0):
        e["is_test"] = False  # a real incident
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, T0)
    api = FakeApi()
    asked: list[str] = []
    with pytest.raises(AssistantError, match="only for simulated"):
        explain.run(
            store, tmp_path, iid, NV, T0,
            confirm=lambda q: asked.append(q) or True, make_client=lambda: api,
        )  # fmt: skip
    assert api.bodies == [] and asked == []  # refused before the question and before any call
    assert budget.spent(tmp_path, T0) == (0, 0.0)
