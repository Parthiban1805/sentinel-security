"""Run the assistant for one incident: pack, budget, confirm, call, check, write (ADR-0014).

Read-only towards Sentinel state: the store is only read. The answer goes to its own file under
<home>/ai-summaries/; spending goes to <home>/ai-usage.jsonl.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.assistant import budget, client, output, pack, prompt
from sentinel.config import AssistantSettings
from sentinel.events.schema import format_time
from sentinel.store.db import Store

OUT_DIR = "ai-summaries"


@dataclass(frozen=True)
class Result:
    path: Path
    text: str
    cost_usd: float


def build_pack(store: Store, incident_id: str) -> pack.Pack:
    incident = store.get_doc("incidents", incident_id)
    if incident is None:
        raise KeyError(f"unknown incident: {incident_id}")
    return pack.build(incident, store.events(), store.assets())


def worst_case(p: pack.Pack, settings: AssistantSettings, *, deep: bool = False) -> float:
    """Most one call for this pack can cost (system prompt, pack and output schema are sent)."""
    model = settings.deep_model if deep else settings.model
    sent = prompt.SYSTEM + prompt.user_message(p) + json.dumps(prompt.OUTPUT_SCHEMA)
    return budget.worst_case(model, budget.estimate_tokens(sent), settings.max_output_tokens)


def run(
    store: Store,
    home: Path,
    incident_id: str,
    settings: AssistantSettings,
    now: datetime,
    *,
    deep: bool = False,
    confirm: Callable[[str], bool],
    make_client: Callable[[], Any] = client.make_client,
    ledger_home: Path | None = None,
) -> Result | None:
    """Returns None when the operator declines at the confirmation prompt. `ledger_home` holds the
    spending ledger (default `home`); the eval set passes the real home so its spend counts."""
    ledger = ledger_home or home
    p = build_pack(store, incident_id)
    user = prompt.user_message(p)
    model = settings.deep_model if deep else settings.model
    worst = worst_case(p, settings, deep=deep)
    budget.check(ledger, now, budget.Limits(settings.daily_calls, settings.monthly_usd), worst)
    question = (
        f"Send the disguised evidence pack for {incident_id} to {model} at {client.BASE_URL}? "
        f"Estimated cost at most ${worst:.3f}. Preview it with --dry-run. Continue? [y/N] "
    )
    if not confirm(question):
        return None
    body = client.request(model, user, settings.max_output_tokens, fallbacks=settings.fallbacks)
    api = make_client()  # fails before any reservation if the key or SDK is missing
    rid = budget.reserve(ledger, now, incident_id, model, worst)  # counts even if the call fails
    reply = client.call(api, body)
    usd = budget.settle(
        ledger, now, rid, worst, reply.model, reply.input_tokens, reply.output_tokens
    )
    answer = output.parse(reply.text)
    text = output.render(
        answer,
        p.mapping,
        incident_id=incident_id,
        model=reply.model,
        when=format_time(now),
        cost_line=(
            f"Estimated cost ${usd:.4f} ({reply.input_tokens} input, {reply.output_tokens} "
            "output tokens). The Anthropic console shows the billed amount."
        ),
    )
    out = home / OUT_DIR
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{incident_id}.ai-summary.md"
    path.write_text(text, encoding="utf-8")
    return Result(path=path, text=text, cost_usd=usd)
