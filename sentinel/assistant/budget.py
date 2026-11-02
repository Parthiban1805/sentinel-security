"""Cost limits for the assistant (ADR-0014): estimate before, cap per day and month, ledger after.

Prices are USD per million tokens from Anthropic's published table (cached 2026-10-06); check the
pricing page before relying on them. A refusal fallback may answer on another model, so the
pre-call check assumes the most expensive fallback, and the ledger prices a response by the model
that answered (unknown models at the highest known price). Every figure here is an estimate; the
Anthropic console is the authority, and its spend cap is the hard limit.
"""

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

PRICES: dict[str, tuple[float, float]] = {  # model -> (input, output) USD per 1M tokens
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-opus-4-8": (5.0, 25.0),  # refusal fallback target (cyber category)
}
WORST = (10.0, 50.0)  # highest published tier; used for any model not in PRICES
FALLBACK_WORST = PRICES["claude-opus-4-8"]
LEDGER = "ai-usage.jsonl"


class BudgetError(ValueError):
    """A call would break the daily call cap or the monthly budget."""


@dataclass(frozen=True)
class Limits:
    daily_calls: int
    monthly_usd: float


def cost(model: str, input_tokens: int, output_tokens: int) -> float:
    p_in, p_out = PRICES.get(model, WORST)
    return (input_tokens * p_in + output_tokens * p_out) / 1_000_000


def estimate_tokens(text: str) -> int:
    """Rough upper estimate (about 3 characters per token for JSON-heavy text)."""
    return len(text) // 3 + 1


def worst_case(model: str, input_tokens: int, max_output: int) -> float:
    """Most a call can cost: the larger of the chosen model and its fallback, at max output."""
    p_in, p_out = max(PRICES.get(model, WORST), FALLBACK_WORST)
    return (input_tokens * p_in + max_output * p_out) / 1_000_000


def _entries(home: Path) -> list[dict[str, object]]:
    path = home / LEDGER
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def spent(home: Path, now: datetime) -> tuple[int, float]:
    """(calls today, USD this month), UTC. A call counts from its reservation, so a failed,
    refused or cut-off call still counts at its worst-case cost."""
    day, month = now.strftime("%Y-%m-%d"), now.strftime("%Y-%m")
    rows = _entries(home)
    calls = sum(1 for r in rows if r.get("kind") == "reserve" and str(r["time"]).startswith(day))
    usd = sum(float(str(r["cost_usd"])) for r in rows if str(r["time"]).startswith(month))
    return calls, usd


def check(home: Path, now: datetime, limits: Limits, worst_usd: float) -> None:
    calls, usd = spent(home, now)
    if calls >= limits.daily_calls:
        raise BudgetError(f"daily AI call cap reached ({calls}/{limits.daily_calls})")
    if usd + worst_usd > limits.monthly_usd:
        raise BudgetError(
            f"monthly AI budget would be exceeded (spent about ${usd:.2f}, this call up to "
            f"${worst_usd:.2f}, budget ${limits.monthly_usd:.2f})"
        )


def _append(home: Path, row: dict[str, object]) -> None:
    home.mkdir(parents=True, exist_ok=True)
    with (home / LEDGER).open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def reserve(home: Path, now: datetime, incident: str, model: str, worst_usd: float) -> str:
    """Record a call at its worst-case cost BEFORE it is sent. Returns the reservation id."""
    rid = uuid.uuid4().hex[:12]
    _append(
        home,
        {
            "time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "kind": "reserve",
            "id": rid,
            "incident": incident,
            "model": model,
            "cost_usd": round(worst_usd, 6),
        },
    )
    return rid


def settle(
    home: Path,
    now: datetime,
    rid: str,
    reserved_usd: float,
    model: str,
    input_tokens: int,
    output_tokens: int,
) -> float:
    """After a successful call: replace the reservation by the estimated actual cost."""
    usd = cost(model, input_tokens, output_tokens)
    _append(
        home,
        {
            "time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "kind": "settle",
            "id": rid,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round(usd - reserved_usd, 6),
        },
    )
    return usd
