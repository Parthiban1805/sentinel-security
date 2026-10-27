"""Run all rules over events; output is deterministic (sorted, deduplicated by key)."""

from sentinel.correlation.model import Context, Match
from sentinel.correlation.rules import (
    Event,
    r1_exposed_then_used,
    r2_risky_workflow_change,
    r4_spend_spike,
    r6_login_then_credential,
    r7_canary,
    r8_workflow_change_before_release,
    r10_exposed_sensitive_path,
    r11_use_after_revocation,
)
from sentinel.store.db import Store

RULES = (
    r1_exposed_then_used,
    r11_use_after_revocation,
    r2_risky_workflow_change,
    r10_exposed_sensitive_path,
    r4_spend_spike,
    r6_login_then_credential,
    r7_canary,
    r8_workflow_change_before_release,
)


def correlate(events: list[Event], ctx: Context) -> list[Match]:
    seen: dict[str, Match] = {}
    for rule in RULES:
        for match in rule(events, ctx):
            seen.setdefault(match.key, match)
    return sorted(seen.values(), key=lambda m: (m.first_time, m.key))


def context_from_store(store: Store) -> Context:
    revoked = frozenset(
        d["cred_ref"] for d in store.docs("findings") if d["status"] == "revoked_verified"
    )
    verified_at = {
        d["cred_ref"]: d["verified_at"]
        for d in store.docs("findings")
        if d["status"] == "revoked_verified" and d.get("verified_at")
    }
    return Context(revoked_verified=revoked, revoked_verified_at=verified_at)
