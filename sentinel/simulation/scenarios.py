"""Scenario generators: simulated source events (always is_test=True, never real data)."""

from datetime import datetime, timedelta
from typing import Any

from sentinel.events.refs import identity_ref
from sentinel.events.schema import make_event


def provider_usage(cred_ref: str, asset_id: str, now: datetime) -> list[dict[str, Any]]:
    """S0: provider reports use of the credential from an unfamiliar origin."""
    return [
        make_event(
            event_type="credential_usage_anomaly",
            source="provider_usage",
            asset_id=asset_id,
            time=now,
            severity="high",
            confidence="medium",
            evidence_ref="simulated/provider-usage",
            credential_ref=cred_ref,
            is_test=True,
            attributes={"origin": "new region/IP (simulated)"},
        )
    ]


def spend_spike(asset_id: str, now: datetime, multiple: float = 5.0) -> list[dict[str, Any]]:
    """R4: spend multiple of the 7-day baseline."""
    return [
        make_event(
            event_type="spend_anomaly",
            source="provider_usage",
            asset_id=asset_id,
            time=now,
            severity="medium",
            confidence="medium",
            evidence_ref="simulated/billing",
            is_test=True,
            attributes={"multiple_of_baseline": multiple, "baseline_days": 7},
        )
    ]


def login_then_token(who: str, asset_id: str, now: datetime) -> list[dict[str, Any]]:
    """S4/S6: login from a new location, then a new token within the hour."""
    ident = identity_ref("user", who)
    return [
        make_event(
            event_type="login_anomaly",
            source="github_audit",
            asset_id=asset_id,
            time=now,
            severity="medium",
            confidence="medium",
            evidence_ref="simulated/github-audit-login",
            identity_ref=ident,
            is_test=True,
            attributes={"location": "new (simulated)", "second_factor": False},
        ),
        make_event(
            event_type="token_created",
            source="github_audit",
            asset_id=asset_id,
            time=now + timedelta(minutes=20),
            severity="medium",
            confidence="medium",
            evidence_ref="simulated/github-audit-token",
            identity_ref=ident,
            is_test=True,
        ),
    ]


def canary(asset_id: str, now: datetime) -> list[dict[str, Any]]:
    """R7: a decoy credential/resource was used."""
    return [
        make_event(
            event_type="canary_triggered",
            source="canary",
            asset_id=asset_id,
            time=now,
            severity="high",
            confidence="high",
            evidence_ref="simulated/canary",
            is_test=True,
        )
    ]
