"""Scenario generators: simulated source events (always is_test=True, never real data)."""

from datetime import datetime, timedelta
from typing import Any

from sentinel.events.refs import identity_ref
from sentinel.events.schema import make_event


def exposure(cred_ref: str, asset_id: str, now: datetime) -> list[dict[str, Any]]:
    """S0: a secret was found (scanner stage)."""
    return [
        make_event(
            event_type="secret_exposure",
            source="gitleaks",
            asset_id=asset_id,
            time=now,
            severity="high",
            confidence="medium",
            evidence_ref="simulated/finding",
            credential_ref=cred_ref,
            is_test=True,
        )
    ]


def risky_workflow_change(asset_id: str, now: datetime) -> list[dict[str, Any]]:
    """R2: a workflow change adds a network call, by an actor outside the usual maintainers."""
    return [
        make_event(
            event_type="workflow_changed",
            source="github_api",
            asset_id=asset_id,
            time=now,
            severity="medium",
            confidence="high",
            evidence_ref="simulated/workflow-commit",
            identity_ref=identity_ref("user", "ab12cd34ef56"),
            is_test=True,
            attributes={
                "adds_network": True,
                "adds_secret_ref": False,
                "patch_missing": False,
                "actor_is_maintainer": False,
                "actor_basis": "simulated",
                "files": [".github/workflows/ci.yml"],
            },
        )
    ]


def workflow_then_release(asset_id: str, now: datetime) -> list[dict[str, Any]]:
    """R8: a (quiet) workflow change followed two hours later by a release."""
    change = make_event(
        event_type="workflow_changed",
        source="github_api",
        asset_id=asset_id,
        time=now,
        severity="low",
        confidence="high",
        evidence_ref="simulated/workflow-commit",
        is_test=True,
        attributes={
            "adds_network": False,
            "adds_secret_ref": False,
            "patch_missing": False,
            "actor_is_maintainer": True,
            "files": [".github/workflows/release.yml"],
        },
    )
    release = make_event(
        event_type="release_published",
        source="github_api",
        asset_id=asset_id,
        time=now + timedelta(hours=2),
        severity="info",
        confidence="high",
        evidence_ref="simulated/release",
        is_test=True,
        attributes={"tag": "v-sim"},
    )
    return [change, release]


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
