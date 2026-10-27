"""Response plans (from docs/runbooks/credential-exposure.md) and the response adapter.

Sentinel recommends; humans approve. The only adapter in v0.1 is a dry run with no side effects.
"""

from dataclasses import dataclass
from typing import Any, Protocol

# name, description, response class, required to close the incident
_Step = tuple[str, str, str, bool]

_CREDENTIAL: tuple[_Step, ...] = (
    (
        "revoke_credential",
        "Revoke/delete the exposed key in the provider console",
        "emergency_preapproved",
        True,
    ),
    (
        "cap_quota",
        "Cap quota/budget on the affected project, if available",
        "approval_required",
        False,
    ),
    (
        "review_usage",
        "Review provider usage and billing for the exposure window",
        "investigate_first",
        True,
    ),
    (
        "review_related_identities",
        "Review GitHub security log, sessions, tokens, SSH/deploy keys, OAuth apps",
        "investigate_first",
        True,
    ),
    (
        "issue_replacement",
        "Issue a replacement key (minimal scope, quota, expiry) kept in a secret store",
        "approval_required",
        True,
    ),
    (
        "clean_history",
        "Rewrite history on a backup clone; collaborators re-clone (revocation is the real fix)",
        "approval_required",
        False,
    ),
)
_PLANS: dict[str, tuple[_Step, ...]] = {
    "R1": _CREDENTIAL,
    "R4": (
        ("cap_quota", "Cap quota/budget on the affected project", "approval_required", True),
        (
            "review_usage",
            "Review provider usage and billing for the spike window",
            "investigate_first",
            True,
        ),
        ("revoke_credential", "Revoke credentials found to be abused", "approval_required", False),
    ),
    "R6": (
        ("revoke_token_or_ssh_key", "Revoke the new token/SSH key", "emergency_preapproved", True),
        (
            "terminate_sessions",
            "Terminate active sessions for the identity",
            "approval_required",
            True,
        ),
        (
            "review_audit_log",
            "Review account security log for related changes",
            "investigate_first",
            True,
        ),
        (
            "re_enroll_2fa",
            "Re-enroll second factor and rotate credentials",
            "approval_required",
            False,
        ),
    ),
    "R7": (
        (
            "investigate_canary_source",
            "Identify where the decoy was read and used",
            "investigate_first",
            True,
        ),
        (
            "review_same_host_credentials",
            "Review other credentials on the same host/repo",
            "investigate_first",
            True,
        ),
        ("revoke_canary", "Disable the triggered decoy", "automatic", False),
    ),
}

# Only these classes may run without an explicit human approval.
NO_APPROVAL_NEEDED = ("investigate_first", "automatic")


def plan_for(rule_id: str) -> list[dict[str, Any]]:
    return [
        {
            "step": name,
            "description": description,
            "response_class": cls,
            "required_for_close": required,
            "state": "pending",
            "approved_by": None,
            "events": [],
        }
        for name, description, cls, required in _PLANS[rule_id]
    ]


@dataclass(frozen=True)
class AdapterResult:
    ok: bool
    detail: str


class ResponseAdapter(Protocol):
    def execute(self, action: str, target: str) -> AdapterResult: ...


class DryRunAdapter:
    """Records what would be done. No network, no side effects."""

    def execute(self, action: str, target: str) -> AdapterResult:
        return AdapterResult(ok=True, detail=f"DRY-RUN: would perform '{action}' on {target}")
