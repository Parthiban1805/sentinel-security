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
        "rescan_clean",
        "Re-scan every recorded location: the credential must no longer be found (system-verified)",
        "investigate_first",
        False,
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
    "R2": (
        ("review_workflow_diff", "Review the workflow diff and actor", "investigate_first", True),
        ("revert_workflow", "Revert the change via reviewed PR", "approval_required", False),
        (
            "rotate_exposed_secrets",
            "Rotate secrets the workflow can read",
            "approval_required",
            False,
        ),
    ),
    "R11": (
        (
            "confirm_revocation_state",
            "Re-check the provider: is the key really deleted, and is it the one you revoked?",
            "investigate_first",
            True,
        ),
        (
            "revoke_again",
            "Revoke the credential again (and any other copy found) in the provider console",
            "approval_required",
            True,
        ),
        (
            "review_usage",
            "Review provider usage and billing since the revocation was verified",
            "investigate_first",
            True,
        ),
        (
            "find_other_copies",
            "Scan other repositories, logs and machines for another copy of the key",
            "investigate_first",
            True,
        ),
    ),
    "R10": (
        (
            "block_path",
            "Remove the file from the web root or block the path in the server config",
            "approval_required",
            True,
        ),
        (
            "rotate_exposed_secrets",
            "Rotate every credential that could be inside the exposed file",
            "approval_required",
            True,
        ),
        (
            "review_access_logs",
            "Review server access logs for who fetched the path during the exposure window",
            "investigate_first",
            True,
        ),
        (
            "verify_path_closed",
            "Re-probe the path: it must no longer serve the file (verified by the system)",
            "investigate_first",
            True,
        ),
    ),
    "R5b": (
        (
            "review_session_inputs",
            "Review what the session read (web pages, files, tool and MCP output) for injected "
            "instructions",
            "investigate_first",
            True,
        ),
        (
            "end_session_revoke",
            "End the agent session and revoke any credential it held",
            "approval_required",
            True,
        ),
        (
            "verify_agent_hooks",
            "Installed hooks match the reviewed patch and the decision log chain is intact "
            "(system-verified)",
            "investigate_first",
            True,
        ),
    ),
    "R12": (
        (
            "review_session_inputs",
            "Review what the session read (web pages, files, tool and MCP output) for injected "
            "instructions, and what it tried to read and send",
            "investigate_first",
            True,
        ),
        (
            "end_session_revoke",
            "End the agent session and revoke any credential it could have read",
            "approval_required",
            True,
        ),
        (
            "verify_agent_hooks",
            "Installed hooks match the reviewed patch and the decision log chain is intact "
            "(system-verified)",
            "investigate_first",
            True,
        ),
    ),
    "R9": (
        (
            "review_agent_session",
            "Review what the agent session ran in the window (commands started, scripts written)",
            "investigate_first",
            True,
        ),
        (
            "identify_decoy_reader",
            "Find the process that touched the decoy (host audit or file-access logs)",
            "investigate_first",
            True,
        ),
        (
            "engage_kill_switch",
            "Turn the agent kill switch on until the source is known (agent kill-switch on)",
            "approval_required",
            False,
        ),
    ),
    "R5c": (
        (
            "review_mcp_server",
            "Review the server (owner, source, pinned version); approve it in the inventory or "
            "remove it",
            "approval_required",
            True,
        ),
        (
            "review_data_sent",
            "Review what the agent sent to the server and what the server could read",
            "investigate_first",
            True,
        ),
        (
            "rotate_exposed_secrets",
            "Rotate credentials the server could have read",
            "approval_required",
            False,
        ),
    ),
    "R8": (
        (
            "review_release_provenance",
            "Check the release build ran from a reviewed workflow",
            "investigate_first",
            True,
        ),
        (
            "pull_release",
            "Unpublish or mark the release unsafe if provenance fails",
            "approval_required",
            False,
        ),
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
