"""Rules R1, R4, R6, R7 (specs: docs/spec/correlation-rules.md). Pure functions over event lists."""

from datetime import datetime, timedelta
from typing import Any

from sentinel.correlation.model import Context, Match

Event = dict[str, Any]


def _ts(event: Event) -> datetime:
    return datetime.fromisoformat(event["time"].replace("Z", "+00:00"))


def _is_test(events: list[Event]) -> bool:
    return any(e["is_test"] for e in events)


def r1_exposed_then_used(events: list[Event], ctx: Context) -> list[Match]:
    """Secret exposure followed by provider usage anomaly on the same credential ref."""
    exposures: dict[str, list[Event]] = {}
    usages: dict[str, list[Event]] = {}
    for e in events:
        ref = e.get("credential_ref")
        if not ref:
            continue
        if e["event_type"] == "secret_exposure":
            exposures.setdefault(ref, []).append(e)
        elif e["event_type"] == "credential_usage_anomaly":
            usages.setdefault(ref, []).append(e)
    matches: list[Match] = []
    for ref, used in usages.items():
        if ref in ctx.revoked_verified:
            continue
        first_exposure = min(exposures.get(ref, []), key=_ts, default=None)
        if first_exposure is None:
            continue
        after = sorted(
            (u for u in used if _ts(u) >= _ts(first_exposure)),
            key=lambda u: (_ts(u), u["event_id"]),
        )
        if not after:
            continue  # usage before exposure: no causal story
        involved = [first_exposure, *after]
        confidence = "high" if all(e["confidence"] == "high" for e in involved) else "medium"
        matches.append(
            Match(
                rule_id="R1",
                key=f"R1:{ref}",
                title=f"Exposed credential {ref} used after exposure",
                severity_floor="critical",
                confidence=confidence,
                facts=(
                    f"Secret exposure recorded for {ref} at {first_exposure['time']}.",
                    f"Provider reported {len(after)} usage anomaly event(s) for the same "
                    f"credential ref, first at {min(after, key=_ts)['time']}.",
                ),
                hypotheses=(
                    "The party using the key obtained it from the exposure. Matching ref and "
                    "timing do not prove this.",
                ),
                event_ids=tuple(e["event_id"] for e in involved),
                asset_id=after[0]["asset_id"],
                first_time=first_exposure["time"],
                last_time=max(after, key=_ts)["time"],
                is_test=_is_test(involved),
                cred_ref=ref,
            )
        )
    return matches


def r4_spend_spike(events: list[Event], ctx: Context) -> list[Match]:
    matches: list[Match] = []
    for e in events:
        if e["event_type"] != "spend_anomaly":
            continue
        multiple = float((e.get("attributes") or {}).get("multiple_of_baseline", 0))
        if multiple < ctx.config.spend_multiple:
            continue
        matches.append(
            Match(
                rule_id="R4",
                key=f"R4:{e['asset_id']}:{e['time'][:10]}",
                title=f"Spend at {multiple:g}x the 7-day baseline on {e['asset_id']}",
                severity_floor="high",
                confidence=e["confidence"],
                facts=(
                    f"Spend anomaly at {e['time']}: {multiple:g}x baseline "
                    f"(threshold {ctx.config.spend_multiple:g}x [confirm]).",
                ),
                hypotheses=(
                    "The spike may come from credential abuse; legitimate load is also possible.",
                ),
                event_ids=(e["event_id"],),
                asset_id=e["asset_id"],
                first_time=e["time"],
                last_time=e["time"],
                is_test=e["is_test"],
            )
        )
    return matches


def r6_login_then_credential(events: list[Event], ctx: Context) -> list[Match]:
    logins = [e for e in events if e["event_type"] == "login_anomaly" and e.get("identity_ref")]
    follow = [
        e
        for e in events
        if e["event_type"] in ("token_created", "ssh_key_added") and e.get("identity_ref")
    ]
    matches: list[Match] = []
    for login in logins:
        hits = sorted(
            (
                f
                for f in follow
                if f["identity_ref"] == login["identity_ref"]
                and timedelta_ok(_ts(f) - _ts(login), ctx)
            ),
            key=lambda f: (_ts(f), f["event_id"]),
        )
        if not hits:
            continue
        involved = [login, *hits]
        matches.append(
            Match(
                rule_id="R6",
                key=f"R6:{login['event_id']}",
                title=f"New token/SSH key soon after anomalous login for {login['identity_ref']}",
                severity_floor="critical",
                confidence="medium",
                facts=(
                    f"Login anomaly at {login['time']}.",
                    f"{len(hits)} new token/SSH key event(s) within "
                    f"{int(ctx.config.r6_window.total_seconds() // 60)} minutes "
                    "for the same identity.",
                ),
                hypotheses=(
                    "The session may be stolen; the user may also have changed device or location.",
                ),
                event_ids=tuple(e["event_id"] for e in involved),
                asset_id=login["asset_id"],
                first_time=login["time"],
                last_time=max(hits, key=_ts)["time"],
                is_test=_is_test(involved),
                identity_ref=login["identity_ref"],
            )
        )
    return matches


def timedelta_ok(delta: timedelta, ctx: Context) -> bool:
    return timedelta(0) <= delta <= ctx.config.r6_window


def r7_canary(events: list[Event], ctx: Context) -> list[Match]:
    return [
        Match(
            rule_id="R7",
            key=f"R7:{e['event_id']}",
            title=f"Canary triggered on {e['asset_id']}",
            severity_floor="critical",
            confidence="high",
            facts=(
                f"A decoy credential/resource was used at {e['time']}. "
                "Decoys have no legitimate use.",
            ),
            hypotheses=("Source and intent are unknown until investigated.",),
            event_ids=(e["event_id"],),
            asset_id=e["asset_id"],
            first_time=e["time"],
            last_time=e["time"],
            is_test=e["is_test"],
        )
        for e in events
        if e["event_type"] == "canary_triggered"
    ]


def r10_exposed_sensitive_path(events: list[Event], ctx: Context) -> list[Match]:
    """A sensitive file is reachable on one of our own hosts (exposure probes, S1/S15)."""
    matches: list[Match] = []
    for e in events:
        if e["event_type"] != "exposed_service":
            continue
        attrs = e.get("attributes") or {}
        path = attrs.get("path", "?")
        shape = str(attrs.get("signature", "sensitive file"))
        article = "an" if shape[:1].lower() in "aeiou" else "a"
        matches.append(
            Match(
                rule_id="R10",
                key=f"R10:{e['asset_id']}:{path}",
                title=f"{attrs.get('signature', 'file')} is served at {path} on {e['asset_id']}",
                severity_floor=e["severity"] if e["severity"] in ("high", "critical") else "high",
                confidence="high",
                facts=(
                    f"At {e['time']} a probe received HTTP {attrs.get('status', '?')} for {path} "
                    f"and the first bytes matched the shape of {article} {shape}; "
                    "no authentication was involved.",
                ),
                hypotheses=(
                    "The contents may already have been fetched by others. Whether any credential "
                    "inside was used is unknown (provider usage evidence, rule R1, would show it).",
                ),
                event_ids=(e["event_id"],),
                asset_id=e["asset_id"],
                first_time=e["time"],
                last_time=e["time"],
                is_test=e["is_test"],
            )
        )
    return matches


def r2_risky_workflow_change(events: list[Event], ctx: Context) -> list[Match]:
    """Workflow change adding network calls or secret refs, by a non-maintainer."""
    matches: list[Match] = []
    for e in events:
        if e["event_type"] != "workflow_changed":
            continue
        attrs = e.get("attributes") or {}
        # patch_missing: GitHub withheld the diff, so the content is unknown (treated as risky).
        risky = [k for k in ("adds_network", "adds_secret_ref", "patch_missing") if attrs.get(k)]
        if not risky or attrs.get("actor_is_maintainer", True):
            continue
        matches.append(
            Match(
                rule_id="R2",
                key=f"R2:{e['event_id']}",
                title=f"Workflow change on {e['asset_id']} by non-maintainer: {', '.join(risky)}",
                severity_floor="high",
                confidence="medium",
                facts=(
                    f"Workflow change at {e['time']} ({', '.join(attrs.get('files', []))}).",
                    f"Added lines contain: {', '.join(risky)}.",
                    "Actor did not commit to this repo in the 90 days before the change.",
                ),
                hypotheses=(
                    "May be a malicious change (S8/S10); may also be a new legitimate contributor.",
                ),
                event_ids=(e["event_id"],),
                asset_id=e["asset_id"],
                first_time=e["time"],
                last_time=e["time"],
                is_test=e["is_test"],
                identity_ref=e.get("identity_ref"),
            )
        )
    return matches


def r8_workflow_change_before_release(events: list[Event], ctx: Context) -> list[Match]:
    """Workflow change followed by a release on the same repo within the R8 window."""
    changes = [e for e in events if e["event_type"] == "workflow_changed"]
    releases = [e for e in events if e["event_type"] == "release_published"]
    matches: list[Match] = []
    for change in changes:
        hits = sorted(
            (
                r
                for r in releases
                if r["asset_id"] == change["asset_id"]
                and timedelta(0) <= _ts(r) - _ts(change) <= ctx.config.r8_window
            ),
            key=lambda r: (_ts(r), r["event_id"]),
        )
        if not hits:
            continue
        involved = [change, *hits]
        matches.append(
            Match(
                rule_id="R8",
                key=f"R8:{change['event_id']}",
                title=f"Release on {change['asset_id']} shortly after a workflow change",
                severity_floor="high",
                confidence="low",
                facts=(
                    f"Workflow changed at {change['time']}.",
                    f"{len(hits)} release(s) within "
                    f"{int(ctx.config.r8_window.total_seconds() // 3600)}h, "
                    f"first at {hits[0]['time']}.",
                ),
                hypotheses=(
                    "The release may have been built by a modified pipeline (S10); "
                    "it may also be a normal release.",
                ),
                event_ids=tuple(e["event_id"] for e in involved),
                asset_id=change["asset_id"],
                first_time=change["time"],
                last_time=hits[-1]["time"],
                is_test=_is_test(involved),
                identity_ref=change.get("identity_ref"),
            )
        )
    return matches
