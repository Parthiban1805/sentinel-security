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


_R7_FACTS = {
    "copied": "The decoy's value was found at another location ({location}) by the secret scan.",
    "modified": "The decoy file was modified.",
    "removed": "The decoy file was removed.",
}


def r7_canary(events: list[Event], ctx: Context) -> list[Match]:
    """A decoy was copied, tampered with, removed or used. A mere 'read' is not an incident."""
    matches: list[Match] = []
    for e in events:
        if e["event_type"] != "canary_triggered":
            continue
        attrs = e.get("attributes") or {}
        reason = attrs.get("reason")
        if reason == "read":
            continue  # low-confidence tripwire (antivirus, indexers): event only
        fact = _R7_FACTS.get(reason or "", "A decoy credential/resource was used.").format(
            location=attrs.get("location", "?")
        )
        matches.append(
            Match(
                rule_id="R7",
                key=f"R7:{e['event_id']}",
                title=f"Canary {reason or 'used'} on {e['asset_id']}",
                # copied, or no reason (the decoy was USED): critical. Tampering: the event's own.
                severity_floor="critical" if reason in (None, "copied") else e["severity"],
                confidence=e["confidence"],
                # Worded so it does not imply who: a decoy has no planned use, but backup jobs,
                # scanners and other automated processes can still touch one (found in the v0.6
                # eval, where "no legitimate use" led readers to conclude "unauthorized").
                facts=(
                    f"{fact} Detected at {e['time']}. Decoys have no planned use, but a backup "
                    "job, scanner or other automated process can still touch one, so this alone "
                    "does not show who touched it or why.",
                ),
                hypotheses=(
                    "Who or what touched the decoy, and why, is unknown until investigated.",
                ),
                event_ids=(e["event_id"],),
                asset_id=e["asset_id"],
                first_time=e["time"],
                last_time=e["time"],
                is_test=e["is_test"],
            )
        )
    return matches


def r11_use_after_revocation(events: list[Event], ctx: Context) -> list[Match]:
    """Provider usage AFTER the revocation was verified: the revocation did not hold."""
    later: dict[str, list[Event]] = {}
    for e in events:
        ref = e.get("credential_ref")
        verified_at = ctx.revoked_verified_at.get(ref or "")
        if e["event_type"] != "credential_usage_anomaly" or not ref or not verified_at:
            continue
        if _ts(e) > datetime.fromisoformat(verified_at.replace("Z", "+00:00")):
            later.setdefault(ref, []).append(e)
    matches: list[Match] = []
    for ref, used in later.items():
        used = sorted(used, key=lambda u: (_ts(u), u["event_id"]))
        verified_at = ctx.revoked_verified_at[ref]
        dead = any((u.get("attributes") or {}).get("reason") == "use_of_dead_key" for u in used)
        matches.append(
            Match(
                rule_id="R11",
                key=f"R11:{ref}",
                title=f"Credential {ref} used after its revocation was verified",
                severity_floor="critical",
                confidence="high" if dead else "medium",
                facts=(
                    f"The revocation of {ref} was verified at {verified_at}.",
                    f"Provider usage was reported for the same credential ref {len(used)} time(s) "
                    f"afterwards, first at {used[0]['time']}.",
                ),
                hypotheses=(
                    "The revocation did not take effect: a different key may have been revoked, "
                    "another copy of the key exists, or the provider is slow to apply it. The "
                    "usage may also be provider data that arrived late.",
                ),
                event_ids=tuple(u["event_id"] for u in used),
                asset_id=used[0]["asset_id"],
                first_time=used[0]["time"],
                last_time=used[-1]["time"],
                is_test=_is_test(used),
                cred_ref=ref,
            )
        )
    return matches


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


def _episode(base: str, events: list[Event], ctx: Context) -> list[Event]:
    """Events of a new episode: only those after the last CLOSED incident for `base`, so a closed
    incident never silences later activity, while an open one is not duplicated."""
    closed = ctx.closed_episodes.get(base)
    if closed is None:
        return events
    cut = datetime.fromisoformat(closed.replace("Z", "+00:00"))
    return [e for e in events if _ts(e) > cut]


def _group_key(base: str, is_test: bool) -> str:
    return f"{base}:test" if is_test else base  # a test event never masks a real one


def r5b_repeated_agent_denials(events: list[Event], ctx: Context) -> list[Match]:
    """At least r5b_count blocked agent actions in one session within r5b_window (S11).

    One incident per session episode, however many denials follow. A single denial (R5a) never
    matches. Denials without a session id share an `unknown` bucket per agent asset."""
    count, window = ctx.config.r5b_count, ctx.config.r5b_window
    groups: dict[str, list[Event]] = {}
    for e in events:
        if e["event_type"] != "agent_tool_denied":
            continue
        session = str((e.get("attributes") or {}).get("session", "")) or f"unknown@{e['asset_id']}"
        groups.setdefault(_group_key(f"R5b:{session}", e["is_test"]), []).append(e)
    matches: list[Match] = []
    for base, group in sorted(groups.items()):
        denials = sorted(_episode(base, group, ctx), key=lambda e: (_ts(e), e["event_id"]))
        burst = next(
            (
                denials[i : i + count]
                for i in range(len(denials) - count + 1)
                if _ts(denials[i + count - 1]) - _ts(denials[i]) <= window
            ),
            None,
        )
        if burst is None:
            continue
        involved = [e for e in denials if _ts(e) >= _ts(burst[0])]  # the burst and what followed
        session = str(burst[0]["attributes"].get("session", "")) or "unknown"
        rules = sorted({str(e["attributes"].get("rule", "?")) for e in involved})
        classes = sorted({str(e["attributes"].get("target_class", "?")) for e in involved})
        minutes = (_ts(burst[-1]) - _ts(burst[0])).total_seconds() / 60
        matches.append(
            Match(
                rule_id="R5b",
                key=f"{base}@{burst[0]['time']}",
                title=f"{len(involved)} blocked agent actions in one session",
                severity_floor="medium",
                confidence="low",
                facts=(
                    f"{count} actions were blocked by the guard hooks within {minutes:.0f} "
                    f"minutes in agent session {session} ({len(involved)} in total from "
                    f"{burst[0]['time']}).",
                    f"Rules hit: {', '.join(rules)}; classes: {', '.join(classes)}.",
                ),
                hypotheses=(
                    "The agent may have been steered by untrusted input (prompt injection) or may "
                    "be pursuing an unsafe goal. Equally plausible until the session's inputs are "
                    "reviewed: harmless commands blocked by keyword matching.",
                ),
                event_ids=tuple(e["event_id"] for e in involved),
                asset_id=burst[0]["asset_id"],
                first_time=burst[0]["time"],
                last_time=involved[-1]["time"],
                is_test=burst[0]["is_test"],
            )
        )
    return matches


def _approved_prefix(tool: str, approved: frozenset[str]) -> bool:
    """Exact match on `mcp__<approved name>__`: no slugging, no guessing where the name ends."""
    return any(tool.startswith(f"mcp__{name}__") for name in approved)


def r5c_unapproved_mcp_server(events: list[Event], ctx: Context) -> list[Match]:
    """An MCP tool call to a server nobody approved (S12). Active only in allowlist mode, i.e.
    once at least one MCP server was approved; one incident per server episode."""
    if not ctx.approved_mcp_servers:
        return []
    groups: dict[str, list[Event]] = {}
    for e in events:
        if e["event_type"] != "agent_tool_allowed":
            continue
        attrs = e.get("attributes") or {}
        tool = str(attrs.get("tool", ""))
        if not tool.startswith("mcp__") or _approved_prefix(tool, ctx.approved_mcp_servers):
            continue
        server = str(attrs.get("mcp_server") or tool)
        groups.setdefault(_group_key(f"R5c:{server}", e["is_test"]), []).append(e)
    matches: list[Match] = []
    for base, group in sorted(groups.items()):
        calls = sorted(_episode(base, group, ctx), key=lambda e: (_ts(e), e["event_id"]))
        if not calls:
            continue
        name = str(calls[0]["attributes"].get("mcp_server", "?"))
        tools = sorted({str(e["attributes"].get("mcp_tool", "?")) for e in calls})
        matches.append(
            Match(
                rule_id="R5c",
                key=f"{base}@{calls[0]['time']}",
                title=f"Agent used MCP server '{name}', which is not approved",
                severity_floor="high",
                confidence="medium",
                facts=(
                    f"The agent called {len(calls)} tool(s) of MCP server '{name}' "
                    f"({', '.join(tools)}) from {calls[0]['time']}; no approved MCP server has "
                    "exactly this name.",
                ),
                hypotheses=(
                    "The server may be untrusted or impersonate a trusted one; it may also be a "
                    "legitimate server that nobody has approved yet (user-scope servers and "
                    "claude.ai connectors are never visible to the inventory).",
                ),
                event_ids=tuple(e["event_id"] for e in calls),
                asset_id=calls[0]["asset_id"],
                first_time=calls[0]["time"],
                last_time=calls[-1]["time"],
                is_test=calls[0]["is_test"],
            )
        )
    return matches
