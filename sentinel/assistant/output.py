"""Check and render the model's answer (ADR-0014).

The answer is untrusted text. It is validated against the schema; control characters, URLs and
Markdown/HTML markup are neutralised; steps that are response actions, or that would open files that
may hold secrets, are dropped; placeholders are swapped back locally as inline code; and the result
is refused if it looks like it holds a credential.

Structural rule (2026-11-02): the model never writes facts. The record's facts, open questions,
reach and response-plan state are printed here from the evidence pack (Sentinel's own data). Every
section the model wrote is headed as AI interpretation. It is written to its own file; the incident
record is untouched.
"""

import json
import re
from dataclasses import dataclass
from typing import Any

import jsonschema

from sentinel.assistant.pack import PLACEHOLDER
from sentinel.assistant.prompt import OUTPUT_SCHEMA
from sentinel.redaction import has_secret_pattern, looks_like_secret

# Words that turn a check into a response action. Such steps are dropped (they belong to the
# approval-gated response plan), and the reader is told how many were dropped.
_ACTION = re.compile(
    r"\b(revok\w*|rotat\w*|delet\w*|remov\w*|disabl\w*|block\w*|close\w*|closing|"
    r"force[- ]?push\w*|push\s+-f|rewrit\w*|purg\w*|reset\w*|kill\w*|uninstall\w*|deploy\w*|"
    r"suspend\w*|ban\w*|wipe\w*|shut\w*|invalidat\w*|regenerat\w*|expir\w*|terminat\w*|"
    r"lock\w*|quarantin\w*|isolat\w*|eras\w*|destroy\w*|filter-repo|bfg)\b",
    re.IGNORECASE,
)
# A check that would put a secret on someone's screen: reading the contents of, or downloading, a
# file or dump that may hold secrets. "Check who fetched /.env" stays; "examine the contents of
# /.env" or "download the dump" goes.
_SENSITIVE = re.compile(
    r"(\.env\b|env file|dump|\.sql\b|backup|private key|key file|id_rsa|\.git\b|git config|"
    r"credential|secret|\.npmrc|\.aws\b)",
    re.IGNORECASE,
)
_READS_CONTENT = re.compile(r"\b(contents?|full text|body)\b|\b(download|curl|wget)\w*", re.I)
# A check that would reveal or test a secret, found in the third scored run: comparing a secret's
# value, testing whether a leaked key still works, working from credentials "found in" an exposed
# file, or listing the secrets stored on a host. Checking a credential's status in the provider's
# console, its usage log, or what it is linked to stays allowed.
_REVEALS_SECRET = re.compile(
    r"\b(secret|key|token|credential|password)s?\b[^.]{0,40}\bmatch(es|ing)?\b"
    r"|\b(value|plaintext|raw)\s+of\s+(the\s+)?(secret|key|token|credential|password)"
    r"|\b(validity|is\s+valid|still\s+valid|still\s+works?)\b"
    r"|\b(test|try)\w*\b[^.]{0,30}\b(key|token|credential|password|secret)\b"
    r"|\b(found|stored|contained|listed)\s+in\s+(the\s+)?(exposed\s+|served\s+)?"
    r"(file|dump|config|archive|backup|env)"
    r"|\b(enumerate|list)\w*\b[^.]{0,40}\b(secrets|credentials|keys|tokens|passwords)\b"
    r"[^.]{0,20}\bstored\b",
    re.IGNORECASE,
)
# Model text must not carry links: once placeholders are swapped back, a URL could carry real
# names to a remote host when a Markdown preview loads it.
_URL = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.-]*:)?//\S+"
    # A scheme counts only when a URL-like character follows the colon: "Test data: Yes" and
    # "**Test data:** Yes" are ordinary text; "data:text/html,..." and "javascript:x()" are not.
    r"|\b(?:https?|ftp|file|data|javascript|mailto|vbscript):(?=[\w/%.])\S*"
    r"|\bwww\.\S+"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")  # C0/C1 controls except tab and newline
_MARKUP = re.compile(r"([<>\[\]`])")


class AnswerError(ValueError):
    """The model's answer is unusable (not JSON, wrong shape, or credential-shaped)."""


@dataclass(frozen=True)
class Answer:
    data: dict[str, Any]
    dropped_steps: int


def _clean(text: str) -> str:
    """Model text: no control characters, no URLs, no Markdown links, images, code or HTML."""
    text = _CONTROL.sub("", text)
    text = _URL.sub("(link removed)", text)
    return _MARKUP.sub(r"\\\1", text)


def _clean_all(obj: Any) -> Any:
    if isinstance(obj, str):
        return _clean(obj)
    if isinstance(obj, list):
        return [_clean_all(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _clean_all(v) for k, v in obj.items()}
    return obj


def _unsafe_step(step: dict[str, str]) -> bool:
    text = step["step"] + " " + step["reason"]
    if _ACTION.search(text) or _REVEALS_SECRET.search(step["step"]):
        return True
    return bool(_SENSITIVE.search(step["step"]) and _READS_CONTENT.search(step["step"]))


def parse(text: str) -> Answer:
    try:
        data = json.loads(text, strict=False)  # models often put raw line breaks inside strings
        jsonschema.validate(data, OUTPUT_SCHEMA)
    except (json.JSONDecodeError, jsonschema.ValidationError) as exc:
        raise AnswerError(f"assistant answer has the wrong shape ({type(exc).__name__})") from None
    data = _clean_all(data)
    steps = data["investigation_steps"]
    kept = [s for s in steps if not _unsafe_step(s)]
    data["investigation_steps"] = kept
    return Answer(data=data, dropped_steps=len(steps) - len(kept))


def _local(value: str) -> str:
    """A real value swapped back in: one line, no controls, shown as inline code (no markup)."""
    one_line = value.replace("\r", " ").replace("\n", " ")
    return "`" + _CONTROL.sub("", one_line).replace("`", "'") + "`"


def rehydrate(text: str, mapping: dict[str, str]) -> str:
    """Swap only placeholders this pack created; everything else stays as written."""
    return PLACEHOLDER.sub(
        lambda m: _local(mapping[m.group(0)]) if m.group(0) in mapping else m.group(0), text
    )


def _record(text: object) -> str:
    """Sentinel's own record text: only control characters are removed."""
    return _CONTROL.sub("", str(text))


def _record_section(record: dict[str, Any]) -> list[str]:
    """What the record says, printed by Sentinel (no AI)."""
    status = f"status {_record(record.get('status'))}"
    if record.get("is_test"):
        status += ", simulated (test) data"
    lines = [
        "## From the record (Sentinel, not AI)",
        f"- Rule {_record(record.get('rule_id'))}: {_record(record.get('title'))}",
        f"- Severity {_record(record.get('severity'))}, confidence "
        f"{_record(record.get('confidence'))}, urgency {_record(record.get('urgency'))}, {status}",
        "",
        "**Facts**",
        *[f"- {_record(f)}" for f in record.get("facts", [])],
    ]
    if record.get("hypotheses"):
        lines += ["", "**Hypotheses already in the record (unproven)**"]
        lines += [f"- {_record(h)}" for h in record["hypotheses"]]
    blast = record.get("blast_radius")
    if isinstance(blast, dict):
        lines += ["", "**What the credential can reach**"]
        if not blast.get("credential_linked_to_assets"):
            lines.append("- Not linked to any asset: its reach is unknown.")
        for e in blast.get("confirmed_access", []):
            lines.append(
                f"- Confirmed: {_record(e.get('asset_id'))} "
                f"({_record(e.get('permission'))}, importance {_record(e.get('importance'))})"
            )
        for e in blast.get("possible_access", []):
            lines.append(
                f"- Possible via {_record(e.get('via'))}: {_record(e.get('asset_id'))} "
                f"({_record(e.get('permission'))}, {_record(e.get('origin'))}, "
                f"importance {_record(e.get('importance'))})"
            )
        if blast.get("exposed_in"):
            exposed = ", ".join(_record(x) for x in blast["exposed_in"])
            lines.append(f"- Exposed in: {exposed}")
    plan = record.get("response_plan", [])
    if plan:
        lines += ["", "**Response plan (approval-gated; run by people)**"]
        for s in plan:
            need = "required" if s.get("required_for_close") else "optional"
            ok = "verified" if s.get("verified") else "not verified"
            lines.append(f"- {_record(s.get('step'))}: {_record(s.get('state'))}, {need}, {ok}")
        pending = [
            _record(s.get("step"))
            for s in plan
            if s.get("required_for_close") and not s.get("verified")
        ]
        if pending:
            lines.append(
                "- The incident cannot close yet. Required steps without a passing verification: "
                + ", ".join(pending)
            )
        else:
            lines.append("- Every required step has a passing verification.")
    return lines


def render(
    answer: Answer,
    mapping: dict[str, str],
    *,
    record: dict[str, Any],
    incident_id: str,
    model: str,
    when: str,
    cost_line: str,
) -> str:
    """`record` is the evidence pack payload (placeholders; swapped back below)."""
    a = answer.data
    record_unknowns = [_record(u) for u in record.get("unknowns", [])]
    ai_unknowns = [u for u in a["unknowns"] if u not in record_unknowns]
    lines = [
        f"# Investigation notes: {incident_id}",
        "",
        "> Sections marked **AI** are AI-generated by "
        f"{model} at {when}: interpretation, not verified. Needs human review before use.",
        "> Sections marked **from the record** are Sentinel's own data. "
        "Sentinel did not change the incident.",
        "",
        *_record_section(record),
        "",
        "## AI assessment (interpretation, not verified)",
        a["summary"],
        "",
        "## AI: possible explanations and impact (hypotheses, not facts)",
        *[f"- [hypothesis] {h}" for h in a["hypotheses"]],
        "",
        "## Open questions",
        "**From the record**",
        *([f"- {u}" for u in record_unknowns] or ["- none recorded"]),
        "",
        "**AI-suggested**",
        *([f"- {u}" for u in ai_unknowns] or ["- none"]),
        "",
        "## AI: suggested read-only checks",
        *[
            f"{n}. {s['step']} (why: {s['reason']})"
            for n, s in enumerate(a["investigation_steps"], 1)
        ],
    ]
    if answer.dropped_steps:
        lines.append(
            f"\n({answer.dropped_steps} suggested step(s) removed: they were response actions, "
            "which go through the approval-gated response plan, or would open, reveal or test "
            "a secret.)"
        )
    lines += ["", "---", cost_line, ""]
    text = "\n".join(lines)
    if looks_like_secret(text):  # the model's text and the disguised record, before real values
        raise AnswerError("assistant answer looks like it contains a credential; not shown")
    text = rehydrate(text, mapping)
    # Real values come from Sentinel's own records and may be long paths, so only known key
    # formats are refused here (the entropy guess would reject a long file name).
    if has_secret_pattern(text):
        raise AnswerError("assistant answer looks like it contains a credential; not shown")
    return text
