"""Check and render the model's answer (ADR-0014).

The answer is untrusted text. It is validated against the schema; control characters, URLs and
Markdown/HTML markup are neutralised; steps that are not read-only are dropped; placeholders are
swapped back locally as inline code; and the result is refused if it looks like it holds a
credential. It is written to its own file, labelled AI-generated; the incident record is untouched.
"""

import json
import re
from dataclasses import dataclass
from typing import Any

import jsonschema

from sentinel.assistant.pack import PLACEHOLDER
from sentinel.assistant.prompt import OUTPUT_SCHEMA
from sentinel.redaction import looks_like_secret

# Words that turn a check into a response action. Such steps are dropped (they belong to the
# approval-gated response plan), and the reader is told how many were dropped.
_ACTION = re.compile(
    r"\b(revok\w*|rotat\w*|delet\w*|remov\w*|disabl\w*|block\w*|close\w*|closing|"
    r"force[- ]?push\w*|push\s+-f|rewrit\w*|purg\w*|reset\w*|kill\w*|uninstall\w*|deploy\w*|"
    r"suspend\w*|ban\w*|wipe\w*|shut\w*|invalidat\w*|regenerat\w*|expir\w*|terminat\w*|"
    r"lock\w*|quarantin\w*|isolat\w*|eras\w*|destroy\w*|filter-repo|bfg)\b",
    re.IGNORECASE,
)
# Model text must not carry links: once placeholders are swapped back, a URL could carry real
# names to a remote host when a Markdown preview loads it.
_URL = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.-]*:)?//\S+"
    r"|\b(?:https?|ftp|file|data|javascript|mailto|vbscript):\S+"
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


def parse(text: str) -> Answer:
    try:
        data = json.loads(text)
        jsonschema.validate(data, OUTPUT_SCHEMA)
    except (json.JSONDecodeError, jsonschema.ValidationError) as exc:
        raise AnswerError(f"assistant answer has the wrong shape ({type(exc).__name__})") from None
    data = _clean_all(data)
    steps = data["investigation_steps"]
    kept = [s for s in steps if not _ACTION.search(s["step"] + " " + s["reason"])]
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


def render(
    answer: Answer,
    mapping: dict[str, str],
    *,
    incident_id: str,
    model: str,
    when: str,
    cost_line: str,
) -> str:
    a = answer.data
    lines = [
        f"# AI investigation notes: {incident_id}",
        "",
        f"> **AI-generated** by {model} at {when}. Not verified. Needs human review before use.",
        "> Sentinel did not change the incident. Items marked hypothesis are unproven.",
        "",
        "## Summary",
        a["summary"],
        "",
        "## Possible impact",
        *[f"- [{i['kind']}] {i['text']}" for i in a["impact"]],
        "",
        "## Unknowns",
        *[f"- {u}" for u in a["unknowns"]],
        "",
        "## Suggested read-only checks",
        *[
            f"{n}. {s['step']} (why: {s['reason']})"
            for n, s in enumerate(a["investigation_steps"], 1)
        ],
    ]
    if answer.dropped_steps:
        lines.append(
            f"\n({answer.dropped_steps} suggested step(s) removed: they were response actions, "
            "which go through the approval-gated response plan.)"
        )
    lines += [
        "",
        "## Draft report (AI-generated)",
        "> Response actions happen only through the approval-gated response plan, never from "
        "this draft.",
        "",
        a["report_draft"],
        "",
        "---",
        cost_line,
        "",
    ]
    text = rehydrate("\n".join(lines), mapping)
    if looks_like_secret(text):
        raise AnswerError("assistant answer looks like it contains a credential; not shown")
    return text
