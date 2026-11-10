"""Context firewall (v0.7d item 2, ADR-0025): what sensitive data a text holds. Stdlib only.

This file is ALSO the gateway's `.claude/hooks/_firewall.py` (a byte-identical copy shipped by the
gateway patch; a test keeps them identical). It must import nothing from `sentinel` and run on
the first `python` on PATH, which can be 3.10.

`scan` reports kinds and counts only: matched text never leaves this module. It stops accidents,
not a determined exfiltration (see ADR-0025). Ideas, not code, from the owner's ORE kernel
(AGPL-3.0); its gaps are fixed here: newer key formats, counts per occurrence, a checksum and
prefixes on card numbers, link-local and metadata addresses in their odd spellings.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import socket
import unicodedata
from collections import Counter
from typing import Any
from urllib.parse import unquote

_START = r"(?<![A-Za-z0-9_])"  # not inside a longer word (risk-..., self_hf_...)
# kind -> (category, pattern). Known formats: a hit is treated as a real credential.
_PATTERNS: dict[str, tuple[str, re.Pattern[str]]] = {
    "private_key": (
        "private_key",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----"),
    ),
    "google_api_key": ("secret", re.compile(_START + r"AIza[0-9A-Za-z_\-]{30,}")),
    "github_token": ("secret", re.compile(_START + r"gh[pousr]_[0-9A-Za-z]{30,}")),
    "github_pat": ("secret", re.compile(_START + r"github_pat_[0-9A-Za-z_]{30,}")),
    "gitlab_token": ("secret", re.compile(_START + r"glpat-[0-9A-Za-z_\-]{20,}")),
    "huggingface_token": ("secret", re.compile(_START + r"hf_[0-9A-Za-z]{30,}")),
    "npm_token": ("secret", re.compile(_START + r"npm_[0-9A-Za-z]{36}")),
    "pypi_token": ("secret", re.compile(_START + r"pypi-[0-9A-Za-z_\-]{50,}")),
    "aws_access_key": ("secret", re.compile(_START + r"(AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])")),
    "stripe_key": ("secret", re.compile(_START + r"[rs]k_(live|test)_[0-9A-Za-z]{16,}")),
    "sk_key": ("secret", re.compile(_START + r"sk-(ant-|proj-)?[0-9A-Za-z_\-]{20,}")),
    "slack_token": ("secret", re.compile(_START + r"xox[abprs]-[0-9A-Za-z\-]{10,}")),
    "jwt": (
        "secret",
        re.compile(_START + r"eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}"),
    ),
}
# A guess, not a known format: `password = <value>` where the value does not look like code.
_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?"
    r"([^\s'\"()\[\]{}$<>,;]{8,})(?=['\"\s]|$)"
)
_CARD = re.compile(r"(?<![0-9])(?:\d[ \-]?){12,18}\d(?![0-9])")
_IPV4 = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
_IPV6 = re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])")
_URL_HOST = re.compile(
    r"(?i)\b[a-z][a-z0-9+.\-]{0,20}://(?:[^/\s@]{0,200}@)?(\[[^\]\s]{0,64}\]|[^/\s:?#]{1,253})"
)
_TOKEN = re.compile(r"[0-9A-Za-z_\-+/=]{32,}")
_LOCAL = re.compile(r"[A-Za-z0-9._%+\-]{1,64}$")
_DOMAIN = re.compile(r"[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}(?![A-Za-z0-9])")
_INJECTION = re.compile(
    r"(?i)\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+"
    r"(instructions|prompts|rules|messages)"
    r"|\byou\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|unrestricted|god)\b"
    r"|\b(reveal|print|show|repeat|leak)\b.{0,30}\b(system\s+prompt|hidden\s+instructions)"
    r"|<\|im_(start|end)\|>|\[/?INST\]"
)
METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})
METADATA_NAMES = frozenset(
    {"metadata.google.internal", "metadata", "instance-data", "metadata.internal"}
)
_DOC_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
_CARD_PREFIX = re.compile(
    r"^(4\d{12}(\d{3}){0,2}|5[1-5]\d{14}|2(2[2-9]|[3-6]\d|7[01])\d{13}|2720\d{12}|3[47]\d{13}|6(011|5\d\d)\d{12,15})$"
)
MAX_TEXT = 1_000_000  # characters scanned from the start; the last TAIL characters are scanned too
TAIL = 65_536
ENTROPY_FLOOR = 4.2
_HIGH_ENTROPY = "high_entropy_token"  # noqa: S105 (a kind name, not a password)
_PASSWORD = "password_assignment"  # noqa: S105 (a kind name, not a password)
GUESSES = frozenset({_HIGH_ENTROPY, _PASSWORD})  # likely but unproven secrets: ask, never block


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _luhn(digits: str) -> bool:
    total, double = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if double:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        double = not double
    return total % 10 == 0


def _is_card(digits: str) -> bool:
    if not 13 <= len(digits) <= 19 or not _CARD_PREFIX.match(digits) or not _luhn(digits):
        return False
    return not (len(digits) == 13 and digits.startswith("1"))  # an epoch-millisecond timestamp


def _address_kind(text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if str(ip) in METADATA_IPS:
        return "metadata_address"
    if ip.is_unspecified or ip.is_loopback or any(ip in net for net in _DOC_NETS):
        return None
    if ip.is_link_local:
        return "link_local_address"
    if ip.is_private:
        return "internal_address"
    return None


def _host_is_metadata(host: str) -> bool:
    host = host.strip("[]").lower().rstrip(".")
    if host in METADATA_NAMES or host in METADATA_IPS:
        return True
    try:
        # inet_aton accepts odd IPv4 spellings a URL may use: 2852039166, 0xa9fea9fe, 0251.0376...
        return socket.inet_ntoa(socket.inet_aton(host)) in METADATA_IPS
    except (OSError, ValueError):
        return False


def _prepare(text: str) -> tuple[str, bool]:
    truncated = len(text) > MAX_TEXT
    if truncated:
        text = text[:MAX_TEXT] + "\n" + text[-TAIL:]
    # Look-alike characters and zero-width characters inside a key are a cheap evasion.
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    if "%" in text:
        text = unquote(text)  # in place: scanning a decoded copy too would double every count
    return text, truncated


def scan(text: str) -> dict[str, Any]:
    """{"counts": {kind: n}, "categories": {category: n}, "truncated": bool}. No matched text."""
    text, truncated = _prepare(text)
    counts: Counter[str] = Counter()
    category: dict[str, str] = {}
    spans: list[tuple[int, int]] = []
    for kind, (cat, pattern) in _PATTERNS.items():
        for match in pattern.finditer(text):
            counts[kind] += 1
            category[kind] = cat
            spans.append(match.span())
    for match in _ASSIGNMENT.finditer(text):
        value = match.group(2)
        letters, digits = any(c.isalpha() for c in value), any(c.isdigit() for c in value)
        if not (letters and digits) or value[0] in "/\.~":
            continue  # a word, a number, a path or a placeholder: not a credential
        counts[_PASSWORD] += 1
        category[_PASSWORD] = "secret"
        spans.append(match.span(2))
    spans.sort()
    for match in _TOKEN.finditer(text):
        if any(a <= match.start() < b or a < match.end() <= b for a, b in spans):
            continue  # already counted as a known format
        token = match.group()
        if any(c.isdigit() for c in token) and _entropy(token) > ENTROPY_FLOOR:
            counts[_HIGH_ENTROPY] += 1
            category[_HIGH_ENTROPY] = "secret"
    _scan_emails(text, counts, category)
    for match in _CARD.finditer(text):
        if _is_card(re.sub(r"\D", "", match.group())):
            counts["card_number"] += 1
            category["card_number"] = "pii"
    for pattern in (_IPV4, _IPV6):
        for match in pattern.finditer(text):
            if len(match.group()) < 3 or not any(c not in ":" for c in match.group()):
                continue
            address = _address_kind(match.group())
            if address:
                counts[address] += 1
                category[address] = "address"
    for match in _URL_HOST.finditer(text):
        host = match.group(1)
        if _host_is_metadata(host) and _address_kind(host.strip("[]")) != "metadata_address":
            counts["metadata_address"] += 1  # odd spellings and names (plain IPs counted above)
            category["metadata_address"] = "address"
    injections = len(_INJECTION.findall(text))
    if injections:
        counts["injection_phrase"] += injections
        category["injection_phrase"] = "injection"
    by_category: Counter[str] = Counter()
    for kind, n in counts.items():
        by_category[category[kind]] += n
    return {
        "counts": dict(sorted(counts.items())),
        "categories": dict(sorted(by_category.items())),
        "truncated": truncated,
    }


def _scan_emails(text: str, counts: Counter[str], category: dict[str, str]) -> None:
    """Find each '@' first and look only at a small window around it: linear in the text."""
    pos = text.find("@")
    while pos >= 0:
        if _LOCAL.search(text, max(0, pos - 64), pos) and _DOMAIN.match(text, pos + 1, pos + 280):
            counts["email"] += 1
            category["email"] = "pii"
        pos = text.find("@", pos + 1)


def summary(result: dict[str, Any]) -> str:
    """'2 github_token, 1 email' - kinds and counts only."""
    return ", ".join(f"{n} {kind}" for kind, n in result["counts"].items()) or "nothing"


def _leaves(value: Any, out: list[str], depth: int = 0) -> None:
    """Every string (and dict key) in a tool input, one per line. Depth-limited."""
    if depth > 50:
        out.append("[nested too deeply]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            _leaves(item, out, depth + 1)
    elif isinstance(value, list | tuple):
        for item in value:
            _leaves(item, out, depth + 1)
    elif value is not None:
        out.append(str(value))


def text_of(value: Any) -> str:
    """Every string (and dict key) in a JSON value, one per line: real newlines, not JSON escapes,
    so word boundaries survive ("README\\nIgnore" must not read as "nIgnore")."""
    out: list[str] = []
    _leaves(value, out)
    return "\n".join(out)


def tool_text(tool: str, tool_input: dict[str, Any]) -> str | None:
    """Everything a data-leaving tool call carries, one string per line; None for other tools."""
    if tool not in ("WebFetch", "WebSearch") and not tool.startswith("mcp__"):
        return None
    out: list[str] = []
    _leaves(tool_input, out)
    return "\n".join(out)


# --- redaction for the output guard (v0.7e F1, ADR-0027) ------------------------------------
# A whole PEM block: up to its END line, or to the end of the text when it has none.
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[\s\S]*?"
    r"(-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----|\Z)"
)
_REDACT: tuple[tuple[str, re.Pattern[str]], ...] = (("private_key", _PEM_BLOCK),) + tuple(
    (kind, pattern) for kind, (_, pattern) in _PATTERNS.items() if kind != "private_key"
)
_MAX_DEPTH = 50


def _tag(kind: str, value: str) -> str:
    """[REDACTED:<kind>:<sha256[:8]>]: a fingerprint (CLAUDE.md rule 1), never the value."""
    return f"[REDACTED:{kind}:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:8]}]"


def _redact_text(text: str, counts: Counter[str], unredacted: Counter[str]) -> str:
    for kind, pattern in _REDACT:

        def _sub(match: re.Match[str], kind: str = kind) -> str:
            counts[kind] += 1
            return _tag(kind, match.group())

        text = pattern.sub(_sub, text)
    # What only the normalised scan sees (zero-width characters, look-alikes, %-encoding) cannot
    # be cut out of the original text safely: report it so the guard treats the output as tainted.
    for kind, n in _known(scan(text)["counts"]).items():
        unredacted[kind] += n
    return text


def _redact_value(value: Any, state: dict[str, Any], depth: int) -> Any:
    if depth > _MAX_DEPTH:
        state["partial"] = True
        return value
    if isinstance(value, str):
        return _redact_text(value, state["counts"], state["unredacted"])
    if isinstance(value, dict):
        return {key: _redact_value(item, state, depth + 1) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return type(value)(_redact_value(item, state, depth + 1) for item in value)
    return value


def redact(value: Any) -> tuple[Any, dict[str, Any]]:
    """A copy of `value` (any JSON value: a tool's output) with each credential in a known format
    and each private key replaced by `[REDACTED:<kind>:<sha256[:8]>]`. Only string leaves change,
    so the output keeps its shape. Guesses (high-entropy tokens, `password = ...`), PII and
    addresses are left alone: they match ordinary code, and a redacted read the agent writes back
    would damage it.

    Returns (copy, info): info = {"counts": {kind: n redacted}, "redacted": total,
    "unredacted": {kind: n seen only after normalising}, "partial": nested too deeply}.
    No matched text is returned."""
    state: dict[str, Any] = {"counts": Counter(), "unredacted": Counter(), "partial": False}
    out = _redact_value(value, state, 0)
    counts: Counter[str] = state["counts"]
    return out, {
        "counts": dict(sorted(counts.items())),
        "redacted": sum(counts.values()),
        "unredacted": dict(sorted(state["unredacted"].items())),
        "partial": state["partial"],
    }


# --- the decisions the hooks apply (ADR-0025) -----------------------------------------------
Verdict = tuple[str, str, str, str]  # decision, rule, class, reason
_NOT_SECRET = ("email", "card_number", "injection_phrase")


def _known(counts: dict[str, int]) -> dict[str, int]:
    return {
        k: n
        for k, n in counts.items()
        if k not in GUESSES and k not in _NOT_SECRET and not k.endswith("_address")
    }


def _partly(result: dict[str, Any]) -> str:
    return " (only part of it could be scanned)" if result["truncated"] else ""


def decide_prompt(prompt: str) -> Verdict | None:
    """Block a prompt that holds a credential in a known format or a private key (it would be
    sent to the model provider). Guesses, PII and addresses are not blocked: it is the user's own
    text, and the gateway checks what leaves through tools."""
    result = scan(prompt)
    known = _known(result["counts"])
    if known:
        reason = (
            f"Sentinel blocked this prompt: it holds {summary({'counts': known})}"
            f"{_partly(result)}. "
            "Send the credential's fingerprint (`sentinel fingerprint`) or a placeholder instead; "
            "rotate it if it was real. The prompt still exists in Claude Code's local transcript."
        )
        return ("block", "FW-10", "prompt_secret", reason)
    return None


def decide_tool(tool: str, tool_input: dict[str, Any]) -> Verdict | None:
    """For tools that send data off the machine (WebFetch, WebSearch, MCP): deny a known
    credential, a private key or a cloud metadata address; ask for guesses, PII, internal
    addresses and input too large to scan. Other tools return None."""
    text = tool_text(tool, tool_input)
    if text is None:
        return None
    result = scan(text)
    counts, partly = result["counts"], _partly(result)
    known = _known(counts)
    if known:
        reason = (
            f"this {tool} call would send {summary({'counts': known})} off the machine{partly}; "
            "use a fingerprint or a placeholder"
        )
        return ("deny", "FW-01", "firewall_secret", reason)
    if counts.get("metadata_address"):
        return ("deny", "FW-02", "firewall_metadata",
                f"this {tool} call names a cloud metadata address{partly}")  # fmt: skip
    asks = {k: n for k, n in counts.items() if k not in known and k != "injection_phrase"}
    if asks:
        reason = f"this {tool} call would send {summary({'counts': asks})} off the machine{partly}"
        return ("ask", "FW-03", "firewall_sensitive", reason)
    if result["truncated"]:
        return (
            "ask",
            "FW-04",
            "firewall_unscanned",
            f"this {tool} call is too large to scan fully",
        )
    return None
