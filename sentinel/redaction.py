"""Refuse credential-shaped text in free-text fields (evidence, notes, actors).

Those fields land in the audit trail and reports, so an operator who pastes a key by accident
must be stopped before it is stored. Heuristic: it can miss exotic formats; it is a safety net.
"""

import math
import re
from collections import Counter

_PATTERNS = (
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),  # Google API key
    re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}"),  # GitHub classic tokens
    re.compile(r"github_pat_[0-9A-Za-z_]{30,}"),  # GitHub fine-grained token
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bsk_(live|test)_[0-9A-Za-z]{16,}"),  # Stripe-style
    re.compile(r"\bsk-[0-9A-Za-z_\-]{20,}"),  # generic sk- keys
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),  # Slack
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}"),  # JWT
)
_TOKENISH = re.compile(r"[0-9A-Za-z_\-+/=]{32,}")
MAX_LEN = 2000


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def has_secret_pattern(text: str) -> bool:
    """Known credential formats only (no entropy guess): for text whose long tokens are expected,
    such as real file paths restored into an answer."""
    return any(p.search(text) for p in _PATTERNS)


def looks_like_secret(text: str) -> bool:
    if has_secret_pattern(text):
        return True
    # Random secrets almost always contain a digit (a 32-character random token has none about
    # 0.1% of the time); a long hyphenated file name made of words does not, and is not a key.
    return any(_entropy(m) > 4.2 for m in _TOKENISH.findall(text) if any(c.isdigit() for c in m))


def check_free_text(label: str, text: str | None) -> str | None:
    """Return the text if safe; raise ValueError (never echoing the text) if it looks secret."""
    if text is None:
        return None
    if len(text) > MAX_LEN:
        raise ValueError(f"{label} is too long (max {MAX_LEN} characters)")
    if looks_like_secret(text):
        raise ValueError(
            f"{label} looks like it contains a credential; refusing to store it. "
            "Describe the evidence instead (for example 'console shows key deleted')."
        )
    return text
