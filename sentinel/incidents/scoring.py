"""Risk score R = f(E, I, X, P, C) with fixed bands (no learned scores).

E exploitation evidence, I asset importance, X external exposure, P privileges, C confidence.
Severity, confidence and urgency stay separate. A rule's floor can only be raised by the score.
"""

from typing import Any

from sentinel.correlation.model import Match

_SEVERITY_ORDER = ("low", "medium", "high", "critical")
_E = {"R1": 1.0, "R7": 1.0, "R6": 0.7, "R4": 0.6}
_P = {"admin": 1.0, "owner": 1.0, "write": 0.7, "read": 0.4}
_C = {"low": 1 / 3, "medium": 2 / 3, "high": 1.0}
_URGENCY = {
    "critical": "immediate",
    "high": "same_day",
    "medium": "this_week",
    "low": "backlog",
}


def _band(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def score(match: Match, blast: dict[str, Any] | None) -> dict[str, Any]:
    e = _E.get(match.rule_id, 0.5)
    rank = (blast or {}).get("max_importance_rank", 0)
    i = rank / 4 if rank else 0.5  # unknown importance: assume medium
    x = 0.5  # external exposure unknown in v0.1
    perms = [a["permission"] for a in (blast or {}).get("confirmed_access", [])]
    p = max((_P.get(perm, 0.5) for perm in perms), default=0.5)
    c = _C[match.confidence]
    total = round(40 * e + 20 * i + 15 * x + 15 * p + 10 * c, 1)
    severity = max(match.severity_floor, _band(total), key=_SEVERITY_ORDER.index)
    return {
        "score": total,
        "severity": severity,
        "confidence": match.confidence,
        "urgency": _URGENCY[severity],
        "factors": {"E": e, "I": round(i, 2), "X": x, "P": p, "C": round(c, 2)},
    }
