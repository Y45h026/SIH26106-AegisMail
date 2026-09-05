"""Fast, explainable rule-based intent classification for email content."""

from __future__ import annotations

import re
from typing import Any

INTENT_PATTERNS: dict[str, tuple[tuple[str, float], ...]] = {
    "financial_fraud": (
        (r"\bwire transfer\b", 0.34), (r"\bbank account (?:has )?changed\b", 0.34),
        (r"\bgift cards?\b", 0.30), (r"\bimmediate payment\b", 0.30),
        (r"\bpayment (?:is )?overdue\b", 0.20),
    ),
    "credential_harvesting": (
        (r"\bverify (?:your )?password\b", 0.34), (r"\baccount (?:is )?suspended\b", 0.30),
        (r"\bclick here to (?:log ?in|login)\b", 0.30), (r"\bconfirm (?:your )?(?:account|identity)\b", 0.24),
        (r"\breset (?:your )?password\b", 0.22),
    ),
    "authority_fraud": (
        (r"\bi am in a meeting\b", 0.28), (r"\bdo not call\b", 0.30),
        (r"\bhandle this immediately\b", 0.30), (r"\bceo\b", 0.14),
        (r"\bconfidential(?:ly)?\b", 0.16),
    ),
}
URGENCY_PATTERNS: tuple[tuple[str, float], ...] = (
    (r"\bimmediately\b", 0.12), (r"\burgent\b", 0.12), (r"\bwithin (?:the )?hour\b", 0.14),
    (r"\btoday\b", 0.07), (r"\baction required\b", 0.12), (r"\bfinal (?:notice|warning)\b", 0.12),
)


def _find_matches(text: str, patterns: tuple[tuple[str, float], ...], category: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for pattern, weight in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            matches.append({"category": category, "phrase": match.group(0), "weight": weight})
    return matches


def analyze_email_intent(subject: str = "", body: str = "") -> dict[str, Any]:
    """Return BEC/phishing intent indicators and a bounded deception score.

    Scores reflect language risk, not a determination that an email is malicious.
    """
    text = f"{subject}\n{body}".strip()
    matches: list[dict[str, Any]] = []
    intent_scores: dict[str, float] = {}

    for intent, patterns in INTENT_PATTERNS.items():
        intent_matches = _find_matches(text, patterns, intent)
        matches.extend(intent_matches)
        intent_scores[intent] = min(0.65, sum(match["weight"] for match in intent_matches))

    urgency_matches = _find_matches(text, URGENCY_PATTERNS, "urgency")
    matches.extend(urgency_matches)
    urgency_score = min(0.35, sum(match["weight"] for match in urgency_matches))
    deception_score = min(1.0, round(sum(intent_scores.values()) + urgency_score, 2))
    detected_intents = [intent for intent, score in intent_scores.items() if score > 0]

    return {
        "urgency_deception_score": deception_score,
        "urgency_score": round(urgency_score, 2),
        "detected_intents": detected_intents,
        "is_high_risk_bec": deception_score >= 0.65,
        "matched_indicators": matches,
    }


classify_bec_intent = analyze_email_intent
