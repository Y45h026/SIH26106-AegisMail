"""Explainable, deterministic aggregation of AegisMail risk signals."""

from __future__ import annotations

from typing import Any, Mapping


def _failed(value: object) -> bool:
    return value is False or (isinstance(value, str) and value.lower().strip() == "fail")


def _enabled(signals: Mapping[str, Any], *names: str) -> bool:
    return any(bool(signals.get(name)) for name in names)


def _category(score: int) -> str:
    if score <= 25:
        return "Legitimate"
    if score <= 65:
        return "Suspicious"
    if score <= 85:
        return "High Risk"
    return "Critical Threat"


def score_email_risk(
    authentication: Mapping[str, Any] | None = None,
    domain: Mapping[str, Any] | None = None,
    headers: Mapping[str, Any] | None = None,
    content: Mapping[str, Any] | None = None,
    urls: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate verified analysis outputs into a 0-100 transparent risk score.

    Each input is optional. A factor is included only when its supporting signal
    is present, so reports can explain exactly why a score changed.
    """
    authentication, domain, headers, content, urls = (
        authentication or {}, domain or {}, headers or {}, content or {}, urls or {},
    )
    factors: list[dict[str, Any]] = []

    def add(code: str, category: str, points: int, description: str) -> None:
        factors.append({"code": code, "category": category, "points": points, "description": description})

    if _failed(authentication.get("dmarc")):
        add("dmarc_fail", "authentication", 30, "DMARC validation failed.")
    if _failed(authentication.get("spf")):
        add("spf_fail", "authentication", 15, "SPF validation failed.")
    if _enabled(domain, "homoglyph_detected", "is_impersonation_suspected"):
        add("homoglyph_or_lookalike", "domain", 25, "Sender domain shows a homoglyph or lookalike-brand indicator.")
    domain_age = domain.get("age_days", domain.get("domain_age_days"))
    if isinstance(domain_age, (int, float)) and domain_age < 30:
        add("new_domain", "domain", 20, "Sender domain is younger than 30 days.")
    if _enabled(headers, "reply_to_mismatch", "has_reply_to_mismatch"):
        add("reply_to_mismatch", "headers", 15, "Reply-To domain does not match the sender domain.")
    if headers.get("has_message_id") is False or _enabled(headers, "missing_message_id"):
        add("missing_message_id", "headers", 10, "Message-ID header is absent.")
    intent_score = content.get("urgency_deception_score", content.get("bec_score", 0.0))
    if _enabled(content, "is_high_risk_bec", "high_urgency_bec") or (
        isinstance(intent_score, (int, float)) and intent_score >= 0.65
    ):
        add("high_urgency_bec", "content", 20, "Content contains high-confidence urgency or BEC deception indicators.")
    if _enabled(urls, "has_ip_based_url", "ip_based_url"):
        add("ip_based_url", "content", 15, "Email contains a URL using a literal IP address.")

    raw_score = sum(factor["points"] for factor in factors)
    score = max(0, min(100, raw_score))
    return {
        "score": score,
        "category": _category(score),
        "raw_score": raw_score,
        "factors": factors,
        "factor_count": len(factors),
    }


calculate_risk_score = score_email_risk
