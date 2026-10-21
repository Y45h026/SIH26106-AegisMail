"""Explainable, deterministic aggregation of AegisMail risk signals."""

from __future__ import annotations

from typing import Any, Mapping

SAFE_MAX_SCORE = 24
RED_RISK_MIN_SCORE = 76


def _failed(value: object) -> bool:
    return value is False or (isinstance(value, str) and value.lower().strip() == "fail")


def _none(value: object) -> bool:
    """Return true only for an explicit recipient-MTA ``mechanism=none``."""
    return isinstance(value, str) and value.lower().strip() == "none"


def _enabled(signals: Mapping[str, Any], *names: str) -> bool:
    return any(bool(signals.get(name)) for name in names)


def _risk_band(score: int) -> tuple[str, str]:
    """Return the analyst-facing category and dashboard color for a score."""
    if score <= SAFE_MAX_SCORE:
        return "Low Observed Risk", "green"
    if score <= 65:
        return "Suspicious", "yellow"
    if score < RED_RISK_MIN_SCORE:
        return "High Risk", "orange"
    if score <= 85:
        return "High Risk", "red"
    return "Critical Threat", "red"


def score_email_risk(
    authentication: Mapping[str, Any] | None = None,
    domain: Mapping[str, Any] | None = None,
    headers: Mapping[str, Any] | None = None,
    content: Mapping[str, Any] | None = None,
    urls: Mapping[str, Any] | None = None,
    identity: Mapping[str, Any] | None = None,
    ml_content_analysis: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate verified analysis outputs into a 0-100 transparent risk score.

    Each input is optional. A factor is included only when its supporting signal
    is present, so reports can explain exactly why a score changed.
    """
    authentication, domain, headers, content, urls, identity, ml_content_analysis = (
        authentication or {}, domain or {}, headers or {}, content or {}, urls or {}, identity or {}, ml_content_analysis or {},
    )
    factors: list[dict[str, Any]] = []

    def add(code: str, category: str, points: int, description: str) -> None:
        factors.append({"code": code, "category": category, "points": points, "description": description})

    if _failed(authentication.get("dmarc")):
        add("dmarc_fail", "authentication", 30, "DMARC validation failed.")
    if _failed(authentication.get("spf")):
        add("spf_fail", "authentication", 15, "SPF validation failed.")
    if _none(authentication.get("dmarc")):
        add("dmarc_missing", "authentication", 20, "DMARC produced no authentication result.")
    if _none(authentication.get("spf")):
        add("spf_missing", "authentication", 10, "SPF produced no authentication result.")
    if _none(authentication.get("dkim")):
        add("dkim_missing", "authentication", 10, "Message has no DKIM authentication result.")
    if _enabled(domain, "homoglyph_detected", "is_impersonation_suspected"):
        add("homoglyph_or_lookalike", "domain", 25, "Sender domain shows a homoglyph or lookalike-brand indicator.")
    domain_age = domain.get("age_days", domain.get("domain_age_days"))
    if isinstance(domain_age, (int, float)) and domain_age < 30:
        add("new_domain", "domain", 20, "Sender domain is younger than 30 days.")
    if _enabled(headers, "reply_to_mismatch", "has_reply_to_mismatch"):
        add("reply_to_mismatch", "headers", 15, "Reply-To domain does not match the sender domain.")
    if headers.get("has_message_id") is False or _enabled(headers, "missing_message_id"):
        add("missing_message_id", "headers", 10, "Message-ID header is absent.")
    if _enabled(headers, "date_weekday_mismatch"):
        add("timestamp_weekday_mismatch", "headers", 5, "A Date or Received timestamp names a weekday that does not match its calendar date; this is a weak header-integrity signal.")
    financial_request = _enabled(content, "financial_request") or "financial_fraud" in content.get("detected_intents", [])
    if financial_request:
        add("financial_request_language", "content", 15, "Message content includes a financial-transfer, payment, or vendor language indicator.")
    if _enabled(identity, "sender_identity_mismatch"):
        detail = identity.get("detail") or "An external sender claims an authority role and targets an organizational recipient."
        add("external_authority_impersonation", "identity", 25, detail)
    if financial_request and _enabled(identity, "sensitive_recipient_roles"):
        roles = ", ".join(identity.get("sensitive_recipient_roles", []))
        add("sensitive_recipient_targeting", "identity", 10, f"A financial request targets a sensitive recipient function: {roles}.")
    intent_score = content.get("urgency_deception_score", content.get("bec_score", 0.0))
    if _enabled(content, "is_high_risk_bec", "high_urgency_bec") or (
        isinstance(intent_score, (int, float)) and intent_score >= 0.65
    ):
        add("high_urgency_bec", "content", 20, "Content contains high-confidence urgency or BEC deception indicators.")
    if _enabled(urls, "has_ip_based_url", "ip_based_url"):
        add("ip_based_url", "content", 15, "Email contains a URL using a literal IP address.")
    if _enabled(urls, "has_deceptive_url_host", "url_lookalike"):
        add("deceptive_url_host", "content", 25, "A URL host contains a lookalike or impersonation indicator.")

    probability = ml_content_analysis.get("phishing_probability")
    if ml_content_analysis.get("enabled") is True and ml_content_analysis.get("prediction") == "phishing" and isinstance(probability, (int, float)):
        if probability >= 0.85:
            add("ml_phishing_content", "content", 15, f"Content-based statistical evidence: the trained text classifier estimated a {probability:.1%} phishing probability.")
        elif probability >= 0.70:
            add("ml_phishing_content", "content", 8, f"Content-based statistical evidence: the trained text classifier estimated a {probability:.1%} phishing probability.")

    raw_score = sum(factor["points"] for factor in factors)
    score = max(0, min(100, raw_score))
    category, color = _risk_band(score)
    return {
        "score": score,
        "category": category,
        "color": color,
        "is_low_observed_risk": score <= SAFE_MAX_SCORE,
        "is_red_risk": score >= RED_RISK_MIN_SCORE,
        "raw_score": raw_score,
        "factors": factors,
        "factor_count": len(factors),
    }


calculate_risk_score = score_email_risk
