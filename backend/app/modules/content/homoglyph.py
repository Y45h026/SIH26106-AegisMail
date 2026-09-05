"""Brand impersonation and lookalike-domain detection.

The detector is intentionally offline: it highlights lookalikes for an analyst
without making a network request or claiming that a domain is malicious.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

# Commonly imitated brands in credential-theft and payment-fraud campaigns.
TARGETED_BRANDS: tuple[str, ...] = (
    "adobe", "airtel", "amazon", "americanexpress", "apple", "axisbank",
    "bankofamerica", "barclays", "chase", "citi", "coinbase", "docusign",
    "dropbox", "facebook", "fedex", "flipkart", "github", "google", "hdfc",
    "icici", "income-tax", "instagram", "linkedin", "microsoft", "netflix",
    "office365", "okta", "outlook", "paypal", "phonepe", "razorpay", "sbi",
    "slack", "spotify", "stripe", "telegram", "tiktok", "twitter", "uber",
    "upi", "visa", "wellsfargo", "whatsapp", "windows", "wise", "yahoo",
    "youtube", "zoho", "zoom", "zomato",
)

SUSPICIOUS_SUBDOMAIN_KEYWORDS = frozenset(
    {"account", "auth", "billing", "confirm", "login", "secure", "security",
     "signin", "support", "update", "verify", "wallet"}
)

# A focused confusable map covers the characters most often used in phishing
# domains while keeping this module free of a heavyweight Unicode dependency.
CONFUSABLES = str.maketrans(
    {
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x", "\u0443": "y",
        "\u0456": "i", "\u0458": "j", "\u04bb": "h", "\u04cf": "l",
        "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p", "\u03c5": "y", "\u03c7": "x",
    }
)


def levenshtein_distance(left: str, right: str) -> int:
    """Return the edit distance using a memory-efficient dynamic-programming loop."""
    if left == right:
        return 0
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            current.append(min(
                current[-1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + (left_char != right_char),
            ))
        previous = current
    return previous[-1]


def _extract_domain(value: str) -> str:
    """Accept either a bare domain or a normal RFC 5322 sender address."""
    candidate = value.strip().lower()
    address_match = re.search(r"@([^@\s>]+)", candidate)
    if address_match:
        candidate = address_match.group(1)
    return candidate.strip(". ")


def _to_unicode_domain(domain: str) -> str:
    labels: list[str] = []
    for label in domain.split("."):
        try:
            labels.append(label.encode("ascii").decode("idna") if label.startswith("xn--") else label)
        except UnicodeError:
            labels.append(label)
    return ".".join(labels)


def _skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).lower().translate(CONFUSABLES)
    return "".join(character for character in normalized if character.isalnum())


def analyze_sender_domain(sender: str) -> dict[str, Any]:
    """Analyze a sender address/domain for brand impersonation indicators.

    The response contains independently reviewable findings; callers should use
    ``is_impersonation_suspected`` as a risk signal, not a final verdict.
    """
    domain = _extract_domain(sender)
    unicode_domain = _to_unicode_domain(domain)
    findings: list[dict[str, Any]] = []
    brands: set[str] = set()

    if not domain or "." not in domain:
        return {
            "input": sender,
            "domain": domain,
            "is_impersonation_suspected": False,
            "matched_brands": [],
            "findings": [{"type": "invalid_domain", "description": "No valid sender domain was supplied."}],
        }

    if "xn--" in domain or any(ord(character) > 127 for character in unicode_domain):
        findings.append({
            "type": "idn_or_punycode",
            "description": "Domain uses an internationalized (IDN) or Punycode label.",
            "evidence": unicode_domain,
        })

    labels = unicode_domain.split(".")
    candidate_labels = labels[:-1]  # The public suffix alone is never a brand label.
    for label in candidate_labels:
        label_skeleton = _skeleton(label)
        for brand in TARGETED_BRANDS:
            brand_skeleton = _skeleton(brand)
            if label_skeleton == brand_skeleton and label != brand:
                brands.add(brand)
                findings.append({
                    "type": "homoglyph",
                    "brand": brand,
                    "description": f"Label '{label}' visually normalizes to '{brand}'.",
                    "evidence": label,
                })
            elif label_skeleton != brand_skeleton and levenshtein_distance(label_skeleton, brand_skeleton) <= 2:
                brands.add(brand)
                findings.append({
                    "type": "typosquat",
                    "brand": brand,
                    "description": f"Label '{label}' is within two edits of '{brand}'.",
                    "evidence": label,
                })

        label_tokens = [token for token in re.split(r"[-_]", label) if token]
        for brand in TARGETED_BRANDS:
            if brand in label_tokens and any(token in SUSPICIOUS_SUBDOMAIN_KEYWORDS for token in label_tokens):
                brands.add(brand)
                findings.append({
                    "type": "brand_keyword_combination",
                    "brand": brand,
                    "description": f"Brand '{brand}' is combined with a suspicious service keyword.",
                    "evidence": label,
                })

    return {
        "input": sender,
        "domain": domain,
        "unicode_domain": unicode_domain,
        "is_impersonation_suspected": bool(findings),
        "matched_brands": sorted(brands),
        "findings": findings,
    }


def check_lookalike_domain(sender_domain: str) -> dict[str, Any]:
    """Check a sender domain/address against the AegisMail brand watchlist.

    This is the focused public API for the typosquatting task. It accepts both
    ``paypa1.com`` and ``alerts@paypa1.com`` and returns analyst-friendly evidence.
    """
    return analyze_sender_domain(sender_domain)


detect_brand_impersonation = analyze_sender_domain
