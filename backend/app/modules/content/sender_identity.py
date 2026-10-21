"""Lightweight identity/context checks using deployment-configurable policy."""

from __future__ import annotations

import os
import re
from typing import Any, Iterable

PUBLIC_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "outlook.com",
    "hotmail.com", "live.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "aol.com", "gmx.com", "mail.com",
}
AUTHORITY_ROLES = {
    "principal": re.compile(r"\bprincipal\b", re.I),
    "president": re.compile(r"\bpresident\b", re.I),
    "chief executive": re.compile(r"\bceo\b|\bchief executive\b", re.I),
    "chief financial officer": re.compile(r"\bcfo\b|\bchief financial officer\b", re.I),
    "director": re.compile(r"\bdirector\b", re.I),
    "dean": re.compile(r"\bdean\b", re.I),
    "treasurer": re.compile(r"\btreasurer\b", re.I),
}
DEFAULT_SENSITIVE_RECIPIENTS = {
    "finance": r"finance", "payroll": r"payroll", "payments": r"payments?",
    "accounting": r"accounting", "accounts payable": r"accounts?[-_.]?payable",
    "treasury": r"treasury", "billing": r"billing",
}


def configured_organization_domains() -> set[str]:
    """Read trusted organizational domains from a comma-separated env setting."""
    return {
        value.strip().lower().lstrip("@.").rstrip(".")
        for value in os.getenv("AEGISMAIL_ORG_DOMAINS", "").split(",")
        if value.strip()
    }


def configured_sensitive_recipient_patterns() -> dict[str, re.Pattern[str]]:
    patterns = {name: re.compile(rf"(?:^|[._+-]){pattern}(?:$|[._+-])", re.I)
                for name, pattern in DEFAULT_SENSITIVE_RECIPIENTS.items()}
    for value in os.getenv("AEGISMAIL_SENSITIVE_RECIPIENTS", "").split(","):
        token = value.strip().lower()
        if token:
            patterns.setdefault(token, re.compile(rf"(?:^|[._+-]){re.escape(token)}(?:$|[._+-])", re.I))
    return patterns


def _matches_domain(domain: str, expected_domains: Iterable[str]) -> bool:
    return any(domain == expected or domain.endswith(f".{expected}") for expected in expected_domains)


def analyze_sender_identity(sender: Any, recipients: Iterable[Any]) -> dict[str, Any]:
    """Find a role/public-mail mismatch when it also targets an org or sensitive inbox.

    A free-mail address by itself is not treated as malicious. The finding needs
    an authority-role claim and an organizational or sensitive recipient context.
    """
    sender_email = (getattr(sender, "email", None) or "").strip().lower()
    sender_name = getattr(sender, "display_name", None) or ""
    sender_domain = sender_email.rsplit("@", 1)[-1] if "@" in sender_email else ""
    org_domains = configured_organization_domains()
    sensitive_patterns = configured_sensitive_recipient_patterns()
    public_mail = sender_domain in PUBLIC_MAIL_DOMAINS
    external = public_mail or (bool(org_domains) and not _matches_domain(sender_domain, org_domains))
    claimed_roles = [role for role, pattern in AUTHORITY_ROLES.items() if pattern.search(sender_name)]

    recipient_list = list(recipients)
    sensitive_roles: set[str] = set()
    recipient_domains: set[str] = set()
    for mailbox in recipient_list:
        address = (getattr(mailbox, "email", None) or "").strip().lower()
        if "@" not in address:
            continue
        local, recipient_domain = address.rsplit("@", 1)
        recipient_domains.add(recipient_domain)
        sensitive_roles.update(role for role, pattern in sensitive_patterns.items() if pattern.search(local))

    org_recipient = bool(org_domains and any(_matches_domain(domain, org_domains) for domain in recipient_domains))
    identity_mismatch = bool(external and claimed_roles and (sensitive_roles or org_recipient))
    detail = None
    if identity_mismatch:
        role_text = ", ".join(claimed_roles)
        target_text = ", ".join(sorted(sensitive_roles)) if sensitive_roles else "an organizational recipient"
        provider_text = sender_domain or "an external domain"
        detail = (
            f"The sender claims the role {role_text}, uses external domain {provider_text}, "
            f"and targets {target_text}. Verify the identity through a trusted channel."
        )
    return {
        "sender_domain": sender_domain or None,
        "is_public_mail_provider": public_mail,
        "is_external_sender": external,
        "claimed_authority_roles": claimed_roles,
        "sensitive_recipient_roles": sorted(sensitive_roles),
        "organization_domains_configured": sorted(org_domains),
        "sender_identity_mismatch": identity_mismatch,
        "detail": detail,
    }
