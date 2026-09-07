"""Optional WHOIS domain-registration age enrichment."""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

try:
    import whois
except ImportError:  # pragma: no cover - deployment guard
    whois = None


def lookup_domain_age(domain: str) -> dict[str, Any]:
    """Look up a domain's registration age without allowing exceptions to escape."""
    if not domain or "." not in domain:
        return {"domain": domain, "status": "invalid", "age_days": None}
    if whois is None:
        return {"domain": domain, "status": "unavailable", "age_days": None, "error": "python-whois not installed"}
    try:
        record = whois.whois(domain)
        created = record.creation_date
        if isinstance(created, list):
            created = next((item for item in created if item), None)
        if isinstance(created, datetime):
            created_date = created.astimezone(timezone.utc).date() if created.tzinfo else created.date()
        elif isinstance(created, date):
            created_date = created
        else:
            return {"domain": domain, "status": "unknown", "age_days": None}
        return {"domain": domain, "status": "ok", "creation_date": created_date.isoformat(), "age_days": (datetime.now(timezone.utc).date() - created_date).days}
    except Exception as exc:  # WHOIS providers expose varied network/parser errors
        return {"domain": domain, "status": "unavailable", "age_days": None, "error": str(exc)}
