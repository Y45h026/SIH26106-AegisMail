"""Single-entry-point orchestration for AegisMail forensic analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.modules.auth.verifier import verify_email
from app.modules.content.homoglyph import analyze_sender_domain
from app.modules.content.nlp_intent import analyze_email_intent
from app.modules.hops.hop_tracer import trace_hops
from app.modules.intel.geoip import lookup_ip
from app.modules.parser.eml_parser import parse_eml
from app.modules.scoring.risk_engine import score_email_risk


def analyze_email(
    eml_file_path: str | Path,
    *,
    enrich_hops: bool = False,
    do_dns_lookup: bool = False,
    do_dkim_crypto: bool = False,
) -> dict[str, Any]:
    """Produce one explainable forensic-analysis dictionary from an EML file.

    Network-based checks are disabled by default. Set ``enrich_hops`` to add
    third-party GeoIP/ISP data and the other flags for live DNS/DKIM checks.
    """
    path = Path(eml_file_path)
    if not path.is_file():
        raise FileNotFoundError(f"EML file not found: {path}")
    parsed = parse_eml(path)
    authentication = verify_email(path, do_dns_lookup=do_dns_lookup, do_dkim_crypto=do_dkim_crypto)
    hop_trace = trace_hops(path)
    domain = analyze_sender_domain(parsed.from_.email or "")
    intent = analyze_email_intent(parsed.subject or "", parsed.plain_text_body or parsed.html_body or "")
    relay_hops = [_relay_hop(hop.model_dump(mode="json"), enrich_hops) for hop in hop_trace.hops]
    anomaly_ids = {finding.id for finding in authentication.anomalies}
    wire_transfer_indicators = [match["phrase"] for match in intent["matched_indicators"] if match["category"] == "financial_fraud"]
    flags = {
        "lookalike_domain": domain["is_impersonation_suspected"],
        "lookalike_details": domain,
        "wire_transfer_keywords": wire_transfer_indicators,
        "has_wire_transfer_indicator": bool(wire_transfer_indicators),
        "mismatched_return_path": "return_path_misaligned" in anomaly_ids,
        "reply_to_mismatch": "reply_to_mismatch" in anomaly_ids,
        "missing_message_id": "missing_message_id" in anomaly_ids,
        "parse_warnings": parsed.parse_warnings,
    }
    risk_score = score_email_risk(
        authentication={"spf": authentication.spf.result, "dkim": authentication.dkim.result, "dmarc": authentication.dmarc.result},
        domain=domain,
        headers={"reply_to_mismatch": flags["reply_to_mismatch"], "has_message_id": parsed.message_id is not None},
        content=intent,
        urls={"has_ip_based_url": _has_ip_based_url(parsed.urls)},
    )
    return {
        "evidence": {
            "filename": path.name,
            "sha256": parsed.sha256,
            "md5": parsed.md5,
            "size_bytes": parsed.size_bytes,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "authentication": authentication.model_dump(mode="json"),
        "relay_hops": {
            "traversal_order": hop_trace.traversal_order,
            "edge_hop_sequence": hop_trace.edge_hop.sequence if hop_trace.edge_hop else None,
            "hops": relay_hops,
            "warnings": hop_trace.warnings,
        },
        "suspicious_flags": flags,
        "content_intent": intent,
        "risk_score": risk_score,
    }


def _relay_hop(hop: dict[str, Any], enrich_hops: bool) -> dict[str, Any]:
    infrastructure = [lookup_ip(ip) for ip in hop["ip_addresses"]] if enrich_hops else [
        {"ip": ip, "status": "not_requested", "location": None, "isp": None}
        for ip in hop["ip_addresses"]
    ]
    return {**hop, "infrastructure": infrastructure}


def _has_ip_based_url(urls: list[str]) -> bool:
    import ipaddress
    from urllib.parse import urlparse

    for url in urls:
        hostname = urlparse(url if "://" in url else f"http://{url}").hostname
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                return True
            except ValueError:
                pass
    return False
