"""Full email-authentication verification for forensic analysis.

This module distinguishes SMTP-time stamped results from optional live DNS
policy lookups and cryptographic DKIM verification.  The latter two can be
disabled for repeatable, offline evidence analysis.
"""

from __future__ import annotations

import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from app.modules.auth.auth_verifier import EmlSource, _parse

try:
    import dkim
except ImportError:  # pragma: no cover - deployment dependency guard
    dkim = None

try:
    import dns.resolver
except ImportError:  # pragma: no cover - deployment dependency guard
    dns = None


AuthOutcome = Literal[
    "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy",
    "policy_found", "policy_found_weak", "no_spf_record", "no_dmarc_record", "lookup_error", "unavailable",
]
AuthSource = Literal["stamped_header", "dns", "dkimpy_signature", "unavailable"]
_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror|policy)\b", re.I)
_DKIM_DOMAIN_RE = re.compile(r"\bd=([^;\s]+)", re.I)
_DKIM_SELECTOR_RE = re.compile(r"\bs=([^;\s]+)", re.I)
_TITLE_RE = re.compile(r"\b(CEO|CFO|COO|President|Director|Founder|Chairman|VP|Vice President|Managing Director)\b", re.I)
_EMBEDDED_ADDRESS_RE = re.compile(r"[\w.\-+]+@[\w.\-]+")
_FREEMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com", "protonmail.com"}


class AuthResult(BaseModel):
    result: AuthOutcome
    source: AuthSource
    detail: str = ""
    policy: str | None = None


class DkimCryptoResult(BaseModel):
    attempted: bool
    verified: bool | None = None
    signing_domain: str | None = None
    selector: str | None = None
    error: str | None = None


class AnomalyFinding(BaseModel):
    id: str
    severity: Literal["low", "medium", "high"]
    description: str


class AlignmentResult(BaseModel):
    spf_aligned: bool | None = None
    reply_to_aligned: bool | None = None


class VerificationReport(BaseModel):
    from_email: str
    from_domain: str | None = None
    spf: AuthResult
    dkim: AuthResult
    dkim_crypto: DkimCryptoResult
    dmarc: AuthResult
    alignment: AlignmentResult
    anomalies: list[AnomalyFinding] = Field(default_factory=list)
    overall_verdict: Literal["pass", "fail", "partial", "unknown"]


def verify_email(
    source: EmlSource, *, do_dns_lookup: bool = False, do_dkim_crypto: bool = False
) -> VerificationReport:
    """Analyse authentication evidence; live network checks are opt-in."""
    message = _parse(source)
    raw_bytes = _source_bytes(source, message)
    _, from_email = parseaddr(str(message.get("From", "")))
    from_domain = _domain_of(from_email)
    return_path_domain = _domain_of(parseaddr(str(message.get("Return-Path", "")))[1])
    reply_to_domain = _domain_of(parseaddr(str(message.get("Reply-To", "")))[1])
    headers = [str(value) for value in message.get_all("Authentication-Results", [])]
    spf = _stamped(headers, "spf")
    dkim_stamped = _stamped(headers, "dkim")
    dmarc = _stamped(headers, "dmarc")
    crypto = _verify_dkim(raw_bytes) if do_dkim_crypto else DkimCryptoResult(attempted=False)
    dkim_result = dkim_stamped
    if dkim_result.result == "unavailable" and crypto.verified is not None:
        dkim_result = AuthResult(
            result="pass" if crypto.verified else "fail", source="dkimpy_signature", detail=crypto.error or "DKIM signature checked"
        )
    if do_dns_lookup:
        if spf.result == "unavailable" and (return_path_domain or from_domain):
            spf = _spf_dns(return_path_domain or from_domain or "")
        if dmarc.result == "unavailable" and from_domain:
            dmarc = _dmarc_dns(from_domain)
    spf_aligned = _aligned(from_domain, return_path_domain)
    reply_aligned = _aligned(from_domain, reply_to_domain)
    anomalies = _anomalies(message, from_email, from_domain, spf_aligned, reply_aligned)
    return VerificationReport(
        from_email=from_email,
        from_domain=from_domain,
        spf=spf,
        dkim=dkim_result,
        dkim_crypto=crypto,
        dmarc=dmarc,
        alignment=AlignmentResult(spf_aligned=spf_aligned, reply_to_aligned=reply_aligned),
        anomalies=anomalies,
        overall_verdict=_overall(spf.result, dkim_result.result, dmarc.result),
    )


def _source_bytes(source: EmlSource, message: Message) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if isinstance(source, Path):
        return source.read_bytes()
    if isinstance(source, str) and "\n" not in source and "\r" not in source and Path(source).is_file():
        return Path(source).read_bytes()
    return message.as_bytes(policy=policy.default)


def _stamped(headers: list[str], mechanism: str) -> AuthResult:
    for header in headers:
        for name, result in _RESULT_RE.findall(header):
            if name.lower() == mechanism:
                policy_match = re.search(r"\bp=(\w+)", header, re.I) if mechanism == "dmarc" else None
                return AuthResult(result=result.lower(), source="stamped_header", detail=header, policy=policy_match.group(1).lower() if policy_match else None)  # type: ignore[arg-type]
    return AuthResult(result="unavailable", source="unavailable", detail="No stamped result found")


def _verify_dkim(raw_bytes: bytes) -> DkimCryptoResult:
    signature = re.search(r"^DKIM-Signature:(.*?)(?:\r?\n(?![ \t])|\Z)", raw_bytes.decode("utf-8", errors="ignore"), re.M | re.S)
    signature_text = signature.group(1) if signature else ""
    domain = _DKIM_DOMAIN_RE.search(signature_text)
    selector = _DKIM_SELECTOR_RE.search(signature_text)
    if dkim is None:
        return DkimCryptoResult(attempted=False, error="dkimpy not installed")
    try:
        return DkimCryptoResult(attempted=True, verified=bool(dkim.DKIM(raw_bytes).verify()), signing_domain=domain.group(1) if domain else None, selector=selector.group(1) if selector else None)
    except Exception as exc:  # dkimpy exposes multiple provider-specific errors
        return DkimCryptoResult(attempted=True, verified=False, signing_domain=domain.group(1) if domain else None, selector=selector.group(1) if selector else None, error=f"{type(exc).__name__}: {exc}")


def _spf_dns(domain: str) -> AuthResult:
    if dns is None:
        return AuthResult(result="unavailable", source="unavailable", detail="dnspython not installed")
    try:
        for answer in dns.resolver.resolve(domain, "TXT"):
            value = _txt(answer)
            if value.lower().startswith("v=spf1"):
                return AuthResult(result="policy_found_weak" if "+all" in value or "?all" in value else "policy_found", source="dns", detail=value)
        return AuthResult(result="no_spf_record", source="dns", detail=f"No SPF policy for {domain}")
    except Exception as exc:
        return AuthResult(result="lookup_error", source="dns", detail=str(exc))


def _dmarc_dns(domain: str) -> AuthResult:
    if dns is None:
        return AuthResult(result="unavailable", source="unavailable", detail="dnspython not installed")
    try:
        for answer in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            value = _txt(answer)
            if value.lower().startswith("v=dmarc1"):
                policy = re.search(r"\bp=(\w+)", value, re.I)
                return AuthResult(result="policy_found", source="dns", detail=value, policy=policy.group(1).lower() if policy else "none")
        return AuthResult(result="no_dmarc_record", source="dns", detail=f"No DMARC policy for {domain}")
    except Exception as exc:
        return AuthResult(result="lookup_error", source="dns", detail=str(exc))


def _txt(answer: object) -> str:
    strings = getattr(answer, "strings", None)
    return b"".join(strings).decode("utf-8", errors="replace") if strings else str(answer).strip('"')


def _domain_of(address: str) -> str | None:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else None


def _aligned(left: str | None, right: str | None) -> bool | None:
    if not left or not right:
        return None
    return ".".join(left.split(".")[-2:]) == ".".join(right.split(".")[-2:])


def _anomalies(message: Message, from_email: str, from_domain: str | None, spf_aligned: bool | None, reply_aligned: bool | None) -> list[AnomalyFinding]:
    findings: list[AnomalyFinding] = []
    if spf_aligned is False:
        findings.append(AnomalyFinding(id="return_path_misaligned", severity="medium", description="From and Return-Path domains do not align."))
    if reply_aligned is False:
        findings.append(AnomalyFinding(id="reply_to_mismatch", severity="medium", description="From and Reply-To domains do not align."))
    for name in ("Message-ID", "Date"):
        if not message.get(name):
            findings.append(AnomalyFinding(id=f"missing_{name.lower().replace('-', '_')}", severity="low", description=f"Missing critical {name} header."))
    display_name, _ = parseaddr(str(message.get("From", "")))
    if _TITLE_RE.search(display_name) and from_domain in _FREEMAIL_DOMAINS:
        findings.append(AnomalyFinding(id="executive_title_freemail_spoof", severity="high", description="Executive title is paired with a freemail sender domain."))
    embedded = _EMBEDDED_ADDRESS_RE.search(display_name)
    if embedded and embedded.group(0).lower() != from_email.lower():
        findings.append(AnomalyFinding(id="display_name_embedded_address_mismatch", severity="high", description="Display name embeds a different email address."))
    return findings


def _overall(spf: str, dkim_result: str, dmarc: str) -> Literal["pass", "fail", "partial", "unknown"]:
    if "fail" in (spf, dkim_result, dmarc):
        return "fail"
    if all(result == "unavailable" for result in (spf, dkim_result, dmarc)):
        return "unknown"
    return "pass" if spf == dkim_result == dmarc == "pass" else "partial"
