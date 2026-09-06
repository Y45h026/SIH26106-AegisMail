"""Day 2 stamped-email authentication and Received-IP extraction helpers."""

from __future__ import annotations

import ipaddress
import re
from email import policy
from email.message import Message
from email.parser import BytesParser, Parser
from pathlib import Path
from typing import Literal, TypeAlias

AuthenticationResult: TypeAlias = Literal[
    "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"
]
EmlSource: TypeAlias = bytes | bytearray | str | Path | Message

_AUTH_RESULT_RE = re.compile(
    r"\b(?P<mechanism>spf|dkim|dmarc)=(?P<result>pass|fail|softfail|neutral|none|temperror|permerror|policy)\b",
    re.IGNORECASE,
)
_IP_CANDIDATE_RE = re.compile(r"(?<![\w:.])(?:\d{1,3}\.){3}\d{1,3}(?![\w:.])|(?<![\w:])(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]+", re.I)


def _parse(source: EmlSource) -> Message:
    """Read an EML source without altering its header ordering."""
    if isinstance(source, Message):
        return source
    if isinstance(source, (bytes, bytearray)):
        return BytesParser(policy=policy.default).parsebytes(bytes(source))
    if isinstance(source, Path):
        return BytesParser(policy=policy.default).parsebytes(source.read_bytes())
    if isinstance(source, str):
        # Raw RFC 5322 text necessarily contains a header/body line break;
        # treating it as a path would fail on Windows for long messages.
        if "\n" not in source and "\r" not in source:
            path = Path(source)
            if path.is_file():
                return BytesParser(policy=policy.default).parsebytes(path.read_bytes())
        return Parser(policy=policy.default).parsestr(source)
    raise TypeError("source must be raw email bytes, a path, text, or an email Message")


def is_fully_authenticated(source: EmlSource) -> dict[str, AuthenticationResult | bool | None]:
    """Read recipient-stamped SPF, DKIM and DMARC results.

    ``Authentication-Results`` is evaluated in wire order: the first result
    for a mechanism belongs to the closest receiving system and is retained.
    This is an evidence read, not a live DNS/cryptographic re-verification.
    """
    message = _parse(source)
    results: dict[str, AuthenticationResult | None] = {"spf": None, "dkim": None, "dmarc": None}
    for header in message.get_all("Authentication-Results", []):
        for match in _AUTH_RESULT_RE.finditer(str(header)):
            mechanism = match.group("mechanism").lower()
            if results[mechanism] is None:
                results[mechanism] = match.group("result").lower()  # type: ignore[assignment]
    return {
        **results,
        "fully_authenticated": all(results[mechanism] == "pass" for mechanism in results),
    }


def extract_received_ip_chain(source: EmlSource) -> list[str]:
    """Return Received-header IPs destination-to-origin (newest to oldest).

    Received headers are prepended by each relay.  Python's ``get_all``
    retains that raw top-to-bottom order, so the first returned address is
    closest to the recipient; no reversal is performed here.
    """
    ip_chain: list[str] = []
    for header in _parse(source).get_all("Received", []):
        for candidate in _IP_CANDIDATE_RE.findall(str(header)):
            try:
                ip_chain.append(str(ipaddress.ip_address(candidate)))
            except ValueError:
                # Ignore date fragments and malformed address-like tokens.
                continue
    return ip_chain
