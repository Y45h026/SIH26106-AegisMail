"""Reconstruct email transport paths from RFC 5322 ``Received`` headers."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import TypeAlias

from pydantic import BaseModel, Field

EmlSource: TypeAlias = bytes | bytearray | str | Path | Message
IP_PATTERN = re.compile(r"(?<![\w:.])(?:\d{1,3}\.){3}\d{1,3}(?![\w:.])|(?<![\w:])(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]+", re.I)
CLAUSE_PATTERN = re.compile(r"\b(from|by|with)\s+([^\s;(]+)", re.I)


class Hop(BaseModel):
    sequence: int = Field(ge=1, description="1 is the origin-side (oldest) received hop.")
    raw_header: str
    from_server: str | None = None
    by_server: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    protocol: str | None = None
    timestamp: datetime | None = None
    is_private_network: bool = False


class HopTrace(BaseModel):
    """Transport path ordered origin-to-destination (oldest header first)."""

    received_header_count: int = Field(ge=0)
    traversal_order: str = "origin_to_destination"
    hops: list[Hop] = Field(default_factory=list)
    edge_hop: Hop | None = None
    warnings: list[str] = Field(default_factory=list)


def _load_message(source: EmlSource) -> Message:
    if isinstance(source, Message):
        return source
    if isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
    elif isinstance(source, (str, Path)):
        raw = Path(source).read_bytes()
    else:
        raise TypeError("source must be raw email bytes, a path, or an email Message")
    return BytesParser(policy=policy.default).parsebytes(raw)


def _valid_ips(header: str) -> list[str]:
    found: list[str] = []
    for candidate in IP_PATTERN.findall(header):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        value = str(ip)
        if value not in found:
            found.append(value)
    return found


def _parse_received_header(raw_header: str, sequence: int, warnings: list[str]) -> Hop:
    clauses = {name.lower(): value.strip("[]") for name, value in CLAUSE_PATTERN.findall(raw_header)}
    timestamp: datetime | None = None
    if ";" in raw_header:
        timestamp_text = raw_header.rsplit(";", 1)[1].strip()
        try:
            timestamp = parsedate_to_datetime(timestamp_text)
        except (TypeError, ValueError, IndexError):
            warnings.append(f"Could not parse timestamp for Received hop {sequence}.")
    ips = _valid_ips(raw_header)
    private = bool(ips) and all(ipaddress.ip_address(ip).is_private for ip in ips)
    return Hop(
        sequence=sequence,
        raw_header=raw_header,
        from_server=clauses.get("from"),
        by_server=clauses.get("by"),
        ip_addresses=ips,
        protocol=clauses.get("with"),
        timestamp=timestamp,
        is_private_network=private,
    )


def trace_hops(source: EmlSource) -> HopTrace:
    """Extract Received headers and traverse them bottom-to-top.

    RFC 5322 headers are stored newest-first (destination side at the top).
    Reversing them yields an origin-to-destination reconstruction.  Without a
    configured trusted-relay list, ``edge_hop`` is a best-effort heuristic: the
    first hop containing a globally routable IP address.
    """
    message = _load_message(source)
    received_headers = message.get_all("Received", [])
    warnings: list[str] = []
    if not received_headers:
        return HopTrace(received_header_count=0, warnings=["No Received headers were present."])

    hops = [
        _parse_received_header(raw, index, warnings)
        for index, raw in enumerate(reversed(received_headers), start=1)
    ]
    edge_hop = next(
        (
            hop
            for hop in hops
            if any(ipaddress.ip_address(ip).is_global for ip in hop.ip_addresses)
        ),
        None,
    )
    if edge_hop is None:
        warnings.append("No globally routable IP address was found in Received headers.")
    return HopTrace(
        received_header_count=len(received_headers), hops=hops, edge_hop=edge_hop, warnings=warnings
    )
