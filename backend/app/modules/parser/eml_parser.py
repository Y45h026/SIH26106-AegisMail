"""Evidence-preserving parsing of RFC 5322 ``.eml`` messages."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import TypeAlias

from pydantic import BaseModel, Field

EmlSource: TypeAlias = bytes | bytearray | str | Path

# Deliberately conservative: trailing punctuation is removed after matching.
URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
TRAILING_URL_PUNCTUATION = ".,;:!?)]}>\"'"


class Mailbox(BaseModel):
    """A mailbox address as displayed in an RFC 5322 header."""

    display_name: str | None = None
    email: str | None = None


class AttachmentMetadata(BaseModel):
    filename: str | None = None
    content_type: str
    size_bytes: int = Field(ge=0)
    sha256: str


class ParsedEmail(BaseModel):
    """Structured, serialisable representation of parsed email evidence."""

    sha256: str
    md5: str
    size_bytes: int = Field(ge=0)
    message_id: str | None = None
    date: datetime | None = None
    subject: str | None = None
    from_: Mailbox = Field(serialization_alias="from")
    to: list[Mailbox] = Field(default_factory=list)
    cc: list[Mailbox] = Field(default_factory=list)
    reply_to: list[Mailbox] = Field(default_factory=list)
    return_path: str | None = None
    plain_text_body: str | None = None
    html_body: str | None = None
    urls: list[str] = Field(default_factory=list)
    attachments: list[AttachmentMetadata] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)


def _decode_header(value: str | None) -> str | None:
    """Decode encoded-word headers without failing on malformed input."""
    if not value:
        return None
    try:
        return str(make_header(decode_header(value))).strip() or None
    except (LookupError, UnicodeError, ValueError):
        return value.strip() or None


def _mailboxes(value: str | None) -> list[Mailbox]:
    if not value:
        return []
    return [
        Mailbox(display_name=_decode_header(name), email=address or None)
        for name, address in getaddresses([value])
    ]


def _single_mailbox(value: str | None) -> Mailbox:
    name, address = parseaddr(value or "")
    return Mailbox(display_name=_decode_header(name), email=address or None)


def _part_bytes(part: Message) -> bytes:
    """Return decoded MIME payload bytes, including malformed payload fallbacks."""
    payload = part.get_payload(decode=True)
    if payload is not None:
        return payload
    raw_payload = part.get_payload()
    if isinstance(raw_payload, str):
        return raw_payload.encode(part.get_content_charset() or "utf-8", errors="replace")
    return b""


def _part_text(part: Message) -> str:
    raw = _part_bytes(part)
    charset = part.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _extract_urls(*contents: str | None) -> list[str]:
    """Extract and de-duplicate URLs while retaining their order of appearance."""
    urls: list[str] = []
    seen: set[str] = set()
    for content in contents:
        if not content:
            continue
        for match in URL_PATTERN.findall(content):
            url = match.rstrip(TRAILING_URL_PUNCTUATION)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def _parse_date(value: str | None, warnings: list[str]) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        warnings.append("The Date header could not be parsed.")
        return None


def _load_raw_content(source: EmlSource) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if isinstance(source, (str, Path)):
        return Path(source).read_bytes()
    raise TypeError("source must be raw email bytes or a filesystem path")


def parse_eml(source: EmlSource) -> ParsedEmail:
    """Parse raw email evidence from bytes or a path.

    Hashes are calculated before parsing so they always describe the original
    artifact rather than a normalised message representation.
    """
    raw = _load_raw_content(source)
    if not raw:
        raise ValueError("The EML file is empty.")

    try:
        message: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("The file could not be parsed as an RFC 5322 email.") from exc

    warnings: list[str] = []
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentMetadata] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        payload = _part_bytes(part)
        if disposition == "attachment" or filename:
            attachments.append(
                AttachmentMetadata(
                    filename=_decode_header(filename),
                    content_type=part.get_content_type(),
                    size_bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
            continue
        if part.get_content_type() == "text/plain":
            plain_parts.append(_part_text(part))
        elif part.get_content_type() == "text/html":
            html_parts.append(_part_text(part))

    plain_text = "\n".join(plain_parts) or None
    html_text = "\n".join(html_parts) or None
    if not message.is_multipart() and not plain_text and not html_text:
        # Preserve an otherwise unclassified single-part body for investigation.
        plain_text = _part_text(message) or None

    return_path = _decode_header(message.get("Return-Path"))
    if return_path:
        return_path = return_path.strip("<>") or None

    return ParsedEmail(
        sha256=hashlib.sha256(raw).hexdigest(),
        md5=hashlib.md5(raw).hexdigest(),  # nosec B303: MD5 is evidence identification, not security
        size_bytes=len(raw),
        message_id=_decode_header(message.get("Message-ID")),
        date=_parse_date(message.get("Date"), warnings),
        subject=_decode_header(message.get("Subject")),
        from_=_single_mailbox(message.get("From")),
        to=_mailboxes(message.get("To")),
        cc=_mailboxes(message.get("Cc")),
        reply_to=_mailboxes(message.get("Reply-To")),
        return_path=return_path,
        plain_text_body=plain_text,
        html_body=html_text,
        urls=_extract_urls(plain_text, html_text),
        attachments=attachments,
        parse_warnings=warnings,
    )
