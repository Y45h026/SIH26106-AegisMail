"""Generate a concise, evidence-focused AegisMail PDF report."""

from __future__ import annotations

from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_forensic_report(analysis: dict[str, Any]) -> bytes:
    """Create a PDF from an ``analyze_email`` result without changing evidence."""
    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=1.6 * cm, leftMargin=1.6 * cm, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("AegisTitle", parent=styles["Title"], textColor=colors.HexColor("#102a43"), fontSize=18, leading=22)
    section = ParagraphStyle("AegisSection", parent=styles["Heading2"], textColor=colors.HexColor("#0b7285"), spaceBefore=12, spaceAfter=6)
    body = styles["BodyText"]
    evidence = analysis["evidence"]
    authentication = analysis["authentication"]
    risk = analysis["risk_score"]
    flags = analysis["suspicious_flags"]
    story: list[Any] = [
        Paragraph("DIGITAL FORENSIC INCIDENT REPORT — AEGISMAIL", title),
        Paragraph(f"Analysis timestamp (UTC): {evidence['analysis_timestamp']}", body), Spacer(1, 8),
        Paragraph(f"Risk assessment: <b>{risk['score']}/100 — {risk['category']}</b>", body),
        Paragraph("Evidence Chain of Custody", section),
        _table([["Original filename", evidence["filename"]], ["SHA-256", evidence["sha256"]], ["MD5 (identifier only)", evidence["md5"]], ["Size", f"{evidence['size_bytes']} bytes"]]),
        Paragraph("Authentication Results", section),
        _table([["SPF", authentication["spf"]["result"]], ["DKIM", authentication["dkim"]["result"]], ["DMARC", authentication["dmarc"]["result"]], ["Overall", authentication["overall_verdict"]]]),
        Paragraph("Explainable Risk Factors", section),
    ]
    factors = risk["factors"] or [{"code": "none", "points": 0, "description": "No scored risk factors were detected."}]
    story.append(_table([[factor["code"], f"+{factor['points']}", factor["description"]] for factor in factors], header=["Factor", "Points", "Evidence"]))
    story.extend([Paragraph("Suspicious Flags", section), _table([[name.replace("_", " ").title(), str(value)] for name, value in flags.items() if isinstance(value, (bool, str, int, float))])])
    story.append(Paragraph("Relay Hop Reconstruction", section))
    hop_rows = []
    for hop in analysis["relay_hops"]["hops"]:
        hop_rows.append([str(hop["sequence"]), ", ".join(hop["ip_addresses"]) or "—", hop.get("from_server") or "—", hop.get("by_server") or "—"])
    story.append(_table(hop_rows or [["—", "—", "—", "—"]], header=["Sequence", "IP addresses", "From", "By"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Scope note: AegisMail provides infrastructure attribution and forensic intelligence. It does not identify a physical human attacker.", body))
    document.build(story)
    return buffer.getvalue()


def _table(rows: list[list[str]], header: list[str] | None = None) -> Table:
    data = ([header] if header else []) + rows
    table = Table(data, colWidths=None, repeatRows=1 if header else 0, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#9fb3c8")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9eaf7") if header else colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold" if header else "Helvetica"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table
