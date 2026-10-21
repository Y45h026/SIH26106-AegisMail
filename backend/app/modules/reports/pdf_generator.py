"""Generate a concise, evidence-focused AegisMail PDF report."""

from __future__ import annotations

from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

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
    ml = analysis.get("ml_content_analysis", {})
    intent = analysis.get("content_intent", {})
    identity = analysis.get("sender_identity_analysis", {})
    story: list[Any] = [
        Paragraph("DIGITAL FORENSIC INCIDENT REPORT — AEGISMAIL", title),
        Paragraph(f"Analysis timestamp (UTC): {evidence['analysis_timestamp']}", body), Spacer(1, 8),
        Paragraph(f"Risk assessment: <b>{risk['score']}/100 — {risk['category']}</b>", body),
        Paragraph("Evidence Chain of Custody", section),
        _table([["Original filename", evidence["filename"]], ["SHA-256", evidence["sha256"]], ["MD5 (identifier only)", evidence["md5"]], ["Size", f"{evidence['size_bytes']} bytes"]]),
        Paragraph("Authentication Results", section),
        _table([["SPF", authentication["spf"]["result"]], ["DKIM", authentication["dkim"]["result"]], ["DMARC", authentication["dmarc"]["result"]], ["Overall", authentication["overall_verdict"]]]),
        Paragraph("Content, Sender Identity &amp; Header Review", section),
        _table([
            ["Content intent score", f"{intent.get('urgency_deception_score', 0):.2f}"],
            ["Matched content indicators", "; ".join(f"{item['phrase']} ({item['category']})" for item in intent.get("matched_indicators", [])) or "None detected"],
            ["Sender identity review", identity.get("detail") or "No configured sender-role mismatch was detected."],
            ["Date/header anomalies", "; ".join(flags.get("date_weekday_mismatch_details", [])) or "None detected"],
            ["Verification suppression", "Detected" if flags.get("verification_suppression_language") else "Not detected"],
        ]),
        Paragraph("ML Content Analysis", section),
        _table(_ml_rows(ml)),
        Paragraph("Explainable Risk Factors", section),
    ]
    factors = risk["factors"] or [{"code": "none", "points": 0, "description": "No scored risk factors were detected."}]
    story.append(_table([[factor["code"], f"+{factor['points']}", factor["description"]] for factor in factors], header=["Factor", "Points", "Evidence"]))
    flag_rows = []
    for name, value in flags.items():
        if isinstance(value, (bool, str, int, float)):
            flag_rows.append([name.replace("_", " ").title(), str(value)])
        elif isinstance(value, list) and value:
            flag_rows.append([name.replace("_", " ").title(), "; ".join(str(item) for item in value)])
    story.extend([Paragraph("Suspicious Flags", section), _table(flag_rows or [["None", "No additional flags"]])])
    story.append(Paragraph("Relay Hop Reconstruction", section))
    hop_rows = []
    for hop in analysis["relay_hops"]["hops"]:
        hop_rows.append([str(hop["sequence"]), ", ".join(hop["ip_addresses"]) or "—", hop.get("from_server") or "—", hop.get("by_server") or "—"])
    story.append(_table(hop_rows or [["—", "—", "—", "—"]], header=["Sequence", "IP addresses", "From", "By"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Scope note: AegisMail provides infrastructure attribution and forensic intelligence. It does not identify a physical human attacker.", body))
    document.build(story)
    return buffer.getvalue()


def _ml_rows(ml: dict[str, Any]) -> list[list[str]]:
    if not ml.get("enabled"):
        return [["Status", str(ml.get("status", "unavailable"))],
                ["Prediction", "Unavailable"], ["Phishing probability", "Unavailable"]]
    indicators = ml.get("top_indicators", [])[:3]
    indicator_text = "; ".join(f"{item['term']} ({item['direction']})" for item in indicators) or "No meaningful feature explanation available"
    probability = ml.get("phishing_probability")
    return [
        ["Prediction", str(ml.get("prediction", "unavailable")).title()],
        ["Phishing probability", f"{probability:.1%}" if isinstance(probability, (int, float)) else "Unavailable"],
        ["Confidence", str(ml.get("confidence", "unavailable")).title()],
        ["Top model indicators", indicator_text],
        ["Interpretation", "One content-analysis signal; the composite score also uses authentication, URLs, domains, and relay evidence."],
    ]


def _table(rows: list[list[str]], header: list[str] | None = None) -> Table:
    data = ([header] if header else []) + rows
    cell_style = ParagraphStyle("AegisTableCell", fontName="Helvetica", fontSize=7.5, leading=9.5)
    wrapped = [[Paragraph(escape(str(cell)), cell_style) for cell in row] for row in data]
    table = Table(wrapped, colWidths=None, repeatRows=1 if header else 0, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#9fb3c8")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9eaf7") if header else colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold" if header else "Helvetica"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table
