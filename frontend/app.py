"""AegisMail Streamlit investigation dashboard.

This frontend intentionally uses isolated demo data until the team's analysis
pipeline exposes its final response model. Replace ``build_demo_result`` with
an adapter for that response when the backend contract is ready.

The app is organised as two in-app "pages" (Home, Upload & Analyze) toggled
via ``st.session_state.page``. This keeps navigation lightweight and avoids
adding a routing dependency that isn't already part of the project.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import streamlit as st

from components.hop_map import render_hop_path_map


def html_block(raw: str) -> str:
    """Flatten pretty-printed HTML so Markdown never treats indented lines as code."""
    return "\n".join(line.strip() for line in raw.strip().splitlines())


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SAMPLE_DIRECTORIES = {
    "legitimate": PROJECT_ROOT / "samples" / "legitimate",
    "spoofed": PROJECT_ROOT / "samples" / "spoofed_dmarc_fail",
    "bec": PROJECT_ROOT / "samples" / "bec_wire_fraud",
}


# Temporary GeoIP handoff fixture. Member 3's output can replace this list
# directly: [(latitude, longitude), ...]. The order is the relay-hop order.
MOCK_HOP_COORDINATES = [
    (28.6139, 77.2090),  # Hop 1 — New Delhi
    (19.0760, 72.8777),  # Hop 2 — Mumbai
    (51.5074, -0.1278),  # Hop 3 — London
]


SEVERITY_STYLES: dict[str, dict[str, str]] = {
    "LOW RISK": {
        "accent": "#56e6bb",
        "headline": "SAFE — LOW RISK EMAIL",
    },
    "HIGH RISK": {
        "accent": "#ffb020",
        "headline": "HIGH RISK — SUSPICIOUS EMAIL",
    },
    "CRITICAL RISK": {
        "accent": "#ff5364",
        "headline": "CRITICAL RISK — LIKELY FRAUD",
    },
}


RECOMMENDED_ACTIONS: dict[str, list[str]] = {
    "LOW RISK": [
        "No immediate action is required.",
        "You can continue with this email as normal.",
        "Stay cautious if it later asks for sensitive information or payment.",
    ],
    "HIGH RISK": [
        "Do not click any links in this email.",
        "Do not download or open any attachments.",
        "Avoid replying with personal or company information.",
        "Report this email to your IT or security team.",
        "Verify the sender through a separate, trusted channel before acting.",
    ],
    "CRITICAL RISK": [
        "Do not click any links or open any attachments.",
        "Do not share sensitive information or process any payment requests.",
        "Report this email to your IT/security team immediately.",
        "If a payment was already made, contact your bank and security team right away.",
        "Preserve this email as-is — do not delete it — for investigation.",
    ],
}


DEMO_SCENARIOS: dict[str, dict[str, str]] = {
    "legitimate": {
        "title": "Legitimate Email",
        "desc": "A normal email with expected authentication results.",
        "button": "Load Legitimate Sample",
    },
    "spoofed": {
        "title": "Spoofed Sender",
        "desc": "An example where the sender or domain cannot be properly verified.",
        "button": "Load Spoofed Sender Sample",
    },
    "bec": {
        "title": "Business Email Scam",
        "desc": (
            "An example of a suspicious email attempting to pressure someone "
            "into an action such as a financial transfer."
        ),
        "button": "Load Business Scam Sample",
    },
}


FEATURES: list[dict[str, str]] = [
    {
        "icon_key": "threat",
        "title": "Email Threat Detection",
        "accent": "#16d6e8",
        "desc": "Identify suspicious patterns and possible phishing or fraud.",
    },
    {
        "icon_key": "auth",
        "title": "Sender Authentication",
        "accent": "#56e6bb",
        "desc": "Check SPF, DKIM and DMARC information to help verify the sender.",
    },
    {
        "icon_key": "route",
        "title": "Server Route Tracing",
        "accent": "#16d6e8",
        "desc": "See how an email travelled through different mail servers.",
    },
    {
        "icon_key": "geo",
        "title": "Geolocation Intelligence",
        "accent": "#ffb020",
        "desc": "Visualize the geographical locations of email server infrastructure.",
    },
    {
        "icon_key": "domain",
        "title": "Lookalike Domain Detection",
        "accent": "#56e6bb",
        "desc": "Identify suspicious domains attempting to imitate trusted organizations.",
    },
    {
        "icon_key": "evidence",
        "title": "Forensic Evidence",
        "accent": "#16d6e8",
        "desc": "Preserve important investigation details such as file hashes and email metadata.",
    },
]


ICON_SVGS: dict[str, str] = {
    "threat": (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 2 L20 5 V11 C20 16.5 16.5 20.5 12 22 '
        'C7.5 20.5 4 16.5 4 11 V5 Z"/>'
        '<line x1="12" y1="8" x2="12" y2="13"/>'
        '<circle cx="12" cy="16.4" r="0.9" fill="currentColor" stroke="none"/>'
        "</svg>"
    ),
    "auth": (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 2 L20 5 V11 C20 16.5 16.5 20.5 12 22 '
        'C7.5 20.5 4 16.5 4 11 V5 Z"/>'
        '<path d="M8.3 12.2 L10.8 14.7 L15.6 9.4"/>'
        "</svg>"
    ),
    "route": (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'
        '<line x1="5.5" y1="16.5" x2="11.3" y2="8.2"/>'
        '<line x1="12.7" y1="8.2" x2="18.5" y2="16.5"/>'
        '<circle cx="5" cy="17.3" r="2.1"/>'
        '<circle cx="12" cy="7" r="2.1"/>'
        '<circle cx="19" cy="17.3" r="2.1"/>'
        "</svg>"
    ),
    "geo": (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 21.5C12 21.5 5.3 14.3 5.3 9.2a6.7 6.7 0 0 1 '
        '13.4 0c0 5.1-6.7 12.3-6.7 12.3Z"/>'
        '<circle cx="12" cy="9.2" r="2.4"/>'
        "</svg>"
    ),
    "domain": (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="3" y="3" width="11" height="11" rx="2"/>'
        '<rect x="10" y="10" width="11" height="11" rx="2"/>'
        "</svg>"
    ),
    "evidence": (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M6 2.5H14.5L19 7V21.5H6Z"/>'
        '<path d="M14.5 2.5V7H19"/>'
        '<line x1="9" y1="12" x2="16" y2="12"/>'
        '<line x1="9" y1="15.3" x2="16" y2="15.3"/>'
        '<line x1="9" y1="18.6" x2="13" y2="18.6"/>'
        "</svg>"
    ),
}


HOW_IT_WORKS_STEPS: list[dict[str, str]] = [
    {
        "num": "1",
        "title": "Upload an Email",
        "desc": "Upload a suspicious .eml file.",
    },
    {
        "num": "2",
        "title": "AegisMail Investigates",
        "desc": (
            "We check authentication, sender details, server routes, suspicious "
            "domains, and other indicators."
        ),
    },
    {
        "num": "3",
        "title": "Understand the Results",
        "desc": (
            "See a clear risk assessment first, followed by deeper forensic "
            "information if needed."
        ),
    },
]


HERO_SVG = """
<svg viewBox="0 0 520 420" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <defs>
    <linearGradient id="mailGlow" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#46d7e8" stop-opacity=".95"/>
      <stop offset="100%" stop-color="#7ae7c2" stop-opacity=".45"/>
    </linearGradient>
    <filter id="softGlow"><feGaussianBlur stdDeviation="10"/></filter>
  </defs>
  <circle cx="260" cy="205" r="145" fill="#18cfe0" opacity=".05" filter="url(#softGlow)"/>
  <circle cx="260" cy="205" r="138" fill="none" stroke="#4dd9e8" stroke-opacity=".14" stroke-width="1"/>
  <circle cx="260" cy="205" r="102" fill="none" stroke="#7ae7c2" stroke-opacity=".11" stroke-width="1" stroke-dasharray="5 9"/>
  <path d="M152 150 Q260 62 368 150 L368 274 Q260 350 152 274 Z" fill="#0c2030" stroke="url(#mailGlow)" stroke-width="2"/>
  <path d="M158 158 L260 238 L362 158" fill="none" stroke="#56dbe8" stroke-opacity=".8" stroke-width="2"/>
  <path d="M154 269 L222 205" fill="none" stroke="#56dbe8" stroke-opacity=".38" stroke-width="1.5"/>
  <path d="M366 269 L298 205" fill="none" stroke="#56dbe8" stroke-opacity=".38" stroke-width="1.5"/>
  <circle cx="130" cy="112" r="7" fill="#56e6bb"/>
  <circle cx="391" cy="116" r="6" fill="#35c7dd"/>
  <circle cx="410" cy="300" r="7" fill="#ffb020"/>
  <circle cx="108" cy="298" r="5" fill="#35c7dd"/>
  <path d="M136 115 L194 150 M385 119 L327 151 M405 294 L358 266 M113 294 L160 267" stroke="#4dd9e8" stroke-opacity=".32" stroke-width="1.2"/>
  <circle cx="260" cy="205" r="10" fill="#56e6bb" opacity=".15"/>
  <circle cx="260" cy="205" r="4" fill="#9df5e0"/>
</svg>
"""


HERO_PREVIEW_HTML = html_block(f"""
<div class="hero-visual">
  <div class="hero-orbit hero-orbit-one"></div>
  <div class="hero-orbit hero-orbit-two"></div>
  <div class="hero-visual-bg">{HERO_SVG}</div>
  <div class="preview-card">
    <div class="preview-card-label"><span class="pulse-dot"></span>LIVE EMAIL CHECK</div>
    <div class="preview-email">
      <span class="preview-email-icon">✉</span>
      <div><span class="preview-muted">MESSAGE</span><strong>Payment update.eml</strong></div>
    </div>
    <div class="preview-status-grid">
      <div class="preview-status pass"><span>✓</span><small>SPF</small><b>Verified</b></div>
      <div class="preview-status pass"><span>✓</span><small>DKIM</small><b>Verified</b></div>
      <div class="preview-status fail"><span>!</span><small>DMARC</small><b>Review</b></div>
    </div>
    <div class="preview-score-row"><span class="preview-score-label">Risk assessment</span><span class="preview-score-value">72 / 100</span></div>
    <div class="preview-bar"><div class="preview-bar-fill" style="width:72%;"></div></div>
    <div class="preview-route"><span class="route-dot route-origin"></span><span class="route-line"></span><span class="route-dot route-relay"></span><span class="route-line"></span><span class="route-dot route-dest"></span></div>
    <div class="preview-route-labels"><span>Sender</span><span>Server route</span><span>You</span></div>
  </div>
</div>
""").strip()


def build_demo_result(profile: str = "bec") -> dict[str, Any]:
    """Return presentation-only data shaped for easy future backend replacement."""

    profiles = {
        "legitimate": {
            "risk_score": 12,
            "severity": "LOW RISK",
            "summary": (
                "This email passed standard authentication checks and shows no "
                "signs of spoofing or fraud."
            ),
            "signals": [
                {
                    "label": "Sender Verified",
                    "technical": "SPF Alignment",
                    "status": "pass",
                    "detail": (
                        "The sending server is authorized to send mail for this domain."
                    ),
                },
                {
                    "label": "Signature Valid",
                    "technical": "DKIM Signature",
                    "status": "pass",
                    "detail": (
                        "The email's digital signature is valid and has not been altered."
                    ),
                },
                {
                    "label": "Domain Policy Passed",
                    "technical": "DMARC Pass",
                    "status": "pass",
                    "detail": "The sender's domain passed alignment checks.",
                },
            ],
            "filename": "clean_invoice.eml",
            "auth": [
                (
                    "SPF",
                    "PASS",
                    "The sending server is authorized for this domain.",
                ),
                (
                    "DKIM",
                    "PASS",
                    "The message signature is valid.",
                ),
                (
                    "DMARC",
                    "PASS",
                    "The sender domain passed alignment checks.",
                ),
            ],
        },
        "spoofed": {
            "risk_score": 73,
            "severity": "HIGH RISK",
            "summary": (
                "This email failed sender verification checks and may not be "
                "from who it claims to be."
            ),
            "signals": [
                {
                    "label": "Sender Authentication Failed",
                    "technical": "DMARC Failure",
                    "status": "danger",
                    "detail": (
                        "Technical checks could not fully verify the sender's domain."
                    ),
                },
                {
                    "label": "Unauthorized Sending Server",
                    "technical": "SPF Misalignment",
                    "status": "danger",
                    "detail": (
                        "The email was sent from a server not authorized by the "
                        "sender's domain."
                    ),
                },
                {
                    "label": "Possible Identity Spoofing",
                    "technical": "Sender Spoofing",
                    "status": "danger",
                    "detail": (
                        "The sender's identity may have been disguised to look "
                        "like a trusted source."
                    ),
                },
            ],
            "filename": "paypal_spoofed.eml",
            "auth": [
                (
                    "SPF",
                    "FAIL",
                    "The sending server could not be verified as authorized.",
                ),
                (
                    "DKIM",
                    "FAIL",
                    "No valid signature was found on this message.",
                ),
                (
                    "DMARC",
                    "FAIL",
                    "The sender domain did not pass alignment checks.",
                ),
            ],
        },
        "bec": {
            "risk_score": 88,
            "severity": "CRITICAL RISK",
            "summary": (
                "This email shows multiple signs of possible spoofing or fraud, "
                "including a suspicious payment request."
            ),
            "signals": [
                {
                    "label": "Sender Authentication Failed",
                    "technical": "DMARC Failure",
                    "status": "danger",
                    "detail": (
                        "Technical checks could not fully verify the sender's domain."
                    ),
                },
                {
                    "label": "Possible Lookalike Domain",
                    "technical": "Lookalike Domain",
                    "status": "danger",
                    "detail": (
                        "The sender's domain closely resembles a trusted domain — "
                        "a common scam tactic."
                    ),
                },
                {
                    "label": "Suspicious Payment Request",
                    "technical": "Wire Transfer Intent",
                    "status": "danger",
                    "detail": (
                        "The email requests an urgent wire transfer or payment, "
                        "a common fraud technique."
                    ),
                },
            ],
            "filename": "ceo_giftcard.eml",
            "auth": [
                (
                    "SPF",
                    "FAIL",
                    "The return path does not match the claimed sending domain.",
                ),
                (
                    "DKIM",
                    "NEUTRAL",
                    "No signature was available to verify.",
                ),
                (
                    "DMARC",
                    "FAIL",
                    "The sender domain did not pass alignment checks.",
                ),
            ],
        },
    }

    selected = profiles.get(profile, profiles["bec"])

    return {
        **selected,
        "file_size": "24.8 KB",
        "sha256": (
            "a9d4e0c7b8a8f2c64f1edb6339007a60962ff9cbca88cb1aa7a67b87d4f108e3"
        ),
        "raw_headers": """Received: from outbound.mail-eu.example (198.51.100.42)
\tby mx.google.com with ESMTPS id a1b2c3; Tue, 02 Sep 2026 09:42:17 +0530
Authentication-Results: mx.google.com; spf=fail; dkim=neutral; dmarc=fail
From: Executive Office <ceo@acme-payrnents.com>
Reply-To: payments@secure-transfer-alert.net
Subject: Urgent: confidential wire approval required
Message-ID: <8e2f5d7a@example.invalid>""",
        "hops": [
            {
                "sequence": 1,
                "ip": "185.220.101.14",
                "host": "edge-relay-14",
                "isp": "Mullvad VPN",
                "country": "Sweden",
                "lat": 59.3293,
                "lon": 18.0686,
                "latency": "—",
            },
            {
                "sequence": 2,
                "ip": "198.51.100.42",
                "host": "outbound.mail-eu",
                "isp": "Example Transit",
                "country": "Germany",
                "lat": 50.1109,
                "lon": 8.6821,
                "latency": "142 ms",
            },
            {
                "sequence": 3,
                "ip": "142.250.150.27",
                "host": "mx.google.com",
                "isp": "Google LLC",
                "country": "India",
                "lat": 19.0760,
                "lon": 72.8777,
                "latency": "96 ms",
            },
        ],
        "urls": [
            {
                "url": "https://secure-transfer-alert.net/approve",
                "reputation": "Suspicious",
                "reason": "Newly observed domain",
            },
            {
                "url": "http://185.220.101.14/invoice",
                "reputation": "High risk",
                "reason": "Direct IP URL",
            },
        ],
        "keywords": [
            "urgent",
            "wire transfer",
            "confidential",
            "do not call",
            "bank details",
        ],
    }


def sample_exists(profile: str) -> bool:
    directory = SAMPLE_DIRECTORIES[profile]
    return directory.exists() and any(directory.glob("*.eml"))


def apply_uploaded_metadata(result: dict[str, Any], uploaded: Any) -> dict[str, Any]:
    if uploaded is None:
        return result

    raw = uploaded.getvalue()

    return {
        **result,
        "filename": uploaded.name,
        "file_size": f"{len(raw) / 1024:.1f} KB",
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def inject_theme() -> None:
    st.markdown(
        """
        <style>
        @import url("https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Sora:wght@500;600;700;800&display=swap");

        #MainMenu, footer, header {
            visibility: hidden;
        }

        .stApp {
            background:
                radial-gradient(circle at 10% 5%, rgba(28, 199, 222, .10), transparent 28%),
                radial-gradient(circle at 92% 12%, rgba(86, 230, 187, .055), transparent 30%),
                radial-gradient(circle at 52% 75%, rgba(22, 214, 232, .035), transparent 38%),
                linear-gradient(rgba(96, 177, 197, .035) 1px, transparent 1px),
                linear-gradient(90deg, rgba(96, 177, 197, .035) 1px, transparent 1px),
                #07111b;

            background-size:
                auto,
                auto,
                auto,
                56px 56px,
                56px 56px;

            color: #eaf6ff;
        }

        .block-container {
            max-width: 1240px;
            padding-top: 1.1rem;
            padding-bottom: 4.5rem;
        }

        [data-testid="stVerticalBlock"] > div { animation: content-reveal .5s ease both; }
        @keyframes content-reveal { from { opacity:.96; } to { opacity:1; } }


        html, body, [class*="css"] {
            font-family: "Manrope", Inter, "Segoe UI", sans-serif;
        }

        .stApp {
            animation: page-enter .55s cubic-bezier(.22,.8,.22,1);
        }

        @keyframes page-enter {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        h1, h2, h3, .hero-title, .section-title, .cta-panel-title, .feature-title, .step-title {
            font-family: "Sora", "Manrope", Inter, sans-serif;
        }

        .hero-title { letter-spacing: -.055em; font-weight: 800; }
        .section-title, .cta-panel-title { letter-spacing: -.045em; font-weight: 800; }
        .navbar-logo { font-family: "Sora", "Manrope", sans-serif; }

        /* BUTTONS */

        .stButton > button {
            min-height: 46px;
            border-radius: 11px;
            font-weight: 700;
            padding: .55rem 1.15rem;
            transition:
                transform .18s ease,
                box-shadow .18s ease,
                border-color .18s ease;
        }

        .stButton > button:hover {
            transform: translateY(-1px);
        }

        .stButton > button[kind="secondary"] {
            background: rgba(255,255,255,.025);
            border: 1px solid rgba(177,214,225,.18);
            color: #d8e7ee;
            box-shadow: none;
        }

        .stButton > button[kind="secondary"]:hover {
            background: rgba(53,204,227,.08);
            border-color: rgba(53,204,227,.42);
            color: #ffffff;
        }

        .stButton > button[kind="primary"] {
            background: linear-gradient(135deg, #177c91, #26abc0);
            border: 1px solid #42d9eb;
            color: #ffffff;
            box-shadow: 0 10px 28px rgba(22,214,232,.18);
        }

        .stButton > button[kind="primary"]:hover {
            background: linear-gradient(135deg, #1a91a8, #35cce3);
            border-color: #9af4ff;
            box-shadow: 0 14px 34px rgba(22,214,232,.30);
        }


        /* NAVIGATION TABS — deliberately flat, not button-in-button boxes */
        .st-key-nav_home button,
        .st-key-nav_analyze button {
            min-height: 36px !important;
            background: transparent !important;
            border: 0 !important;
            border-radius: 0 !important;
            box-shadow: none !important;
            color: #a9bdc9 !important;
            padding: .3rem .35rem !important;
            font-family: "Manrope", Inter, sans-serif !important;
            font-size: .92rem !important;
            font-weight: 600 !important;
        }

        .st-key-nav_home button:hover,
        .st-key-nav_analyze button:hover {
            background: transparent !important;
            color: #f5fbff !important;
            transform: none !important;
            box-shadow: none !important;
        }

        .st-key-nav_home,
        .st-key-nav_analyze {
            position: relative;
        }

        .st-key-nav_home::after {
            content: "";
            position: absolute;
            right: -.35rem;
            top: .7rem;
            width: 1px;
            height: 20px;
            background: rgba(159,211,225,.22);
        }


        .st-key-cta_analyze_bottom { margin-top: .65rem; }

        /* FILE UPLOADER */

        [data-testid="stFileUploader"] {
            background:
                linear-gradient(
                    145deg,
                    rgba(13,37,54,.82),
                    rgba(8,22,35,.86)
                );

            border: 1.5px dashed rgba(53,204,227,.52);
            border-radius: 18px;
            padding: 1.1rem;
        }

        [data-testid="stFileUploader"] section {
            background: transparent;
        }


        /* NAVBAR */

        .navbar-logo {
            display: flex;
            align-items: center;
            gap: .65rem;
            font-size: 1.32rem;
            font-weight: 800;
            color: #f5fbff;
            letter-spacing: -.01em;
            padding-top: .25rem;
        }

        .navbar-logo::before {
            content: "";
            width: 30px;
            height: 30px;
            border-radius: 10px;

            background:
                linear-gradient(
                    145deg,
                    rgba(53,204,227,.28),
                    rgba(86,230,187,.10)
                );

            border: 1px solid rgba(83,227,238,.32);
            box-shadow: 0 0 20px rgba(53,204,227,.10);
        }

        .navbar-divider {
            height: 1px;
            background:
                linear-gradient(
                    90deg,
                    rgba(22,214,232,.25),
                    rgba(22,214,232,.05) 55%,
                    transparent
                );

            margin: .45rem 0 1.35rem;
        }

        .nav-active-indicator {
            height: 2px;
            width: 34px;
            background: linear-gradient(90deg, #35c7dd, #72e6ee);
            border-radius: 999px;
            margin: -1.7rem auto 0;
            box-shadow: 0 0 12px rgba(53,199,221,.35);
            animation: nav-indicator-in .6s cubic-bezier(.22,.8,.22,1) both;
        }

        @keyframes nav-indicator-in {
            from { opacity: 0; transform: scaleX(.4); }
            to { opacity: 1; transform: scaleX(1); }
        }

        .section-divider {
            height: 1px;
            width: 100%;
            margin: 3.8rem 0 0;
            background: linear-gradient(90deg, transparent, rgba(53,204,227,.28) 18%, rgba(159,211,225,.10) 50%, rgba(53,204,227,.28) 82%, transparent);
            position: relative;
        }

        .section-divider::after {
            content: "";
            position: absolute;
            left: 50%;
            top: -2px;
            width: 5px;
            height: 5px;
            transform: translateX(-50%) rotate(45deg);
            background: #35c7dd;
            box-shadow: 0 0 12px rgba(53,199,221,.45);
        }


        /* HERO */

        .hero-copy {
            padding: 2.2rem 0 2.5rem;
            animation: hero-reveal .7s cubic-bezier(.22,.8,.22,1) both;
        }

        @keyframes hero-reveal {
            from { opacity: 0; transform: translateY(18px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .hero-eyebrow {
            display: inline-flex;
            align-items: center;
            gap: .45rem;
            font: 700 .7rem "DM Sans", sans-serif;
            letter-spacing: .18em;
            color: #8beefa;
            padding: .5rem .82rem;
            border: 1px solid rgba(83,227,238,.24);
            background: linear-gradient(90deg, rgba(53,204,227,.10), rgba(86,230,187,.04));
            border-radius: 999px;
            margin-bottom: 1.25rem;
            box-shadow: inset 0 1px 0 rgba(255,255,255,.04);
        }

        .hero-eyebrow::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: #56e6bb; box-shadow: 0 0 14px rgba(86,230,187,.8); }

        .hero-title {
            font-size: clamp(4.3rem, 8vw, 6.6rem);
            font-weight: 800;
            color: #f5fbff;
            margin: 0;
            letter-spacing: -.075em;
            line-height: .9;
            text-shadow: 0 12px 35px rgba(0,0,0,.28);
        }

        .hero-tagline {
            font-size: clamp(1.12rem, 1.8vw, 1.38rem);
            font-weight: 700;
            color: #91e7ef;
            max-width: 620px;
            margin: 1.85rem 0 .85rem;
            line-height: 1.4;
        }

        .hero-subtitle {
            font-size: 1.05rem;
            color: #b4c6d0;
            line-height: 1.75;
            max-width: 620px;
            margin: 0 0 1.55rem;
        }

        .hero-points { display:flex; flex-wrap:wrap; gap:.55rem; margin:0 0 1.7rem; }
        .hero-point { font-size:.82rem; color:#c0d1da; padding:.52rem .72rem; border-radius:10px; background:rgba(10,29,44,.72); border:1px solid rgba(128,190,207,.14); transition:transform .2s ease,border-color .2s ease,background .2s ease; }
        .hero-point:hover { transform:translateY(-2px); border-color:rgba(83,227,238,.28); background:rgba(20,51,68,.7); }
        .hero-point b { color:#73eefa; margin-right:.28rem; }

        /* HERO PREVIEW */

        .hero-visual { position:relative; min-height:470px; display:flex; align-items:center; justify-content:center; animation:hero-reveal .8s .08s cubic-bezier(.22,.8,.22,1) both; }
        .hero-visual-bg { position:absolute; inset:0; display:flex; align-items:center; justify-content:center; opacity:.95; pointer-events:none; }
        .hero-visual-bg svg { width:100%; max-width:520px; filter:drop-shadow(0 0 28px rgba(22,214,232,.12)); }
        .hero-orbit { position:absolute; border:1px solid rgba(83,227,238,.09); border-radius:50%; pointer-events:none; }
        .hero-orbit-one { width:330px; height:330px; animation:orbit-breathe 6s ease-in-out infinite; }
        .hero-orbit-two { width:410px; height:410px; border-style:dashed; opacity:.55; animation:orbit-breathe 8s ease-in-out infinite reverse; }
        @keyframes orbit-breathe { 50% { transform:scale(1.04); opacity:.45; } }
        .preview-card { position:relative; z-index:2; width:100%; max-width:380px; box-sizing:border-box; padding:1.45rem; border-radius:22px; background:linear-gradient(150deg, rgba(20,51,70,.94), rgba(7,19,31,.96)); border:1px solid rgba(115,238,250,.22); box-shadow:0 28px 80px rgba(0,0,0,.34), 0 0 45px rgba(22,214,232,.08); backdrop-filter:blur(12px); overflow:hidden; }
        .preview-card::after { content:""; position:absolute; inset:0; background:linear-gradient(135deg, rgba(255,255,255,.035), transparent 42%); pointer-events:none; }
        .preview-card-label { position:relative; z-index:1; display:flex; align-items:center; gap:.5rem; font:700 .68rem "DM Sans",sans-serif; letter-spacing:.16em; color:#9deef6; margin-bottom:1.05rem; }
        .pulse-dot { width:7px; height:7px; border-radius:50%; background:#56e6bb; box-shadow:0 0 0 0 rgba(86,230,187,.45); animation:pulse 2.2s infinite; }
        @keyframes pulse { 70% { box-shadow:0 0 0 8px rgba(86,230,187,0); } 100% { box-shadow:0 0 0 0 rgba(86,230,187,0); } }
        .preview-email { position:relative; z-index:1; display:flex; align-items:center; gap:.7rem; padding:.78rem .85rem; margin-bottom:1rem; border-radius:13px; background:rgba(255,255,255,.035); border:1px solid rgba(255,255,255,.055); }
        .preview-email-icon { width:32px; height:32px; display:grid; place-items:center; border-radius:10px; color:#8ceff7; background:rgba(53,204,227,.1); }
        .preview-email div { display:flex; flex-direction:column; gap:.12rem; min-width:0; }
        .preview-email strong { color:#edf8fc; font-size:.88rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .preview-muted { color:#7894a1; font-size:.62rem; letter-spacing:.12em; }
        .preview-status-grid { position:relative; z-index:1; display:grid; grid-template-columns:repeat(3,1fr); gap:.45rem; margin-bottom:1.1rem; }
        .preview-status { padding:.62rem .35rem; border-radius:11px; display:flex; flex-direction:column; gap:.18rem; text-align:center; border:1px solid rgba(255,255,255,.05); }
        .preview-status span { font-size:.82rem; font-weight:800; }
        .preview-status small { font-size:.58rem; letter-spacing:.08em; color:#8fa5b0; }
        .preview-status b { font-size:.67rem; }
        .preview-status.pass { background:rgba(86,230,187,.08); color:#65e5b8; }
        .preview-status.fail { background:rgba(255,83,100,.08); color:#ff7f8d; }
        .preview-score-row { position:relative; z-index:1; display:flex; justify-content:space-between; align-items:center; margin-bottom:.55rem; }
        .preview-score-label { color:#b2c4ce; font-size:.85rem; }
        .preview-score-value { color:#ffc363; font-size:1rem; font-weight:800; }
        .preview-bar { position:relative; z-index:1; height:8px; border-radius:99px; overflow:hidden; background:#263847; margin-bottom:1.25rem; }
        .preview-bar-fill { height:100%; border-radius:inherit; background:linear-gradient(90deg,#f6b84c,#ff6372); box-shadow:0 0 18px rgba(255,99,114,.22); }
        .preview-route { position:relative; z-index:1; display:flex; align-items:center; gap:.35rem; }
        .route-dot { width:10px; height:10px; border-radius:50%; flex:none; }
        .route-origin { background:#56e6bb; box-shadow:0 0 12px rgba(86,230,187,.5); }.route-relay { background:#5ed9ee; }.route-dest { background:#ffb020; }
        .route-line { height:2px; flex:1; background:linear-gradient(90deg,rgba(86,230,187,.65),rgba(94,217,238,.55)); }
        .preview-route-labels { position:relative; z-index:1; display:flex; justify-content:space-between; color:#809aa6; font-size:.62rem; text-transform:uppercase; letter-spacing:.11em; margin-top:.65rem; }

        .chip {
            display: inline-block;
            margin: .2rem .35rem .2rem 0;
            padding: .4rem .7rem;
            border-radius: 8px;
            font-size: .82rem;
            font-weight: 700;
        }

        .chip-pass {
            background: rgba(86,230,187,.13);
            color: #66eabd;
        }

        .chip-fail {
            background: rgba(255,92,108,.13);
            color: #ff7180;
        }

        .preview-score-row {
            position: relative;
            z-index: 1;

            display: flex;
            justify-content: space-between;
            align-items: baseline;

            margin-bottom: .55rem;
        }

        .preview-score-label {
            color: #9eb5c4;
            font-size: .88rem;
        }

        .preview-score-value {
            color: #ffbe47;
            font-weight: 850;
            font-size: 1.08rem;
        }

        .preview-bar {
            position: relative;
            z-index: 1;

            height: 8px;
            border-radius: 99px;
            background: rgba(255,255,255,.08);
            overflow: hidden;

            margin-bottom: 1.6rem;
        }

        .preview-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #ffb020, #ff5c6c);
            border-radius: 99px;
        }

        .preview-route {
            position: relative;
            z-index: 1;

            display: flex;
            align-items: center;

            margin-bottom: .55rem;
        }

        .route-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }

        .route-origin { background: #56e6bb; }
        .route-relay { background: #35cce3; }
        .route-dest { background: #ffb020; }

        .route-line {
            flex: 1;
            height: 2px;

            background:
                linear-gradient(
                    90deg,
                    rgba(86,230,187,.65),
                    rgba(53,204,227,.45),
                    rgba(255,176,32,.65)
                );

            margin: 0 .35rem;
        }

        .preview-route-labels {
            position: relative;
            z-index: 1;

            display: flex;
            justify-content: space-between;

            color: #7695a5;
            font-size: .67rem;
            letter-spacing: .08em;
            text-transform: uppercase;
        }


        /* SECTION HEADERS */

        .section-block {
            margin: 4.3rem 0 1.45rem;
            max-width: 780px;
        }

        .section-eyebrow {
            font: 700 .71rem monospace;
            letter-spacing: .17em;
            color: #66dbe9;
            margin-bottom: .55rem;
        }

        .section-title {
            font-size: clamp(1.7rem, 3vw, 2.2rem);
            font-weight: 800;
            color: #f4fbff;
            margin: 0 0 .6rem;
            letter-spacing: -.025em;
            line-height: 1.15;
        }

        .section-desc {
            color: #a9bdc9;
            font-size: 1rem;
            max-width: 760px;
            line-height: 1.65;
            margin: 0;
        }


        /* FEATURE CARDS */

        .feature-card {
            height: 100%;
            min-height: 210px;
            box-sizing: border-box;

            padding: 1.45rem;
            border-radius: 17px;

            background:
                linear-gradient(
                    150deg,
                    rgba(15,40,59,.86),
                    rgba(8,21,33,.90)
                );

            border: 1px solid rgba(159,211,225,.09);

            box-shadow:
                0 16px 34px rgba(0,0,0,.18);

            margin-bottom: 1.1rem;

            transition:
                transform .18s ease,
                border-color .18s ease,
                box-shadow .18s ease;
        }

        .feature-card:hover {
            transform: translateY(-4px);
            border-color: rgba(83,227,238,.28);

            box-shadow:
                0 22px 44px rgba(0,0,0,.26);
        }

        .feature-index {
            font: 700 .65rem monospace;
            color: #4f7180;
            letter-spacing: .12em;
            margin-bottom: .65rem;
        }

        .feature-icon-badge {
            width: 46px;
            height: 46px;
            border-radius: 13px;

            display: flex;
            align-items: center;
            justify-content: center;

            margin-bottom: 1.1rem;
        }

        .feature-icon-badge svg {
            width: 23px;
            height: 23px;
        }

        .feature-title {
            font-size: 1.02rem;
            font-weight: 750;
            color: #eff8fc;
            margin-bottom: .5rem;
        }

        .feature-desc {
            color: #a9bdc9;
            font-size: .9rem;
            line-height: 1.6;
            margin: 0;
        }


        /* HOW IT WORKS */

        .journey-wrap { display:none; }

        .step-card {
            min-height: 190px;
            box-sizing: border-box;
            text-align: left;
            padding: 1.35rem;
            border-radius: 18px;
            background: linear-gradient(150deg, rgba(15,40,59,.72), rgba(8,21,33,.76));
            border: 1px solid rgba(159,211,225,.09);
            box-shadow: 0 16px 34px rgba(0,0,0,.14);
            transition: transform .22s ease, border-color .22s ease, box-shadow .22s ease;
        }
        .step-card:hover { transform: translateY(-4px); border-color: rgba(83,227,238,.26); box-shadow: 0 22px 44px rgba(0,0,0,.22); }

        .step-number {
            width: 40px;
            height: 40px;

            border-radius: 12px;
            border: 2px solid #35c7dd;

            color: #83f4ff;
            font-weight: 800;
            font-size: 1rem;

            display: flex;
            align-items: center;
            justify-content: center;

            margin: 0 0 .9rem;

            background: rgba(53,199,221,.08);
        }

        .step-title {
            font-weight: 750;
            color: #eff8fc;
            margin-bottom: .5rem;
            font-size: 1rem;
        }

        .step-desc {
            color: #a9bdc9;
            font-size: .9rem;
            line-height: 1.6;
            max-width: none;
            margin: 0;
        }

        .step-arrow {
            display: none;
        }


        /* CTA */

        .cta-shell { display:none; }

        .cta-panel {
            max-width: 900px;
            margin: 4.5rem auto 1.1rem;
            text-align: center !important;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 2.8rem 1.5rem 2.2rem;
            border-radius: 24px;
            background: radial-gradient(circle at 50% 0%, rgba(53,204,227,.13), transparent 56%), linear-gradient(150deg, rgba(14,39,55,.82), rgba(7,19,31,.82));
            border: 1px solid rgba(83,227,238,.15);
            box-shadow: 0 22px 55px rgba(0,0,0,.18);
        }

        .cta-panel-title {
            width: 100%;
            text-align: center !important;
            font-size: clamp(1.7rem, 3vw, 2.2rem);
            font-weight: 700;
            color: #f4fbff;
            margin: 0 0 .7rem;
            line-height: 1.2;
        }

        .cta-panel-desc {
            width: 100%;
            text-align: center !important;
            color: #a9c0ce;
            font-size: 1rem;
            max-width: 620px;
            margin: 0 auto 1.55rem;
            line-height: 1.65;
        }


        /* UPLOAD */

        .upload-intro {
            padding: 1.7rem;
            border-radius: 18px;

            background:
                linear-gradient(
                    145deg,
                    rgba(13,39,57,.85),
                    rgba(8,20,32,.86)
                );

            border: 1px solid rgba(83,227,238,.12);
            margin-bottom: 1.2rem;
        }

        .upload-kicker {
            font: 700 .7rem monospace;
            letter-spacing: .16em;
            color: #69e4f0;
            margin-bottom: .45rem;
        }

        .upload-title {
            font-size: 1.55rem;
            font-weight: 800;
            color: #f2f8fc;
            margin-bottom: .45rem;
        }

        .upload-copy {
            color: #a9bdc9;
            line-height: 1.6;
            margin: 0;
        }


        /* DEMO CARDS */

        .scenario-card {
            height: 100%;
            min-height: 165px;
            box-sizing: border-box;

            padding: 1.35rem;
            border-radius: 16px;

            background: rgba(13,33,50,.68);
            border: 1px solid rgba(255,255,255,.07);

            margin-bottom: .75rem;
        }

        .scenario-kicker {
            font: 700 .66rem monospace;
            letter-spacing: .13em;
            color: #6694a6;
            margin-bottom: .6rem;
        }

        .scenario-title {
            font-weight: 750;
            color: #eef8ff;
            font-size: 1rem;
            margin-bottom: .45rem;
        }

        .scenario-desc {
            color: #a8c0cf;
            font-size: .9rem;
            line-height: 1.55;
            margin: 0;
        }

        .demo-note {
            color: #8fa8b5;
            font-size: .88rem;
            line-height: 1.55;
            margin-top: -.2rem;
        }


        /* EMPTY STATE */

        .empty-state {
            padding: 2.2rem;
            border-radius: 16px;

            border: 1px dashed rgba(126,183,205,.28);
            background: rgba(13,32,49,.35);

            color: #9fb4bf;
            text-align: center;
            font-size: .98rem;
        }


        /* GENERIC PANEL */

        .panel {
            height: 100%;
            box-sizing: border-box;

            padding: 1.7rem 1.85rem;
            border: 1px solid rgba(255,255,255,.07);
            border-radius: 18px;

            background:
                linear-gradient(
                    150deg,
                    rgba(14,37,56,.92),
                    rgba(7,17,29,.94)
                );

            box-shadow: 0 18px 40px rgba(0,0,0,.28);
        }

        .panel-title {
            font: 700 .76rem monospace;
            letter-spacing: .14em;
            color: #72eefa;
            margin-bottom: 1.05rem;
        }


        /* RISK ASSESSMENT */

        .verdict-panel {
            display: flex;
            flex-direction: column;
            justify-content: center;
            min-height: 230px;
        }

        .gauge-wrap {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: .3rem 0;
        }

        .gauge {
            width: 176px;
            height: 176px;
            border-radius: 50%;

            display: flex;
            align-items: center;
            justify-content: center;
        }

        .gauge-inner {
            width: 138px;
            height: 138px;
            border-radius: 50%;

            background:
                linear-gradient(
                    150deg,
                    #102a3f,
                    #081420
                );

            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        .gauge-value {
            font-size: 2.65rem;
            font-weight: 800;
            line-height: 1;
        }

        .gauge-max {
            font-size: .82rem;
            color: #9cb5c7;
            margin-top: .2rem;
            letter-spacing: .04em;
        }

        .verdict-headline {
            font-size: 1.65rem;
            font-weight: 800;
            margin-bottom: .8rem;
            letter-spacing: -.01em;
        }

        .verdict-summary {
            color: #c3d6e2;
            font-size: 1.02rem;
            line-height: 1.65;
            margin: 0;
        }


        /* SIGNAL CARDS */

        .signal-card {
            height: 100%;
            box-sizing: border-box;

            padding: 1.3rem 1.4rem;
            border-radius: 16px;

            background: rgba(13,32,49,.6);
            border: 1px solid rgba(255,255,255,.06);
        }

        .signal-card.status-pass {
            border-left: 3px solid #56e6bb;
        }

        .signal-card.status-warning {
            border-left: 3px solid #ffb020;
        }

        .signal-card.status-danger {
            border-left: 3px solid #ff5364;
        }

        .signal-label {
            font-size: 1.02rem;
            font-weight: 700;
            color: #eef8ff;
            margin-bottom: .5rem;
        }

        .signal-detail {
            color: #a8c0cf;
            font-size: .92rem;
            line-height: 1.55;
            margin: 0 0 .85rem;
        }

        .signal-tech {
            display: inline-block;

            font: 700 .68rem monospace;
            letter-spacing: .06em;

            color: #7fa6b8;
            background: rgba(255,255,255,.05);

            border-radius: 6px;
            padding: .22rem .5rem;
        }


        /* RECOMMENDED ACTION */

        .action-box {
            padding: 1.5rem 1.7rem;
            border-radius: 16px;

            background: rgba(13,32,49,.55);
            border: 1px solid rgba(255,255,255,.06);
        }

        .action-item {
            display: flex;
            gap: .7rem;
            align-items: flex-start;

            padding: .5rem 0;

            color: #d7e6ef;
            font-size: .98rem;
            line-height: 1.5;
        }

        .action-item b {
            flex-shrink: 0;
            margin-top: .05rem;
        }


        /* CHAIN OF CUSTODY */

        .custody-row {
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            gap: 1rem;

            padding: .6rem 0;

            border-bottom: 1px solid rgba(126,183,205,.10);

            color: #a8c3d1;
            font-size: .92rem;
        }

        .custody-row:last-child {
            border-bottom: none;
        }

        .custody-row b {
            color: #ecf8ff;
            font-weight: 600;
            text-align: right;
            overflow-wrap: anywhere;
            font-size: .96rem;
        }


        /* AUTH CARDS */

        .auth-card {
            height: 100%;
            box-sizing: border-box;

            padding: 1.25rem 1.35rem;
            border-radius: 14px;

            background: rgba(13,32,49,.6);
            border: 1px solid rgba(255,255,255,.06);
        }

        .auth-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: .7rem;
        }

        .auth-protocol {
            font: 700 .82rem monospace;
            letter-spacing: .08em;
            color: #eaf6ff;
        }

        .auth-status {
            font: 800 .7rem monospace;
            letter-spacing: .06em;
            padding: .3rem .6rem;
            border-radius: 99px;
        }

        .auth-finding {
            color: #a8c0cf;
            font-size: .9rem;
            line-height: 1.5;
            margin: 0;
        }


        .stTabs [data-baseweb="tab"] {
            font-weight: 700;
            font-size: .95rem;
        }


        @media (max-width: 700px) {
            .block-container {
                padding-left: 1rem;
                padding-right: 1rem;
            }

            .section-block {
                margin-top: 3.4rem;
            }

            .hero-visual {
                min-height: 330px;
            }

            .cta-shell {
                padding: 2.3rem 1rem;
            }
        }


        @media (max-width: 800px) {
            .hero-title { font-size: clamp(3.4rem, 16vw, 5rem); }
            .cta-panel { padding: 2.25rem 1.1rem 1.9rem; }
            .section-divider { margin-top: 3rem; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_signal_card(signal: dict[str, str]) -> str:
    icon = "✓" if signal["status"] == "pass" else "⚠"

    return (
        f'<div class="signal-card status-{signal["status"]}">'
        f'<div class="signal-label">{icon} {signal["label"]}</div>'
        f'<p class="signal-detail">{signal["detail"]}</p>'
        f'<span class="signal-tech">{signal["technical"]}</span>'
        "</div>"
    )


def render_auth_card(protocol: str, status: str, finding: str) -> str:
    status_upper = status.upper()

    if status_upper == "PASS":
        color = "#56e6bb"
        bg = "rgba(86,230,187,.16)"
    elif status_upper == "FAIL":
        color = "#ff5364"
        bg = "rgba(255,83,100,.16)"
    else:
        color = "#ffb020"
        bg = "rgba(255,176,32,.16)"

    return (
        '<div class="auth-card">'
        '<div class="auth-top">'
        f'<span class="auth-protocol">{protocol}</span>'
        f'<span class="auth-status" style="color:{color};background:{bg}">'
        f"{status_upper}</span>"
        "</div>"
        f'<p class="auth-finding">{finding}</p>'
        "</div>"
    )


def render_feature_card(
    feature: dict[str, str],
    index: str | None = None,
) -> str:
    accent = feature["accent"]
    svg = ICON_SVGS[feature["icon_key"]]

    index_html = (
        f'<div class="feature-index">{index}</div>'
        if index
        else ""
    )

    return (
        '<div class="feature-card">'
        f"{index_html}"
        f'<div class="feature-icon-badge" '
        f'style="color:{accent}; background:{accent}1A; '
        f'border:1px solid {accent}40;">'
        f"{svg}</div>"
        f'<div class="feature-title">{feature["title"]}</div>'
        f'<p class="feature-desc">{feature["desc"]}</p>'
        "</div>"
    )


def render_scenario_card(meta: dict[str, str]) -> str:
    return (
        '<div class="scenario-card">'
        '<div class="scenario-kicker">DEMO SCENARIO</div>'
        f'<div class="scenario-title">{meta["title"]}</div>'
        f'<p class="scenario-desc">{meta["desc"]}</p>'
        "</div>"
    )


def render_step_card(step: dict[str, str]) -> str:
    return (
        '<div class="step-card">'
        f'<div class="step-number">{step["num"]}</div>'
        f'<div class="step-title">{step["title"]}</div>'
        f'<p class="step-desc">{step["desc"]}</p>'
        "</div>"
    )


def section_header(
    eyebrow: str,
    title: str,
    desc: str,
) -> None:
    st.markdown(
        f'<div class="section-block">'
        f'<div class="section-eyebrow">{eyebrow}</div>'
        f'<div class="section-title">{title}</div>'
        f'<p class="section-desc">{desc}</p>'
        "</div>",
        unsafe_allow_html=True,
    )


def render_navbar() -> None:
    logo_col, spacer_col, home_col, analyze_col = st.columns(
        [2.4, 5.1, .82, 1.35]
    )

    with logo_col:
        st.markdown(
            '<div class="navbar-logo">AegisMail</div>',
            unsafe_allow_html=True,
        )

    with home_col:
        if st.button(
            "Home",
            key="nav_home",
            use_container_width=True,
            type="secondary",
        ):
            st.session_state.page = "home"
            st.session_state.analyzed = False
            st.rerun()

        if st.session_state.page == "home":
            st.markdown(
                '<div class="nav-active-indicator"></div>',
                unsafe_allow_html=True,
            )

    with analyze_col:
        if st.button(
            "Upload & Analyze",
            key="nav_analyze",
            use_container_width=True,
            type="secondary",
        ):
            st.session_state.page = "analyze"
            st.rerun()

        if st.session_state.page == "analyze":
            st.markdown(
                '<div class="nav-active-indicator"></div>',
                unsafe_allow_html=True,
            )

    st.markdown(
        '<div class="navbar-divider"></div>',
        unsafe_allow_html=True,
    )


def render_home() -> None:
    hero_text_col, hero_visual_col = st.columns(
        [1.15, .95],
        gap="large",
    )

    with hero_text_col:
        st.markdown(
            html_block("""
            <div class="hero-copy">

                <div class="hero-eyebrow">
                    AI-POWERED EMAIL FORENSICS
                </div>

                <div class="hero-title">
                    AegisMail
                </div>

                <p class="hero-tagline">
                    AI-Powered Email Threat Detection &amp;
                    Forensic Intelligence
                </p>

                <p class="hero-subtitle">
                    Upload a suspicious email and AegisMail will explain what
                    looks suspicious, whether the sender can be verified,
                    where the message travelled, and what evidence was found —
                    no cybersecurity background required.
                </p>

                <div class="hero-points">
                    <span class="hero-point">
                        <b>01</b> Threat check
                    </span>

                    <span class="hero-point">
                        <b>02</b> Sender verification
                    </span>

                    <span class="hero-point">
                        <b>03</b> Route tracing
                    </span>

                    <span class="hero-point">
                        <b>04</b> Evidence review
                    </span>
                </div>

            </div>
            """).strip(),
            unsafe_allow_html=True,
        )

        if st.button(
            "Analyze an Email",
            type="primary",
            key="cta_analyze_hero",
        ):
            st.session_state.page = "analyze"
            st.rerun()

    with hero_visual_col:
        st.markdown(
            HERO_PREVIEW_HTML,
            unsafe_allow_html=True,
        )


    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    section_header(
        "WHAT AEGISMAIL DOES",
        "Understand Every Email You Investigate",
        (
            "AegisMail starts with a clear verdict, then gives you the evidence "
            "behind it when you need more detail."
        ),
    )

    for row_start in range(0, 6, 3):
        feature_cols = st.columns(3, gap="large")

        for col, feature, index in zip(
            feature_cols,
            FEATURES[row_start:row_start + 3],
            range(row_start + 1, row_start + 4),
        ):
            with col:
                st.markdown(
                    render_feature_card(
                        feature,
                        index=f"0{index}",
                    ),
                    unsafe_allow_html=True,
                )


    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    section_header(
        "HOW IT WORKS",
        "From Upload to Understanding, in Three Simple Steps",
        (
            "The process is designed to be easy to follow, even if email "
            "security terminology is unfamiliar."
        ),
    )

    step_cols = st.columns(3, gap="large")

    for col, step in zip(step_cols, HOW_IT_WORKS_STEPS):
        with col:
            st.markdown(
                render_step_card(step),
                unsafe_allow_html=True,
            )

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    st.markdown(
        html_block("""
        <div class="cta-panel">

            <div class="cta-panel-title">
                Ready to investigate a suspicious email?
            </div>

            <p class="cta-panel-desc">
                Upload a .eml file or try a demo scenario. AegisMail will
                guide you through what it finds and explain what the results
                mean.
            </p>

        </div>
        """).strip(),
        unsafe_allow_html=True,
    )

    _, cta_col, _ = st.columns([1, 1.25, 1])

    with cta_col:
        if st.button(
            "Analyze an Email",
            type="primary",
            use_container_width=True,
            key="cta_analyze_bottom",
        ):
            st.session_state.page = "analyze"
            st.rerun()



def render_results(result: dict[str, Any]) -> None:
    style = SEVERITY_STYLES[result["severity"]]
    accent = style["accent"]
    is_safe = result["severity"] == "LOW RISK"

    st.markdown(
        (
            '<div class="section-eyebrow" '
            'style="margin-top:2.6rem;">'
            "ANALYSIS RESULTS"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


    section_header(
        "RESULT",
        "Email Risk Assessment",
        (
            "A plain-language summary of what was found, followed by the "
            "technical details behind it."
        ),
    )

    gauge_col, verdict_col = st.columns(
        [1, 1.7],
        gap="large",
    )

    with gauge_col:
        st.markdown(
            html_block(f'''
            <div class="panel verdict-panel">

                <div class="panel-title">
                    RISK SCORE
                </div>

                <div class="gauge-wrap">

                    <div class="gauge"
                        style="
                        background: conic-gradient(
                            {accent}
                            {result["risk_score"] * 3.6}deg,
                            rgba(255,255,255,.10)
                            0deg
                        );
                        ">

                        <div class="gauge-inner">

                            <div class="gauge-value"
                                style="color:{accent}">
                                {result["risk_score"]}
                            </div>

                            <div class="gauge-max">
                                / 100
                            </div>

                        </div>
                    </div>

                </div>
            </div>
            ''').strip(),
            unsafe_allow_html=True,
        )

    with verdict_col:
        st.markdown(
            html_block(f'''
            <div class="panel verdict-panel"
                style="border-left:4px solid {accent};">

                <div class="panel-title">
                    VERDICT
                </div>

                <div class="verdict-headline"
                    style="color:{accent}">
                    {style["headline"]}
                </div>

                <p class="verdict-summary">
                    {result["summary"]}
                </p>

            </div>
            ''').strip(),
            unsafe_allow_html=True,
        )


    section_header(
        "EXPLAINABILITY",
        "Why This Email Looks Safe"
        if is_safe
        else "Why Was It Flagged?",
        (
            "These checks explain the verdict above using plain language, "
            "with the underlying technical signal shown for reference."
            if is_safe
            else
            "These are the specific signals that raised concern about this email."
        ),
    )

    signal_cols = st.columns(
        len(result["signals"]),
        gap="medium",
    )

    for col, signal in zip(signal_cols, result["signals"]):
        with col:
            st.markdown(
                render_signal_card(signal),
                unsafe_allow_html=True,
            )


    section_header(
        "NEXT STEPS",
        "Recommended Action",
        (
            "No immediate action is required, but here are a few good habits "
            "to keep in mind."
            if is_safe
            else
            "Follow these steps to stay safe and help preserve evidence for "
            "investigation."
        ),
    )

    action_items = RECOMMENDED_ACTIONS[result["severity"]]
    bullet = "✓" if is_safe else "•"

    items_html = "".join(
        (
            f'<div class="action-item">'
            f'<b style="color:{accent}">{bullet}</b>'
            f"<span>{item}</span>"
            f"</div>"
        )
        for item in action_items
    )

    st.markdown(
        (
            f'<div class="action-box" '
            f'style="border-left:4px solid {accent};">'
            f"{items_html}"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


    section_header(
        "EVIDENCE",
        "Chain of Custody",
        (
            "Original file metadata, preserved for forensic verification "
            "and reporting."
        ),
    )

    st.markdown(
        html_block(f'''
        <div class="panel">

            <div class="panel-title">
                EVIDENCE RECORD
            </div>

            <div class="custody-row">
                <span>Original filename</span>
                <b>{result["filename"]}</b>
            </div>

            <div class="custody-row">
                <span>File size</span>
                <b>{result["file_size"]}</b>
            </div>

            <div class="custody-row">
                <span>SHA-256 hash</span>
                <b>{result["sha256"][:20]}…</b>
            </div>

        </div>
        ''').strip(),
        unsafe_allow_html=True,
    )

    with st.expander("View & copy full SHA-256 hash"):
        st.code(
            result["sha256"],
            language=None,
        )


    section_header(
        "GEOLOCATION",
        "Email Server Route",
        (
            "See the route this email travelled through different mail servers "
            "before reaching its destination: origin → intermediate relays → "
            "final destination."
        ),
    )

    render_hop_path_map(MOCK_HOP_COORDINATES)

    st.caption(
        (
            "Mock GeoIP relay path — replace `MOCK_HOP_COORDINATES` with "
            "Member 3's ordered coordinate list when available."
        )
    )


    section_header(
        "TECHNICAL DETAILS",
        "Detailed Forensics",
        (
            "Full technical findings for cybersecurity analysts and forensic "
            "investigators."
        ),
    )

    header_tab, hop_tab, content_tab = st.tabs(
        [
            "Header Inspector",
            "Relay Hop Timeline",
            "Content & URLs",
        ]
    )

    with header_tab:
        st.markdown(
            (
                '<p style="color:#c3d6e2; font-weight:600; '
                'margin-bottom:1rem;">'
                "Authentication verification"
                "</p>"
            ),
            unsafe_allow_html=True,
        )

        auth_cols = st.columns(
            len(result["auth"]),
            gap="medium",
        )

        for col, (protocol, status, finding) in zip(
            auth_cols,
            result["auth"],
        ):
            with col:
                st.markdown(
                    render_auth_card(
                        protocol,
                        status,
                        finding,
                    ),
                    unsafe_allow_html=True,
                )

        st.markdown(
            "<div style='height:1.2rem;'></div>",
            unsafe_allow_html=True,
        )

        with st.expander("View raw email headers"):
            st.code(
                result["raw_headers"],
                language="text",
            )


    with hop_tab:
        st.markdown(
            (
                '<p style="color:#c3d6e2; font-weight:600; '
                'margin-bottom:1rem;">'
                "Reverse-hop reconstruction timeline"
                "</p>"
            ),
            unsafe_allow_html=True,
        )

        st.dataframe(
            [
                {
                    "Hop": f'{hop["sequence"]:02d}',
                    "IP": hop["ip"],
                    "Host": hop["host"],
                    "ISP": hop["isp"],
                    "Country": hop["country"],
                    "Latency": hop["latency"],
                }
                for hop in result["hops"]
            ],
            use_container_width=True,
            hide_index=True,
        )


    with content_tab:
        left, right = st.columns(
            [1.7, 1],
            gap="large",
        )

        with left:
            st.markdown(
                (
                    '<p style="color:#c3d6e2; font-weight:600; '
                    'margin-bottom:1rem;">'
                    "Extracted links & reputation"
                    "</p>"
                ),
                unsafe_allow_html=True,
            )

            st.dataframe(
                [
                    {
                        "URL": item["url"],
                        "Reputation": item["reputation"],
                        "Signal": item["reason"],
                    }
                    for item in result["urls"]
                ],
                use_container_width=True,
                hide_index=True,
            )

        with right:
            st.markdown(
                (
                    '<p style="color:#c3d6e2; font-weight:600; '
                    'margin-bottom:1rem;">'
                    "Extracted keywords"
                    "</p>"
                ),
                unsafe_allow_html=True,
            )

            keyword_chips = "".join(
                (
                    '<span class="chip" '
                    'style="background:rgba(114,238,250,.12); '
                    'color:#83f4ff;">'
                    f"{keyword}"
                    "</span>"
                )
                for keyword in result["keywords"]
            )

            st.markdown(
                keyword_chips,
                unsafe_allow_html=True,
            )


    st.markdown(
        "<div style='margin-top:3rem;'></div>",
        unsafe_allow_html=True,
    )

    st.divider()

    export_col, note_col = st.columns(
        [1, 2],
        gap="large",
    )

    with export_col:
        if st.button(
            "Export Forensic Report",
            type="primary",
            use_container_width=True,
        ):
            st.info(
                (
                    "Report export will connect here when the reporting "
                    "module is available."
                )
            )

    with note_col:
        st.caption(
            (
                "PDF generation is intentionally not implemented in the frontend; "
                "it remains owned by the reporting module."
            )
        )


def render_upload_analyze() -> None:
    st.markdown(
        html_block("""
        <div class="upload-intro">

            <div class="upload-kicker">
                UPLOAD &amp; ANALYZE
            </div>

            <div class="upload-title">
                Start an email investigation
            </div>

            <p class="upload-copy">
                Upload a suspicious .eml file and AegisMail will turn technical
                checks into a clear investigation summary. You can also explore
                a pre-loaded example first.
            </p>

        </div>
        """).strip(),
        unsafe_allow_html=True,
    )


    uploaded = st.file_uploader(
        "Choose an email file",
        type=["eml"],
        help=(
            "Only standard .eml email files are supported. The UI runs on mock "
            "analysis data until the backend pipeline is connected."
        ),
    )

    if uploaded is not None:
        st.session_state.analyzed = True
        st.session_state.last_action = "upload"


    section_header(
        "TRY A DEMO",
        "Explore AegisMail Before Uploading",
        (
            "These pre-loaded example emails show how the investigation works. "
            "Choose one to see the type of results AegisMail can present."
        ),
    )

    st.markdown(
        (
            '<p class="demo-note">'
            "A demo is simply an example email, so you can explore the platform "
            "without uploading your own file."
            "</p>"
        ),
        unsafe_allow_html=True,
    )


    demo_cols = st.columns(
        3,
        gap="large",
    )

    for col, (profile, meta) in zip(
        demo_cols,
        DEMO_SCENARIOS.items(),
    ):
        with col:
            st.markdown(
                render_scenario_card(meta),
                unsafe_allow_html=True,
            )

            if st.button(
                meta["button"],
                use_container_width=True,
                key=f"sample_{profile}",
            ):
                st.session_state.profile = profile
                st.session_state.analyzed = True
                st.session_state.last_action = "sample"

                if not sample_exists(profile):
                    st.toast(
                        (
                            "Sample .eml is not committed yet — loading the "
                            "matching mock investigation."
                        )
                    )

                st.rerun()


    if not st.session_state.analyzed:
        st.markdown(
            (
                '<div class="empty-state">'
                "Your investigation results will appear here after you upload "
                "an email or choose a demo scenario above."
                "</div>"
            ),
            unsafe_allow_html=True,
        )
        return


    result = apply_uploaded_metadata(
        build_demo_result(
            st.session_state.profile
        ),
        uploaded,
    )

    if (
        uploaded is not None
        and st.session_state.last_action == "upload"
    ):
        st.info(
            (
                "Showing demo analysis output while the scoring backend is "
                "connected. Chain-of-custody details below reflect your "
                "uploaded file."
            )
        )

    render_results(result)


def main() -> None:
    st.set_page_config(
        page_title="AegisMail | Forensic Intelligence",
        page_icon="📨",
        layout="wide",
    )

    inject_theme()

    if "page" not in st.session_state:
        st.session_state.page = "home"

    if "profile" not in st.session_state:
        st.session_state.profile = "bec"

    if "analyzed" not in st.session_state:
        st.session_state.analyzed = False

    if "last_action" not in st.session_state:
        st.session_state.last_action = None


    render_navbar()

    if st.session_state.page == "analyze":
        render_upload_analyze()
    else:
        render_home()


if __name__ == "__main__":
    main()