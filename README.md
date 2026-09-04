# AegisMail — AI-Powered Email Threat Forensics & Infrastructure Intelligence Platform

[![SIH 2026](https://img.shields.io/badge/SIH-2026-blue.svg)](https://sih.gov.in)
[![Theme](https://img.shields.io/badge/Theme-Blockchain%20%26%20Cybersecurity-orange.svg)]()
[![Team](https://img.shields.io/badge/Team-YAPTAG-green.svg)]()

> **Problem Statement ID:** SIH26106  
> **Organization:** All India Council for Technical Education (AICTE)  
> **Category:** Software  
> **Theme:** Blockchain & Cybersecurity  

---

## 🛡️ Executive Summary

**AegisMail** is a digital email forensics and investigative threat intelligence platform designed for Cyber Defense Centers, Security Operations Centers (SOC), and forensic investigators.

Unlike conventional phishing email detectors that merely output a black-box probability score, AegisMail answers the critical investigative questions:
1. **Where did this email actually originate from?**
2. **What server hops did it traverse, and which relays can be cryptographically trusted?**
3. **What domain and network infrastructure (IP, ASN, ISP, Hosting) is connected to it?**
4. **Is there brand impersonation, display-name spoofing, or lookalike domain activity?**
5. **How can this evidence be preserved in a tamper-proof, court-admissible audit trail?**

---

## 🏛️ System Architecture

```text
                                  ┌───────────────────────┐
                                  │      User / SOC       │
                                  │     Analyst Upload    │
                                  └──────────┬────────────┘
                                             │ (.eml / .msg / raw)
                                             ▼
                       ┌─────────────────────────────────────────────┐
                       │           INSPECTION & INGESTION            │
                       │  - SHA-256 / SHA-1 / MD5 Evidence Hash      │
                       │  - ISO/IEC 27037 Chain-of-Custody Manifest  │
                       │  - RFC 822 / MIME Canonical Stream Parser   │
                       └─────────────────────┬───────────────────────┘
                                             │
             ┌───────────────────────────────┼───────────────────────────────┐
             ▼                               ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│     HEADER & RELAY      │     │    CONTENT & ENTITY     │     │     URL & ATTACHMENT    │
│        FORENSICS        │     │        FORENSICS        │     │        FORENSICS        │
├─────────────────────────┤     ├─────────────────────────┤     ├─────────────────────────┤
│ • Reverse-hop tracer    │     │ • NLP Semantic Intent   │     │ • URL unshortener       │
│ • Stamped Auth-Results  │     │   (Urgency, Wire-fraud) │     │ • Homoglyph / Punycode  │
│ • Live SPF/DKIM/DMARC   │     │ • Brand Impersonation   │     │ • Attachment hash check │
│ • Header Anomalies      │     │   (Levenshtein / Typo)  │     │   (Magic bytes / Hash)  │
│ • Client X-Mailer / MUA │     │ • Suspicious QR Codes   │     │ • Domain age / RDAP     │
└────────────┬────────────┘     └────────────┬────────────┘     └────────────┬────────────┘
             │                               │                               │
             └───────────────────────────────┼───────────────────────────────┘
                                             ▼
                       ┌─────────────────────────────────────────────┐
                       │          GRAPH & ENRICHMENT ENGINE          │
                       │  - MaxMind GeoLite2 / ASN lookup            │
                       │  - Reverse DNS (PTR) / MX record validator  │
                       │  - AbuseIPDB / Passive DNS correlation      │
                       │  - Multi-email Campaign Clustering          │
                       └─────────────────────┬───────────────────────┘
                                             ▼
                       ┌─────────────────────────────────────────────┐
                       │       EXPLAINABLE DECISION ENGINE           │
                       │  - Composite Risk Engine (0-100 Score)      │
                       │  - Transparent Threat Breakdown Factors     │
                       │  - MITRE ATT&CK Mapping (T1566 Phishing)    │
                       └─────────────────────┬───────────────────────┘
                                             │
             ┌───────────────────────────────┴───────────────────────────────┐
             ▼                                                               ▼
┌─────────────────────────────────────────┐     ┌─────────────────────────────────────────┐
│         INVESTIGATION DASHBOARD         │     │         EVIDENCE & REPORTING            │
├─────────────────────────────────────────┤     ├─────────────────────────────────────────┤
│ • Interactive Network Graph (Cytoscape) │     │ • Court-Ready PDF Forensic Report       │
│ • Geolocation Hop Map (Leaflet.js)      │     │ • Cryptographic Verification Seal       │
│ • Header Breakdown & Tree View          │     │   (SHA-256 / Tamper-evident receipt)    │
│ • Threat Factor Attribution Breakdown   │     │ • Evidence Custody Manifest (JSON)      │
└─────────────────────────────────────────┘     └─────────────────────────────────────────┘
```

---

## 👥 Team YAPTAG — Roles & Branch Mapping

| Role / Module | Team Member Focus | Branch Name | Responsibilities |
| :--- | :--- | :--- | :--- |
| **System Lead & Core Engine** | Member 1 (Lead) | `feat/core-engine` | MIME Parser, Reverse Hop Parser, FastAPI Orchestration |
| **Cybersecurity & Auth** | Member 2 | `feat/auth-forensics` | SPF/DKIM/DMARC Validation, Header Anomalies, Test Datasets |
| **Threat Intel & GeoIP** | Member 3 | `feat/threat-intel` | IP Geolocation, ASN/ISP resolution, RDAP/WHOIS Domain age |
| **Frontend & Visualization** | Member 4 | `feat/frontend-ui` | Streamlit / React Dashboard, Hop Path Map, Graph View |
| **ML & Content Threat Engine** | Member 5 | `feat/content-threat-engine`| NLP Intent Classification, Homoglyph/Typosquatting Engine |
| **Reporting & Evidence Ledger**| Member 6 | `feat/forensic-reporting` | PDF Forensic Report Generation, Chain-of-Custody Manifest |

---

## 🗂️ Project Directory Structure

```text
SIH26106-AegisMail/
├── .github/
│   └── workflows/              # CI/CD validation
├── backend/
│   ├── app/
│   │   ├── api/                # FastAPI router endpoints
│   │   ├── core/               # Configuration & pipeline orchestrator
│   │   ├── modules/
│   │   │   ├── parser/         # EML parser & MIME canonicalization
│   │   │   ├── auth/           # SPF, DKIM, DMARC, ARC verifier
│   │   │   ├── hops/           # Reverse-hop path reconstruction
│   │   │   ├── intel/          # GeoIP, ASN, RDAP, AbuseIPDB integration
│   │   │   ├── content/        # NLP, homoglyphs, BEC intent scoring
│   │   │   ├── scoring/        # Explainable risk aggregation engine
│   │   │   └── reports/        # PDF generation & evidence receipt
│   │   └── main.py             # API entrypoint
│   └── requirements.txt
├── frontend/                   # Streamlit / Web UI Dashboard
│   ├── app.py
│   └── components/
├── samples/                    # Curated .eml test corpus
│   ├── legitimate/
│   ├── spoofed_dmarc_fail/
│   ├── bec_wire_fraud/
│   └── malicious_redirect/
├── docs/                       # Presentation slides, specs & research notes
├── README.md
└── .gitignore
```

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/Y45h026/SIH26106-AegisMail.git
cd SIH26106-AegisMail
```

### 2. Set up Python Virtual Environment
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r backend/requirements.txt
```

---

## ⚖️ Technical Disclaimer
AegisMail provides **infrastructure attribution and forensic investigative intelligence** (identifying mail relays, hosting providers, autonomous systems, and routing paths). It does **not** claim to identify the physical human identity of an attacker, as malicious actors frequently leverage VPNs, compromised relays, Tor, and open proxies.

---
*Developed by Team YAPTAG for Smart India Hackathon 2026 (Internal College Round: Sept 8, 2026)*
