# Team YAPTAG — AI Agent Master Guide & Prompts for SIH 2026 (PS: SIH26106)

This document contains the **Universal Master Prompt** that establishes context for any LLM/AI coding assistant (ChatGPT, Claude, Gemini, Cursor, Copilot), followed by **Module-Specific Tailored Prompts** for each team member.

---

## 🌐 SECTION 1: The Universal Master Context
*(Every team member must paste this block at the very top of their conversation with their AI assistant before adding their role-specific task.)*

```text
================================================================================
                    AEGISMAIL PROJECT MASTER CONTEXT
================================================================================
You are acting as an expert Senior Cybersecurity Engineer and Python Architect assisting our BTech 3rd-year team (Team YAPTAG) for the Smart India Hackathon 2026.

PROJECT DETAILS:
- Problem Statement ID: SIH26106
- Organization: All India Council for Technical Education (AICTE)
- Category: Software | Theme: Blockchain & Cybersecurity
- Project Name: AegisMail (AI-Powered Email Threat Forensics & Infrastructure Intelligence Platform)
- Target Deadline: Internal College Evaluation & Live Prototype Demo on September 8, 2026.
- GitHub Repository: https://github.com/Y45h026/SIH26106-AegisMail.git

WHAT THIS PROJECT IS (AND IS NOT):
- It is NOT merely a simple spam/phishing email classifier (upload text -> 94% phishing).
- It IS an investigative digital forensics and infrastructure intelligence platform for SOC analysts and cyber investigators.
- Core philosophy: "Where did this email actually travel from, what infrastructure (relays, IPs, ASNs, domains) is associated with it, how suspicious is it, and what is the court-admissible cryptographic evidence?"

KEY ARCHITECTURAL CAVEAT:
We explicitly DO NOT claim to identify the physical human attacker behind the keyboard. Malicious actors use VPNs, proxies, compromised servers, and botnets. We strictly perform "Infrastructure attribution and investigative intelligence."

PLANNED DEMO PROTOTYPE WORKFLOW:
1. User uploads a raw .eml file.
2. The system computes SHA-256 / SHA-1 hashes (ISO/IEC 27037 chain-of-custody).
3. The parser extracts RFC 822 / MIME headers, body, URLs, and Received: hops.
4. Reverse-hop reconstruction traces the email path from recipient backwards to the edge socket IP.
5. Domain & IP threat intelligence enriches hops (GeoIP, ASN, ISP, domain age).
6. Security checks run: Stamped vs Live SPF/DKIM/DMARC, homoglyph/typosquatting detection, and BEC/urgency NLP intent scoring.
7. An Explainable Risk Score (0-100) is generated with exact factor attribution (+25 DMARC fail, +20 lookalike domain, etc.).
8. The UI visualizes the hop route on an interactive map, shows an infrastructure graph, and generates a downloadable PDF Forensic Investigation Report.

TECH STACK:
- Backend: Python 3.11+, FastAPI, Pydantic, dnspython, dkimpy, python-whois, reportlab, networkx.
- Frontend: Streamlit (or React + Leaflet/Cytoscape) for high-speed, interactive demo UI.
- Architecture: Modular, clean Python functions returning strictly-typed dictionaries/Pydantic models.
================================================================================
```

---

## 🎯 SECTION 2: Role-Specific Prompts for Each Team Member

---

```text
# 1. Clone the repository
git clone https://github.com/Y45h026/SIH26106-AegisMail.git
cd SIH26106-AegisMail

# 2. Switch to your assigned feature branch:
# Member 1 (Lead):
git checkout feat/core-engine

# Member 2 (Cybersecurity/Auth):
git checkout feat/auth-forensics

# Member 3 (Threat Intel/GeoIP):
git checkout feat/threat-intel

# Member 4 (Frontend UI):
git checkout feat/frontend-ui

# Member 5 (ML/Content Engine):
git checkout feat/content-threat-engine

# Member 6 (Forensic Reporting/PPT):
git checkout feat/forensic-reporting

```

### 👑 Member 1 (Team Leader): System Architect & Core Engine
* **Branch:** `feat/core-engine`
* **Focus:** EML MIME parser, reverse-hop path reconstruction logic, and FastAPI orchestrator.
* **Copy & paste this below the Universal Context:**

```text
[MEMBER ROLE: MEMBER 1 — SYSTEM ARCHITECT & CORE PIPELINE LEAD]
Branch: feat/core-engine
Current Goal: Build the core EML ingestion engine, MIME parser, reverse-hop extraction, and FastAPI orchestrator.

MY SPECIFIC TASKS FOR TODAY:
1. Create `backend/app/modules/parser/eml_parser.py`:
   - Accept either file path or raw bytes of an .eml file.
   - Compute SHA-256 and MD5 hash of the raw file content (Evidence Preservation).
   - Parse RFC 5322 MIME structure using Python's built-in `email` library.
   - Extract: Message-ID, Date, Subject, From (display name + email address), To, Cc, Reply-To, Return-Path.
   - Extract plain text body, HTML body, and list of all extracted URLs (using regex or BeautifulSoup).
   - Extract attachment metadata (filename, content-type, size, SHA-256 hash).
2. Create `backend/app/modules/hops/hop_tracer.py`:
   - Extract all `Received:` headers.
   - CRITICAL REQUIREMENT (Reverse-hop validation): Parse `Received:` headers in reverse order (bottom to top / destination to origin). Identify the first untrusted external hop (edge relay) and extract relay server names, IP addresses, protocol, and timestamps.
3. Create `backend/app/main.py`:
   - Set up a FastAPI app with CORS enabled.
   - Provide a `POST /api/v1/analyze` endpoint accepting an `.eml` upload via `UploadFile`.
   - Wire the parser to return a structured JSON response.

Please write clean, well-commented, robust Python code with type hints and error handling for malformed or missing headers.
```

---

### 🛡️ Member 2: Cybersecurity & Email Authentication Specialist
* **Branch:** `feat/auth-forensics`
* **Focus:** SPF/DKIM/DMARC dual-check verification, header anomaly detection, and sample `.eml` testbeds.
* **Copy & paste this below the Universal Context:**

```text
[MEMBER ROLE: MEMBER 2 — CYBERSECURITY & EMAIL AUTHENTICATION]
Branch: feat/auth-forensics
Current Goal: Build the authentication validator (SPF, DKIM, DMARC, ARC) and curate 4 distinct test .eml fixtures.

MY SPECIFIC TASKS FOR TODAY:
1. Create `backend/app/modules/auth/verifier.py`:
   - Dual-Check Verification:
     a) Stamped Check: Parse `Authentication-Results:` and `ARC-Authentication-Results:` headers from the email to read what the recipient server stamped (e.g. spf=pass, dkim=pass, dmarc=pass).
     b) Active DNS Check: Using `dnspython`, query the TXT records of the sender's domain to inspect active SPF (`v=spf1 ...`) and DMARC (`v=DMARC1; p=reject/quarantine/none`) policies.
   - Header Anomaly Detection:
     - Check if `From` domain matches `Return-Path` domain (SPF alignment).
     - Check if `From` domain matches `Reply-To` domain (flag suspicious mismatches).
     - Check for missing critical headers (`Message-ID`, `Date`).
     - Detect suspicious `X-Mailer` or user agents.
2. Create 4 synthetic yet realistic `.eml` test files in the `samples/` directory:
   - `samples/legitimate/clean_invoice.eml`: Valid SPF/DKIM/DMARC, legitimate corporate headers.
   - `samples/spoofed_dmarc_fail/paypal_spoofed.eml`: Spoofed From header (`support@paypal.com`) with unauthorized sending IP and DMARC fail.
   - `samples/bec_wire_fraud/ceo_giftcard.eml`: Display-name spoofing (`CEO Name <compromised_account@external.com>`) requesting urgent wire transfer/gift cards.
   - `samples/malicious_redirect/account_verify_link.eml`: Phishing link using open-redirects or IP-based URLs.

Please provide complete Python code for `verifier.py` and the raw RFC 822 text content for the 4 `.eml` sample files.
```

---

### 🌍 Member 3: Threat Intelligence & Geolocation Engineer
* **Branch:** `feat/threat-intel`
* **Focus:** IP Geolocation, ASN/ISP lookup, reverse DNS, and RDAP domain age.
* **Copy & paste this below the Universal Context:**

```text
[MEMBER ROLE: MEMBER 3 — THREAT INTELLIGENCE & GEOLOCATION]
Branch: feat/threat-intel
Current Goal: Build the enrichment engine that converts extracted IP addresses and domains into geographical coordinates, network ASN/ISP details, and domain age reputation.

MY SPECIFIC TASKS FOR TODAY:
1. Create `backend/app/modules/intel/ip_enricher.py`:
   - Accept an IPv4/IPv6 address.
   - Filter out private/internal RFC 1918 IPs (e.g. 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1) and mark them as "Internal LAN / Private Relay".
   - For public IPs, fetch geolocation using a free, reliable service (like `http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query` or `ipinfo.io`).
   - Implement caching (using a simple dictionary or `functools.lru_cache`) so we don't query the same IP twice.
   - Perform reverse DNS lookup (PTR record) using socket/dnspython.
2. Create `backend/app/modules/intel/domain_enricher.py`:
   - Query RDAP/WHOIS for domain creation date and registrar using `whois` or free RDAP APIs.
   - Calculate domain age in days. Flag domains younger than 30 days as high-risk.
   - Extract MX records for the sender domain.
3. Return a clean Python dataclass / dictionary containing:
   `{ip, city, country, country_code, lat, lon, isp, asn, is_private, reverse_dns}`.

Please write clean, asynchronous or fast synchronous Python code with timeout protections so network delays don't freeze the prototype.
```

---

### 💻 Member 4: Frontend UI & Visualization Engineer
* **Branch:** `feat/frontend-ui`
* **Focus:** Interactive Investigation Dashboard, Route Map on Leaflet/Folium, and Graph view.
* **Copy & paste this below the Universal Context:**

```text
[MEMBER ROLE: MEMBER 4 — FRONTEND UI & VISUALIZATION]
Branch: feat/frontend-ui
Current Goal: Build a stunning, dark-themed, cyber-investigation dashboard using Streamlit (or React + Tailwind + Leaflet) for the live September 8th demo.

MY SPECIFIC TASKS FOR TODAY:
1. Create the main UI in `frontend/app.py`:
   - Design: Sleek, high-contrast dark cybersecurity theme (dark navy/slate background, neon cyan/red accents, crisp badges).
   - Header: "AegisMail — Cyber Forensic Email Intelligence Platform" with SIH 2026 badges.
   - Upload Section: File uploader accepting `.eml` files with sample quick-load buttons ("Load Legitimate Sample", "Load Spoofed DMARC Sample", "Load BEC Scam Sample").
2. Threat Overview Component:
   - High-impact visual Risk Gauge / Score Card (e.g., 88/100 - CRITICAL RISK).
   - Threat Breakdown badges (e.g., [⚠ DMARC Failure], [⚠ Lookalike Domain], [⚠ Wire Transfer Intent]).
   - Chain of Custody Card: Original filename, File size, SHA-256 hash with one-click copy.
3. Server Relay Path Map:
   - Interactive map (using `folium`, `st_folium`, or `pydeck`) plotting each server hop with numbered markers and connecting geodesic lines showing the geographic path traversed by the email.
4. Detailed Forensics Tabs:
   - Tab 1: Header Inspector (expandable raw headers, authentication verification table).
   - Tab 2: Relay Hop Timeline (hop sequence, IP, host, ISP, country, latency).
   - Tab 3: Content & URLs (extracted links, domain reputation, extracted keywords).
5. "Export Forensic Report" button to trigger PDF download.

Please provide a complete, runnable `frontend/app.py` script that can run with `streamlit run frontend/app.py` and mock or consume the backend JSON.
```

---

### 🧠 Member 5: ML & Content Threat Engine Specialist
* **Branch:** `feat/content-threat-engine`
* **Focus:** NLP intent classification, urgency/wire-transfer BEC detection, homoglyph/lookalike domain engine, and explainable scoring formula.
* **Copy & paste this below the Universal Context:**

```text
[MEMBER ROLE: MEMBER 5 — ML & CONTENT THREAT ENGINE]
Branch: feat/content-threat-engine
Current Goal: Build the content analysis module, typosquatting/homoglyph detector, and explainable multi-factor risk scoring formula.

MY SPECIFIC TASKS FOR TODAY:
1. Create `backend/app/modules/content/homoglyph.py`:
   - Brand Impersonation / Typosquatting detection: Compare extracted email sender domains against a list of top 50 targeted organizations (e.g., paypal, microsoft, google, sbi, icici, amazon, netflix, income-tax).
   - Detect: Levenshtein distance $\le 2$ (e.g. `paypa1.com` vs `paypal.com`), Punycode / IDN homoglyphs (e.g. Cyrillic 'а' replacing Latin 'a'), and suspicious keywords in subdomains (`paypal-security-update.com`).
2. Create `backend/app/modules/content/nlp_intent.py`:
   - Rule-based & heuristic NLP intent classifier for Business Email Compromise (BEC):
     - Financial urgency ("wire transfer", "bank account changed", "gift card", "immediate payment").
     - Credential harvesting ("verify your password", "account suspended", "click here to login").
     - Fake authority / CEO fraud ("I am in a meeting, do not call, handle this immediately").
   - Calculate an urgency/deception score (0.0 to 1.0).
3. Create `backend/app/modules/scoring/risk_engine.py`:
   - Build the Explainable Threat Scorer combining all signals:
     - Authentication score (DMARC fail = +30, SPF fail = +15).
     - Domain score (Homoglyph detected = +25, domain age < 30 days = +20).
     - Header score (Reply-to mismatch = +15, missing Message-ID = +10).
     - Content score (High urgency/BEC = +20, IP-based URL = +15).
   - Total score bounded between 0 and 100 with category: Legitimate (0-25), Suspicious (26-65), High Risk (66-85), Critical Threat (86-100).
   - Return a detailed list of contributing risk factors for transparency!

Please write clean, well-tested Python code with no external heavyweight model downloads so it executes instantly in our demo.
```

---

### 📄 Member 6: Forensic Reporting & Presentation Lead
* **Branch:** `feat/forensic-reporting`
* **Focus:** PDF Forensic Investigation Report generation, ISO/IEC 27037 Evidence Manifest, and SIH PPT slide deck.
* **Copy & paste this below the Universal Context:**

```text
[MEMBER ROLE: MEMBER 6 — FORENSIC REPORTING & PRESENTATION LEAD]
Branch: feat/forensic-reporting
Current Goal: Build the automated court-admissible PDF Forensic Report generator and craft the complete content and script for our 10-slide SIH 2026 presentation on September 8th.

MY SPECIFIC TASKS FOR TODAY:
1. Create `backend/app/modules/reports/pdf_generator.py`:
   - Using Python's `reportlab` or `fpdf2`, generate a formal, high-impact "Cyber Incident Forensic Report":
     - Official Header: "DIGITAL FORENSIC INCIDENT REPORT — AEGISMAIL" with Case ID & Timestamp.
     - Section 1: Chain of Custody & Evidence Integrity (Filename, SHA-256 Hash, MD5 Hash, Ingestion Time, Analyst).
     - Section 2: Executive Threat Assessment (Overall Risk Score, Classification Badge, Contributing Risk Factors).
     - Section 3: Technical Email Headers & Authentication Summary (SPF, DKIM, DMARC status table).
     - Section 4: Reconstructed Relay Hop Path (Table of hops, server names, IPs, ISPs, and Countries).
     - Section 5: Extracted Indicators of Compromise (IOCs) (Suspicious URLs, IPs, domains).
     - Footer: ISO/IEC 27037 compliance notice and tamper-evident cryptographic seal statement.
2. Complete PPT Pitch Deck Content (`docs/presentation_deck.md`):
   - Produce the exact slide-by-slide text, bullet points, diagram descriptions, and 5-minute verbal pitch script for our college evaluation on September 8th covering:
     - Slide 1: Title & Team YAPTAG
     - Slide 2: Real-World Industry Problem (Beyond simple spam filtering)
     - Slide 3: AegisMail Forensic Solution
     - Slide 4: End-to-End System Architecture
     - Slide 5: Novelty & Competitive Advantage (Reverse-hop parsing, evidence hashing, explainability)
     - Slide 6: Technology Stack & Implementation
     - Slide 7: Live Prototype Demonstration & Walkthrough
     - Slide 8: Technical Feasibility & Limitations (Attribution realities)
     - Slide 9: Future Grand Finale Roadmap (Blockchain ledger, Neo4j graph)
     - Slide 10: Conclusion & Q&A defense.

Please output the complete Python PDF generator script and the full markdown presentation deck.
```

