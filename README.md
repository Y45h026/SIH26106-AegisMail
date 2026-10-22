# AegisMail

AegisMail is an email forensics prototype for reviewing `.eml` evidence. It combines message parsing, authentication results, sender and URL checks, relay analysis, explainable risk scoring, an investigation dashboard, and PDF reporting. It is intended to support analyst review; it does not identify the person behind an email or prove that a message is safe or malicious.

## What it does

- Parses RFC 5322/MIME email headers and message content, extracts URLs and attachments, and computes evidence hashes.
- Reviews stamped SPF/DKIM/DMARC results, header anomalies, lookalike sender domains, suspicious content, and sender identity context.
- Reconstructs the `Received` relay path and calculates an explainable composite risk score.
- Optionally enriches public relay IPs and sender domains with third-party GeoIP/ISP and registration-age lookups. These network lookups are opt-in.
- Provides a Streamlit dashboard with a relay map and downloadable forensic PDF report.
- Includes a TF-IDF and Logistic Regression content classifier at `backend/models/phishing_text_classifier.joblib`. Training data and generated reports remain local and are not included.

## Repository layout

```text
backend/
  app/main.py                 FastAPI API
  app/modules/                Parser, authentication, analysis, scoring, intel, reports
  data/README.md              Local training-data instructions
  models/README.md            Local model instructions
  training/                   Classifier training script
  tests/                      Backend unit and API tests
frontend/
  app.py                      Streamlit dashboard
  components/hop_map.py       Relay path map
samples/                      Sample .eml messages for manual review
docs/TEAM_PROMPTS_GUIDE.md     Legacy team planning prompts
```

## Run locally

Requires Python 3.11 or newer.

1. Create and activate a virtual environment from the repository root:

   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

2. Install backend and frontend dependencies:

   ```powershell
   python -m pip install -r backend/requirements.txt
   python -m pip install -r frontend/requirements.txt
   ```

3. Start the API in one terminal:

   ```powershell
   cd backend
   python -m uvicorn app.main:app --reload
   ```

   The API health endpoint is `http://127.0.0.1:8000/health`; interactive API docs are at `http://127.0.0.1:8000/docs`.

4. Start the dashboard in another terminal from the repository root:

   ```powershell
   streamlit run frontend/app.py
   ```

The dashboard uses `http://127.0.0.1:8000` by default. Set `AEGISMAIL_API_URL` to point it at a different API URL.

The API accepts `.eml` uploads at `POST /api/v1/analyze` (maximum 25 MiB). Optional `enrich_hops` and `enrich_domain` query parameters enable third-party lookups. `POST /api/v1/report` accepts an analysis response and returns a PDF report.

## Optional local ML classifier

The checked-in model was trained from individual source CSVs described in [backend/data/README.md](backend/data/README.md). The training script is `backend/training/train_phishing_classifier.py`; local datasets, generated manifests, and reports remain excluded by `.gitignore`. The model uses subject and body text only and complements the forensic checks. See [backend/models/README.md](backend/models/README.md) for provenance, licensing, integrity, and compatibility notes.

## Development

Run the backend test suite from the `backend` directory:

```powershell
python -m unittest discover -s tests -v
```

Frontend packages are listed in `frontend/requirements.txt`; backend packages are listed in `backend/requirements.txt`.

## Limitations and safe use

- This is a prototype. The API currently permits requests from any origin for local demo use; do not expose it to untrusted networks without adding authentication, deployment hardening, and appropriate CORS restrictions.
- Live DNS, DKIM cryptographic verification, GeoIP/ISP, and domain-age lookups depend on external services or local configuration and can fail or return incomplete data. Network enrichment is disabled unless requested.
- Email headers and authentication results can be forged. A successful authentication result does not establish the human identity of the sender. Risk scores and model predictions are indicators for human review, not proof.
- Treat uploaded messages as sensitive evidence. Do not publish real email samples, credentials, recipient addresses, or local training data.

## Project

Developed by Team YAPTAG for Smart India Hackathon problem statement SIH26106 (AICTE), 2026.
