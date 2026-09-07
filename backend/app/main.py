"""FastAPI entry point for the AegisMail forensic ingestion pipeline."""

from __future__ import annotations

from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from typing import Any

from app.modules.analysis.email_analyzer import analyze_email
from app.modules.reports.pdf_generator import generate_forensic_report

MAX_EML_SIZE_BYTES = 25 * 1024 * 1024


app = FastAPI(title="AegisMail API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Demo prototype: restrict this in deployed environments.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/analyze")
async def analyze_uploaded_email(
    file: UploadFile = File(..., description="Raw RFC 5322 .eml email"),
    enrich_hops: bool = False,
    enrich_domain: bool = False,
) -> dict[str, Any]:
    """Analyze uploaded evidence without persisting or modifying the bytes."""
    filename = file.filename or "uploaded.eml"
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Only .eml uploads are accepted.")
    raw = await file.read(MAX_EML_SIZE_BYTES + 1)
    await file.close()
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The uploaded EML file is empty.")
    if len(raw) > MAX_EML_SIZE_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="EML file exceeds the 25 MiB limit.")
    try:
        return analyze_email(raw, filename=filename, enrich_hops=enrich_hops, enrich_domain=enrich_domain)
    except (TypeError, ValueError, OSError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Unable to analyze EML: {exc}") from exc


@app.post("/api/v1/report")
async def generate_report(analysis: dict[str, Any]) -> StreamingResponse:
    """Create a downloadable PDF from an existing analysis response."""
    try:
        pdf = generate_forensic_report(analysis)
        filename = analysis.get("evidence", {}).get("filename", "email").removesuffix(".eml")
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid analysis report payload: {exc}") from exc
    return StreamingResponse(iter([pdf]), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{filename}_forensic_report.pdf"'})
