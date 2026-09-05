"""FastAPI entry point for the AegisMail forensic ingestion pipeline."""

from __future__ import annotations

from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.modules.hops.hop_tracer import HopTrace, trace_hops
from app.modules.parser.eml_parser import ParsedEmail, parse_eml

MAX_EML_SIZE_BYTES = 25 * 1024 * 1024


class AnalysisResponse(BaseModel):
    filename: str
    email: ParsedEmail
    hop_trace: HopTrace


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


@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_email(file: UploadFile = File(..., description="Raw RFC 5322 .eml email")) -> AnalysisResponse:
    """Ingest an EML artifact without persisting or modifying the uploaded bytes."""
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
        return AnalysisResponse(filename=filename, email=parse_eml(raw), hop_trace=trace_hops(raw))
    except (TypeError, ValueError, OSError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Unable to analyze EML: {exc}") from exc
