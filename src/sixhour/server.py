"""HTTP API + static UI. Stateless: nothing a customer uploads is stored."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import gemini, pipeline

HERE = Path(__file__).parent
IST = timezone(timedelta(hours=5, minutes=30))
MAX_CHARS = 600_000

SAMPLES = {
    "ransomware": {
        "label": "Ransomware on the accounts server",
        "org": {"name": "Kovai Tex Exports Pvt Ltd", "sector": "Textile manufacturing / export", "location": "Coimbatore, Tamil Nadu"},
    },
    "patient-portal": {
        "label": "Patient reports scraped from a lab portal",
        "org": {"name": "Rockfort Diagnostics", "sector": "Healthcare / diagnostic laboratory", "location": "Tiruchirappalli, Tamil Nadu"},
    },
    "workspace-phish": {
        "label": "Phished employee, KYC files downloaded",
        "org": {"name": "SwiftLoans Finserv", "sector": "Financial services / loan DSA", "location": "Chennai, Tamil Nadu"},
    },
}

app = FastAPI(title="SixHour", docs_url=None, redoc_url=None)


class Org(BaseModel):
    name: str = ""
    sector: str = ""
    location: str = ""
    contact_name: str = ""
    contact_role: str = ""
    contact_phone: str = ""
    contact_email: str = ""


class AnalyzeRequest(BaseModel):
    logs: str = Field(min_length=1, max_length=MAX_CHARS)
    org: Org = Org()
    noticed_at: str = ""
    use_model: bool = True


class TranslateRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    language: str = Field(pattern="^(Hindi|Tamil|Telugu|Kannada|Malayalam|Marathi|Bengali|Gujarati)$")


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "gemini": gemini.available(), "model": gemini.model_name()}


@app.get("/api/samples")
def samples() -> list[dict]:
    return [{"id": key, **value} for key, value in SAMPLES.items()]


@app.get("/api/samples/{sample_id}")
def sample(sample_id: str) -> dict:
    if sample_id not in SAMPLES:
        raise HTTPException(404, "Unknown sample")
    text = (HERE / "samples" / f"{sample_id}.log").read_text(encoding="utf-8")
    return {"id": sample_id, **SAMPLES[sample_id], "logs": text}


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    try:
        noticed = datetime.fromisoformat(request.noticed_at) if request.noticed_at else datetime.now(IST)
    except ValueError:
        raise HTTPException(422, "noticed_at must be an ISO date-time") from None
    if noticed.tzinfo is None:
        noticed = noticed.replace(tzinfo=IST)
    return pipeline.run(request.logs, request.org.model_dump(), noticed.astimezone(IST), request.use_model)


@app.post("/api/translate")
def translate(request: TranslateRequest) -> dict:
    if not gemini.available():
        raise HTTPException(503, "Translation needs a Gemini API key (set GEMINI_API_KEY).")
    try:
        return {"text": gemini.translate(request.text, request.language)}
    except Exception as exc:
        raise HTTPException(502, f"Gemini call failed: {type(exc).__name__}") from None


@app.get("/")
def index() -> FileResponse:
    return FileResponse(HERE / "web" / "index.html")


app.mount("/", StaticFiles(directory=HERE / "web"), name="web")


def main() -> None:
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8080")))


if __name__ == "__main__":
    main()
