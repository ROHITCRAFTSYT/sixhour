"""HTTP API + site. Stateless: nothing a customer uploads is stored or logged."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Annotated

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StringConstraints
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, gemini, pipeline

HERE = Path(__file__).parent
WEB = HERE / "web"
IST = timezone(timedelta(hours=5, minutes=30))
MAX_CHARS = 600_000
MAX_BODY_BYTES = 2_500_000
PAGES = {"/app": "app.html", "/security": "security.html", "/privacy": "privacy.html", "/terms": "terms.html"}

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

# Only our own origin may supply code, styles, fonts or receive data. No inline script or style.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

log = logging.getLogger("sixhour")
if not log.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    log.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
    log.propagate = False


class RateLimiter:
    """Sliding one-minute window per client and route, held in memory.

    Each server instance counts on its own, so on serverless or multi-instance hosting this
    is a brake on abuse from one address, not an exact quota.
    """

    WINDOW = 60.0

    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = {}
        self._lock = Lock()

    def check(self, client: str, route: str, limit: int) -> float:
        """Record a hit. Returns 0 if allowed, else the seconds until the next slot."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 20_000:  # bound memory under an address-spraying flood
                self._hits = {k: q for k, q in self._hits.items() if q and now - q[-1] < self.WINDOW}
            hits = self._hits.setdefault((client, route), deque())
            while hits and now - hits[0] >= self.WINDOW:
                hits.popleft()
            if len(hits) >= limit:
                return max(1.0, self.WINDOW - (now - hits[0]))
            hits.append(now)
            return 0.0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def _limits() -> dict[str, int]:
    return {
        "/api/analyze": int(os.environ.get("RATE_LIMIT_ANALYZE", "12")),
        "/api/translate": int(os.environ.get("RATE_LIMIT_TRANSLATE", "20")),
    }


def client_ip(request: Request) -> str:
    """The address the hosting platform saw. Vercel sets x-real-ip; Cloud Run appends to x-forwarded-for."""
    real = request.headers.get("x-real-ip")
    if real:
        return real.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _cache_policy(path: str) -> str:
    if path.startswith("/api/") or path == "/healthz":
        return "no-store"
    if path.startswith("/fonts/"):
        return "public, max-age=31536000, immutable"
    return "no-cache"  # pages, CSS and JS are revalidated (ETag), so a deploy is live at once


app = FastAPI(title="SixHour", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def guard(request: Request, call_next) -> Response:
    """Request id, size and rate limits, security headers, and an access log with no payloads."""
    started = time.perf_counter()
    request_id = uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    path = request.url.path
    response: Response | None = None

    if request.method == "POST":
        length = request.headers.get("content-length")
        if length is None or not length.isdigit():
            response = JSONResponse({"detail": "Content-Length is required."}, status_code=411)
        elif int(length) > MAX_BODY_BYTES:
            response = JSONResponse({"detail": "Request is too large."}, status_code=413)
        elif path in (limits := _limits()):
            wait = limiter.check(client_ip(request), path, limits[path])
            if wait:
                response = JSONResponse(
                    {"detail": "Too many requests. Try again shortly."},
                    status_code=429,
                    headers={"Retry-After": str(int(wait))},
                )

    if response is None:
        try:
            response = await call_next(request)
        except Exception:
            log.exception(json.dumps({"event": "unhandled_error", "id": request_id, "path": path}))
            response = JSONResponse({"detail": "Something went wrong on our side.", "request_id": request_id}, status_code=500)

    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.headers.get("x-forwarded-proto", request.url.scheme) == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    response.headers.setdefault("Cache-Control", _cache_policy(path))
    response.headers["X-Request-ID"] = request_id

    log.info(
        json.dumps(
            {
                "event": "request",
                "id": request_id,
                "method": request.method,
                "path": path,
                "status": response.status_code,
                "ms": round((time.perf_counter() - started) * 1000),
            }
        )
    )
    return response


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
    wants_page = request.method == "GET" and not request.url.path.startswith("/api/")
    if exc.status_code == 404 and wants_page and "text/html" in request.headers.get("accept", ""):
        return FileResponse(WEB / "404.html", status_code=404)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


class Org(BaseModel):
    name: str = Field("", max_length=200)
    sector: str = Field("", max_length=200)
    location: str = Field("", max_length=200)
    contact_name: str = Field("", max_length=200)
    contact_role: str = Field("", max_length=200)
    contact_phone: str = Field("", max_length=40)
    contact_email: str = Field("", max_length=200)


class AnalyzeRequest(BaseModel):
    logs: str = Field(min_length=1, max_length=MAX_CHARS)
    org: Org = Org()
    noticed_at: str = Field("", max_length=40)
    use_model: bool = True


class TranslateRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    language: str = Field(pattern="^(Hindi|Tamil|Telugu|Kannada|Malayalam|Marathi|Bengali|Gujarati)$")
    keep: list[Annotated[str, StringConstraints(max_length=200)]] = Field(default_factory=list, max_length=12)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "version": __version__, "gemini": gemini.available(), "model": gemini.model_name()}


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
        text, not_kept = gemini.translate(request.text, request.language, request.keep)
        return {"text": text, "not_kept": not_kept}
    except Exception as exc:
        log.warning(json.dumps({"event": "translate_failed", "error": type(exc).__name__}))
        raise HTTPException(502, "The translation service is busy. Try again in a moment.") from None


@app.get("/")
def index(sample: str | None = None) -> Response:
    # Links shared before the desk moved to /app (/?sample=patient-portal) still work.
    if sample in SAMPLES:
        return RedirectResponse(f"/app?sample={sample}", status_code=307)
    return FileResponse(WEB / "index.html")


def _page(filename: str):
    def serve() -> FileResponse:
        return FileResponse(WEB / filename)

    return serve


for _route, _file in PAGES.items():
    app.add_api_route(_route, _page(_file), methods=["GET"], include_in_schema=False)

app.mount("/", StaticFiles(directory=WEB), name="web")


def main() -> None:
    uvicorn.run(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8080")),
        access_log=False,  # the guard middleware writes one structured line per request
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
