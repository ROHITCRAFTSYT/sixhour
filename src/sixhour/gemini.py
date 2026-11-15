"""Gemini client (REST, structured output). Works with a Gemini API key or, on
Google Cloud, with the service account's Vertex AI access."""

from __future__ import annotations

import json
import os
import time

import httpx

from .model import INCIDENT_SCHEMA

API = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
TIMEOUT = httpx.Timeout(30.0, connect=10.0)

SYSTEM = """You are an incident responder for small Indian businesses that have no security team.
You are given numbered log lines (personal data already masked as <KIND_n> tokens) and a first-pass
analysis from a rules engine. Produce the incident record.

Rules:
- State only what the log lines support. Every timeline event must cite the line number that shows it
  in evidence_line. Never invent IPs, hostnames, counts or times.
- Put anything you cannot establish from the logs into `unknowns` instead of guessing.
- incident_types must use the CERT-In Annexure I categories given in the schema; pick all that apply.
- personal_data.involved is true only if the logs show personal data of individuals was accessed,
  copied, encrypted, exposed or lost. Give the evidence in `basis`.
- Times: copy them from the logs in 'YYYY-MM-DD HH:MM:SS' local time.
- containment: concrete steps an office IT person can do today, most urgent first.
- Write plainly, for a business owner. No jargon without a short explanation."""


def model_name() -> str:
    return os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")


def available() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))


FALLBACK_MODEL = "gemini-3.5-flash-lite"
RETRYABLE = {429, 500, 502, 503, 504}
RETRY_DELAYS = (1.5, 3.0)


def _models() -> list[str]:
    primary = model_name()
    fallback = os.environ.get("GEMINI_FALLBACK_MODEL", FALLBACK_MODEL)
    return [primary] if not fallback or fallback == primary else [primary, fallback]


def _call(body: dict) -> str:
    """POST to Gemini; on overload/rate-limit retry briefly, then try the fallback model."""
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
    last: httpx.HTTPError | None = None
    for model in _models():
        for delay in (0.0, *RETRY_DELAYS):
            if delay:
                time.sleep(delay)
            try:
                response = httpx.post(
                    API.format(model=model),
                    headers={"x-goog-api-key": key},
                    json=body,
                    timeout=TIMEOUT,
                )
            except httpx.TimeoutException as exc:
                last = exc
                break  # a hung model rarely recovers within seconds: go to the fallback
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if response.status_code not in RETRYABLE:
                    raise
                last = exc
                continue
            parts = response.json()["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parts)
    assert last is not None
    raise last


def incident(numbered_logs: str, first_pass: dict, org: dict) -> dict:
    prompt = (
        f"Organisation: {org.get('name', 'unknown')} ({org.get('sector', 'unknown sector')}).\n\n"
        f"Rules-engine first pass (may be incomplete or wrong):\n{json.dumps(first_pass, indent=1)}\n\n"
        f"Log lines:\n{numbered_logs}"
    )
    text = _call(
        {
            "systemInstruction": {"parts": [{"text": SYSTEM}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
                "responseSchema": INCIDENT_SCHEMA,
            },
        }
    )
    return json.loads(text)


def translate(text: str, language: str) -> str:
    """Translate a customer notice. Legal meaning must survive, so the prompt forbids additions."""
    return _call(
        {
            "systemInstruction": {
                "parts": [
                    {
                        "text": f"Translate this data-breach notice into simple, respectful {language} "
                        "that a non-technical person can read. Keep every fact, number, date, name, "
                        "phone number and email exactly. Add nothing, remove nothing. Output only the translation."
                    }
                ]
            },
            "contents": [{"role": "user", "parts": [{"text": text}]}],
            "generationConfig": {"temperature": 0.2},
        }
    ).strip()
