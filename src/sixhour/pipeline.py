"""Logs in, incident record + deadlines + drafts out."""

from __future__ import annotations

import logging
from datetime import datetime

from . import drafts, gemini, rules
from .model import clean
from .redact import redact

log = logging.getLogger("sixhour")
MAX_LINES = 4000


def run(logs: str, org: dict, noticed_at: datetime, use_model: bool = True) -> dict:
    lines = [ln for ln in logs.splitlines() if ln.strip()][:MAX_LINES]
    masked, masked_counts = redact("\n".join(lines))
    first_pass = rules.analyze(masked)

    incident, engine, note = first_pass, "rules", ""
    if use_model and gemini.available():
        numbered = "\n".join(f"{n}: {ln}" for n, ln in enumerate(masked.splitlines(), 1))
        try:
            incident = clean(gemini.incident(numbered, first_pass, org), len(lines))
            engine = gemini.model_name()
            # The model may not downgrade what the rules engine proved from the logs.
            if first_pass["personal_data"]["involved"] and not incident["personal_data"]["involved"]:
                incident["personal_data"] = first_pass["personal_data"]
                note = "Model found no personal data; kept the rules-engine finding for review."
            for ip in first_pass["attacker_ips"]:
                if ip not in incident["attacker_ips"]:
                    incident["attacker_ips"].append(ip)
        except Exception as exc:  # network, quota, malformed answer: fall back, never fail the clock
            log.warning("Gemini call failed, using rules engine: %s", exc)
            note = f"Gemini unavailable ({type(exc).__name__}); showing the rules-engine analysis."

    return {
        "engine": engine,
        "note": note,
        "incident": incident,
        "masked": masked_counts,
        "lines": masked.splitlines(),
        "noticed_at": noticed_at.isoformat(),
        "deadlines": drafts.deadlines(noticed_at, incident["personal_data"]["involved"]),
        "drafts": drafts.build(incident, org, noticed_at),
    }
