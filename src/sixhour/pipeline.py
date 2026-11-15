"""Logs in, incident record + deadlines + drafts out."""

from __future__ import annotations

import logging
from datetime import datetime

from . import drafts, gemini, rules
from .model import clean
from .redact import redact

log = logging.getLogger("sixhour")
MAX_LINES = 4000


def _keep_proven_findings(incident: dict, first_pass: dict) -> str:
    """The model may add findings but may not drop what the rules engine proved from the logs.

    Mutates `incident` in place and returns a note for the reviewer naming anything restored.
    """
    kept = []
    if first_pass["personal_data"]["involved"] and not incident["personal_data"]["involved"]:
        incident["personal_data"] = first_pass["personal_data"]
        kept.append("the personal-data finding")
    missing = [t for t in first_pass["incident_types"] if t not in incident["incident_types"]]
    if missing:
        # A dropped CERT-In category would silently shrink the report, so restore it.
        incident["incident_types"].extend(missing)
        kept.append("the CERT-In " + ("category" if len(missing) == 1 else "categories") + " " + "; ".join(missing))
    for ip in first_pass["attacker_ips"]:
        if ip not in incident["attacker_ips"]:
            incident["attacker_ips"].append(ip)
    if not kept:
        return ""
    return "The model left out " + " and ".join(kept) + ", which the rules engine found in the logs; kept for your review."


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
            note = _keep_proven_findings(incident, first_pass)
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
