"""The incident record every analyzer must produce, and the schema Gemini is held to."""

from __future__ import annotations

# Incident types from Annexure I of the CERT-In Directions of 28 April 2022.
CERT_IN_TYPES = [
    "Targeted scanning/probing of critical networks/systems",
    "Compromise of critical systems/information",
    "Unauthorised access of IT systems/data",
    "Defacement of website or intrusion into a website",
    "Malicious code attacks (virus, worm, trojan, bots, spyware, ransomware, cryptominers)",
    "Attack on servers (database, mail, DNS) and network devices",
    "Identity theft, spoofing and phishing attacks",
    "Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks",
    "Attacks on critical infrastructure, SCADA and operational technology systems",
    "Attacks on applications such as e-governance and e-commerce",
    "Data breach",
    "Data leak",
    "Attacks on Internet of Things (IoT) devices and associated systems",
    "Attacks or incidents affecting digital payment systems",
    "Attacks through malicious mobile apps",
    "Fake mobile apps",
    "Unauthorised access to social media accounts",
    "Attacks or malicious/suspicious activities affecting cloud computing systems",
    "Attacks or malicious/suspicious activities affecting big data, blockchain, virtual assets or robotics systems",
    "Attacks or malicious/suspicious activities affecting AI and ML systems",
]

SEVERITIES = ["low", "medium", "high", "critical"]


def _strings() -> dict:
    return {"type": "ARRAY", "items": {"type": "STRING"}}


# Gemini responseSchema (OpenAPI subset).
INCIDENT_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "title": {"type": "STRING"},
        "summary": {"type": "STRING"},
        "incident_types": {"type": "ARRAY", "items": {"type": "STRING", "enum": CERT_IN_TYPES}},
        "severity": {"type": "STRING", "enum": SEVERITIES},
        "first_malicious_activity": {"type": "STRING"},
        "timeline": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "time": {"type": "STRING"},
                    "event": {"type": "STRING"},
                    "evidence_line": {"type": "INTEGER"},
                },
                "required": ["time", "event", "evidence_line"],
            },
        },
        "attacker_ips": _strings(),
        "affected_assets": _strings(),
        "personal_data": {
            "type": "OBJECT",
            "properties": {
                "involved": {"type": "BOOLEAN"},
                "categories": _strings(),
                "estimated_records": {"type": "INTEGER"},
                "basis": {"type": "STRING"},
            },
            "required": ["involved", "categories", "estimated_records", "basis"],
        },
        "root_cause": {"type": "STRING"},
        "containment": _strings(),
        "unknowns": _strings(),
    },
    "required": [
        "title",
        "summary",
        "incident_types",
        "severity",
        "first_malicious_activity",
        "timeline",
        "attacker_ips",
        "affected_assets",
        "personal_data",
        "root_cause",
        "containment",
        "unknowns",
    ],
}


def empty_incident() -> dict:
    return {
        "title": "",
        "summary": "",
        "incident_types": [],
        "severity": "low",
        "first_malicious_activity": "",
        "timeline": [],
        "attacker_ips": [],
        "affected_assets": [],
        "personal_data": {"involved": False, "categories": [], "estimated_records": 0, "basis": ""},
        "root_cause": "",
        "containment": [],
        "unknowns": [],
    }


def clean(incident: dict, line_count: int) -> dict:
    """Coerce a model answer into the record shape and drop anything outside it."""
    out = empty_incident()
    for key in ("title", "summary", "first_malicious_activity", "root_cause"):
        out[key] = str(incident.get(key) or "").strip()
    out["incident_types"] = [t for t in incident.get("incident_types") or [] if t in CERT_IN_TYPES]
    out["severity"] = incident.get("severity") if incident.get("severity") in SEVERITIES else "medium"
    for key in ("attacker_ips", "affected_assets", "containment", "unknowns"):
        out[key] = [str(v).strip() for v in incident.get(key) or [] if str(v).strip()]
    for row in incident.get("timeline") or []:
        if not isinstance(row, dict) or not row.get("event"):
            continue
        try:
            line = int(row.get("evidence_line") or 0)
        except (TypeError, ValueError):
            line = 0
        out["timeline"].append(
            {
                "time": str(row.get("time") or ""),
                "event": str(row["event"]),
                # A line number that is not in the log is not evidence.
                "evidence_line": line if 1 <= line <= line_count else 0,
            }
        )
    pd = incident.get("personal_data") or {}
    try:
        records = max(0, int(pd.get("estimated_records") or 0))
    except (TypeError, ValueError):
        records = 0
    out["personal_data"] = {
        "involved": bool(pd.get("involved")),
        "categories": [str(c) for c in pd.get("categories") or []],
        "estimated_records": records,
        "basis": str(pd.get("basis") or ""),
    }
    return out
