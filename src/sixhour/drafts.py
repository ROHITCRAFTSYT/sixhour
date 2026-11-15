"""Regulatory drafts.

The model extracts facts; these templates carry the legal structure. That split keeps
every filing in the same reviewable shape and stops a model from dropping a required field.

- CERT-In: Directions of 28 April 2022 under s.70B(6) IT Act - report within 6 hours of noticing.
- DPDP Rules 2025, Rule 7 - tell the Board and each affected person without delay; detailed
  report to the Board within 72 hours of becoming aware.

Every draft is for a human to review before filing. Nothing is sent automatically.
"""

from __future__ import annotations

from datetime import datetime, timedelta

CERT_IN_HOURS = 6
DPDP_HOURS = 72
TODO = "[TO CONFIRM]"


def deadlines(noticed_at: datetime, personal_data: bool) -> list[dict]:
    out = [
        {
            "id": "cert_in",
            "label": "CERT-In incident report",
            "law": "CERT-In Directions, 28 Apr 2022 (IT Act s.70B)",
            "hours": CERT_IN_HOURS,
            "due": (noticed_at + timedelta(hours=CERT_IN_HOURS)).isoformat(),
            "applies": True,
        },
        {
            "id": "dpdp",
            "label": "DPDP detailed report to the Board",
            "law": "DPDP Rules 2025, Rule 7",
            "hours": DPDP_HOURS,
            "due": (noticed_at + timedelta(hours=DPDP_HOURS)).isoformat(),
            "applies": personal_data,
        },
    ]
    return out


def _bullets(items: list[str], empty: str = TODO) -> str:
    return "\n".join(f"- {i}" for i in items) if items else f"- {empty}"


def _timeline(incident: dict) -> str:
    rows = [f"- {e['time'] or 'time unknown'} : {e['event']}" for e in incident["timeline"]]
    return "\n".join(rows) or f"- {TODO}"


def _fmt(dt: datetime) -> str:
    return dt.strftime("%d %b %Y, %H:%M IST")


def cert_in(incident: dict, org: dict, noticed_at: datetime) -> str:
    return f"""CERT-In INCIDENT REPORT (draft for review)
To: incident@cert-in.org.in

1. REPORTING ORGANISATION
Name: {org.get("name") or TODO}
Sector: {org.get("sector") or TODO}
Address / location: {org.get("location") or TODO}
Point of contact: {org.get("contact_name") or TODO}, {org.get("contact_role") or TODO}
Phone: {org.get("contact_phone") or TODO}    Email: {org.get("contact_email") or TODO}

2. TYPE OF INCIDENT (Annexure I)
{_bullets(incident["incident_types"])}

3. DATE AND TIME
Incident first observed in logs: {incident["first_malicious_activity"] or TODO}
Incident noticed by the organisation: {_fmt(noticed_at)}
This report due by: {_fmt(noticed_at + timedelta(hours=CERT_IN_HOURS))}

4. AFFECTED SYSTEMS
{_bullets(incident["affected_assets"])}
Operating system / application versions: {TODO}
Is the affected system critical to operations: {"Yes" if incident["severity"] in ("high", "critical") else TODO}

5. DESCRIPTION OF THE INCIDENT
{incident["summary"] or TODO}

Sequence of events:
{_timeline(incident)}

6. SOURCE OF ATTACK (apparent)
{_bullets(incident["attacker_ips"], "Not established from available logs")}

7. LIKELY CAUSE / VULNERABILITY EXPLOITED
{incident["root_cause"] or "Not yet established"}

8. IMPACT
Severity (our assessment): {incident["severity"].upper()}
Personal data involved: {"Yes - " + ", ".join(incident["personal_data"]["categories"]) if incident["personal_data"]["involved"] else "No evidence so far"}
Has this occurred before: {TODO}

9. ACTIONS TAKEN / PLANNED
{_bullets(incident["containment"])}

10. NOT YET KNOWN
{_bullets(incident["unknowns"], "None identified")}

11. OTHER AGENCIES INFORMED
{TODO} (police cyber cell / sector regulator / Data Protection Board)

Relevant logs are preserved and available to CERT-In on request.
"""


def dpdp_board(incident: dict, org: dict, noticed_at: datetime) -> str:
    pd = incident["personal_data"]
    count = f"approximately {pd['estimated_records']}" if pd["estimated_records"] else TODO
    return f"""INTIMATION OF PERSONAL DATA BREACH TO THE DATA PROTECTION BOARD OF INDIA
(DPDP Act 2023 s.8(6); DPDP Rules 2025, Rule 7) - draft for review

Data Fiduciary: {org.get("name") or TODO}, {org.get("location") or TODO}
Contact person: {org.get("contact_name") or TODO} ({org.get("contact_role") or TODO}), {org.get("contact_phone") or TODO}, {org.get("contact_email") or TODO}

PART A - INITIAL INTIMATION (send without delay)
Nature of the breach: {incident["title"] or TODO}
Extent: {count} individuals' records; data types: {", ".join(pd["categories"]) or TODO}
Timing: began {incident["first_malicious_activity"] or TODO}; became aware {_fmt(noticed_at)}
Location: {", ".join(incident["affected_assets"]) or TODO}
Likely impact: {_impact(pd["categories"])}

PART B - DETAILED REPORT (due {_fmt(noticed_at + timedelta(hours=DPDP_HOURS))})
1. Events, circumstances and reasons leading to the breach
{_timeline(incident)}
Cause: {incident["root_cause"] or "Under investigation"}

2. Measures implemented or proposed to mitigate risk
{_bullets(incident["containment"])}

3. Findings regarding the person who caused the breach
{_bullets(["Apparent source address: " + ip for ip in incident["attacker_ips"]], "Not established")}

4. Remedial measures to prevent recurrence
- {TODO}

5. Report on intimations given to affected Data Principals
- Notices sent on: {TODO}; channel: {TODO}; number notified: {TODO}

6. Not yet known
{_bullets(incident["unknowns"], "None identified")}
"""


def _impact(categories: list[str]) -> str:
    risks = []
    joined = " ".join(categories).lower()
    if "health" in joined:
        risks.append("exposure of sensitive health information; targeted scam calls")
    if "id" in joined or "aadhaar" in joined:
        risks.append("identity fraud using ID details")
    if "financial" in joined:
        risks.append("financial fraud and phishing using account or loan details")
    if "contact" in joined:
        risks.append("spam, phishing and impersonation calls")
    return "; ".join(risks) or TODO


def principal_notice(incident: dict, org: dict, noticed_at: datetime) -> str:
    pd = incident["personal_data"]
    advice = ["Be careful with calls, SMS or emails that mention your details with us. We will never ask for OTPs or passwords."]
    joined = " ".join(pd["categories"]).lower()
    if "financial" in joined:
        advice.append("Check your bank and loan statements and report anything you do not recognise to your bank.")
    if "aadhaar" in joined or "id" in joined:
        advice.append("Consider locking your Aadhaar biometrics at myaadhaar.uidai.gov.in.")
    advice.append("Report fraud attempts at cybercrime.gov.in or call 1930.")
    return f"""Important notice about your personal data

Dear customer,

We are writing to tell you about a security incident at {org.get("name") or TODO} that involved your personal data.

What happened
On {incident["first_malicious_activity"] or TODO}, an unauthorised person gained access to our systems. We became aware of this on {_fmt(noticed_at)}.

What data was involved
{_bullets(pd["categories"])}

What this could mean for you
{_impact(pd["categories"])}.

What we have done
{_bullets(incident["containment"][:4])}
We have reported the incident to CERT-In and the Data Protection Board of India.

What you can do
{_bullets(advice)}

Who to contact
{org.get("contact_name") or TODO}, {org.get("contact_role") or TODO}
Phone: {org.get("contact_phone") or TODO}   Email: {org.get("contact_email") or TODO}

We are sorry this happened.
{org.get("name") or TODO}
"""


def build(incident: dict, org: dict, noticed_at: datetime) -> dict:
    out = {"cert_in": cert_in(incident, org, noticed_at)}
    if incident["personal_data"]["involved"]:
        out["dpdp_board"] = dpdp_board(incident, org, noticed_at)
        out["principal_notice"] = principal_notice(incident, org, noticed_at)
    return out
