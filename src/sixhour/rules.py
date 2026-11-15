"""Deterministic log analyzer.

It runs first on every incident, with or without Gemini: it gives the model a
grounded starting point, a floor the product never falls below when the model is
unreachable, and a second opinion to compare the model's answer against.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter

from .model import CERT_IN_TYPES, empty_incident

TYPE_UNAUTH = "Unauthorised access of IT systems/data"
TYPE_MALWARE = next(t for t in CERT_IN_TYPES if t.startswith("Malicious code"))
TYPE_PHISH = "Identity theft, spoofing and phishing attacks"
TYPE_BREACH = "Data breach"
TYPE_WEB = "Attacks on applications such as e-governance and e-commerce"
TYPE_CLOUD = "Attacks or malicious/suspicious activities affecting cloud computing systems"
TYPE_SCAN = "Targeted scanning/probing of critical networks/systems"

IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
ISO = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
CLF = re.compile(r"\[(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})")
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}

FAILED = re.compile(r"EventID=4625|logon failure|failed password|authentication failure|invalid user", re.I)
SUCCESS = re.compile(r"EventID=4624|logon success|login_success|accepted password", re.I)
RANSOM = re.compile(r"vssadmin\s+delete\s+shadows|\.lockbit|\.encrypted\b|\.locked\b|README[-_ ]?RESTORE|ransom", re.I)
PRIV = re.compile(r"EventID=4720|EventID=4732|added to administrators|user account created", re.I)
SQLI = re.compile(r"union(?:\s|%20|\+)+select|(?:'|%27)(?:\s|%20|\+)*or(?:\s|%20|\+)*1=1|sqlmap", re.I)
SUSPICIOUS_LOGIN = re.compile(r"suspicious_login|impossible_travel|device=new", re.I)
MAIL_RULE = re.compile(r"forwarding_enabled|forward_to=|filter_created|inbox rule", re.I)
PHISH = re.compile(r"hxxps?://|phish|entered password on a link", re.I)
DOWNLOAD = re.compile(r"\bdownload\b|\bexport\b", re.I)
PUBLIC_SHARE = re.compile(r"anyone_with_link|visibility=public|allUsers", re.I)
EGRESS = re.compile(r"bytes_out=(\d+)")
ROWS = re.compile(r"\b(?:rows|fetched)[= ](\d+)")
RECORD_GET = re.compile(r'"GET (/api/(?:reports|patients|customers|users|orders|records)[^ "]*)[^"]*" 200')
HOST = re.compile(r"^\S+ \S+ ([A-Z][A-Z0-9]*-[A-Z0-9-]+)\b")

PERSONAL = {
    "health records": re.compile(r"patient|report|diagnos|thyroid|test_name|prescription", re.I),
    "government ID (Aadhaar/PAN)": re.compile(r"aadhaar|\bpan\b|_pan|kyc", re.I),
    "financial details": re.compile(r"bank[_ ]?ac|salary|payroll|loan|card", re.I),
    "contact details": re.compile(r"phone|contacts|address|email", re.I),
    "date of birth": re.compile(r"\bdob\b|date of birth", re.I),
}


def timestamp(line: str) -> str:
    """Timestamp of a log line as 'YYYY-MM-DD HH:MM:SS', or ''."""
    if m := ISO.search(line):
        return f"{m.group(1)} {m.group(2)}"
    if m := CLF.search(line):
        month = MONTHS.get(m.group(2))
        if month:
            return f"{m.group(3)}-{month:02d}-{m.group(1)} {m.group(4)}"
    return ""


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def analyze(text: str) -> dict:
    lines = text.splitlines()
    inc = empty_incident()
    events: list[tuple[str, str, int]] = []  # (time, event, line number)
    types: list[str] = []
    attackers: Counter[str] = Counter()
    assets: list[str] = []

    def add(kind: str) -> None:
        if kind not in types:
            types.append(kind)

    def note(n: int, event: str) -> None:
        events.append((timestamp(lines[n - 1]), event, n))

    failed: Counter[str] = Counter()
    first_fail: dict[str, int] = {}
    record_gets: Counter[str] = Counter()
    first_get: dict[str, int] = {}
    suspicious_ips: set[str] = set()
    downloads = 0
    rows = 0
    egress = 0
    flags = {k: False for k in ("ransom", "priv", "sqli", "mail", "phish", "share", "break_in")}

    for n, line in enumerate(lines, 1):
        ips = [ip for ip in IP.findall(line) if is_public(ip)]
        src = ips[0] if ips else ""
        if (m := HOST.match(line)) and m.group(1) not in assets:
            assets.append(m.group(1))

        if FAILED.search(line) and src:
            failed[src] += 1
            first_fail.setdefault(src, n)
        elif SUCCESS.search(line) and src and failed[src] >= 5 and not flags["break_in"]:
            flags["break_in"] = True
            attackers[src] += failed[src]
            note(first_fail[src], f"Password guessing begins from {src} ({failed[src]} failed logons)")
            note(n, f"Attacker logs in successfully from {src}")
            add(TYPE_UNAUTH)
        if SUSPICIOUS_LOGIN.search(line) and src:
            if src not in suspicious_ips:
                note(n, f"Suspicious sign-in from new location/device ({src})")
            suspicious_ips.add(src)
            attackers[src] += 1
            add(TYPE_UNAUTH)
        if PHISH.search(line) and not flags["phish"]:
            flags["phish"] = True
            note(n, "Phishing message or credential-harvesting link involved")
            add(TYPE_PHISH)
        if PRIV.search(line):
            if not flags["priv"]:
                note(n, "New account created / added to administrators")
            flags["priv"] = True
        if RANSOM.search(line):
            if not flags["ransom"]:
                note(n, "Ransomware activity: shadow copies deleted / files encrypted")
            flags["ransom"] = True
            add(TYPE_MALWARE)
        if SQLI.search(line):
            if not flags["sqli"]:
                note(n, f"SQL injection attempt from {src or 'unknown source'}")
            flags["sqli"] = True
            if src:
                attackers[src] += 1
            add(TYPE_WEB)
        if MAIL_RULE.search(line):
            if not flags["mail"]:
                note(n, "Mail forwarding or filter rule created by the intruder")
            flags["mail"] = True
            add(TYPE_CLOUD)
        if PUBLIC_SHARE.search(line):
            if not flags["share"]:
                note(n, "Internal file made publicly accessible")
            flags["share"] = True
        if (m := RECORD_GET.search(line)) and src:
            record_gets[src] += 1
            first_get.setdefault(src, n)
        if DOWNLOAD.search(line) and (src in suspicious_ips or "caller_user_id" in line):
            downloads += 1
            if downloads == 1:
                note(n, "Bulk download/export of business data begins")
        if m := EGRESS.search(line):
            if int(m.group(1)) > 500_000_000:
                egress = max(egress, int(m.group(1)))
                note(n, f"Large outbound transfer ({int(m.group(1)) / 1e9:.1f} GB) to external host")
        for m in ROWS.finditer(line):
            rows = max(rows, int(m.group(1)))

    for ip, count in record_gets.items():
        if count >= 8:
            attackers[ip] += count
            note(first_get[ip], f"Automated harvesting of records from {ip} ({count} record requests)")
            add(TYPE_WEB)
            downloads += count

    exfil = bool(downloads or egress)
    categories = [name for name, pat in PERSONAL.items() if pat.search(text)]
    personal = bool(categories) and (exfil or flags["ransom"] or flags["share"])
    if personal and exfil:
        add(TYPE_BREACH)
    if not types and (failed or flags["sqli"]):
        add(TYPE_SCAN)
        for ip, count in failed.most_common(3):
            if count >= 5:
                attackers[ip] += count
                note(first_fail[ip], f"Repeated failed logons from {ip} ({count})")

    events.sort(key=lambda e: (e[0] or "9999", e[2]))
    inc["timeline"] = [{"time": t, "event": e, "evidence_line": n} for t, e, n in events]
    inc["incident_types"] = types
    inc["attacker_ips"] = [ip for ip, _ in attackers.most_common(5)]
    if record_gets:
        assets.append("Customer-facing web portal / records API")
    if flags["mail"] or suspicious_ips:
        assets.append("Cloud email and file-storage account")
    inc["affected_assets"] = assets[:8]
    inc["first_malicious_activity"] = events[0][0] if events else ""

    if flags["ransom"]:
        inc["severity"] = "critical"
        inc["title"] = "Ransomware attack with file encryption"
    elif personal and exfil:
        inc["severity"] = "critical" if rows >= 1000 or egress else "high"
        inc["title"] = "Unauthorised access with personal data exfiltration"
    elif types and types != [TYPE_SCAN]:
        inc["severity"] = "high"
        inc["title"] = "Unauthorised access to systems"
    elif types:
        inc["severity"] = "medium"
        inc["title"] = "Scanning / password-guessing activity, no confirmed compromise"
    else:
        inc["title"] = "No clear incident pattern found"

    causes = []
    if flags["break_in"]:
        causes.append("remote login exposed to the internet and a guessable password")
    if flags["phish"]:
        causes.append("credentials entered on a phishing page, no MFA on the account")
    if record_gets and max(record_gets.values()) >= 8:
        causes.append("missing ownership/authorisation check on a records API")
    if flags["sqli"]:
        causes.append("SQL injection in a web application")
    cause = "; ".join(causes)
    inc["root_cause"] = cause[:1].upper() + cause[1:]

    inc["personal_data"] = {
        "involved": personal,
        "categories": categories if personal else [],
        "estimated_records": rows if personal else 0,
        "basis": (
            "Log lines name personal-data fields/files that were encrypted, downloaded or exposed."
            if personal
            else "No evidence in these logs that personal data was accessed."
        ),
    }

    steps = []
    if inc["attacker_ips"]:
        steps.append("Block " + ", ".join(inc["attacker_ips"]) + " at the firewall / WAF")
    if flags["break_in"] or flags["ransom"]:
        steps.append("Isolate the affected servers from the network; do not power them off (preserve memory)")
        steps.append("Disable the compromised and attacker-created accounts; close RDP to the internet")
    if flags["ransom"]:
        steps.append("Check offline backups before any restore; do not pay or contact the attacker from company email")
    if suspicious_ips or flags["phish"]:
        steps.append("Reset the user's password, revoke all sessions and tokens, enforce MFA")
    if flags["mail"]:
        steps.append("Remove the forwarding rule and filters; warn finance about the fraudulent email thread")
    if flags["share"]:
        steps.append("Revoke public link sharing on the exposed files")
    if record_gets and max(record_gets.values()) >= 8:
        steps.append("Disable the abusing account; deploy the ownership check on the records API; rate-limit it")
    if types:
        steps.append("Preserve logs for 180 days and take forensic copies before changing anything else")
    inc["containment"] = steps

    unknowns = []
    if types:
        if exfil or flags["ransom"]:
            unknowns.append("Exact list of records and people affected (needs a data inventory match)")
        if not exfil and flags["ransom"]:
            unknowns.append("Whether data was copied out before encryption")
        unknowns.append("Whether the attacker still has access through another account or device")
    inc["unknowns"] = unknowns

    parts = [inc["title"] + "."]
    if inc["attacker_ips"]:
        parts.append("Source: " + ", ".join(inc["attacker_ips"]) + ".")
    if inc["root_cause"]:
        parts.append("Likely cause: " + cause + ".")
    if personal:
        parts.append("Personal data involved: " + ", ".join(categories) + (f" (about {rows} records)." if rows else "."))
    inc["summary"] = " ".join(parts)
    return inc
