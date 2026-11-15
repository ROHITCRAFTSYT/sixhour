"""Privacy gateway: mask personal data in logs before they leave the customer's network.

Each value is replaced by a stable token (same value -> same token) so the model can
still reason about "the same account" without seeing the raw identifier.
IP addresses and hostnames are kept: they are the evidence.
"""

from __future__ import annotations

import re

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("AADHAAR", re.compile(r"(?<![\d.])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d.])")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("CARD", re.compile(r"(?<![\d.])(?:\d{4}[ -]?){3}\d{4}(?![\d.])")),
    ("PHONE", re.compile(r"(?<![\d.:])(?:\+91[ -]?|0)?[6-9]\d{9}(?![\d.])")),
]


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Return (masked text, count of masked values per kind)."""
    counts: dict[str, int] = {}
    seen: dict[tuple[str, str], str] = {}

    for kind, pattern in PATTERNS:

        def swap(match: re.Match[str], kind: str = kind) -> str:
            key = (kind, match.group(0))
            if key not in seen:
                counts[kind] = counts.get(kind, 0) + 1
                seen[key] = f"<{kind}_{counts[kind]}>"
            return seen[key]

        text = pattern.sub(swap, text)
    return text, counts
