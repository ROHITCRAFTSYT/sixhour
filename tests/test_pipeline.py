from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sixhour import gemini, pipeline, rules
from sixhour.model import clean
from sixhour.redact import redact

SAMPLES = Path(__file__).parents[1] / "src" / "sixhour" / "samples"
IST = timezone(timedelta(hours=5, minutes=30))
NOTICED = datetime(2026, 11, 13, 9, 0, tzinfo=IST)


def load(name: str) -> str:
    return (SAMPLES / f"{name}.log").read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def no_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)


def test_redact_masks_identifiers_and_keeps_ips():
    text, counts = redact("user a@b.in phone 9843012345 pan ABCDE1234F aadhaar 2345 6789 0123 from 185.220.101.47")
    assert "a@b.in" not in text and "9843012345" not in text and "ABCDE1234F" not in text
    assert "2345 6789 0123" not in text
    assert "185.220.101.47" in text
    assert counts == {"EMAIL": 1, "AADHAAR": 1, "PAN": 1, "PHONE": 1}


def test_redact_same_value_same_token():
    text, counts = redact("a@b.in wrote to a@b.in")
    assert text == "<EMAIL_1> wrote to <EMAIL_1>" and counts == {"EMAIL": 1}


def test_ransomware_sample():
    inc = rules.analyze(load("ransomware"))
    assert inc["severity"] == "critical"
    assert inc["attacker_ips"] == ["185.220.101.47"]
    assert any(t.startswith("Malicious code") for t in inc["incident_types"])
    assert "TALLY-SRV01" in inc["affected_assets"]
    assert inc["first_malicious_activity"] == "2026-11-13 01:52:10"
    assert inc["personal_data"]["involved"]


def test_patient_portal_sample():
    inc = rules.analyze(load("patient-portal"))
    assert "Data breach" in inc["incident_types"]
    assert inc["attacker_ips"][0] == "45.134.26.9"
    assert "103.21.58.14" not in inc["attacker_ips"]  # the genuine patient
    assert inc["personal_data"]["estimated_records"] == 4188
    assert "health records" in inc["personal_data"]["categories"]


def test_phish_sample():
    inc = rules.analyze(load("workspace-phish"))
    assert "Identity theft, spoofing and phishing attacks" in inc["incident_types"]
    assert inc["attacker_ips"] == ["91.92.243.160"]
    assert inc["personal_data"]["involved"]


def test_quiet_logs_raise_no_incident():
    inc = rules.analyze('10.0.0.5 - - [13/Nov/2026:10:00:00 +0530] "GET / HTTP/1.1" 200 512')
    assert inc["incident_types"] == [] and not inc["personal_data"]["involved"]


def test_every_timeline_event_cites_a_real_line():
    for name in ("ransomware", "patient-portal", "workspace-phish"):
        text = load(name)
        count = len(text.splitlines())
        for event in rules.analyze(text)["timeline"]:
            assert 1 <= event["evidence_line"] <= count


def test_pipeline_deadlines_and_drafts():
    out = pipeline.run(load("patient-portal"), {"name": "Rockfort Diagnostics"}, NOTICED)
    assert out["engine"] == "rules"
    due = {d["id"]: d for d in out["deadlines"]}
    assert due["cert_in"]["due"] == "2026-11-13T15:00:00+05:30"
    assert due["dpdp"]["due"] == "2026-11-16T09:00:00+05:30" and due["dpdp"]["applies"]
    assert set(out["drafts"]) == {"cert_in", "dpdp_board", "principal_notice"}
    assert "Rockfort Diagnostics" in out["drafts"]["cert_in"]
    assert "@" not in "\n".join(out["lines"])  # emails masked in what the UI and model see


def test_no_dpdp_draft_without_personal_data():
    logs = "\n".join(f"2026-11-13 01:00:0{i} WEB-SRV01 Security EventID=4625 Logon failure user=admin src=185.220.101.47" for i in range(6))
    out = pipeline.run(logs, {}, NOTICED)
    assert set(out["drafts"]) == {"cert_in"}
    assert not {d["id"]: d for d in out["deadlines"]}["dpdp"]["applies"]


def test_model_cannot_drop_personal_data_or_invent_evidence(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test")

    def fake(numbered, first_pass, org):
        return {
            "title": "Scraping",
            "severity": "apocalyptic",
            "incident_types": ["Data breach", "Made-up category"],
            "timeline": [{"time": "x", "event": "invented", "evidence_line": 9999}],
            "personal_data": {"involved": False},
        }

    monkeypatch.setattr(gemini, "incident", fake)
    out = pipeline.run(load("patient-portal"), {}, NOTICED)
    inc = out["incident"]
    assert inc["incident_types"] == ["Data breach"]
    assert inc["severity"] == "medium"
    assert inc["timeline"][0]["evidence_line"] == 0
    assert inc["personal_data"]["involved"] and out["note"]
    assert "45.134.26.9" in inc["attacker_ips"]


def test_model_failure_falls_back_to_rules(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test")

    def boom(*args):
        raise TimeoutError

    monkeypatch.setattr(gemini, "incident", boom)
    out = pipeline.run(load("ransomware"), {}, NOTICED)
    assert out["engine"] == "rules" and "TimeoutError" in out["note"]


def test_clean_handles_garbage():
    assert clean({"timeline": [None, {"event": ""}], "personal_data": None}, 5)["timeline"] == []


class _Resp:
    def __init__(self, code: int, text: str = "{}"):
        self.status_code = code
        self._text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError(str(self.status_code), request=None, response=self)

    def json(self):
        return {"candidates": [{"content": {"parts": [{"text": self._text}]}}]}


def test_gemini_retries_then_uses_fallback_model(monkeypatch):
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url.split("/models/")[1].split(":")[0])
        return _Resp(200, "ok") if "lite" in url else _Resp(503)

    monkeypatch.setattr(gemini.httpx, "post", fake_post)
    monkeypatch.setattr(gemini.time, "sleep", lambda s: None)
    assert gemini._call({}) == "ok"
    assert calls == ["gemini-3.5-flash"] * 3 + ["gemini-3.5-flash-lite"]


def test_gemini_does_not_retry_client_errors(monkeypatch):
    import httpx

    calls = []
    monkeypatch.setattr(gemini.httpx, "post", lambda url, **kw: calls.append(url) or _Resp(400))
    with pytest.raises(httpx.HTTPStatusError):
        gemini._call({})
    assert len(calls) == 1


def test_gemini_timeout_moves_to_fallback(monkeypatch):
    import httpx

    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        if "lite" in url:
            return _Resp(200, "ok")
        raise httpx.ReadTimeout("slow")

    monkeypatch.setattr(gemini.httpx, "post", fake_post)
    assert gemini._call({}) == "ok"
    assert len(calls) == 2
