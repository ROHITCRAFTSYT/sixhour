import logging
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sixhour import server

WEB = Path(server.__file__).parent / "web"
PAGES = ["/", "/app", "/security", "/privacy", "/terms"]
QUIET_LOG = '10.0.0.5 - - [13/Nov/2026:10:00:00 +0530] "GET / HTTP/1.1" 200 512'


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    server.limiter.reset()


@pytest.fixture
def client():
    return TestClient(server.app)


@pytest.mark.parametrize("path", PAGES)
def test_pages_are_served_with_security_headers(client, path):
    res = client.get(path)
    assert res.status_code == 200 and "SixHour" in res.text
    assert "script-src 'self'" in res.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in res.headers["content-security-policy"]
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["referrer-policy"] == "no-referrer"
    assert len(res.headers["x-request-id"]) == 16


@pytest.mark.parametrize("page", sorted(p.name for p in WEB.glob("*.html")))
def test_pages_obey_their_own_csp(page):
    """The policy forbids inline script and style, so no page may rely on either."""
    html = (WEB / page).read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"<style|\sstyle=|\son[a-z]+=", html)
    assert not re.search(r'<(?:script|link|img|iframe)[^>]*(?:src|href)="https?://', html), f"{page} loads from another origin"


def test_site_makes_no_third_party_requests():
    for sheet in WEB.glob("*.css"):
        assert "http" not in sheet.read_text(encoding="utf-8").replace("http://www.w3.org/2000/svg", "")


def test_old_sample_links_still_work(client):
    res = client.get("/?sample=patient-portal", follow_redirects=False)
    assert res.status_code == 307 and res.headers["location"] == "/app?sample=patient-portal"
    assert client.get("/?sample=//evil.example", follow_redirects=False).status_code == 200


def test_not_found_is_a_page_for_browsers_and_json_for_clients(client):
    page = client.get("/nope", headers={"accept": "text/html"})
    assert page.status_code == 404 and "Not on file" in page.text
    assert client.get("/api/samples/nope").json() == {"detail": "Unknown sample"}


def test_api_is_never_cached_and_fonts_are(client):
    assert client.get("/healthz").headers["cache-control"] == "no-store"
    assert "immutable" in client.get("/fonts/bigshoulders.woff2").headers["cache-control"]


def test_healthz_reports_version(client):
    body = client.get("/healthz").json()
    assert body["ok"] and body["version"] == server.__version__ and body["gemini"] is False


def test_analyze_end_to_end(client):
    logs = client.get("/api/samples/patient-portal").json()["logs"]
    res = client.post("/api/analyze", json={"logs": logs, "org": {"name": "Rockfort"}, "noticed_at": "2026-11-13T09:00"})
    body = res.json()
    assert res.status_code == 200 and body["engine"] == "rules"
    assert body["deadlines"][0]["due"] == "2026-11-13T15:00:00+05:30"
    assert set(body["drafts"]) == {"cert_in", "dpdp_board", "principal_notice"}


def test_analyze_rejects_bad_input(client):
    assert client.post("/api/analyze", json={"logs": ""}).status_code == 422
    assert client.post("/api/analyze", json={"logs": "x", "noticed_at": "yesterday"}).status_code == 422
    assert client.post("/api/analyze", json={"logs": "x", "org": {"name": "n" * 201}}).status_code == 422


def test_oversized_request_is_refused_before_parsing(client):
    res = client.post("/api/analyze", content=b"x" * (server.MAX_BODY_BYTES + 1), headers={"content-type": "application/json"})
    assert res.status_code == 413


def test_rate_limit(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ANALYZE", "2")
    send = lambda ip: client.post("/api/analyze", json={"logs": QUIET_LOG}, headers={"x-real-ip": ip})  # noqa: E731
    assert [send("203.0.113.9").status_code for _ in range(3)] == [200, 200, 429]
    blocked = send("203.0.113.9")
    assert int(blocked.headers["retry-after"]) >= 1 and "content-security-policy" in blocked.headers
    assert send("203.0.113.10").status_code == 200  # another address is unaffected


def test_translate_without_key_is_unavailable(client):
    assert client.post("/api/translate", json={"text": "hello", "language": "Tamil"}).status_code == 503
    assert client.post("/api/translate", json={"text": "hello", "language": "Klingon"}).status_code == 422


def test_request_log_never_contains_payload(client):
    seen = []

    class Capture(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())

    handler = Capture()
    server.log.addHandler(handler)
    try:
        client.post("/api/analyze", json={"logs": "secret-marker-9f3 user=a@b.in", "org": {"name": "HushCo"}})
    finally:
        server.log.removeHandler(handler)
    joined = "\n".join(seen)
    assert '"path": "/api/analyze"' in joined
    assert "secret-marker" not in joined and "HushCo" not in joined and "a@b.in" not in joined


def test_unhandled_error_returns_request_id_not_a_traceback(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("internal detail")

    monkeypatch.setattr(server.pipeline, "run", boom)
    res = TestClient(server.app, raise_server_exceptions=False).post("/api/analyze", json={"logs": "x"})
    assert res.status_code == 500 and "internal detail" not in res.text
    assert res.json()["request_id"] == res.headers["x-request-id"]


def test_rate_limiter_window():
    limiter = server.RateLimiter()
    assert limiter.check("a", "/r", 1) == 0
    assert limiter.check("a", "/r", 1) >= 1
    assert limiter.check("b", "/r", 1) == 0


def test_translate_passes_names_and_reports_losses(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test")
    seen = {}

    def fake(text, language, keep):
        seen.update(text=text, language=language, keep=keep)
        return "translated", ["Rockfort"]

    monkeypatch.setattr(server.gemini, "translate", fake)
    res = client.post("/api/translate", json={"text": "hello Rockfort", "language": "Tamil", "keep": ["Rockfort"]})
    assert res.json() == {"text": "translated", "not_kept": ["Rockfort"]} and seen["keep"] == ["Rockfort"]
    assert client.post("/api/translate", json={"text": "x", "language": "Tamil", "keep": ["n" * 201]}).status_code == 422
    assert client.post("/api/translate", json={"text": "x", "language": "Tamil", "keep": ["a"] * 13}).status_code == 422
