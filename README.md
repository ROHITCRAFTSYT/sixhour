# SixHour

**From first alert to filed report, inside the legal clock.**

**Live:** https://sixhour-ashen.vercel.app. Open a sample incident on the desk: https://sixhour-ashen.vercel.app/app?sample=patient-portal

When an Indian business is breached, two clocks start:

| Clock | Law | Deadline |
|---|---|---|
| CERT-In incident report | CERT-In Directions of 28 April 2022 (IT Act s.70B(6)) | 6 hours from noticing |
| Personal data breach report | DPDP Rules 2025, Rule 7 (in force 13 May 2027) | Board and affected people without delay; detailed report to the Board in 72 hours |

A large company has a SOC and a law firm for this. A 40-person exporter, diagnostic lab or loan agency has one IT person and a folder of logs nobody can read. SixHour is the incident responder they don't have.

Paste or forward the logs. SixHour:

1. **Masks personal data** (Aadhaar, PAN, phone, email, card numbers) before a single line reaches a model.
2. **Reconstructs the incident** with Gemini: what happened, when, from where, which systems, whether personal data was touched. Every timeline event links to the log line that proves it.
3. **Starts both clocks** and shows time left.
4. **Drafts the filings**: the CERT-In incident report, the Data Protection Board intimation (initial + 72-hour detailed), and the notice to affected people, in plain language and in the customer's language.
5. **Gives the IT person a checklist** of what to do in the next hour.

A person reviews and files. SixHour never files on its own.

## Run it

```bash
uv sync
uv run sixhour          # http://127.0.0.1:8080
```

Open `http://127.0.0.1:8080/app?sample=patient-portal` to load and analyse a sample incident in one step.

Set a Gemini key to use the model (get one in Google AI Studio):

```bash
export GEMINI_API_KEY=...        # PowerShell: $env:GEMINI_API_KEY="..."
export GEMINI_MODEL=gemini-3.5-flash   # optional; falls back to gemini-3.5-flash-lite
```

Without a key the app still works: the deterministic rules engine analyses the logs and the header shows "offline rules engine". Translation of the customer notice needs the key.

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

Settings are environment variables; see `.env.example`.

## How it works

```
logs ──► privacy gateway ──► rules engine ──► Gemini (structured output) ──► guardrails ──► incident record
         mask Aadhaar/PAN/     first pass,      JSON schema with the           drop uncited      │
         phone/email/card      always runs      20 CERT-In categories          evidence, never   ├─► deadlines (6 h / 72 h)
                                                                               downgrade rules   ├─► CERT-In report
                                                                                                 ├─► DPDP Board intimation
                                                                                                 └─► notice to affected people ──► Gemini translation
```

- `redact.py` - privacy gateway. Same value maps to the same token, so the model can still follow "the same account". IP addresses stay: they are the evidence.
- `rules.py` - deterministic analyzer. Runs on every incident. It is the floor when the model is unreachable and a second opinion when it is not.
- `gemini.py` - Gemini REST client. The response schema restricts incident types to the 20 categories in Annexure I of the CERT-In Directions.
- `model.py` - the incident record, and `clean()`, which discards anything outside the schema, including evidence line numbers that are not in the log.
- `pipeline.py` - guardrails: the model cannot remove a personal-data finding or an attacker address the rules engine proved. A model failure never stops the clock; the rules result is shown instead.
- `drafts.py` - the model extracts facts, fixed templates carry the legal structure. Unknown fields are marked `[TO CONFIRM]`, never guessed.
- `server.py` - FastAPI. Stateless: nothing pasted is stored or logged.
- `web/` - the site and the desk. Plain HTML, CSS and JS with self-hosted fonts: no build step, no third-party requests.

## Production notes

- **Headers:** strict Content-Security-Policy (own origin only, no inline script or style), HSTS behind HTTPS, `nosniff`, no framing, no referrer. A test fails if any page stops obeying the policy.
- **Limits:** request bodies over 2.5 MB are refused before parsing; `/api/analyze` and `/api/translate` are rate limited per address (`RATE_LIMIT_ANALYZE`, `RATE_LIMIT_TRANSLATE`, per minute). The limiter is in memory, so on multi-instance hosting it is a brake on abuse, not an exact quota.
- **Logs:** one JSON line per request (id, method, path, status, milliseconds). Never bodies. Every response carries `X-Request-ID`.
- **Failure:** unhandled errors return a request ID, never a traceback. A Gemini failure falls back to the rules engine.
- **Browser:** the open incident is kept in `localStorage` so the clocks survive a reload; "Close incident" deletes it.
- **CI:** GitHub Actions runs ruff and pytest on Python 3.11 to 3.13 and builds and boots the container. Dependabot watches uv, Actions and the Docker base image.
- Security policy: [SECURITY.md](SECURITY.md).

## Deploy

Vercel: `vercel deploy --prod` (entrypoint `app.py`).

Google Cloud Run:

```bash
gcloud run deploy sixhour --source . --region asia-south1 --allow-unauthenticated \
  --set-secrets GEMINI_API_KEY=gemini-api-key:latest
```

Region `asia-south1` (Mumbai) keeps processing in India, which matters for the CERT-In requirement to keep logs within Indian jurisdiction.

## Status

Working today: privacy gateway, rules engine, Gemini analysis with guardrails, both clocks, three drafts, translation, three sample incidents, file drop, printable incident dossier, the public site with security, privacy and terms pages, 39 tests.

Not built yet: accounts and teams, log connectors (Google Workspace, firewall syslog, Tally server agent), Gemma on the customer's own machine for the privacy gateway, Gemini Live voice intake for the owner at 2 a.m., evidence vault with 180-day retention, filing history.

The drafts are structured after the CERT-In incident reporting form and DPDP Rule 7. They are drafting aids, not legal advice.

## License

MIT
