# LaunchShield — R1 logic prototype

One ordinary page, **no accounts**, no database, no visual-redesign phase yet. The backend coordinates five external security/data providers and optionally explains their evidence with Gemini.

**This is passive/read-only assessment, not penetration testing or a guarantee of security.** Only submit a public website you own or are explicitly authorized to assess. Some provider reports/history are public or cached.

## Current verification

- Release isolated suite: **72 tests passed**, including job lifecycle, failures, quotas, exports, capabilities, CSRF, SSRF/redirect checks, duplicate evidence, cancellation, restart interruption, provider HTTP contracts and bounded safe retries.
- Real Google generation succeeded with **`gemini-3.5-flash-lite`** using explicitly synthetic evidence (not a real website scan). Actual model version and token usage: `r1/evidence/gemini-real.json`.
- Real OSV batch lookup succeeded for a known exact package/version fixture. That does **not** prove that any website runs that package: `r1/evidence/osv-real.json`.
- Genuine desktop/mobile browser screenshots and downloaded mock reports are under `r1/`.
- Real website-provider end-to-end verification must use an explicitly approved public origin. See the append-only **[R1 work record](R1.md)** and deployment status for the latest verified outcome. Never infer that a live scan passed from a mock test.

## Run

Python 3.12+:

```sh
python -m pip install -r requirements.txt
# Optional server-side AI credential. Never put a real key in browser code or Git.
export GEMINI_API_KEY='YOUR_PRIVATE_KEY'
export GEMINI_MODEL='gemini-3.5-flash-lite'
export LAUNCHSHIELD_DATA_DIR='./data'
# Exact approved public origins only; empty means mock mode remains available.
export LAUNCHSHIELD_LIVE_TARGETS='https://YOUR-OWNED-PUBLIC-WEBSITE'
uvicorn app:app --host 0.0.0.0 --port 8080 --workers 1
```

Open `/`. Choose **Mock fixtures** to exercise eight explicitly synthetic scenarios without contacting a target or scanner provider. **Real external providers** requires authorization, public-visibility acknowledgement, and an origin on the server allowlist. OSV skips when no reliable package identity/version was supplied by a supported provider; skipped is not a clean vulnerability result.

The opaque browser capability protects jobs without a signup/login/account system. A job ID alone does not authorize reading someone else's reports. Browser refresh retrieves job files; it does not repeat scan-start requests.

## Test

```sh
python -m pip install -r requirements-test.txt
python -m pytest -q
node --check static/main.js  # optional JS syntax verification
```

Automated unit/HTTP contract tests use fixtures and mocked transports. They require no production API key and must not silently fall back to live targets.

## Container / Koyeb

The included Dockerfile runs as an unprivileged user on `$PORT` (8080 by default), with a single Uvicorn worker and health endpoint `/healthz`. Configure `GEMINI_API_KEY` as a **runtime secret**, not a Git file. The application does not need GitHub, Koyeb, Vercel, Supabase or SSH credentials at runtime.

Use a single instance. The job manager and quotas are not a distributed multi-instance queue. Do not add more Uvicorn workers. No local ZAP/Nuclei, terminal, Redis, database or VPS is included.

On free/ephemeral hosting, sleeping/restarting/redeploying can interrupt jobs or erase files. Where files survive a restart, unfinished jobs are marked interrupted/failed rather than silently re-submitted. Where files do not survive, the UI reports the job unavailable instead of pretending it completed. Download JSON/HTML reports you need. Better Stack or a health ping does not provide persistence.

## Important implementation rules

- Target normalization removes path/query/fragment and rejects URL credentials and non-web ports. Public DNS and same-origin redirects are checked; this app's own HTTPS preflight pins the validated public IP while retaining Host/TLS SNI. External providers have their own DNS/scope controls.
- Per-provider quotas/cache and `Retry-After` are respected. No IP rotation or multi-account/key rotation to evade a limit. No duplicate scan-start on refresh. POST timeouts are not blindly retried.
- Website Auditor cache age is shown. SEO-only modules are not main security findings. MDN v2 summaries do not become invented per-header evidence.
- Source findings, severity, observation confidence and interpretation confidence remain linked after grouping. Provider scores are not averaged into a misleading security score.
- AI sees normalized selected evidence, not server credentials. AI output is schema-validated and can only reference existing finding IDs. It stays visibly separate from scanner evidence. AI failure cannot prevent report download.
- Treat provider output as untrusted. Cap response sizes, redact sensitive credential material, never execute provider/AI text, and escape evidence in HTML.
- Cancellation stops local pending work/polling; it cannot guarantee cancellation at an external provider that lacks such an API.
- Before public multi-user SaaS launch, confirm current provider terms, particularly xlogs/Vibe Check, and stronger domain ownership verification.

## Files

- `app.py` — API, capability/CSRF/origin guards, static one-page UI, downloads.
- `shield/harness.py` — bounded worker, per-provider progress, normalization/report lifecycle.
- `shield/providers.py` — five replaceable external provider adapters and file-backed quotas/cache.
- `shield/safety.py` — target scope, public DNS and redirect/SSRF protection.
- `shield/persistence.py` — isolated job files, atomic writes, event logs, redaction, expiry.
- `shield/normalize.py` — evidence-preserving normalization, overlap grouping, package provenance.
- `shield/ai.py` — optional server-side Gemini explanation with strict output validation.
- `static/` — simple HTML/CSS/JS, not the final visual design.
- `tests/` — isolated reproducible tests.
- `R1.md` / `r1/events.jsonl` — chronological actions and actual outcomes. Later product requests belong to a later owner-named revision.

**Do not add uploads, real `.env` files, runtime `data*` directories, credential attachments, private keys or browser session state to Git.**
