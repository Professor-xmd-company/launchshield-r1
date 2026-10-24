# LaunchShield R1

**Website link → Test → real website checks → automatic AI report cards.**

- **Website:** https://launchshield-r1-professorcj-43cf1823.koyeb.app
- **Source:** https://github.com/Professor-xmd-company/launchshield-r1
- **Revision/work record:** [R1.md](R1.md) and `r1/events.jsonl`.

## The public website

One website-link field and a **Test** button. No execution modes, scenarios, checkboxes, AI switches, provider dashboard, raw AI JSON, accounts or manual report loading.

Pressing Test automatically runs real public/read-only provider checks, then Gemini explains the returned evidence. A readable AI overview and finding cards appear on the same page. Download a readable HTML report or the full evidence JSON if needed. A failed/unavailable provider is disclosed; it never becomes a fake pass or an overall security score.

**Production rejects mock scan requests.** Synthetic adapters remain only for isolated automated tests, explicitly enabled in their test fixtures. They are not public website features and are never a fallback for real scans or AI failures.

### Authorized public websites

The deployed service accepts public website origins after a clearly displayed click-through ownership/permission and public-provider disclosure. There is no old restriction to scanning LaunchShield itself. This is self-declared permission, not proof of domain ownership; only test websites you own or are explicitly authorized to assess.

Private/loopback/link-local/cloud-metadata addresses, non-public DNS results, invalid ports, URL credentials and redirects outside the submitted origin remain blocked. The app's own preflight pins validated IPs while retaining Host/TLS SNI. External providers apply their own scope/DNS controls. Only the normalized website origin is sent, not URL query strings or fragments.

## Run

Python3.12+:

```sh
python -m pip install -r requirements.txt
export GEMINI_API_KEY='YOUR_PRIVATE_SERVER_KEY'
export GEMINI_MODEL='gemini-3.5-flash-lite'
export LAUNCHSHIELD_DATA_DIR='./data'
export LAUNCHSHIELD_ALLOW_PUBLIC_TARGETS=true
export LAUNCHSHIELD_ALLOW_MOCK=false
uvicorn app:app --host 0.0.0.0 --port 8080 --workers 1
```

For an operator-restricted installation, set `LAUNCHSHIELD_ALLOW_PUBLIC_TARGETS=false` and `LAUNCHSHIELD_LIVE_TARGETS` to exact approved origins. Never put a real credential in frontend code, `.env.example`, a README or a commit.

The application needs only its Gemini runtime secret. It does not need GitHub, Koyeb, Vercel, Supabase or SSH credentials at runtime.

## Verification

- **100 isolated tests passed**: lifecycle, provider contracts, real-only defaults, production mock rejection, automatic AI, public submission permission, DNS/SSRF/redirect guards, private capabilities, exports, cache age, quota handling and readable/escaped reports.
- Tests inject fixtures/transports. They do not mean100 websites were scanned and need no production key.
- Genuine previous owned-origin assessments verified MDN, full Vibe retrieval and Gemini. They also exposed actual provider limits/failures and a corrected Vibe agent-summary contract. Original failures remain preserved rather than rewritten.
- The simplified real-only UI is being reverified against the deployed revision; actual current outcome, screenshots and source pin are in `docs/deployment.json` and the append-only R1 record. Do not treat a fixture/test run as a live scan.

```sh
python -m pip install -r requirements-test.txt
python -m pytest -q
node --check static/main.js
```

## Evidence, AI and provider limits

- Four website providers: Website Auditor, xlogs, Vibe Check and MDN Observatory. OSV is queried only for reliable exact package/version evidence; otherwise it is explicitly not applicable, not a clean vulnerability result.
- Quotas and `Retry-After` are respected. No blind scan-start POST retries, IP rotation, account/key rotation or quota reset workaround.
- Optional `LAUNCHSHIELD_PROVIDER_COOLDOWNS` carries known provider not-before times across an ephemeral redeploy. It is operator configuration, not a UI control.
- Vibe agent summaries are not complete findings: retrieve the full result using the existing scan ID when required. Preserve native timestamps, confidence, partial/unknown module coverage and original evidence.
- Website Auditor cache age is retained; SEO-only modules are not security findings. MDN summary grades do not become invented per-header vulnerabilities. Provider scores are not combined into a security guarantee.
- AI is automatic but separate from observed evidence. Its structured output can only reference supplied finding IDs. It receives no server credentials. Provider output is untrusted; nothing in it is executed. AI failure cannot block evidence downloads.
- Provider signals can be wrong: a Vibe certificate-expiry signal conflicted with an independently CA/hostname-verified TLS handshake showing expiry2027-01-20. It remains labelled provider-reported/potential, not independently confirmed. Verify before changing configuration or following AI remediation.

## Hosting and privacy

No accounts or database. Private anonymous browser/job capabilities protect reports; knowing a job ID is not sufficient. Reload retrieves stored files without resubmitting checks. One instance, one worker, bounded concurrency and queue. No command runner, ZAP/Nuclei, authenticated testing, exploitation, Redis or VPS.

File-backed reports can expire/disappear on sleep, restart or redeploy. Download what you need; browser history is not a database or a recovery guarantee. Free Koyeb sleep policy is preserved, with no paid upgrade.

Only the owner-authorized old `professor-xmd` app was removed. Protected `database`, Supabase, other repositories and shared tokens were not modified.

## Source and records

- `app.py` — API, private capabilities, CSRF/origin guards and downloads.
- `static/` — the simple live URL/Test/report-card page.
- `shield/harness.py` — worker orchestration and report generation.
- `shield/providers.py` — provider requests, quotas, cache and bounded polling.
- `shield/safety.py` — public DNS, IP pinning and redirect/SSRF guards.
- `shield/normalize.py` — native evidence/confidence, grouping and package provenance.
- `shield/ai.py` — server-side Gemini explanation and schema validation.
- `tests/` — isolated regressions, never hosted demo results.
- `docs/deployment.json` — actual owned resource IDs, code pin and verification metadata; no secret values.
- `R1.md`, `r1/events.jsonl`, `r1/evidence/`, `r1/screenshots/` — chronological actions, failures and genuine evidence. Older harness screenshots are historical, not the current UI.

Never commit `data*`, browser capability state, credentials, uploaded handoff files or private keys.
