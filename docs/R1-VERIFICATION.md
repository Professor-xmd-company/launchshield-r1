# R1 — simple real-only website testing

## Current website

https://launchshield-r1-professorcj-43cf1823.koyeb.app

**Website link → Test → real read-only checks → automatic AI report cards on the same page.**

One blank website-link field and one Test button initially. No execution/scenario selectors, permission checkboxes, AI switch, provider dashboard, raw AI JSON, manual report generation or accounts. Clicking Test attests to the plainly displayed ownership/permission and public-provider disclosure. Accepts authorized public website origins, not just LaunchShield itself. Bare hostnames automatically receive HTTPS.

## Latest provider-reliability verification —2026-10-24

The current runtime is `c2172b41dae3f8d182bb2e8365ea1d091ea5267c`, deployment `6474a91f-b1e7-48e3-a953-7facad6bbda1`, HEALTHY/root200/health200. **123isolated tests passed**. See [provider diagnosis](R1-PROVIDER-DIAGNOSIS.md) for exact causes, fixes and unresolved provider limitations.

Actual current owned-origin browser job `d716a1b2c93c3b976e189d13943c27d1`: one hostname/Test click after the preserved xlogs window. xlogs returned a confirmed server-side429 HTML Vercel security checkpoint, not a presumed JSON hourly quota. Website Auditor cached read404/new trigger held by a preserved local restart guard. Vibe/MDN returned real reports; Vibe CORS41/96 unknown and API80-request cap/timeouts remain partial. OSV not tested without exact packages. Real Gemini completed; signals0 is **inconclusive, not clean**. An unsupported missing/zero Vibe expiry is no longer a vulnerability finding; native evidence remains unchanged. Existing strict connection validation recorded real CA/hostname-verifiedTLS1.3, expiry2027-01-20.

Genuine current screenshots under `r1/screenshots/provider-diagnosis-*` were captured and visually inspected. Viewport/document390/390; no selectors/checkboxes/raw AI code; console0. Actual browser HTML5486bytes/JSON8877bytes match the server. Reload restored the same job with1original browser scan POST total. Final optional operator startup probe is disabled. No further deploy/scan after verification; docs-only pushes do not deploy.

## Historical first simple-flow test


- Runtime code: `9f74ea1a384293bad975ac755edbf085bb740f56`.
- Same existing app/service; deployment `26d65f6a-01ba-4318-a378-7c60a08243de`, healthy/root200/health200.
- Runtime: real execution, public targets enabled, production mock execution disabled, Gemini configured. A tampered mock POST was actually rejected422 without a synthetic job.
- Browser job `5d6028ce93d5d5aa5877df78a309889f`: entered the owned LaunchShield hostname without HTTPS and clicked Test exactly once. No other person's website was scanned.
- Real MDN and Vibe reports returned. Website Auditor timed out; xlogs returned429. OSV not applicable because no reliable exact package version was detected.
- Gemini actually completed. Its overview and finding card appeared automatically without a second user action.
- Finished with partial coverage, honestly displayed as **Limited coverage /2 of4 website reports received**. No fake fallback or overall secure score.
- At that historical time, one provider-reported potential TLS signal was unconfirmed. The current correction described above excludes the unsupported missing/zero-date finding. The AI says verify first and do not order immediate certificate renewal. An independent CA/hostname-verified TLS check previously showed expiry2027-01-20, contradicting the potential Vibe signal; no certificate configuration was changed.

## Genuine browser evidence

All captured from the actual deployed website and visually inspected:

- `r1/screenshots/simple-real-only-empty-desktop.png`
- `r1/screenshots/simple-real-only-progress.png`
- `r1/screenshots/simple-real-only-report-desktop.png`
- `r1/screenshots/simple-real-only-report-mobile.png`
- `r1/screenshots/simple-real-only-mobile-viewport.png`

Mobile viewport/document width390/390, no horizontal page overflow. Field1, selectors0, checkboxes0, raw code blocks0. Browser console0errors/0warnings.

Actual browser downloads match server evidence exactly: HTML6384bytes, JSON7963bytes. HTML is a readable AI overview/finding-card report. JSON retains normalized source evidence.

Reload automatically retrieved the same stored job/report; browser network log contains only the original1scan POST. An early measurement sampled while the asynchronous report fetch was pending; that transient evidence is preserved. Waiting for the visible report heading returned the actual same job ID, reportVisible=true and progressHidden=true. A subsequent audit assertion assumed spaced JSON, but the CLI returned compact JSON; parsing its actual JSON confirmed success. No new scan or manual report loading was used.

## Automated verification

**100 isolated tests passed**, Python compile and JS syntax checks passed.18 added contracts cover real/AI defaults, production mock rejection, public input, permission/disclosure, private/mixed DNS and redirect rejection, the one-input page and readable escaped HTML. Existing82 remain green.

These are injected fixture/transport tests, not100 live websites or hosted demo modes. First expanded run caught consent metadata being secret-redacted; renamed the safe enum to `consent_method` without weakening Authorization-header redaction. All meaningful failures/fixes remain recorded under R1.

## Limits and protections

Provider results can be unavailable, stale, partial or wrong. OSV skipped is not a clean result. AI interpretation is not scanner evidence. No exploitation or security guarantee.

Public DNS/private-address checks, IP pinning and single-origin redirects remain enforced. Anonymous private capabilities, CSRF/origin guards and bounded quotas remain active. Newly observed provider cooldowns are recorded for future same-service updates; the current pod retains its private quota files. No extra scan, redeploy or IP/key/account rotation was used to bypass failures.

One existing free Koyeb instance/worker, native min0/max1sleep policy. No paid upgrade, database or extra app/service. Other protected workloads, repositories and shared secrets were not altered. Reports are temporary and may disappear on restart/sleep/redeploy/expiry: download a copy.

Runtime remains pinned to the verified code; evidence-only Git pushes do not deploy. See `R1.md`, `r1/events.jsonl`, `docs/deployment.json` and `r1/evidence/simple-real-only-*`. Older harness screenshots are historical, not the current public UI.
