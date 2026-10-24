# R1 — provider cooldown and scan-dispatch fix

## Root cause: backend/release bugs, not just UI wording

1. **Fabricated restart cooldown.** The earlier updater wrote `website_trigger = deployment time + 1 hour`, plus short Vibe/MDN holds, without an actual sent request or upstream429. Replacing the instance restarted that hold and incorrectly blocked first Website Auditor triggers. The same flat configuration mixed provider-wide penalties with per-target intervals.
2. **Premature sent accounting.** `reserve()` appended an attempt and a target timestamp before constructing the HTTP client/request. Failure before transport could therefore consume dispatch budget or create a target interval without a sent request.
3. **Ambiguous lifecycle.** Cache GETs, scan starts, polling and received reports were not represented separately. A Website Auditor cache404 followed by a locally skipped trigger was flattened into one generic result.
4. **Cache/clock edge cases.** Future-dated local cache entries could suppress dispatch; malformed/naive cooldown values and restart behavior lacked complete acceptance coverage.

The prior real xlogs429/security-checkpoint penalty was **not** a fictional hold. Its absolute20:10:58UTC expiry was preserved, not cleared to force a test.

## Underlying changes

### Dispatch and cooldown accounting

- A capacity permit is not a sent request. Provider counters and target timestamps commit at confirmed HTTP transport-header dispatch, or at an actual response for alternate/injected transports.
- Connect/pool failures and locally blocked attempts do not increment sent counters. Uncertain partial writes are separately and conservatively budgeted; POSTs are never blindly retried.
- Provider-wide upstream penalties, global sent-request budgets, per-target intervals, in-flight permits and successful-report counters are distinct.
- xlogs stays60scans/IP/hour. Its optional deliberately configured local target interval defaults to0. Website Auditor/MDN keep hostname-based intervals, including legacyHTTP/HTTPS keys.
- A local skip is read-only for cooldown accounting: it never adds an attempt, updates the last dispatch, or changes the expiry.
- Stored UTC deadlines are absolute. Expired gates become eligible on the next user attempt; process recreation with the same files does not start a new window. Corrupt state/clock rollback fails explicitly instead of silently resetting budgets.

### Adapters and results

- Website Auditor: documented cached JSON endpoint → on404, one eligible documented `/report/{domain}` GET → bounded5polls/60seconds, with network/body size/deadline limits. Trigger-page200 is **not** a report.
- xlogs: documented `POST https://xlogs.com/api/v1/scan`, JSON `{"url": normalized_origin}`. Actual status/body metadata classifies429, checkpoint,5xx, invalid target, invalid JSON and transport failure.
- A report is received only after strict native schema validation. Invalid cached data is ignored and cannot permanently hide a required dispatch; a cache hit does not refresh its original storage age or sent counters.
- Logs/artifacts contain method, destination without query credentials, operation, dispatch time, status, response category, elapsed time, scan-sent/report-received flags and next allowed time. No raw headers, challenge tokens, cookies, secret values or executable HTML are logged.

### Release and UI

- `tools/cooldown_manifest.py` imports only verified upstream429/checkpoint or explicitly structured operator deadlines. It never computes `now + window` during deployment. The existing release helper and canonical Koyeb configuration use this function.
- No Website Auditor/Vibe/MDN fictional startup holds remain in the applied release configuration.
- The existing one-link/Test flow is preserved. Provider coverage explicitly separates `skipped_cooldown`, `request_sent`, `polling`, validated completion and failure.
- A **Retry test** button uses the existing authorized/CSRF-protected submission path, is disabled until the first eligible failure deadline, and becomes available without changing that deadline. It does not automatically send background scans.
- Refresh/reopen retrieves the saved job only. UI times are aligned to server time. HTML/JSON exports retain the same dispatch/report truth.
- SSRF, private/mixed DNS, pinned validation, single-origin redirects, permission/public-provider disclosure, CSRF/origin checks, anonymous report capabilities, response caps and real-only production settings are unchanged.

## Test evidence

**174 isolated tests passed**, including51 new dispatch/cooldown acceptance cases. These inject transports; they are not174 live website scans.

```sh
python -m pytest -q --disable-warnings --junitxml=r1/evidence/tests-dispatch-cooldown.xml
node --check static/main.js
python -m compileall -q app.py shield tools tests
```

| Required case | Evidence |
|---|---|
| First target, no cached report | Actual trigger/poll transport calls asserted; no default cooldown |
| Existing cached report | Cached JSON accepted; zero scan triggers |
| Active cooldown | Zero scan dispatches; unchanged sent count/file/deadline |
| Retry after expiry | Next POST/trigger reaches transport, no reinitialization |
|429,5xx, invalid target/JSON, timeout | Actual status/category, sent/report flags, bounded retry behavior |
| Repeated refresh/reopen | Status/report/events/artifact reads do not alter quota bytes or send requests |
| One provider fails | Other providers still return valid reports |
| Persistence/clock | Same-file recreation, absolute UTC/HTTP-date expiry, corrupt state and clock rollback |
| Deployment recurrence | Rebuilding a manifest later preserves the original deadline; no restart hold |

Detailed names and assertions: `tests/test_dispatch_acceptance.py`. Output/XML: `r1/evidence/tests-dispatch-cooldown.{txt,xml}`. Existing security/routing regressions remain green.

## Actual hosted verification — first attempt

Runtime `8f993435748179995a2c3d31e02e3c10b8915cf8`, same existing free service; deployment `e19ba3b8-edc1-4dc2-a8f7-b9c968a4de30` healthy.

Owned-origin browser job `e43ad16d127ed45dc88ee87fa00506ad`:

- Website Auditor cache GET404; **documented trigger actually sent at20:02:26UTC, HTTP200**, before the former bogus20:04:39 hold would have expired. Five report polls then returned404. Actual requests7, scan-starts1, valid reports0. No fabricated success.
- Its next trigger deadline is21:02:26UTC, derived from that actual sent trigger — **not** deployment, the last poll, refresh, or a blocked attempt.
- xlogs correctly remained `skipped_cooldown`, requests0/scan-starts0, next allowed20:10:58UTC, unchanged from the real prior penalty.
- Vibe and MDN independently returned valid reports; real Gemini completed. Incomplete coverage remains inconclusive.

Exact artifacts/events: `r1/evidence/dispatch-first-*`. The real Retry button became enabled after20:10:58UTC with no state reset, new deployment, or automatic background scan. A refresh restored the same first job and original deadline.

### Actual hosted verification — eligible retry

The user-facing **Retry test** action created job `c3443208cf2318c888baa0de151871f7` on the same deployment:

- xlogs **POST was actually dispatched at20:11:47UTC**, after the original expiry. It returned actualHTTP429 HTML Vercel security checkpoint. Its new21:11:48UTC deadline comes from that actual new response, not from the UI click or a locally blocked attempt. Requests1/scan-starts1/reports0.
- Website Auditor cache GET404 was dispatched. A duplicate trigger was correctly `skipped_cooldown` because of the **real first trigger**. Its deadline stayed exactly21:02:26.298216UTC before and after retry. Additional scan triggers0; no creeping cooldown.
- Vibe and MDN returned real reports again. Gemini returnedHTTP503 on this second job; evidence and downloads remained available. The first job's real AI explanation had completed. No key/provider fallback was used.
- Desktop/mobile screenshots were captured and visually inspected. Mobile390px/document390px; console0errors/0warnings; one input/no mode selectors, checkboxes or raw AI JSON.
- Browser network shows exactly **two scan submissions total**: the original Test and the explicit eligible Retry. Refreshes did not resubmit. HTML6544bytes/JSON29947bytes downloads match the server exactly, and the retry job was restored after reload.

Proof: `r1/evidence/dispatch-live-acceptance-proof.json`, `dispatch-browser-proof.json`, `dispatch-first-*`, `dispatch-retry-*`, and `dispatch-final-health.json`. Browser closed. No further provider call or replacement was used after verification.

## Files changed

- `shield/quotas.py` — separate gate/permit/sent/report accounting and persisted expiry.
- `shield/dispatch.py` — bounded secret-safe lifecycle and HTTP timing traces.
- `shield/providers.py` — actual transport commit, documented adapters, bounded polling/retries and strict report validation.
- `shield/persistence.py`, `shield/harness.py`, `shield/models.py`, `shield/diagnostics.py` — cache clocks, detailed artifacts/events, terminal states/settings and error classification.
- `tools/cooldown_manifest.py`, `docs/koyeb-service.json` — evidence-based absolute cooldown carry-over; no fabricated restart window.
- `app.py`, `static/index.html`, `static/main.js` — server time, truthful sent/report flags and working user-triggered retry; no security controls removed.
- `.env.example`, tests, R1 records and deployment/verification docs — configuration and reproducible evidence.

## Scope and persistence limits

This fixes **local dispatch/cooldown bugs**, not the third-party providers' ability to generate a report or allow API access. A sent request is not a received report. Provider failures are not a pass.

Files survive a process restart only while the underlying filesystem survives. A destroyed free-instance filesystem is not a durable quota database. Release carry-over uses verified absolute upstream penalties, never a guessed blanket cooldown. Do not redeploy to evade budgets or target intervals; preserve actual dispatch state or wait for its real expiry before another replacement. No database, persistent paid volume, extra service, new secret or IP/key rotation was introduced.
