# R1 — user-reported missing providers and evidence reliability

## Why the earlier report was not sufficient

The user's screenshots correctly show an incomplete assessment. Returned configuration/header observations are real, but missing exposure/dependency checks and inconclusive modules cannot support a full website-security verdict. AI does not create missing test coverage.

## Evidence collected before changing code

### Website Auditor

Actual cached API reads returned **HTTP404**, JSON `No cached report. Run a scan first.` for the owned LaunchShield origin and for the API documentation's example. Earlier documented report-route requests did not yield an available cached report. A report-page200 is not proof that a scan was accepted or completed.

The old adapter described this as a generic timeout and immediately closed the trigger stream after headers. The corrected adapter drains the bounded documented response without parsing/scraping its HTML, polls5times over60seconds instead of20, records trigger/cache statuses and acceptance uncertainty, and reports `report_not_generated` separately from a network timeout. It never switches to browser scraping or an undocumented scan endpoint. Provider recovery is not claimed without an actual API report200.

### xlogs

The old adapter treated everyHTTP429 as a60/hour source-IP quota and discarded its body. Read-only diagnostics discovered **HTTP429 HTML Vercel Security Checkpoint**, not the documented API JSON. A GET with no target and no `x-xlogs-scan` header cannot initiate a scan under xlogs' documented contract. The initial diagnostic was from the test environment, not the Koyeb instance; it cannot prove what the historical Koyeb429 body contained.

The corrected adapter distinguishes a provider security checkpoint, real JSON quota response, and a local preserved cooldown where no request was sent. It records a bounded redacted receipt, HTTP/content type, retry time, error code and body hash; never stores challenge tokens/cookies/raw HTML, solves a challenge, rotates an IP/key/account or retries a scan-start POST. A gate is not fixed merely by waiting; provider-approved API access may be required.

Same-instance administrative exec attempts were unsuccessful and are not presented as production evidence. A short-lived operator-only non-scanning diagnostic was enabled on the first diagnostic deployment; its result was not exported. The final runtime disables that probe to prevent repeating it on replacement. The definitive current xlogs result must come from the ordinary owned-origin assessment after the known cooldown, not an alternate outbound identity.

### Vibe Check

The full native result is real but shows specific coverage limits:

- API surface stopped at its80-request scan budget.
- Some CORS probes had no HTTP result; those cases were not tested successfully.
- TLS key data was `unknown`/raw certificate unavailable.
- `certExpiry` returned `valid:false`, `daysUntilExpiry:0` with no actual certificate date.

Our normalizer previously promoted that unsupported expiry default to a medium provider signal. That was an evidence-quality defect. The corrected normalizer does not turn the missing/zero date into an expired-certificate finding; it retains the raw provider artifact and marks expiry inconclusive. Actual negative expiry-day evidence remains an unverified provider signal rather than being discarded.

An actual CA/hostname-verified connection to the owned origin at2026-10-24T18:52:14Z negotiatedTLS1.3 and showed certificate expiry2027-01-20T15:33:21Z, contradicting the zero-value signal. The same metadata is now captured from the existing strict IP-pinned scope-validation connection with **zero extra target requests**. It verifies that one connection, not every TLS setting or application vulnerability.

### MDN and OSV

MDN returned its real HTTP-configuration summary; a good grade is not a penetration-test result, and its current API does not provide dedicated TLS certificate data.

OSV is not a domain scanner. No trustworthy exact package/version means not tested/not applicable, never “no vulnerabilities”. It is not an API outage.

## Released correction

- Same existing R1 repository/app/service; no new app, worker, database, paid plan or unrelated resource change.
- Public page remains one link field/Test, automatic real providers/Gemini/report cards; no mocks or mode controls.
- Missing/unknown coverage is visibly **Assessment incomplete / Security result: inconclusive** before the AI explanation.
- Provider reasons, not-before times, module coverage and direct connection provenance are readable.
-123isolated tests passed, including23new diagnostic/reliability contracts. These are not123live websites.
- HTTP/HTTPS now share hostname-based Website Auditor/MDN throttle keys, including legacy stored-key continuity.
- Known cooldowns survive replacement. Because an exact prior per-target trigger snapshot could not be obtained, Website Auditor received a conservative one-hour restart guard rather than silently resetting its budget; cached reads still run. This is a local protection, not an assertion that the provider itself imposed that exact time.
- No active injection, authentication, business-logic or exploit testing has been added. A full audit would require a separately approved, scoped engine/worker and a different coverage promise.

## Current ordinary live recheck

The actual browser-created job `d716a1b2c93c3b976e189d13943c27d1` ran against the **owned LaunchShield origin only**, after the preserved xlogs not-before time19:10:28UTC. Runtime `c2172b41dae3f8d182bb2e8365ea1d091ea5267c`, deployment `6474a91f-b1e7-48e3-a953-7facad6bbda1`, healthy/root200/health200.

- At19:10:58UTC the normal Koyeb-backed **POST** to xlogs returned429, `content-type:text/html`, `x-vercel-mitigated:challenge`, classified `provider_security_checkpoint`. This is definitive current same-service evidence, not a sandbox-IP assumption. The scan-start POST was not retried; provider-approved API access or an explicitly approved replacement is needed. Waiting alone does not establish recovery. Historical discarded bodies remain unknown.
- Website Auditor's cached read still returned404. The fresh trigger was **not sent** because of the conservative local restart guard until20:04UTC. That exact time is a local safety carry-over, not an asserted upstream Retry-After. The draining/longer-poll correction is unit-verified, **not a claimed live Website Auditor recovery**.
- Vibe returned a full real result. In this new result headers/TLS were complete; CORS had55 HTTP results and41/96 unknown probes. API surface reported timeouts and stopped after80 requests. Its RSC-only advisory check was not applicable, not a general all-CVE clean result.
- MDN returnedA+, score115,12passed/0failed for its limited configuration tests. OSV was skipped for lack of trustworthy package/version input.
- Direct strict TLS handshake at19:10:58UTC verified chain/hostname, TLS1.3 and certificate expiry2027-01-20T15:33:21UTC. No added target request.
- Real Gemini completed. Normalized signals0, but the conclusion is explicitly **inconclusive**, not “no vulnerabilities”.
- Actual desktop/mobile screenshots captured **and inspected**. Mobile390px/document390px; no horizontal overflow; field1/selectors0/checkboxes0/raw-code blocks0; console0errors/0warnings.
- Actual browser HTML5486bytes/JSON8877bytes match the server report exactly. Reload restored the same job, with **one original browser scan POST total**. Browser closed. No further provider scan or deployment was performed afterward.

See `docs/deployment.json`, `r1/evidence/provider-diagnosis-*` and the append-only R1 record. Screenshots did not reveal the user's original target/job, so no claim is made that this owned-origin test is a re-scan of that unknown target.
