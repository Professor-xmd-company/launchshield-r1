# LaunchShield R1 — Hali ya uwasilishaji

**24 Oktoba 2026 · Logic-first prototype · si full pentest**

## Fungua

- **Website live:** https://launchshield-r1-professorcj-43cf1823.koyeb.app
- **Repo mpya:** https://github.com/Professor-xmd-company/launchshield-r1
- **Rekodi yote ya R1:** https://github.com/Professor-xmd-company/launchshield-r1/blob/main/R1.md
- **Code inayotumika Koyeb:** `869ffca6cfd24b770cbcb88c67c4415995173578`.

Page moja ya kawaida imejengwa: hakuna signup/login/accounts, hakuna database, wala redesign kubwa. Koyeb deployment ni **HEALTHY**; `/` na `/healthz` zimerudisha **HTTP 200**. Instance ni free, moja tu kwa wakati, na inafuata sleep policy ya Koyeb. Hakuna paid upgrade au VPS iliyotumika.

## Vipimo vilivyofanyika

- **82 isolated tests zimepita**; hizi hutumia mocks/fixtures na recorded-native responses, si madai kwamba websites 82 zimescaniwa.
- **Checks 9 za HTTP halisi zimepita:** page/assets, routes zisizopo za accounts, private-target rejection, cross-origin protection, na kutoruhusu kusoma ripoti kwa job ID pekee.
- Assessments halisi zimetumia **LaunchShield hii mpya yenyewe tu**, si app/domain za zamani wala private preview.
- Gemini **`gemini-3.5-flash-lite`** imezalisha explanations halisi. Key iko backend kupitia runtime secret; si frontend, README au commit.
- Nimechukua na kufungua screenshots halisi za desktop na simu. Tatizo la maandishi kupita upana wa simu lilirekebishwa na ku-deployiwa: viewport 390px, document 390px. Jedwali la providers pekee lina scroll yake.
- Nimebonyeza downloads kwenye browser: JSON **8,375 bytes**, HTML **7,848 bytes**; yaliyopakuliwa yamelingana na ripoti ya server.
- Reload imerudisha job ileile bila kuanzisha scan nyingine. Browser session imeonyesha POST moja ya kuanzisha scan na **console errors 0/warnings 0**.

## Matokeo halisi ya providers — coverage bado ina mapungufu

| Provider | Matokeo yaliyothibitishwa |
|---|---|
| MDN Observatory | Ripoti halisi imepokelewa. Hii si uthibitisho wa usalama wote wa app. |
| Vibe Check Scan | Full result imepokelewa baada ya kurekebisha agent-summary contract. API-surface coverage ni partial; timeouts/path limits zimehifadhiwa. |
| xlogs | Jaribio la kwanza lilirudisha HTTP 429. Cooldown imeheshimiwa hata baada ya redeploy; hakuna IP/key/account rotation. |
| Website Auditor | Cached report iliendelea kurudisha 404 baada ya trigger moja na bounded polling. Trigger haijarudiwa ndani ya cooldown. |
| OSV | Imekuwa `skipped_not_applicable`: hakuna ushahidi wa kuaminika wa exact package/version. Hii si clean vulnerability result. Real OSV fixture lookup ya awali imehifadhiwa tofauti. |
| Gemini | Explanation halisi imekamilika; imetenganishwa na scanner evidence. AI haizuii downloads ikishindwa. |

Hali ya assessment ya mwisho ni **`completed_with_warnings`**, si “providers zote zimepita.”

### Tahadhari kuhusu TLS signal

Vibe imeripoti `certExpiry` kama **provider-reported/potential**, si vulnerability iliyothibitishwa. TLS handshake moja ya kujitegemea ilifaulu CA/hostname verification na kuonyesha certificate expiry **20 Januari 2027**. Huo ni ushahidi unaokinzana unaohitaji review; haujafutwa au kufichwa. **Usichukulie pendekezo la AI la kurekebisha certificate kuwa uthibitisho au idhini ya kubadilisha Koyeb-managed TLS.** Hakuna certificate iliyobadilishwa.

## Jinsi ya kujaribu

1. Fungua website. **Mock fixtures** zina scenarios 8 bila external scans.
2. **Real external providers** kwa R1 hii imewekewa allowlist ya origin ya LaunchShield yenyewe. Origin nyingine inahitaji approval na server allowlist; checkbox peke yake haitoi ruhusa ya kuscan domain nyingine.
3. Thibitisha ownership/permission na public/cached provider visibility kabla ya real assessment.
4. Angalia actual provider states, evidence/confidence na timestamps; pakua ripoti unayohitaji.

## Ulinzi wa resources na limitations

- **`professor-xmd` pekee imefutwa kwa idhini yako**, na GET yake imethibitishwa 404.
- `database` app pamoja na service yake ya awali zipo; zote zimethibitishwa HTTP 200. Supabase, repos nyingine na existing tokens hazijaguswa.
- Hakuna database ya LaunchShield: ripoti ni temporary per-job files. Sleep/restart/redeploy au expiry inaweza kuzipoteza. Browser history si report database; hakuna permanent archive/recovery guarantee.
- Hii ni passive/read-only, public/unauthenticated assessment; hakuna terminal, exploitation, ZAP/Nuclei, authenticated scan au overall security guarantee.

## Mahali pa ushahidi kwenye repo/workspace

- `R1.md`, `r1/events.jsonl` — hatua, matokeo, failures na marekebisho ya R1.
- `r1/evidence/tests-release.txt` / `.xml` — 82 passing isolated tests.
- `r1/evidence/live-final-*` — actual final job, provider-native artifacts, events na exports.
- `r1/evidence/browser-download-final.json` / `.html` — downloads halisi za Chromium.
- `r1/evidence/browser-final-*` — layout, reload, requests na console checks.
- `r1/evidence/tls-independent-check.json` — independent TLS observation.
- `r1/evidence/protected-resources-final.json` — scoped cleanup/protection/free-quota verification.
- `r1/screenshots/koyeb-completed-desktop.png`, `koyeb-completed-mobile.png`, `koyeb-mobile-viewport.png` — final inspected screenshots.
- `docs/deployment.json`, `docs/koyeb-service.json` — actual resource/config metadata; hakuna secret value.

**R1 imewasilishwa kama prototype inayofanya kazi, yenye limitations zilizo wazi. Urembo wa full product bado haujafanywa, kama ulivyoelekeza.**
