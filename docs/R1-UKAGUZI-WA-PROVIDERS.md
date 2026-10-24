# R1 — kwa nini providers hawajibu vizuri?

**Uko sahihi: report iliyokuwa na coverage hii haikutosha kuitwa full security audit.** Nimekagua majibu halisi ya API, nikarekebisha makosa yetu ya kutafsiri matokeo, na kufanya jaribio moja kwenye website yetu wenyewe.

## Kilichothibitishwa

### 1. xlogs imezuiwa na security checkpoint

Tarehe 24 Oktoba 2026, saa **22:10 EAT**, server yetu ya Koyeb ilituma request ya kawaida baada ya cooldown kuisha. Jibu lilikuwa:

- HTTP **429**;
- **HTML**, si JSON ya scan;
- header `x-vercel-mitigated: challenge` — **Vercel Security Checkpoint**.

Code yetu ya zamani ilikuwa ikiita kila 429 “request limit”, ikaficha tofauti hii. Sasa inaitambua kama **blocked**. Kusubiri saa moja pekee hakuthibitishi kuwa itafunguka. Tunahitaji provider aruhusu API access hii, au provider mbadala aidhinishwe; sijajaribu kuvuka checkpoint au kubadilisha IP/key.

### 2. Website Auditor bado haina cached report

API inarudisha **404: hakuna cached report**. Jaribio la awali la njia yao iliyoandikwa kwenye docs halikuthibitisha kwamba scan ilikamilika.

Nimerekebisha kusoma response yao kikamilifu ndani ya size limit na kuongeza polling kutoka sekunde 20 hadi 60. Hili limepimwa kwenye tests za code, **si uthibitisho kwamba provider amepona**. Kwenye live recheck, trigger mpya haikutumwa kwa sababu ya cooldown ya ndani iliyohifadhiwa baada ya redeploy, ili tusireset quota kimyakimya.

### 3. Vibe inajibu, lakini baadhi ya checks hazijakamilika

Kwenye jaribio jipya:

- CORS: **41 kati ya probes 96 hazikupata HTTP result**;
- API checks: baadhi zili-timeout, na scanner ilisimama kwenye budget ya **requests 80**;
- headers na TLS zilirudi kwenye jaribio hili.

Pia nilipata kosa letu: data ya awali ya certificate yenye `0/unknown` bila tarehe halisi ilikuwa ikigeuzwa kuwa TLS finding. Sasa hiyo inawekwa **inconclusive**, si ushahidi wa certificate iliyo-expire. Data halisi ya provider haijafutwa.

Connection yetu ya kawaida ya validation ilihakiki certificate chain/hostname na expiry ya **20 Januari 2027**, bila kuongeza request nyingine ya scan. Huo ni uthibitisho wa connection hiyo, si usalama wote wa website.

### 4. MDN na OSV

**MDN ilijibu:** A+, checks 12 zimepita — kwa scope yake ya HTTP configuration tu. **OSV haikupimwa** kwa sababu hatukuwa na package/version ya kuaminika; hiyo si “hakuna vulnerabilities”.

## Kilichorekebishwa na kilichobaki

- Sababu halisi za failure, muda wa kusubiri na mipaka ya modules zinaonekana sasa.
- Coverage ikiwa pungufu, report na Gemini zinasema **Assessment incomplete / inconclusive**, si “website iko salama”.
- **Tests 123 za code zimepita.** Jaribio halisi lilipokea reports 2/4; hii si madai ya websites 123 zilizoscaniwa.
- Marekebisho yako live kwenye [LaunchShield R1](https://launchshield-r1-professorcj-43cf1823.koyeb.app).

**Bado si full penetration test.** Provider access/coverage iliyokosekana haijarekebishwa kwa kuongeza disclaimer au AI. Full security assessment itahitaji engine na scope ya ziada iliyoidhinishwa; haijaongezwa kimyakimya.

Jaribio langu lilikuwa kwenye website yetu, si target isiyoonekana kwenye screenshot yako. Ukinipa **Download JSON** ya report yako, naweza kukagua findings za website ile hasa. Usitume password, API key au session token.
