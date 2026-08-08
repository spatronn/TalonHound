# Missing Auth/Authz Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis only (no live exploit traffic)  
**Scope note:** Admin/analyst privilege does not eliminate impact; prerequisites are stated per finding. Focus is unauthenticated access and **vertical** privilege escalation (not IDOR).

## Executive Summary

- Endpoints / authz surfaces analyzed: **28**
- Vulnerable (Confirmed): **5**
- Likely Vulnerable (Probable): **2**
- Not Vulnerable (Rejected): **21**
- Needs Manual Review: **0**
- N/A: **0** (class applies; HTTP session/API-key authz surfaces exist)

| Bucket | Count | Finding IDs |
|---|---|---|
| Confirmed | 5 | AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05 |
| Probable | 2 | AUTH-06, AUTH-07 |
| Rejected | 21 | (see Rejected) |
| N/A | 0 | — |

Skill tag map: Confirmed → `[VULNERABLE]`; Probable → `[LIKELY VULNERABLE]`; Rejected → `[NOT VULNERABLE]`.

---

## Confirmed

### [VULNERABLE] AUTH-01 — IPinfo Lite admin config mutations lack `requireRole(ADMIN)`

- **Finding ID:** AUTH-01
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-863 (Incorrect Authorization); CWE-285
- **Files:lines:**
  - `backend/routes/ipEnrichment.js:454-513` (`PUT .../ipinfo-lite`)
  - `backend/routes/ipEnrichment.js:515-541` (`POST .../test`)
  - `backend/routes/ipEnrichment.js:543-562` (`POST .../remove-key`)
  - Contrast: `backend/routes/abuseipdbEnrichment.js:236+` / `spamhausDropEnrichment.js:203+` use `requireRole(ROLES.ADMIN)`
  - `backend/lib/rbac.js:73-96` (`rbacHttpPolicy` only blocks `readonly`, not analyst)
- **Entry point:** `PUT|POST /api/admin/enrichment-providers/ipinfo-lite` (+ `/test`, `/remove-key`)
- **Prerequisites / role:** Authenticated session (cookie) as **analyst** (or any non-readonly role). UI intentionally enables IPinfo forms for `canWrite` (analyst), while AbuseIPDB/Spamhaus UI are admin-only — backend matches UI for IPinfo, not the `/api/admin` + peer-provider admin gate.
- **Data flow:** Analyst session → `apiAuthGate`/`rbacHttpPolicy` (allows analyst writes) → handler with **no** `requireRole(ADMIN)` → writes `threat_intel_provider_configs` (`api_key` / `config.base_url`).
- **Impact:** Analyst can enable/disable provider, set token, clear token, and set arbitrary `base_url` (ties to SSRF-03). Vertical escalation into enrichment secret and outbound base configuration that sibling providers restrict to admin.
- **Safe verification procedure (static only):**
  1. Confirm route registrations for IPinfo PUT/test/remove-key have no `requireRole(...)`.
  2. Confirm AbuseIPDB/Spamhaus PUT use `requireRole(ROLES.ADMIN)`.
  3. Confirm `rbacHttpPolicy` returns `next()` for `role !== readonly`.
  4. Do not live-probe with stolen tokens against production.
- **Expected secure behavior:** Same admin gate as other enrichment provider admin routes (`requireRole(ADMIN)`).
- **Remediation direction only:** Add `requireRole(ROLES.ADMIN)` (or equivalent) on all IPinfo admin mutate/test/remove routes; align UI to admin-only.
- **Regression tests later:** Yes

### [VULNERABLE] AUTH-02 — VirusTotal admin config mutations lack `requireRole(ADMIN)`

- **Finding ID:** AUTH-02
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-863; CWE-285
- **Files:lines:**
  - `backend/server.js:6245-6265` (`PUT /api/admin/enrichment-providers/virustotal`)
  - `backend/server.js:6267-6269` (`POST .../virustotal/remove-key`)
  - `backend/server.js:6272-6301` (`POST .../virustotal/test`)
  - `frontend/src/components/EnrichmentProvidersPage.jsx:399-441` (VT forms gated by `canWrite`, not `isAdmin`)
- **Entry point:** `PUT|POST /api/admin/enrichment-providers/virustotal` (+ remove-key, test)
- **Prerequisites / role:** Authenticated **analyst** (non-readonly). Session auth only; CSRF applies for cookie clients.
- **Data flow:** Analyst → global auth gate → no role middleware → upsert/clear VT `api_key` and TTL/timeout in `threat_intel_provider_configs`.
- **Impact:** Analyst can install/replace/remove the shared VirusTotal API key and change provider enablement — admin-tier secret/config control without admin role.
- **Safe verification procedure (static only):** Diff VT handlers against AbuseIPDB `requireRole(ADMIN)`; note absence of role middleware on VT registrations.
- **Expected secure behavior:** Admin-only mutation of shared enrichment API keys.
- **Remediation direction only:** Apply `requireRole(ROLES.ADMIN)` consistently; tighten UI to `isAdmin`.
- **Regression tests later:** Yes

### [VULNERABLE] AUTH-03 — JWT Bearer auth bypasses `rbacHttpPolicy` readonly write lock

- **Finding ID:** AUTH-03
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-863; CWE-284
- **Files:lines:**
  - `backend/lib/rbac.js:71-78` (`if (req.authVia === 'ingest' || req.authVia === 'bearer') return next();`)
  - `backend/lib/auth.js:160-176` (Bearer JWT when `ALLOW_JWT_BEARER=1`)
  - `backend/lib/auth.js:207` (CSRF also skipped for bearer)
- **Entry point:** Any mutating `/api/*` route that relies on `rbacHttpPolicy` alone (no `requireRole` / no in-handler role check) — e.g. `POST /api/ioc/ip`, integration credential/schedule writes, VT/IPinfo PUTs, etc.
- **Prerequisites / role:** `ALLOW_JWT_BEARER=1`; valid JWT for a **readonly** (or otherwise low-privilege) user presented as `Authorization: Bearer`.
- **Data flow:** Bearer verify → `req.authVia='bearer'`, `req.user.role` from claim → `rbacHttpPolicy` skips readonly enforcement → handler runs writes.
- **Impact:** Readonly (and any role) Bearer clients escape the documented GET/HEAD-only policy, achieving vertical write privilege equal to analyst on ungated mutate routes. Cookie sessions remain correctly blocked.
- **Safe verification procedure (static only):** Trace `rbacHttpPolicy` early-return for `authVia === 'bearer'`; confirm cookie path still blocks readonly POST. No live attacks required.
- **Expected secure behavior:** Role policy applies uniformly regardless of cookie vs Bearer transport; Bearer should not weaken RBAC.
- **Remediation direction only:** Remove bearer exemption from `rbacHttpPolicy` (keep CSRF exemption if needed); enforce role on Bearer the same as cookie.
- **Regression tests later:** Yes

### [VULNERABLE] AUTH-04 — Ingest token: `rbacHttpPolicy` bypass + `isAdminUser` gap vs `requireRole` ingest deny

- **Finding ID:** AUTH-04
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-863; CWE-288 (Authentication Bypass Using an Alternate Path) for function-level controls
- **Files:lines:**
  - `backend/lib/auth.js:144-157` (ingest → synthetic `role: ADMIN`, `authVia: 'ingest'`)
  - `backend/lib/rbac.js:48-58` (`requireRole` **rejects** ingest)
  - `backend/lib/rbac.js:77-78` (`rbacHttpPolicy` **allows** ingest through)
  - `backend/server.js:2770-2772` / `backend/routes/iocDelete.js:3-9` (`isAdminUser` checks role only — **does not** reject ingest)
- **Entry point:** Machine header `X-Api-Ingest-Token` against routes without `requireRole`, including:
  - All mutate routes that only depend on `rbacHttpPolicy`
  - Admin-ish handlers gated only by `isAdminUser(req)` (e.g. `DELETE /api/ioc/:publicId`, `/api/admin/tags*`, IOC suppressions, `/api/admin/ioc-evidence-coverage`)
- **Prerequisites / role:** Knowledge of configured `API_INGEST_TOKEN` / `API_BEARER_TOKEN` env secret.
- **Data flow:** Valid ingest header → synthetic admin user → CSRF skipped → readonly policy skipped → `requireRole` would 403, but many privileged handlers never use it → action succeeds.
- **Impact:** Intentional machine credential is documented as blocked by `requireRole`, yet parallel admin checks (`isAdminUser`) and ungated writes remain callable — incomplete function-level authorization / alternate path to admin functions (hard IOC delete, tag admin, suppressions, enrichment config, feed credentials, etc.).
- **Safe verification procedure (static only):** Compare `requireRole` ingest deny with `isAdminUser` and no-role routes; list reachable admin operations under ingest.
- **Expected secure behavior:** Single privilege decision for ingest (deny all interactive admin, or an explicit allowlist of automation endpoints).
- **Remediation direction only:** Reject ingest in `isAdminUser`/shared admin helpers, or route ingest only through scoped handlers; do not treat synthetic admin as UI-admin for `isAdminUser` paths.
- **Regression tests later:** Yes

### [VULNERABLE] AUTH-05 — Unauthenticated `POST /api/setup/complete` can finish timezone setup on existing installs

- **Finding ID:** AUTH-05
- **Severity:** Medium
- **Confidence:** High
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Files:lines:**
  - `backend/lib/auth.js:232-238` (`apiAuthGate` skips auth for setup status/preview/complete)
  - `backend/routes/setup.js:90-110` (`POST /api/setup/complete` — no login)
  - `backend/lib/systemTime.js:386-415` (`completeInitialSetup` only 409 when already completed **and** runtime-ready)
  - `backend/lib/systemTime.js:296-368` (existing install may set `timezone_configuration_required` with `initial_setup_completed=FALSE` while users/IOCs already exist)
  - Contrast: `PUT /api/system/timezone` requires session + in-handler admin check (`setup.js:138-143`)
- **Entry point:** `POST /api/setup/complete` (public)
- **Prerequisites / role:** App in initial setup **or** existing-install `TIMEZONE_CONFIGURATION_REQUIRED` / incomplete timezone runtime (users may already exist). Network reachability to backend.
- **Data flow:** Unauthenticated POST → `completeInitialSetup` updates `system_settings` timezone flags → unlocks API (`createSetupGate` allows traffic once runtime-ready).
- **Impact:** On existing deployments waiting for admin timezone configuration, an anonymous client can set the system timezone and clear the gate without admin authentication, bypassing the admin-only `PUT /api/system/timezone` path. Fresh first-run exposure is expected but still unauthenticated critical config.
- **Safe verification procedure (static only):** Confirm gate skip + lack of auth on complete; confirm `completeInitialSetup` allows write when `initial_setup_completed` is false even if installation is “existing”; confirm admin PUT path is separate.
- **Expected secure behavior:** After users exist / `timezone_configuration_required`, only authenticated admins may complete timezone adoption; public complete limited to true greenfield.
- **Remediation direction only:** Bind public complete to greenfield-only checks; require admin session when installation is “existing”.
- **Regression tests later:** Yes

---

## Probable

### [LIKELY VULNERABLE] AUTH-06 — Built-in integration secret/control mutations without `requireRole`

- **Finding ID:** AUTH-06
- **Severity:** Medium
- **Confidence:** Medium
- **CWE:** CWE-863
- **Files:lines:**
  - `backend/server.js:1754-1806` (`POST /api/integrations/run-now`)
  - `backend/server.js:1808+` (`POST /api/integrations/:key/run-now`)
  - `backend/server.js:1863+` (`PATCH .../active` — custom feeds extra-gated via `assertCustomFeedSettingsAllowed`)
  - `backend/server.js:2088+`, `2181+`, `2249+`, `2353+`, `2424+` (trust-level / schedule / default-confidence / **credentials** / credentials test)
  - `backend/lib/customThreatFeedAccess.js:12-18` (custom feed keys admin-only; **vendor** feeds remain analyst-writable by design comment)
- **Entry point:** Integration control and credential APIs under `/api/integrations/...`
- **Prerequisites / role:** Authenticated **analyst** (cookie); or ingest/Bearer per AUTH-03/04.
- **Data flow / concern:** No `requireRole(ADMIN)` on vendor feed credential rotation and many control planes; only `rbacHttpPolicy` blocks readonly. Product comments suggest analyst write access is intentional for vendor feeds, but rotating outbound `auth_key` secrets is admin-tier in practice (and inconsistent with enrichment admin providers that require admin).
- **Impact:** Analyst can change feed auth keys, schedules, enable/disable vendor feeds, and trigger runs — potential over-privilege if policy intent is admin-only for secrets.
- **Safe verification procedure (static only):** Confirm absence of `requireRole` on credentials PUT; confirm Analyst is not blocked by `assertCustomFeedSettingsAllowed` for non-`ctf-*` keys.
- **Expected secure behavior:** At least credential write (+ maybe schedule) restricted to admin; triage actions separately allowlisted.
- **Remediation direction only:** Split “triage trigger” vs “secret/config” routes; add `requireRole(ADMIN)` to credential and sensitive settings.
- **Regression tests later:** Yes

### [LIKELY VULNERABLE] AUTH-07 — `GET /api/api-keys` lists key inventory for any authenticated role

- **Finding ID:** AUTH-07
- **Severity:** Low
- **Confidence:** Medium-High
- **CWE:** CWE-862
- **Files:lines:**
  - `backend/routes/apiKeys.js:110-123` (list — **no** `requireRole`)
  - Contrast: create/reveal/patch/delete use `requireRole(ROLES.ADMIN)` (`apiKeys.js:126+`)
  - `frontend/src/main.jsx:6475-6520` (`ApiKeysPage` loads list for any session; nav not admin-only)
- **Entry point:** `GET /api/api-keys`
- **Prerequisites / role:** Any valid session including **readonly**.
- **Data flow / concern:** Authenticated caller receives all non-deleted API key metadata (name, type, scopes summary, prefix/last_four mask, last_used_ip/at, status). Mutate/reveal remain admin-gated.
- **Impact:** Low — inventory and usage metadata disclosure to non-admin roles (aids targeting key abuse if combined with other issues). Not full secret disclosure.
- **Safe verification procedure (static only):** Confirm list handler has no role middleware; mutations do.
- **Expected secure behavior:** List restricted to admin (or least-privilege readers explicitly approved).
- **Remediation direction only:** Add `requireRole(ADMIN)` to list (and optionally hide nav for non-admin).
- **Regression tests later:** Yes

---

## Rejected

### [NOT VULNERABLE] AUTH-R01 — Public OpenAPI / Swagger docs

- **Files:lines:** `backend/lib/auth.js:217-243`; `backend/routes/apiDocs.js`
- **Endpoint:** `GET /api/docs`, `/api/openapi.json`, `/api/docs/static/*`
- **Protection:** Intentionally excluded from `apiAuthGate`. Contract documents machine API auth requirements; tests assert no secret material in OpenAPI. Info disclosure of public API shape is accepted product behavior, not missing auth on a privileged state-changing function.

### [NOT VULNERABLE] AUTH-R02 — `/api/v1` session-gate skip with API-key middleware

- **Files:lines:** `backend/lib/auth.js:244-248`; `backend/routes/apiV1Iocs.js:15-80`; `backend/lib/apiKeyAuth.js:38-118`
- **Endpoint:** `POST /api/v1/iocs`, `PATCH /api/v1/iocs/:id`
- **Protection:** Session gate skipped so browser cookies cannot inherit UI roles; handlers require `authenticateApiKey` + `requireApiScope`. Missing Bearer → 401; wrong scope → 403.

### [NOT VULNERABLE] AUTH-R03 — Published feed pull (`?api_key=` / legacy path token)

- **Files:lines:** `backend/routes/publicFeeds.js:196-302`; `backend/lib/auth.js:249-260`
- **Endpoint:** `GET /api/published-feeds/:slug?api_key=`; `GET /public/feeds/:token/feed.txt`
- **Protection:** Authz by API key / feed-bound token (+ rate limit). Modern `published_feed` keys are **intentionally feed-agnostic** (code comment). Not missing authentication; scope model is product design (cross-feed read is not vertical role escalation in the UI RBAC sense).

### [NOT VULNERABLE] AUTH-R04 — Fresh-install setup status/preview (read)

- **Files:lines:** `backend/routes/setup.js:72-88`
- **Endpoint:** `GET /api/setup/status`, `/api/setup/preview`
- **Protection:** Public reads required before first login exist; no privileged user/data mutation.

### [NOT VULNERABLE] AUTH-R05 — Login / logout / health

- **Endpoint:** `POST /api/auth/login|logout`; `GET /healthz|/readyz|/health`
- **Protection:** Expected public auth bootstrap and health probes.

### [NOT VULNERABLE] AUTH-R06 — AbuseIPDB enrichment admin

- **Files:lines:** `backend/routes/abuseipdbEnrichment.js:212+`
- **Protection:** `requireRole(ROLES.ADMIN)` on GET/PUT/test/remove-key.

### [NOT VULNERABLE] AUTH-R07 — Spamhaus DROP enrichment admin

- **Files:lines:** `backend/routes/spamhausDropEnrichment.js:182+`
- **Protection:** `requireRole(ROLES.ADMIN)` on GET/PUT/sync.

### [NOT VULNERABLE] AUTH-R08 — User admin / password reset

- **Files:lines:** `backend/routes/users.js` (create/status/reset/delete)
- **Protection:** `requireRole(ROLES.ADMIN)`; self-service PUT for readonly constrained in-handler.

### [NOT VULNERABLE] AUTH-R09 — Custom threat feed create/update/delete

- **Files:lines:** `backend/routes/customThreatFeeds.js`
- **Protection:** Admin `requireRole` on mutating config; test-fetch/sync allow admin+analyst explicitly.

### [NOT VULNERABLE] AUTH-R10 — Published feed admin CRUD / key ops

- **Files:lines:** `backend/routes/publishedFeeds.js` (session routes)
- **Protection:** `requireRole(ROLES.ADMIN)` on create/patch/delete/regenerate/access-key ops. Public pull is separate key-authenticated path (AUTH-R03).

### [NOT VULNERABLE] AUTH-R11 — API key create/reveal/patch/delete

- **Files:lines:** `backend/routes/apiKeys.js:126+`
- **Protection:** `requireRole(ROLES.ADMIN)` (list gap tracked as AUTH-07).

### [NOT VULNERABLE] AUTH-R12 — Backups

- **Files:lines:** `backend/routes/backups.js`
- **Protection:** Admin `requireRole` wrapper on backup routes.

### [NOT VULNERABLE] AUTH-R13 — Audit log export

- **Files:lines:** `backend/routes/auditLogs.js:181+`
- **Protection:** Export CSV requires `requireRole(ADMIN)`; read paths require admin or analyst.

### [NOT VULNERABLE] AUTH-R14 — Threat actors / classifications / IOC sources admin

- **Files:lines:** `backend/routes/threatActors.js`, `threatClassifications.js`, `iocSources.js`
- **Protection:** `requireRole(ROLES.ADMIN)` on admin mutations.

### [NOT VULNERABLE] AUTH-R15 — Cookie-session readonly write lock (baseline)

- **Files:lines:** `backend/lib/rbac.js:81-95`
- **Protection:** Cookie/`authVia` other than ingest|bearer: readonly limited to GET/HEAD (+ self preference PUTs). Gaps are AUTH-03/04 alternate paths, not failure of the cookie policy itself.

### [NOT VULNERABLE] AUTH-R16 — `PUT /api/system/timezone` admin check

- **Files:lines:** `backend/routes/setup.js:138-143`
- **Protection:** Requires authenticated session (gate) + in-handler `role === admin`. (Unauth setup complete gap is AUTH-05.)

### [NOT VULNERABLE] AUTH-R17 — Admin tags via `isAdminUser` for cookie admin

- **Files:lines:** `backend/server.js:2865-3008`
- **Protection:** Analyst correctly denied by `isAdminUser`. Ingest alternate path covered under AUTH-04, not a missing check for normal sessions.

### [NOT VULNERABLE] AUTH-R18 — IOC hard delete admin check (session)

- **Files:lines:** `backend/routes/iocDelete.js:8-9`
- **Protection:** Non-admin roles denied for cookie sessions. Ingest bypass via synthetic admin is AUTH-04.

### [NOT VULNERABLE] AUTH-R19 — CSRF on cookie mutations

- **Files:lines:** `backend/lib/auth.js:198-214`
- **Protection:** CSRF required for cookie mutating `/api` (except login/logout/setup complete). Not a substitute for role checks; documented exemptions for machine auth are separate findings where they weaken RBAC.

### [NOT VULNERABLE] AUTH-R20 — Analyst intelligence / source-tag hide require triage roles

- **Files:lines:** `backend/routes/analystIntelligence.js`; `server.js` source hide/restore
- **Protection:** `requireRole(ADMIN, ANALYST)` present.

### [NOT VULNERABLE] AUTH-R21 — Integration queue recover admin-only

- **Files:lines:** `backend/server.js:1697`
- **Protection:** `requireRole(ROLES.ADMIN)`.

---

## Findings (skill classification order)

### Vulnerable

(See **Confirmed**: AUTH-01 … AUTH-05.)

### Likely Vulnerable

(See **Probable**: AUTH-06, AUTH-07.)

### Needs Manual Review

None.

### Not Vulnerable

(See **Rejected**: AUTH-R01 … AUTH-R21.)

---

## Coverage notes (requested focus)

| Focus area | Result |
|---|---|
| `apiAuthGate` exclusions | Docs, setup bootstrap, `/api/v1`, published-feed `?api_key=` GET — evaluated |
| `requireRole` gaps (IPinfo/VT) | **AUTH-01**, **AUTH-02** Confirmed |
| Setup | Public complete on incomplete/existing timezone states — **AUTH-05** |
| Docs | Rejected (intentional public contract) |
| `/api/v1` | Rejected (API key + scope) |
| Published feeds | Rejected as designed key model; admin routes admin-gated |
| Ingest / Bearer `rbacHttpPolicy` bypass | **AUTH-03**, **AUTH-04** Confirmed |
| Readonly | Cookie path OK; Bearer/ingest alternate paths escalate |

## Intermediates

No `sast/missingauth-recon.md` or `sast/missingauth-batch-*.md` retained (analysis performed in-process; final artifact only).
