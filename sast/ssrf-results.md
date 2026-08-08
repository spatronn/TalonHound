# SSRF Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis only (no live HTTP to localhost, private IPs, metadata, or production)  
**Scope note:** Admin/analyst privilege does not eliminate impact; prerequisites are stated per finding.

## Executive Summary

- Outbound call sites analyzed: **14** (production sinks; tests/scripts excluded)
- Vulnerable (Confirmed): **2**
- Likely Vulnerable (Probable): **1**
- Not Vulnerable (Rejected): **11**
- Needs Manual Review: **0**
- N/A: **0** (SSRF class applies; surfaces exist)

| Bucket | Count | Finding IDs |
|---|---|---|
| Confirmed | 2 | SSRF-01, SSRF-03 |
| Probable | 1 | SSRF-02 |
| Rejected | 11 | (see Rejected) |
| N/A | 0 | — |

---

## Confirmed

### [VULNERABLE] SSRF-01 — Custom threat feed URL fetch (blocklist-only, no DNS pin, redirect follow)

- **Finding ID:** SSRF-01
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Files:lines:**
  - `backend/lib/customThreatFeedUtils.js:77-107` (`isPrivateOrLocalHost`, `validateFeedUrl`)
  - `backend/lib/customThreatFeedFetch.js:9-42` (`fetchFeedUrl`)
  - `backend/routes/customThreatFeeds.js:341+` (create), `453+` (update), `669-700` (test-fetch), `703+` (sync enqueue)
  - `backend/lib/customThreatFeedSync.js:221+` (worker/sync path reuses `fetchFeedUrl`)
- **Entry point:**
  - `POST /api/custom-threat-feeds` / `PUT /api/custom-threat-feeds/:id` (store URL)
  - `POST /api/custom-threat-feeds/:id/test-fetch` / `POST .../sync` / scheduler worker (issue outbound GET)
- **Prerequisites / role:** Authenticated **admin** to set URL; **admin or analyst** to trigger test-fetch/sync once configured. Feed credentials may be attached as auth headers on the outbound request.
- **Data flow:** `req.body.url` → `validateFeedUrl` (literal hostname blocklist) → DB `custom_threat_feeds` / `integration_feeds` → `fetchFeedUrl` → `fetch(url, { redirect: 'follow' })` → optional post-response `validateFeedUrl(res.url)` → body returned/parsed into IOCs.
- **Why controls fail:**
  1. Only HTTP(S) + **hostname/IP literal blocklist** — no host allowlist; skill treats blocklists as insufficient.
  2. **No DNS resolution / IP pin** before connect → DNS rebinding (public name → private/metadata IP) bypasses `validateFeedUrl`.
  3. `redirect: 'follow'` completes the network request (including hops to private IP literals) **before** `validateFeedUrl(res.url)`; rejected redirects still constitute blind SSRF side effects. Post-check also only re-applies the same literal-host blocklist.
- **Impact:** Server-side requests to arbitrary HTTP(S) destinations reachable from the backend/worker network (internal services, cloud metadata, LAN). Response body (test-fetch) and/or feed import may expose content. Stored feed credentials can be sent to attacker-controlled hosts.
- **Safe verification procedure (static only):**
  1. Confirm `validateFeedUrl` never calls `dns.lookup` / `getaddrinfo` and only inspects `URL.hostname` (`customThreatFeedUtils.js`).
  2. Confirm `fetch(..., { redirect: 'follow' })` precedes redirect validation (`customThreatFeedFetch.js:25-42`).
  3. Confirm create/update accept URL after `validateFeedUrl` only; test-fetch calls `fetchFeedUrl(row.url)` for admin/analyst.
  4. Do **not** send live requests to metadata/`127.0.0.1`/private ranges.
- **Expected secure behavior:** Deny by default with a strict destination allowlist, or resolve+pin resolved addresses for the request (no TOCTOU), disable or manually validate each redirect hop against the same pinned policy, and never attach secrets to untrusted destinations.
- **Remediation direction only:** Replace blocklist with allowlist or DNS-pinning + redirect policy; treat analyst-triggered fetch as equally sensitive. Do not implement exploit details here.
- **Regression tests later:** Yes

### [VULNERABLE] SSRF-03 — IPinfo Lite configurable `base_url` (unvalidated) + token in query

- **Finding ID:** SSRF-03
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-918 (Server-Side Request Forgery); related credential exposure via URL
- **Files:lines:**
  - `backend/routes/ipEnrichment.js:454-513` (`PUT /api/admin/enrichment-providers/ipinfo-lite`)
  - `backend/services/ipinfoLiteService.js:36-41` (`parseConfig`), `224-230` (`fetchIpinfoLite`)
  - `backend/lib/rbac.js:73-96` (`rbacHttpPolicy` allows analyst mutating `/api/admin/...` absent `requireRole`)
- **Entry point:** `PUT /api/admin/enrichment-providers/ipinfo-lite` with `base_url` / `token`; subsequent enrich/test: `POST .../ipinfo-lite/test`, `/api/enrichment/ip/*/refresh`, bulk enrich paths using `fetchIpinfoLite`.
- **Prerequisites / role:** Authenticated session that is **not** `readonly` — **no `requireRole(ADMIN)`** on this PUT (unlike some other enrichment admin routes). Analyst can set `base_url`. Token from DB/env is appended as `?token=`.
- **Data flow:** `req.body.base_url` → stored in `threat_intel_provider_configs.config.base_url` → `getIpinfoLiteConfig` → `` `${config.base_url}/${ip}?token=...` `` → `fetch(url)`.
- **Why controls fail:** No scheme/host allowlist, no private-IP check, no destination validation at all on `base_url`. IP path segment is constrained via `validatePublicIp`, but **host/base is fully attacker-controlled**. Privilege gate is weaker than admin-only expectation for `/api/admin/...`.
- **Impact:** Full SSRF to arbitrary bases (internal HTTP services, metadata endpoints if reachable). Configured IPinfo token is leaked on the query string to the attacker-chosen base. Enrichment/test paths amplify reuse after one malicious config write.
- **Safe verification procedure (static only):**
  1. Read PUT handler: `baseUrl` taken from `req.body.base_url` with only `.trim()` / trailing-slash strip (`ipEnrichment.js:462-470`).
  2. Confirm absence of `requireRole(ROLES.ADMIN)` on that route registration.
  3. Confirm URL construction in `fetchIpinfoLite` uses `config.base_url` verbatim.
  4. No live probing of attacker/metadata URLs.
- **Expected secure behavior:** Hardcode or allowlist IPinfo host prefixes (e.g. `https://api.ipinfo.io/`); reject user `base_url` or restrict to that allowlist; prefer Authorization header over query token; gate admin config mutations with `requireRole(ADMIN)`.
- **Remediation direction only:** Remove or strictly allowlist `base_url`; harden role checks; avoid putting secrets in URLs. No exploit PoC in this assessment.
- **Regression tests later:** Yes

---

## Probable

### [LIKELY VULNERABLE] SSRF-02 — Incomplete literal IP blocking in `validateFeedUrl` (IPv4-mapped / weak IPv6)

- **Finding ID:** SSRF-02
- **Severity:** Medium
- **Confidence:** Medium-High
- **CWE:** CWE-918; CWE-184 (Incomplete denylist)
- **Files:lines:**
  - `backend/lib/customThreatFeedUtils.js:77-88` (`isPrivateOrLocalHost`)
  - `backend/lib/feedFormatter.js:114-143` (`parseIpv4` / `isPrivateOrReservedIp` — IPv4-only; non-IPv4 returns **false** “not private”)
- **Entry point:** Same as SSRF-01 (custom feed URL validation on create/update/fetch).
- **Prerequisites / role:** Admin (set URL); analyst can trigger fetch afterward.
- **Data flow:** Hostname → `isPrivateOrReservedIp` (dotted-quad only) → optional IPv6 heuristics limited to `::1`, `fc*`, `fd*`, `fe80*` prefixes → otherwise allowed → `fetch`.
- **Why controls fail / concern:** Literals such as `::ffff:127.0.0.1` / `::ffff:169.254.169.254` are not covered by the IPv4 parser and are not matched by the narrow IPv6 prefix checks. Alternate spellings and other IPv6 special ranges may also slip the denylist. Complements SSRF-01 (DNS rebinding) even when the attacker uses a literal host.
- **Impact:** Bypass of intended private/loopback/metadata literal refusal on the custom-feed gate; same SSRF impact class as SSRF-01 when Node/fetch accepts the form.
- **Safe verification procedure (static only):** Trace `isPrivateOrLocalHost('::ffff:127.0.0.1')` against code branches (no DNS, no IPv4-mapped handling). Optionally unit-test validators in isolation later — do not issue live SSRF requests in this assessment.
- **Expected secure behavior:** Normalize all IP literals (including IPv4-mapped IPv6), then apply a complete private/reserved policy; prefer allowlist over denylist.
- **Remediation direction only:** Fix denylist completeness or replace with allowlist/DNS-pinning as in SSRF-01.
- **Regression tests later:** Yes

---

## Findings (skill classification order)

### Vulnerable

(See **Confirmed**: SSRF-01, SSRF-03.)

### Likely Vulnerable

(See **Probable**: SSRF-02.)

### Needs Manual Review

None.

### Not Vulnerable

(See **Rejected** below for detail.)

---

## Rejected

### [NOT VULNERABLE] VirusTotal enrichment / connection test

- **File:** `backend/server.js` (~5979, ~6280)
- **Endpoint / function:** IOC VT refresh; admin VT test
- **Reason:** Destination host is hardcoded `https://www.virustotal.com/api/v3...`. User/IOC values only affect path segments after `encodeURIComponent` / VT URL id helper — not host/scheme. Not SSRF.

### [NOT VULNERABLE] AbuseIPDB check

- **File:** `backend/services/abuseipdbService.js` (~176-188); `backend/lib/abuseipdbEnrichment.js` (`ABUSEIPDB_API_BASE`)
- **Endpoint / function:** `fetchAbuseIpdbCheck`
- **Reason:** Fixed `https://api.abuseipdb.com/api/v2`. IP is a query param only; public-IP validation is separate from destination control.

### [NOT VULNERABLE] Spamhaus DROP sync

- **File:** `backend/lib/spamhausDropSync.js:7-10,238-242`
- **Endpoint / function:** `fetchListJson` / DROP sync
- **Reason:** URLs are frozen constants on `www.spamhaus.org`. No user-controlled host.

### [NOT VULNERABLE] URLhaus / MalwareBazaar connection tests

- **Files:** `backend/lib/urlhausIntegration.js:64-66`, `backend/lib/malwarebazaarIntegration.js:36-38`
- **Reason:** Hardcoded abuse.ch API hosts; auth key only in path. Not SSRF.

### [NOT VULNERABLE] ThreatFox connection test / importer API URL

- **Files:** `backend/lib/threatfoxIntegration.js:42-53`; `integration/config.js` (`THREATFOX_API_URL`)
- **Reason:** API URL from **operator env**/default, not HTTP request body. Credential test does not accept client `apiUrl`. Not attacker SSRF via app API.

### [NOT VULNERABLE] AlienVault OTX connection test / API base

- **Files:** `backend/lib/alienvaultOtxIntegration.js:43-56`; env `ALIENVAULT_OTX_API_BASE`
- **Reason:** Host from env/default hardcoded OTX base; path fixed. Not user SSRF.

### [NOT VULNERABLE] USOM official API client

- **File:** `integration/lib/usomOfficialApi.js:34-53`
- **Reason:** Env base URL must be `https://siberguvenlik.gov.tr` unless explicit non-official override for tooling — **host allowlist**. Not user-controlled via app API.

### [NOT VULNERABLE] Built-in integration feeds (PhishTank, Emerging Threats index, etc.)

- **Files:** `integration/config.js`; `integration/importer.js` (`fetchWithSignal` to config URLs)
- **Reason:** Destinations from process env / defaults (operator-controlled), not end-user URL fields. SSRF requires user influence on destination — absent here.

### [NOT VULNERABLE] DNSMania enrichment outbound

- **Files:** `backend/services/dnsmaniaEnrichmentService.js:43-55,353-439`; `backend/lib/dnsmaniaTarget.js`
- **Endpoint / function:** `lookupDomain` / `lookupIp` via `POST /api/enrichment/dnsmania/refresh`
- **Reason:** Base URL is **env-only** (`DNSMANIA_BASE_URL`). User/IOC values are path-encoded onto that fixed base (`encodeURIComponent`). That is not attacker choice of host. (Separate product note: private IPs may be allowed as **lookup subjects** to DNSMania — not classic SSRF to arbitrary destinations.)

### [NOT VULNERABLE] RDAP domain enrichment + IANA bootstrap

- **Files:** `backend/lib/rdapBootstrap.js`; `backend/services/rdapEnrichmentService.js:198-206`
- **Reason:** Bootstrap/fallback bases from env/IANA; domain only appended via `encodeURIComponent`. User cannot set RDAP server URL through the API. Following redirects to registrar RDAP servers is inherent to the RDAP protocol under those trusted bases — not application SSRF from user-supplied base URLs.

### [NOT VULNERABLE] `integration/lib/job-cancellation.js` `fetchWithSignal`

- **Reason:** Thin wrapper around `fetch`; destination entirely determined by callers above (env/fixed). Not an independent SSRF sink.

---

## N/A

No SSRF N/A declaration for the product class: outbound HTTP exists and was reviewed. (GraphQL/XXE/SSTI N/A belongs to those skills, not here.)

---

## Outbound call site inventory (analyzed)

| # | Sink | Destination origin | Classification |
|---|---|---|---|
| 1 | `customThreatFeedFetch.fetchFeedUrl` | User/admin stored URL | SSRF-01 / SSRF-02 |
| 2 | `ipinfoLiteService.fetchIpinfoLite` | Admin/analyst `base_url` + public IP path | SSRF-03 |
| 3 | `dnsmaniaEnrichmentService.fetchJson` | Env base + encoded lookup | Not vulnerable |
| 4 | `rdapEnrichmentService.fetchRdapJsonFromUrl` | IANA/env base + domain | Not vulnerable |
| 5 | `rdapBootstrap` IANA bootstrap `fetch` | Env/default IANA URL | Not vulnerable |
| 6 | URLhaus test `fetch` | Hardcoded host | Not vulnerable |
| 7 | MalwareBazaar test `fetch` | Hardcoded host | Not vulnerable |
| 8 | ThreatFox test `fetch` | Env/default | Not vulnerable |
| 9 | OTX test `fetch` | Env/default | Not vulnerable |
| 10 | Spamhaus DROP `fetch` | Hardcoded | Not vulnerable |
| 11 | VirusTotal enrich/test `fetch` | Hardcoded | Not vulnerable |
| 12 | AbuseIPDB `fetchAbuseIpdbCheck` | Hardcoded | Not vulnerable |
| 13 | Integration importer built-in feeds | Env/default | Not vulnerable |
| 14 | Custom feed sync worker | Same as #1 | Same as SSRF-01 |

---

## Summary counts (for rollup)

| Classification | Count |
|---|---|
| Confirmed / [VULNERABLE] | 2 |
| Probable / [LIKELY VULNERABLE] | 1 |
| Rejected / [NOT VULNERABLE] | 11 |
| [NEEDS MANUAL REVIEW] | 0 |
| N/A | 0 |
