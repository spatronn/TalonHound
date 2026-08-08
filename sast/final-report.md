# Security Assessment Final Report

**Project:** TalonHound  
**Generated:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67` (`main`)  
**Skill toolkit:** `https://github.com/utkusen/sast-skills` @ `db52227eab1043bf122cbff7206fac6708b4d6c9`  
**Method:** Static analysis only (detection phase; no remediation)  
**Scans completed:** analysis, sqli, graphql, xss, rce, ssrf, idor, xxe, ssti, jwt, missingauth, pathtraversal, fileupload, businesslogic, hardcodedsecrets, report  
**Cross-check:** `sast/verification-summary.md`

---

## Executive Summary

**Overall verdict:** `HIGH-RISK FINDINGS PRESENT`

No claim is made that the project is “secure.” The statement below reflects **confirmed** issues in reviewed code after false-positive / dedupe pass.

| Severity | Count (confirmed, de-duplicated) |
|----------|-------|
| Critical | 0 |
| High     | 10 |
| Medium   | 3 |
| Low      | 0 |
| **Total confirmed** | **13** |

| Probable / unconfirmed (not in confirmed total) | Count |
|---|---|
| Probable (`[LIKELY VULNERABLE]`) | 5 |
| Needs manual review | 1 (backup tar extract ZipSlip residual) |

**Top 5 highest-risk findings**

1. **SSRF-03** — Unvalidated IPinfo `base_url` + token-in-query (analyst-writable) → SSRF + credential leak  
2. **SSRF-01** — Custom threat feed fetch with blocklist-only validation, no DNS pin, follow-redirects  
3. **AUTH-01 / AUTH-02** — Enrichment admin (IPinfo / VirusTotal) missing `requireRole(ADMIN)`  
4. **JWT-01 / JWT-02** — Role fail-open to admin; `must_change_password` gate bypass when `userId` absent  
5. **SECRET-01** — Hard-coded clean-install default admin password (usable pre-change)

| Question | Answer |
|---|---|
| Unauthenticated remote attack path identified? | **Yes (limited):** default admin login on fresh install (`SECRET-01`); unauthenticated timezone setup complete when setup incomplete (`AUTH-05`). No unauthenticated RCE/SQLi/SSRF. |
| Read-only user → admin privilege escalation? | **No direct path confirmed** under default config. Conditional: `ALLOW_JWT_BEARER=1` lets readonly JWTs bypass write lock (`AUTH-03`). JWT role fail-open (`JWT-01`) elevates tokens **without** a valid role claim (not normal readonly claim). |
| Secret exposure identified? | **Yes:** default admin password constant; Redis insecure default; enrichment/API secrets mismanagement via analyst-writable provider config (not plaintext frontend leak). |
| SSRF path to internal/private destinations? | **Yes (confirmed, authenticated):** SSRF-01 (admin/analyst+feed), SSRF-03 (analyst+). |
| Confirmed RCE / SQLi / XSS / IDOR / auth bypass? | **RCE:** no. **SQLi:** no. **XSS:** no. **IDOR:** none confirmed (1 probable). **Auth bypass / broken authz:** yes (AUTH-01…05, JWT-01/02/03). |

---

## Vulnerability Index

| ID | Severity | Confidence | Class | Component | Attack prerequisites | Impact | Evidence | Status |
|---|---|---|---|---|---|---|---|---|
| SSRF-03 | High | High | SSRF | IPinfo Lite `base_url` | Auth’d non-readonly (analyst+) | SSRF + IPinfo token exfil | `ipEnrichment.js:454+`, `ipinfoLiteService.js:224-230` | Confirmed |
| SSRF-01 | High | High | SSRF | Custom threat feed fetch | Admin sets URL; admin/analyst triggers | SSRF to attacker/internal URL; secret headers may follow | `customThreatFeedUtils.js:77-107`, `customThreatFeedFetch.js:25-42` | Confirmed |
| AUTH-01 | High | High | Missing authz | IPinfo admin routes | Analyst session | Analyst mutates provider secret/`base_url` | `ipEnrichment.js:431-562` vs AbuseIPDB admin gate | Confirmed |
| AUTH-02 | High | High | Missing authz | VirusTotal admin routes | Analyst session | Analyst sets/removes shared VT API key | `server.js:6245-6272` | Confirmed |
| AUTH-03 | High | High | Missing authz | `rbacHttpPolicy` Bearer skip | `ALLOW_JWT_BEARER=1` + valid user JWT | Readonly write lock bypass | `rbac.js:77-78`, `auth.js:160-176` | Confirmed |
| AUTH-04 | High | High | Missing authz | Ingest vs `isAdminUser` | Valid `API_INGEST_TOKEN` | Machine credential reaches admin helpers without `requireRole` | `auth.js:144-157`, `rbac.js:51-53`, `iocDelete.js`/`isAdminUser` | Confirmed |
| JWT-01 | High | High | JWT | Role claim verify fail-open | Valid JWT missing/empty role | Elevates to admin RBAC | `rbac.js:22-28`, `auth.js:98-105` | Confirmed |
| JWT-02 | High | High | JWT | Password-change gate | JWT without `userId` + `must_change_password` | Forced password-change workflow bypass | `passwordChangeGate.js:26-29` | Confirmed |
| SECRET-01 | High | High | Hardcoded secrets | Default admin bootstrap | Reach `/api/auth/login` on fresh/unforced install | Admin session before password change | `defaultAdminBootstrap.js:3-4` | Confirmed |
| SECRET-02 | Medium | High | Hardcoded secrets | Redis AUTH default | Redis network reachability | Queue inject / worker influence | `ensure-redis-password.js`, `docker-compose.yml` redis requirepass default | Confirmed (sev ↓) |
| AUTH-05 | Medium | High | Missing auth | Setup complete | Setup/timezone incomplete | Anonymous sets system timezone / clears gate | `auth.js:232-238`, `systemTime.js:386-415` | Confirmed |
| JWT-03 | Medium | High | JWT | No revocation | Stolen JWT within TTL | Post-reset/logout token reuse until `exp` | `users.js:465-472`, logout clears cookies only | Confirmed |
| SSRF-02 | Medium | Med-High | SSRF | IPv4-mapped denylist gap | Admin URL set | Literal private bypass of feed URL check | `customThreatFeedUtils.js:77-88` | Probable |
| AUTH-06 | Medium | Medium | Missing authz | Integration credentials | Analyst | Rotate vendor feed secrets | `server.js` integrations credentials routes | Probable |
| AUTH-07 | Low | Med-High | Missing authz | `GET /api/api-keys` | Any session incl. readonly | Key inventory metadata | `apiKeys.js:110-123` | Probable |
| IDOR-01 | Medium | Med-High | IDOR | Export/deep-search ACL | Username recycle after delete/rename | Inherit prior user’s task artifacts | `iocSearchExports.js:34-37` | Probable |
| JWT-05 | Medium | Medium | JWT | Cookie Secure flag | Misconfig / missing proto | Session cookie on HTTP | `auth.js:29-37` | Probable |

Deduplicated (not counted separately in totals): JWT-04 (=AUTH-03), BIZ-01 (=AUTH-01/02), BIZ-02 (=JWT-02), BIZ-03 (=IDOR-01).

---

## Findings — Critical

*None.*

---

## Findings — High (detailed evidence)

### SSRF-03 — IPinfo Lite configurable `base_url` (unvalidated) — SSRF

- **Source scan:** `sast/ssrf-results.md` (+ AUTH-01)
- **Classification:** Vulnerable
- **Endpoint / File:** `PUT /api/admin/enrichment-providers/ipinfo-lite` → `fetchIpinfoLite`
- **Severity rationale:** Attacker-influenced destination with credential in query string; reachable by analyst (weaker than “admin-only Critical”). Soft-target internal services/metadata if network permits.
- **Issue:** `base_url` persisted after trim only; outbound URL built as `` `${base_url}/${ip}?token=...` `` with no allowlist.
- **Impact:** SSRF; IPinfo token sent to attacker-controlled host.
- **Proof:**
  - `backend/routes/ipEnrichment.js:462-487` — no URL validation, no `requireRole(ADMIN)`
  - `backend/services/ipinfoLiteService.js:224-230` — fetch uses configured base + token query
- **Remediation direction:** Hardcode/allowlist IPinfo hosts; remove user `base_url` or restrict; Authorization header instead of query token; `requireRole(ADMIN)`.
- **Safe verification:** Static review of PUT + fetch construction; **do not** point `base_url` at metadata/internal hosts in production.
- **Regression tests later:** Yes

### SSRF-01 — Custom threat feed URL fetch — SSRF

- **Source scan:** `sast/ssrf-results.md`
- **Classification:** Vulnerable
- **Endpoint / File:** Custom feed CRUD + `test-fetch` / sync worker `fetchFeedUrl`
- **Severity rationale:** Full outbound GET with optional credential headers; DNS rebinding / redirect side-effects despite literal blocklist. Admin to set; analyst can trigger.
- **Issue:** Blocklist-only host checks; no DNS pin; `redirect: 'follow'` before validating final URL.
- **Impact:** Server-side requests to attacker or internal destinations; possible response exposure via test-fetch / import.
- **Proof:**
  - `backend/lib/customThreatFeedUtils.js:90-106`
  - `backend/lib/customThreatFeedFetch.js:25-42`
- **Remediation direction:** Allowlist or resolve+pin + per-hop redirect policy; treat analyst fetch as sensitive.
- **Safe verification:** Static (no live SSRF).
- **Regression tests later:** Yes

### AUTH-01 / AUTH-02 — Enrichment provider admin missing role checks

- **Source scan:** `sast/missingauth-results.md`
- **Classification:** Vulnerable
- **Endpoints:** IPinfo Lite + VirusTotal `/api/admin/enrichment-providers/*` mutations
- **Severity rationale:** Vertical privilege into shared secrets / SSRF-capable config; not unauthenticated.
- **Issue:** Peer providers use `requireRole(ADMIN)`; these do not.
- **Impact:** Analyst replaces/removes VT/IPinfo keys; sets IPinfo `base_url`.
- **Proof:** Route registrations without `requireRole`; contrast AbuseIPDB/Spamhaus.
- **Remediation direction:** Uniform `requireRole(ADMIN)` + UI `isAdmin`.
- **Regression tests later:** Yes

### AUTH-03 — Bearer JWT bypasses readonly HTTP policy

- **Source scan:** `sast/missingauth-results.md` (JWT-04 same root)
- **Prerequisites:** `ALLOW_JWT_BEARER=1`
- **Issue:** `rbacHttpPolicy` early-return for `authVia==='bearer'`.
- **Impact:** Readonly Bearer JWT can hit mutating routes lacking per-route `requireRole`.
- **Proof:** `backend/lib/rbac.js:77-78`; `auth.js:160-176`, `207`
- **Remediation direction:** Apply role policy to Bearer; keep feature off; prefer API keys for machines.
- **Regression tests later:** Yes

### AUTH-04 — Ingest token alternate admin path

- **Issue:** Synthetic admin + policy bypass; `requireRole` denies ingest but `isAdminUser` / ungated routes do not.
- **Impact:** With ingest secret: privileged operations outside intended automation allowlist.
- **Proof:** `auth.js:144-157`; `rbac.js:51-53`; handlers using role-only admin checks.
- **Remediation direction:** Central ingest allowlist or reject ingest in all admin helpers.
- **Regression tests later:** Yes

### JWT-01 — Missing role claim → admin

- **Issue:** Fail-open elevation in verify path.
- **Impact:** Legacy/forged-without-role tokens (with valid signature) become admin.
- **Proof:** `rbac.js:22-28`; `auth.js:102-105`
- **Remediation direction:** Fail closed; remove string `signUserToken` admin helper.
- **Regression tests later:** Yes

### JWT-02 — Password-change gate fail-open

- **Issue:** Null `userId` skips `must_change_password` enforcement.
- **Impact:** Post-reset/bootstrap lockout incomplete for that token class.
- **Proof:** `passwordChangeGate.js:26-29`
- **Remediation direction:** Fail closed; token versioning on reset.
- **Regression tests later:** Yes

### SECRET-01 — Default admin password constant

- **Issue:** Usable hard-coded default in bootstrap + docs.
- **Impact:** Unauth login as admin on clean install until password change.
- **Proof:** `defaultAdminBootstrap.js:3-4`
- **Remediation direction:** One-time random bootstrap secret; stop documenting fixed password.
- **Regression tests later:** Yes

---

## Findings — Medium

#### AUTH-05 — Unauthenticated setup complete

- Existing/incomplete timezone installs can be completed anonymously via `POST /api/setup/complete` (`systemTime.js:386-415`). Gate admin PUT separately.

#### JWT-03 — No server-side JWT revocation

- Reset/logout do not invalidate outstanding JWTs server-side (up to default 24h). Documented; gate partially compensates when `userId` present.

#### SECRET-02 — Redis default AUTH password

- Known default in compose/ensure scripts; severity Medium under current “Redis not published” compose posture; Critical/High if Redis exposed.

---

## Findings — Probable (runtime / lifecycle)

See index rows SSRF-02, AUTH-06, AUTH-07, IDOR-01, JWT-05. Also pathtraversal `[NEEDS MANUAL REVIEW]` on Node `extractTarGz` ZipSlip residual when archive already on disk — not HTTP upload reachable.

---

## Coverage

| Skill | Result file | Status |
|---|---|---|
| sast-analysis | `sast/architecture.md` | Findings (architecture map) |
| sast-sqli | `sast/sqli-results.md` | Clean (0 confirmed) |
| sast-graphql | `sast/graphql-results.md` | N/A |
| sast-xss | `sast/xss-results.md` | Clean |
| sast-rce | `sast/rce-results.md` | Clean |
| sast-ssrf | `sast/ssrf-results.md` | Findings |
| sast-idor | `sast/idor-results.md` | Findings (probable only) |
| sast-xxe | `sast/xxe-results.md` | N/A |
| sast-ssti | `sast/ssti-results.md` | N/A |
| sast-jwt | `sast/jwt-results.md` | Findings |
| sast-missingauth | `sast/missingauth-results.md` | Findings |
| sast-pathtraversal | `sast/pathtraversal-results.md` | Clean / 1 NMR |
| sast-fileupload | `sast/fileupload-results.md` | N/A |
| sast-businesslogic | `sast/businesslogic-results.md` | Findings (mostly cross-ref) |
| sast-hardcodedsecrets | `sast/hardcodedsecrets-results.md` | Findings |
| sast-report | `sast/final-report.md` | This document |

---

## Assessment limitations

- Static analysis only; no exploit traffic to production (`192.168.1.190`), metadata endpoints, or private networks.
- DNS rebinding / IPv4-mapped acceptance not executed at runtime (classified confirmed/probable from code evidence).
- `ALLOW_JWT_BEARER`, Redis exposure, and cookie Secure depend on deployment env not fully known from repo alone.
- Intentional product choices (analyst integration writes; feed-agnostic API keys) may or may not match operator policy.
- Large monolith (`server.js` / `main.jsx`) reviewed via architecture-guided prioritization; residual risk remains in unprobed corners.
- Parallel detection subagents partially stalled; results completed in-session using the same skill methodology and evidence standard.

---

## Recommended remediation order

### P0

1. Lock IPinfo `base_url` (remove or allowlist) + `requireRole(ADMIN)` on IPinfo/VT admin mutators (SSRF-03, AUTH-01, AUTH-02).  
2. Harden custom feed fetch: DNS pin / allowlist / safe redirects (SSRF-01, SSRF-02).  
3. Fail-closed JWT role + `userId` / password-change gate (JWT-01, JWT-02); add token version on reset (JWT-03).  
4. Replace default admin bootstrap password with one-time random secret (SECRET-01).

### P1

5. Remove Bearer exemption from `rbacHttpPolicy` (AUTH-03 / JWT-04); tighten ingest allowlisting (AUTH-04).  
6. Require strong Redis password with no compose default (SECRET-02).  
7. Authenticate `setup/complete` after greenfield (AUTH-05).

### P2

8. Ownership by user id for exports/deep searches (IDOR-01).  
9. Credential routes admin-only if policy requires (AUTH-06); restrict API key list (AUTH-07).  
10. Cookie Secure enforce in production (JWT-05); harden backup tar extract (pathtraversal NMR).

**Do not implement in this phase.**

---

## Recommended regression / security tests (future remediation)

- Role middleware: analyst **403** on IPinfo/VT admin PUT; admin **200**.  
- Reject non-allowlisted IPinfo `base_url` (including private/literal/`file:`).  
- Custom feed URL unit tests: DNS to private (mock resolver), IPv4-mapped literals, redirect-to-private.  
- JWT: missing role / missing `userId` → 401; `must_change_password` enforced.  
- Bearer with readonly + `ALLOW_JWT_BEARER=1` still GET-only (or feature removed).  
- Ingest token **403** on hard-delete / tag-admin / credential endpoints unless explicitly allowlisted.  
- Soft-deleted/disabled API keys rejected (already true — keep coverage).  
- Username recycle: new user cannot download prior export.  
- Setup: after users exist, anonymous `setup/complete` denied.  
- No default Redis/admin password accepted in production compose profile tests.

---

## Defense-in-depth (non-vulnerability notes)

These are **not** filed as vulnerabilities:

- Public OpenAPI/Swagger by design.  
- Wide Express `cors()` behind same-origin nginx (hardening opportunity).  
- Provider API keys stored as plaintext TEXT in DB (encryption-at-rest improvement).  
- Feed-agnostic modern published-feed keys (product model).

---

## Appendix: artifact list

See end-of-assessment `git status` and `sast/` file listing in operator summary.
