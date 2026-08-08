# Verification Summary — TalonHound SAST Cross-Check

**Date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Scope:** Critical/High (and near-High) findings re-traced from entry → authz → sink; auth middleware re-checked; dead-code/test-only paths excluded; duplicates merged for reporting.

---

## Findings confirmed after cross-check

| ID | Class | Severity (final) | Notes |
|---|---|---|---|
| SSRF-01 | SSRF | High | Re-traced: `validateFeedUrl` literal blocklist only; `fetch(..., redirect:'follow')` before final-URL check; admin sets URL, analyst can fetch. DNS pin absent. |
| SSRF-03 | SSRF | High | Re-traced: `PUT .../ipinfo-lite` accepts unchecked `base_url`; `fetchIpinfoLite` concatenates token query; **no** `requireRole(ADMIN)`. |
| AUTH-01 | Missing authz | High | IPinfo admin mutate/test/remove lack `requireRole(ADMIN)`; AbuseIPDB/Spamhaus contrast confirmed. |
| AUTH-02 | Missing authz | High | VT PUT/remove/test lack `requireRole(ADMIN)`; UI `canWrite` aligns — backend gap vs peer providers. |
| AUTH-03 | Missing authz | High | `rbacHttpPolicy` skips for `authVia==='bearer'`; requires `ALLOW_JWT_BEARER=1`. CSRF also skipped. |
| AUTH-04 | Missing authz | High | Ingest rejected by `requireRole` but accepted by `rbacHttpPolicy` + `isAdminUser(role)` paths; needs ingest secret. |
| AUTH-05 | Missing auth | Medium | `POST /api/setup/complete` unauthenticated; `completeInitialSetup` allows write unless completed **and** runtime-ready — covers existing-install timezone gate. |
| JWT-01 | JWT | High | Verify-path fail-open: missing/empty role → admin (`effectiveRoleFromPayload` + `role \|\| ADMIN`). Modern login sets role; defect remains in verify. |
| JWT-02 | JWT | High | `passwordChangeGate` `next()` when `userId` null — re-confirmed. |
| JWT-03 | JWT | Medium | Stateless JWT; reset docs confirm non-revocation; logout cookie-only. |
| SECRET-01 | Hardcoded secrets | High | Usable default bootstrap password in source + docs; fresh-install / pre-change window. |
| SECRET-02 | Hardcoded secrets | **Medium** (downgraded) | Known Redis default; compose does not publish Redis; still confirmed insecure default if Redis reachable or miscomposed. |

---

## Findings downgraded

| ID | From → To | Reason |
|---|---|---|
| SECRET-02 | High → Medium | Default Compose publishes only 80/443; Redis stays internal. Impact requires additional Redis network exposure or host compromise of compose network. Code/default remains real CWE-798. |
| JWT-04 | High (counted) → **Deduplicated** | Same root as AUTH-03 (`authVia==='bearer'` skips RBAC/CSRF). Retained in `jwt-results.md` as analysis; **not double-counted** in final severity totals. |
| BIZ-01 | High → **Deduplicated** | Same root as AUTH-01 + AUTH-02 (+ SSRF-03 for base_url). |
| BIZ-02 | High → **Deduplicated** | Same root as JWT-02. |
| BIZ-03 | Medium → **Deduplicated** | Same root as IDOR-01. |

---

## Findings rejected as false positives (this pass)

| Candidate | Reason |
|---|---|
| Soft-deleted/disabled API key acceptance | `apiKeyAuth.js` filters `deleted_at IS NULL` and rejects disabled/expired via `keyStatus`. |
| Classic SQLi on `ORDER BY ${orderBy}` (suppressions) | `orderBy` mapped from allowlisted `sort` ternary (`server.js:4984-4985`). |
| DSL `queryBuilder` SQLi | Values `$n`-bound; fields/operators from allowlist. |
| Backup `child_process` RCE | Argv list-form, fixed binaries; paths guard-railed. |
| Swagger HTML XSS / SSTI | Constant HTML string; no user interpolation; not a template engine. |
| Multipart upload RCE | No upload middleware/deps. |
| GraphQL / XXE | No technology surface (explicit N/A evidence). |
| Feed-agnostic published-feed keys as IDOR | Intentional product design; rejected as vuln class. |
| Export/backup path traversal download | `resolveExportFilePath` / `pathSafety` + basename re-resolve prevent escape. |
| `dangerouslySetInnerHTML` XSS | Zero matches; React default escaping. |
| Analyst intelligence `javascript:` href | Server `URL_RE` requires `https?://`. |

---

## Probable retained (need runtime / lifecycle validation)

| ID | Why still probable |
|---|---|
| SSRF-02 | IPv4-mapped / incomplete IPv6 denylist — static true; Node fetch acceptance of forms needs env-local unit test, not live SSRF. |
| AUTH-06 | Analyst write to vendor integration credentials may be product intent; over-privilege vs peer admin-only enrichment secrets. |
| AUTH-07 | Non-admin/readonly API key inventory disclosure — low sensitivity metadata. |
| IDOR-01 | Username recycle ownership transfer — requires admin lifecycle + recycle; not exerciseable in single request. |
| JWT-05 | Cookie `Secure` depends on deploy env (`AUTH_COOKIE_SECURE` / proxy headers). |

---

## Auth middleware re-check (critical for High findings)

Stack order confirmed in `server.js`: `setupGate` → `apiAuthGate` → `csrfProtection` → `passwordChangeGate` → `rbacHttpPolicy`.

| Finding | Does middleware stop it? |
|---|---|
| SSRF-01 | Auth required; validation insufficient for destination — **no**. |
| SSRF-03 / AUTH-01 | Session auth yes; admin role **no**. |
| AUTH-02 | Same. |
| AUTH-03 | Cookie path blocked for readonly; Bearer path **skips** policy. |
| AUTH-04 | `requireRole` stops ingest; many admin helpers do **not**. |
| AUTH-05 | Explicitly excluded from `apiAuthGate`. |
| JWT-02 | Gate present but fail-open branch. |

---

## Overall cross-check verdict

High-risk findings remain after independent re-trace. Primary themes: **SSRF (feeds + IPinfo base_url)**, **broken function-level authorization on enrichment admin**, **JWT/RBAC fail-open and Bearer/ingest alternate paths**, **default credentials**. No confirmed RCE, SQLi, XSS, GraphQL, XXE, SSTI, or classic file-upload issues in reviewed code.
