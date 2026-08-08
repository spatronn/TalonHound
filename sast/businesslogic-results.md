# Business Logic Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis only (skill `sast-businesslogic`)  
**Focus:** Security-impact workflows (keys, feeds, password gate, system-admin, privilege mismatch) — not ordinary product bugs.

## Executive Summary

- Workflows analyzed: **9**
- Vulnerable (Confirmed): **2**
- Likely Vulnerable (Probable): **1**
- Not Vulnerable (Rejected): **6**
- Needs Manual Review: **0**

| Bucket | Count | Finding IDs |
|---|---|---|
| Confirmed | 2 | BIZ-01, BIZ-02 |
| Probable | 1 | BIZ-03 |
| Rejected | 6 | BIZ-R01 … BIZ-R06 |

Duplicate root causes already filed under missingauth/JWT/SSRF are cross-referenced and not re-scored as separate Critical issues here unless the logic angle adds distinct impact.

---

## Confirmed

### [VULNERABLE] BIZ-01 — Enrichment admin path privilege inconsistency (analyst can mutate VT/IPinfo secrets & IPinfo base_url)

- **Finding ID:** BIZ-01
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-840 (Business Logic Errors) / CWE-863
- **Files:lines:**
  - `backend/routes/ipEnrichment.js:454+` (no `requireRole(ADMIN)`)
  - `backend/server.js:6245+` (VT PUT/remove/test — no `requireRole(ADMIN)`)
  - Contrast admin-gated: AbuseIPDB / Spamhaus admin routes
  - UI: `EnrichmentProvidersPage.jsx` gates IPinfo/VT by `canWrite` (analyst), peers by admin
- **Entry point:** `/api/admin/enrichment-providers/ipinfo-lite|virustotal` mutations
- **Prerequisites:** Authenticated **analyst**
- **Data flow / why logic fails:** Product labels routes `/api/admin/...` and peers require admin, but IPinfo/VT backend (+ UI) allow analyst. UI restriction is **not stronger** than backend (they match each other) — backend is weaker than consistent admin policy. Combines with SSRF-03 (`base_url`).
- **Impact:** Analyst obtains admin-tier control of shared enrichment API keys and outbound base URL (SSRF/token leak chain).
- **Cross-ref:** AUTH-01, AUTH-02, SSRF-03 (same root; remediation shared).
- **Safe verification:** Static role middleware diff across enrichment providers.
- **Expected secure behavior:** Uniform admin-only secret/config mutation for all enrichment providers.
- **Remediation direction:** Align all enrichment provider admin mutators + UI to `requireRole(ADMIN)`.
- **Regression tests later:** Yes

### [VULNERABLE] BIZ-02 — `must_change_password` enforcement fail-open when JWT lacks `userId`

- **Finding ID:** BIZ-02
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-840; workflow bypass
- **Files:lines:** `backend/lib/passwordChangeGate.js:26-29`; issuance/verify in `auth.js`; admin reset comments in `users.js:465-472`
- **Entry point:** Global password-change gate after auth
- **Prerequisites:** Valid JWT without `userId` while account has `must_change_password=true` (legacy/string tokens; not modern login)
- **Data flow:** Gate skip → forced password-change workflow bypassed → API use continues until `exp`
- **Impact:** Undermines bootstrap/reset invariant that outstanding sessions are limited until password change.
- **Cross-ref:** JWT-02 (same defect; business-logic framing of the workflow bypass).
- **Safe verification:** Static gate branch + token claim optionality.
- **Expected secure behavior:** Fail closed when subject id cannot be resolved.
- **Remediation direction:** Deny when `userId` missing; revoke/version tokens on reset.
- **Regression tests later:** Yes

---

## Probable

### [LIKELY VULNERABLE] BIZ-03 — Username recycle transfers export/deep-search ownership (email-keyed ACL)

- **Finding ID:** BIZ-03
- **Severity:** Medium
- **Confidence:** Medium-High
- **CWE:** CWE-840; CWE-639
- **Cross-ref:** IDOR-01
- **Files:lines:** `iocSearchExports.js` / `iocDeepSearches.js` `canAccess*`; user delete/rename frees `username`
- **Prerequisites:** Admin deletes/renames user; new user reuses username; accesses prior exports/deep searches
- **Impact:** Horizontal access to prior principal’s private task artifacts after identity string recycle — identity lifecycle logic flaw.
- **Safe verification:** Static ownership compare vs `requested_by_id` unused for ACL.
- **Expected secure behavior:** Bind ACL to stable user id; expire artifacts on delete.
- **Remediation direction:** Id-scoped ACL; cleanup on user delete.
- **Regression tests later:** Yes

---

## Rejected

### [NOT VULNERABLE] BIZ-R01 — Soft-deleted / disabled API keys accepted

- **Evidence:** `backend/lib/apiKeyAuth.js:54-78` — `deleted_at IS NULL`; `keyStatus` rejects deleted/disabled/expired.
- **Reason:** Deleted/disabled keys are not accepted for `/api/v1` auth.

### [NOT VULNERABLE] BIZ-R02 — API key reveal without Cache-Control

- **Evidence:** Reveal route sets admin gate; audit `API_KEY_REVEALED`; response packing uses no-store pattern on other sensitive password endpoints. Spot-check reveal handler in `apiKeys.js` (admin + decrypt path). Not a double-submit privilege gain; residual caching hardening is Informational if no-store missing — **not confirmed** as exploitable business-logic flaw in this pass (verify headers in remediation phase).

### [NOT VULNERABLE] BIZ-R03 — Published feed regenerate double-submit without security impact

- **Evidence:** Regenerate uses advisory locks / admin role (`publishedFeeds.js`). Duplicate regenerates do not elevate privilege.

### [NOT VULNERABLE] BIZ-R04 — System-admin invariant bypass

- **Evidence:** `users.js` uses `evaluateProtectedMutation` for rename/demote/status/delete of `is_system_admin` rows. No confirmed bypass path in static review.

### [NOT VULNERABLE] BIZ-R05 — Modern published-feed keys reading all feeds

- **Evidence:** Intentional feed-agnostic `th_pf_` design (architecture + publicFeeds). Not a broken ownership check between peers; documented product key model. Rejected as IDOR/business-logic bug; note as design property.

### [NOT VULNERABLE] BIZ-R06 — Soft race on disable-then-use API key

- **Evidence:** Auth re-reads DB state including `enabled`/`deleted_at` on each request. Classic TOCTOU after concurrent disable is limited to in-flight requests already past auth — not a persistent logic bypass of disable.

---

## Cross-class duplicates (do not double-count severity independently)

| This file | Primary filing |
|---|---|
| BIZ-01 | AUTH-01 / AUTH-02 (+ SSRF-03 for base_url) |
| BIZ-02 | JWT-02 |
| BIZ-03 | IDOR-01 |
