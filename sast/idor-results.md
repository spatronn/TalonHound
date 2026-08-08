# IDOR Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis only (no live cross-user HTTP)  
**Scope note:** Horizontal object access focus. Admin-only shared resources and intentional feed-agnostic API keys are classified Rejected (not IDOR) with rationale. Privilege prerequisites stated per finding.

## Executive Summary

- Candidates analyzed: **11**
- Vulnerable (Confirmed): **0**
- Likely Vulnerable (Probable): **1**
- Not Vulnerable (Rejected): **10**
- Needs Manual Review: **0**
- N/A: **0** (IDOR class applies; object-id surfaces exist)

| Bucket | Count | Finding IDs |
|---|---|---|
| Confirmed | 0 | — |
| Probable | 1 | IDOR-01 |
| Rejected | 10 | IDOR-R01 … IDOR-R10 |
| N/A | 0 | — |

---

## Confirmed

None.

---

## Probable

### [LIKELY VULNERABLE] IDOR-01 — Export / deep-search ownership bound to recyclable username email, not stable user id

- **Finding ID:** IDOR-01
- **Severity:** Medium
- **Confidence:** Medium-High
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key); CWE-284
- **Files:lines:**
  - `backend/routes/iocSearchExports.js:30-37` (`actorEmail`, `canAccessExport`)
  - `backend/routes/iocDeepSearches.js:21-28` (`actorEmail`, `canAccess`)
  - `backend/migrations/124_ioc_search_exports.sql:8-26` (email ownership + `requested_by_id … ON DELETE SET NULL`)
  - `backend/migrations/144_ioc_deep_searches.sql:13-33` (same pattern)
  - `backend/routes/users.js:204-315` (admin can rename `username`); `591-630` (hard `DELETE` frees unique username)
- **Entry points:**
  - `GET /api/iocs/search-exports/:id`, `…/:id/download`, cancel/retry/create-again
  - `GET /api/iocs/deep-searches/:id`, `…/:id/results`, cancel/create-again
- **Prerequisites / role:** Authenticated non-admin (typically **analyst**) whose JWT `email`/`username` equals a prior owner’s `requested_by_email`. Reaching that state requires **username recycle** after admin rename or hard delete of the original user (`users.username` is `UNIQUE` but reusable once freed). Admins already bypass via `isAdminRole`.
- **Data flow:** Job rows store both `requested_by_id` and `requested_by_email`. Access helpers **ignore** `requested_by_id` and authorize solely with `row.requested_by_email === actorEmail(req)` (email derived from JWT username/email). After user delete, FK sets `requested_by_id` null while the email string remains; a new account with the same username inherits object access.
- **Why controls fail / concern:** Peer isolation tests prove different concurrent usernames get 403, but the ownership key is not the durable internal/`public_id` identity. Lifecycle events (delete/rename + recreate) transfer access to private export files and deep-search result sets without an object-level re-bind.
- **Impact:** Horizontal read (and cancel/retry where allowed) of another principal’s search-export CSV and deep-search spool after identity string recycle. Export download streams full query result artifacts.
- **Safe verification procedure (static only):**
  1. Confirm `canAccessExport` / `canAccess` compare email strings only (`iocSearchExports.js`, `iocDeepSearches.js`).
  2. Confirm migrations document intentional email ownership and `ON DELETE SET NULL` on `requested_by_id`.
  3. Confirm `DELETE FROM users` hard-deletes and username uniqueness then allows reuse (`users.js`, `034_users_rbac.sql`).
  4. Do not run live cross-user downloads against shared environments in this assessment.
- **Expected secure behavior:** Authorize on stable `requested_by_id` (or `public_id`) matching `req.user.id` / token `userId`; treat email as display/audit only. On user delete, expire or reassign private artifacts rather than leaving perpetual email grants.
- **Remediation direction only:** Prefer id-scoped queries (`WHERE id = $1 AND requested_by_id = $2`); keep admin override explicit. No exploit PoC here.
- **Regression tests later:** Yes (username recycle + download/results cross-access)

---

## Findings (skill classification order)

### Vulnerable

None (see Confirmed).

### Likely Vulnerable

(See **Probable**: IDOR-01.)

### Needs Manual Review

None.

### Not Vulnerable

(See **Rejected** below.)

---

## Rejected

### [NOT VULNERABLE] IDOR-R01 — Search export download / object access (`canAccessExport`) for concurrent peers

- **Finding ID:** IDOR-R01
- **File:** `backend/routes/iocSearchExports.js:34-37,276-347`; tests `iocSearchExports.test.js` (USER_B → 403)
- **Endpoint:** `GET /api/iocs/search-exports/:id`, `…/download`, cancel; list scoped by requester email
- **Reason:** Non-admin access requires matching `requested_by_email`. Concurrent user B cannot read/download user A’s export (covered by unit tests). Residual recycle risk is tracked as **IDOR-01**, not a missing check for same-period peers.

### [NOT VULNERABLE] IDOR-R02 — Deep search object access (`canAccess`)

- **Finding ID:** IDOR-R02
- **File:** `backend/routes/iocDeepSearches.js:25-28,109-127,198-226`; test `another user cannot read a private deep search`
- **Endpoint:** `GET /api/iocs/deep-searches/:id`, `…/results`, cancel/create-again; list email-scoped unless admin `?scope=all`
- **Reason:** Same ownership helper pattern as exports; peer isolation holds for distinct usernames. Lifecycle email bind → **IDOR-01**.

### [NOT VULNERABLE] IDOR-R03 — Backup download / mutate by `:id`

- **Finding ID:** IDOR-R03
- **File:** `backend/routes/backups.js:122-123,264+`
- **Endpoint:** `GET /api/backups/:id/download`, verify/delete/list (all behind `requireRole(ADMIN)`)
- **Reason:** Backups are org-level artifacts, not per-user private objects. Any admin may access any backup by id by design. Non-admins cannot call the routes. Not horizontal IDOR.

### [NOT VULNERABLE] IDOR-R04 — Users self `PUT /api/users/:id`

- **Finding ID:** IDOR-R04
- **File:** `backend/routes/users.js:155-196`; `backend/lib/rbac.js:91`; `backend/server.js:2577-2608`
- **Endpoint:** `PUT /api/users/:id` (public UUID)
- **Reason:** Readonly branch enforces `req.user.id ===` resolved internal id and strips role/password/username. Non-admin non-readonly receives 403; admin path is intentional privilege. Changing `:id` to another user’s UUID fails the self check. (Note: `rbacHttpPolicy` allowlists only `/api/users/\d+` while the API uses UUIDs, so cookie readonly self-edit often fails closed with policy 403 — availability quirk, not horizontal write IDOR.)

### [NOT VULNERABLE] IDOR-R05 — API keys by `:keyId` (reveal / patch / delete)

- **Finding ID:** IDOR-R05
- **File:** `backend/routes/apiKeys.js:203+,253+,330+`
- **Endpoint:** `GET /api/api-keys/:keyId/reveal`, `PATCH|DELETE /api/api-keys/:keyId`
- **Reason:** Mutations/reveal require `requireRole(ADMIN)`. Keys are platform credentials (`feed_id` null for modern profiles), not end-user-owned records. Looking up another key id as admin is expected. Non-admin cannot forge object access via id.

### [NOT VULNERABLE] IDOR-R06 — API key inventory list (any authenticated session)

- **Finding ID:** IDOR-R06
- **File:** `backend/routes/apiKeys.js:110-122`
- **Endpoint:** `GET /api/api-keys`
- **Reason:** Returns org-wide key metadata to any authenticated caller. That may be excess visibility (function-level / disclosure), but it is not IDOR via object-id swap of another user’s private resource. Out of IDOR class.

### [NOT VULNERABLE] IDOR-R07 — Published feed admin CRUD / access-keys by feed id

- **Finding ID:** IDOR-R07
- **File:** `backend/routes/publishedFeeds.js` (mutations `requireRole(ADMIN)`; GETs session-authenticated shared config)
- **Endpoint:** `/api/published-feeds/:id`, `…/access-keys/:keyId`, etc.
- **Reason:** Feeds are shared TI configuration, not per-analyst private objects. Admin mutations are role gates; peer analysts reading feed definitions is platform visibility, not user-to-user object theft via id.

### [NOT VULNERABLE] IDOR-R08 — Modern published-feed API keys are feed-agnostic (intentional)

- **Finding ID:** IDOR-R08
- **File:** `backend/routes/publicFeeds.js:197-254`; create path `backend/routes/apiKeys.js:125-156` (`feed_id` **NULL**)
- **Endpoint:** `GET /api/published-feeds/:slug?api_key=`
- **Reason:** Documented product behavior: any active `published_feed` / `th_pf_` key may pull **any** enabled feed slug. Authz is capability (key type + active status), not per-feed ACL. Changing slug with a valid key is **by design**, not broken ownership of a private object. Contrast legacy feed-bound tokens (IDOR-R09).

### [NOT VULNERABLE] IDOR-R09 — Legacy `/public/feeds/:token/feed.txt` feed binding

- **Finding ID:** IDOR-R09
- **File:** `backend/routes/publicFeeds.js:261-296`
- **Endpoint:** `GET /public/feeds/:token/feed.txt`
- **Reason:** Token hash joins `published_feed_access_keys` to **its** `feed_id`; response serves only that feed. Possession of the path token is the secret — not an authenticated user swapping another user’s id. Not IDOR.

### [NOT VULNERABLE] IDOR-R10 — Preferences self-scope

- **Finding ID:** IDOR-R10
- **File:** `backend/server.js:2611-2645`
- **Endpoint:** `GET|PUT /api/users/me/preferences`
- **Reason:** Email key taken only from `req.user.email` (JWT); body cannot select another principal. Same recyclable-username caveat as preferences rows is minor and follows identity lifecycle; not a `:id` IDOR.

---

## Coverage map (requested surfaces)

| Surface | Verdict | ID |
|---|---|---|
| Export download / `canAccessExport` | Peer-safe; email-recycle → Probable | IDOR-R01 + IDOR-01 |
| Deep searches / `canAccess` | Peer-safe; email-recycle → Probable | IDOR-R02 + IDOR-01 |
| Backups `:id` download | Rejected (admin shared) | IDOR-R03 |
| Users self PUT | Rejected (self + field gates) | IDOR-R04 |
| API keys by id | Rejected (admin / platform objects) | IDOR-R05–R06 |
| Published feeds | Rejected (shared / admin) | IDOR-R07 |
| Modern feed keys feed-agnostic | Rejected (intentional) | IDOR-R08 |
| Legacy feed tokens | Rejected (feed-bound) | IDOR-R09 |

---

## Intermediate artifacts

None retained. Analysis performed in-session without writing `sast/idor-recon.md` or `sast/idor-batch-*.md`.

---

## Summary counts

| Classification | Count |
|---|---|
| Confirmed / [VULNERABLE] | 0 |
| Probable / [LIKELY VULNERABLE] | 1 |
| Rejected / [NOT VULNERABLE] | 10 |
| Needs Manual Review | 0 |
| N/A | 0 |
| **Candidates analyzed** | **11** |
