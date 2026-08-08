# JWT Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis only (no live JWT forgery against running services)  
**Library:** `jsonwebtoken` `^9.0.2` (lock/install: `9.x`; verify defaults read from `backend/node_modules/jsonwebtoken/verify.js`)  
**Scope note:** Admin/analyst privilege and env-gated emergency features do not eliminate impact; prerequisites are stated per finding.

## Executive Summary

- Verification sites analyzed: **2** (`requireAuth` cookie path; `requireAuth` Bearer path when `ALLOW_JWT_BEARER=1`)
- Issuance sites mapped: **2** (login; change-password re-issue) + latent string `signUserToken` helper
- Vulnerable (Confirmed): **4**
- Likely Vulnerable (Probable): **1**
- Not Vulnerable (Rejected): **7**
- Needs Manual Review: **0**
- N/A: **0** (JWT class applies; surfaces exist)

| Bucket | Count | Finding IDs |
|---|---|---|
| Confirmed | 4 | JWT-01, JWT-02, JWT-03, JWT-04 |
| Probable | 1 | JWT-05 |
| Rejected | 7 | (see Rejected) |
| N/A | 0 | — |

---

## Token lifecycle (recon condensed)

| Stage | Location | Notes |
|---|---|---|
| Secret bootstrap | `backend/lib/ensure-jwt-secret.js` (imported first from `auth.js`) | Non-empty, ≥32 chars, rejects known placeholders |
| Sign | `signUserToken` → `jwt.sign(..., secret, { subject, expiresIn })` | Default `JWT_EXPIRES_IN` / cookie maxAge **24h**; HS via string secret (library default HS256) |
| Transport | Cookie `demo_session` (HttpOnly, SameSite=lax, Secure via `cookieSecureFlag`); optional `Authorization: Bearer` if `ALLOW_JWT_BEARER=1` | CSRF cookie `demo_csrf` not HttpOnly (intentional) |
| Verify | `jwt.verify(token, secret)` — **no** `{ algorithms: [...] }` option | jsonwebtoken 9 with secret key type auto-allows only `HS256/384/512`; rejects empty signature / `none` unless algorithms explicitly includes `none` |
| Authz claims | `userId`, `role`, `email`/`username`/`sub` | Role **not** re-loaded from DB on each request; `effectiveRoleFromPayload` + dual admin fallbacks |

---

## Confirmed

### [VULNERABLE] JWT-01 — Missing/empty/invalid JWT `role` claim elevates to admin

- **Finding ID:** JWT-01
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-287 (Improper Authentication) / CWE-269 (Improper Privilege Management); JWT claim trust
- **Files:lines:**
  - `backend/lib/rbac.js:22-28` (`effectiveRoleFromPayload` — null/undefined/`''` → `admin`)
  - `backend/lib/auth.js:98-106` (`userFromJwtPayload` — `role: role \|\| ROLES.ADMIN`)
  - `backend/lib/rbac.js:48-58`, `73-84` (`requireRole` / `rbacHttpPolicy` also `normalizeAppRole(...) \|\| ROLES.ADMIN`)
  - `backend/lib/auth.js:82-86` (legacy string `signUserToken('email')` forces admin and omits `userId`)
- **Entry point / function:** Any authenticated `/api/*` after `requireAuth` → `userFromJwtPayload`
- **Prerequisites / role:** Possession of a **cryptographically valid** session JWT whose `role` claim is absent, empty, or (via the second fallback) non-normalized. Current login/change-password always write a normalized `role` from DB; impact targets **legacy/compatible tokens**, hand-minted tokens with a leaked secret, or any future issuance that omits `role`. String helper still encodes admin elevation if used.
- **Data flow:** Cookie/Bearer JWT → `jwt.verify` → `effectiveRoleFromPayload(payload.role)` → if missing → `admin` → `req.user.role` → RBAC middleware/`requireRole` treats as admin (again defaulting to admin if falsy).
- **Why controls fail:** Authorization role is taken solely from the JWT. Fail-open defaults map “unknown/legacy” to **highest** privilege instead of deny/`readonly`. Invalid non-empty roles become `null` in `effectiveRoleFromPayload`, then are flipped to admin by `role \|\| ROLES.ADMIN`.
- **Impact:** Privilege escalation to full app **admin** for any still-valid token lacking a proper role claim (migration/legacy window within `exp`, or secret-compromise forging that omits role). Compromises the RBAC model (`admin` / `analyst` / `readonly`).
- **Safe verification procedure (static only):**
  1. Confirm `effectiveRoleFromPayload(undefined\|null\|'') === 'admin'` (`rbac.js:23-27`).
  2. Confirm `userFromJwtPayload` applies `role \|\| ROLES.ADMIN` (`auth.js:102-105`).
  3. Confirm modern `signUserToken({...})` always sets `role` (`auth.js:90-95`) — finding is verify-path fail-open, not current happy-path login omission.
  4. Do not forge/send live tokens against production.
- **Expected secure behavior:** Missing/invalid role → **reject 401** or map to least privilege (`readonly`); never default to `admin`. Prefer binding role to a server-side session/`token_version` checked against DB.
- **Remediation direction only:** Remove admin defaults; require allowlisted role claim; reject legacy tokens or force re-login; delete unused string `signUserToken` admin path.
- **Regression tests later:** Yes

### [VULNERABLE] JWT-02 — `passwordChangeGate` skips when JWT `userId` is null (forces password-change bypass)

- **Finding ID:** JWT-02
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-287; broken session lockdown after credential change events
- **Files:lines:**
  - `backend/lib/passwordChangeGate.js:26-29` (`userId == null` → `next()`)
  - `backend/lib/auth.js:92-94`, `103-105` (`userId` optional on sign / null on verify)
  - `backend/lib/auth.js:82-86` (string signer omits `userId`)
  - `backend/routes/users.js:465-472` (reset documents reliance on gate + hash rotation — **not** JWT kill)
- **Entry point / function:** Global middleware `createPasswordChangeGate` (after `apiAuthGate` / CSRF)
- **Prerequisites / role:** Authenticated request with `req.user` set but `req.user.id` null/non-finite (JWT without `userId`), while the account may have `must_change_password=true` (e.g. after admin reset / bootstrap). Modern login includes `userId`; legacy/string tokens and any verified JWT minted without `userId` hit the skip.
- **Data flow:** Valid JWT (no `userId`) → `requireAuth` sets `id: null` → gate returns `next()` without querying `users.must_change_password` → full API (subject to RBAC) continues. Compensating control intended by password reset is skipped.
- **Why controls fail:** Gate treats missing `userId` as “nothing to check” instead of “cannot enforce / deny”. Combined with JWT-01, a role-less + userId-less legacy token is **admin** and **ungated**.
- **Impact:** After password reset / forced change, outstanding tokens **without** `userId` retain full API access until `exp` (default 24h). Undermines the documented “existing sessions restricted via must_change_password” guarantee for that token class.
- **Safe verification procedure (static only):**
  1. Read `passwordChangeGate.js:26-29` skip branch.
  2. Trace `userFromJwtPayload` null `id` when claim absent.
  3. Cross-read reset comments in `users.js:465-472` and test note in `users.test.js` (“stateless JWTs are not revoked”).
  4. No live session hijack tests in this assessment.
- **Expected secure behavior:** Reject or force re-auth when `userId` missing; always bind sessions to stable subject id; deny API when password-change enforcement cannot be evaluated.
- **Remediation direction only:** Fail closed on missing `userId`; require claim on all issued tokens; add `token_version` / denylist checked in `requireAuth`.
- **Regression tests later:** Yes

### [VULNERABLE] JWT-03 — No server-side JWT revocation on password reset (or logout)

- **Finding ID:** JWT-03
- **Severity:** Medium
- **Confidence:** High
- **CWE:** CWE-613 (Insufficient Session Expiration) / CWE-384 related session fixation patterns for stolen JWTs
- **Files:lines:**
  - `backend/routes/users.js:465-472`, `473+` (`POST /api/admin/users/:id/reset-password` — explicit note: tokens NOT revoked)
  - `backend/routes/users.test.js:155-157` (documents non-revocation)
  - `backend/lib/auth.js:6-7`, `82-95` (`expiresIn` default `24h`; no `jti` / version claim)
  - `backend/server.js:2555-2566` (logout only `clearAuthCookie` / CSRF clear — client cookie drop)
- **Entry point / function:** Admin password reset; user logout; any post-compromise window while JWT still verifies
- **Prerequisites / role:** Attacker holds a previously issued valid JWT (theft via XSS elsewhere, shared machine, log leakage, etc.). Reset/logout does not invalidate that token server-side. With JWT-02, lockdown may not apply.
- **Data flow:** Outstanding JWT → `jwt.verify` succeeds until `exp` → `req.user` restored. Reset sets `must_change_password` + new hash (blocks old password login) but does not blacklist token. Logout clears **this** browser’s cookies only.
- **Why controls fail:** Purely stateless HMAC JWT with up to **24h** lifetime and no rotation/`jti` store. Compensating `passwordChangeGate` is incomplete (JWT-02) and only restricts—not kills—sessions when `userId` is present.
- **Impact:** Stolen sessions remain usable until natural expiry; after reset, tokens with `userId` are limited to allowlisted auth routes (if gate works), but tokens without `userId` keep full access. Logout does not protect other copies of the cookie/Bearer token.
- **Safe verification procedure (static only):** Confirm absence of denylist/`token_version` in `requireAuth`; read reset comment block; confirm logout does not hit a revoke table.
- **Expected secure behavior:** Increment per-user `token_version` (or revoke list) on reset/logout/password change and assert claim in `jwt.verify` / post-verify check; shorten TTL + refresh if needed.
- **Remediation direction only:** Server-side session versioning or short-lived access tokens with revoke-capable refresh.
- **Regression tests later:** Yes

### [VULNERABLE] JWT-04 — `ALLOW_JWT_BEARER=1` bypasses `rbacHttpPolicy` and CSRF for JWT Bearer auth

- **Finding ID:** JWT-04
- **Severity:** High
- **Confidence:** High
- **CWE:** CWE-863 (Incorrect Authorization); CWE-352 (CSRF) when Bearer used from browser context
- **Files:lines:**
  - `backend/lib/auth.js:160-176` (Bearer accepted only if `ALLOW_JWT_BEARER === '1'`)
  - `backend/lib/auth.js:207` (`csrfProtection` skips when `req.authVia === 'bearer'`)
  - `backend/lib/rbac.js:73-79` (`rbacHttpPolicy` returns `next()` for `authVia === 'bearer'` **without** role checks)
  - `.env.example:9-10` (documents feature as emergency / weak; default off)
- **Entry point / function:** Any `/api/*` behind `apiAuthGate` when client sends `Authorization: Bearer <user JWT>` and env flag is enabled
- **Prerequisites / role:** Operator sets `ALLOW_JWT_BEARER=1`. Attacker (or automation) presents a **valid user JWT** (including a `readonly` user’s token). Cookie SameSite/CSRF protections no longer apply to that request path.
- **Data flow:** Bearer JWT → `authVia='bearer'` → CSRF middleware skip → `rbacHttpPolicy` skip → route handlers. `readonly` mutations that cookie sessions would block (403) are allowed at the policy layer; per-route `requireRole` still applies where present, but the **global** read-only write shield is gone.
- **Why controls fail:** Bearer mode is treated like machine ingest for policy purposes (`ingest || bearer` short-circuit) even though the credential is a **user** JWT with roles. Env flag is the only gate; default is off but a single mis-set env enables class-wide bypass.
- **Impact:** When enabled: CSRF bypass for state-changing APIs using stolen/exported JWTs; **readonly** (and any role) can perform mutations permitted by individual routes lacking `requireRole`, defeating the central read-only HTTP policy. Same JWT privileges otherwise.
- **Safe verification procedure (static only):** Trace `authVia === 'bearer'` in `csrfProtection` and `rbacHttpPolicy`; confirm `.env.example` emergency framing; do not enable the flag on shared/prod assessment targets solely to exploit.
- **Expected secure behavior:** If Bearer user JWT is required, enforce the **same** RBAC + CSRF (or equivalent anti-CSRF for cookie-less clients) as cookie auth; do not alias user Bearer to ingest bypass. Prefer API keys for machines.
- **Remediation direction only:** Remove user-JWT Bearer bypass of `rbacHttpPolicy`/CSRF; keep feature off by default; separate machine credentials.
- **Regression tests later:** Yes

---

## Probable

### [LIKELY VULNERABLE] JWT-05 — Auth cookie `Secure` can be forced off (`AUTH_COOKIE_SECURE=0`); Trusted-proxy / `X-Forwarded-Proto` coupling

- **Finding ID:** JWT-05
- **Severity:** Medium
- **Confidence:** Medium
- **CWE:** CWE-614 (Sensitive Cookie in HTTPS Session Without Secure Attribute) when misconfigured
- **Files:lines:**
  - `backend/lib/auth.js:29-46` (`cookieSecureFlag`, `appendAuthCookie`)
  - `proxy/nginx.conf:63-75` (edge sets `X-Forwarded-Proto https` on proxied HTTPS)
- **Entry point / function:** Login / change-password cookie issuance (`appendAuthCookie` / `appendCsrfCookie`)
- **Prerequisites / role:** `AUTH_COOKIE_SECURE=0`, **or** deployment where requests reach Express without HTTPS indicators (`req.secure` false and `x-forwarded-proto` not `https`) so cookies are issued without `Secure`.
- **Data flow:** `cookieSecureFlag(req)` → `res.cookie(..., { secure: ... })` for `demo_session` (session JWT) and CSRF cookie.
- **Why controls fail / concern:** HttpOnly + SameSite=lax are set and are sound defaults. `Secure` is **not** hardcoded true: env `AUTH_COOKIE_SECURE=0` forces cleartext-eligible cookies even on HTTPS. Auto-detection trusts `X-Forwarded-Proto` from the request Express sees—safe under this repo’s nginx (header overwritten to `https`), weaker if the app is exposed without that edge or with unrestricted trust of client-controlled forwarded headers.
- **Impact:** Session JWT cookie may be sent on HTTP and intercepted on mixed-content / cleartext paths; session theft → full identity for TTL (compounded by JWT-03).
- **Safe verification procedure (static only):** Review `cookieSecureFlag` branches; confirm compose/edge always terminate TLS and set proto; audit whether `AUTH_COOKIE_SECURE=0` appears in any deploy env (out of band).
- **Expected secure behavior:** Production: force `Secure` (and ideally `__Host-`/`__Secure-` cookie prefixes); never allow `AUTH_COOKIE_SECURE=0` outside local HTTP.dev.
- **Remediation direction only:** Default Secure on in non-dev; remove or hard-block `AUTH_COOKIE_SECURE=0` when `NODE_ENV=production`.
- **Regression tests later:** Yes

---

## Findings (skill classification order)

### Vulnerable

(See **Confirmed**: JWT-01, JWT-02, JWT-03, JWT-04.)

### Likely Vulnerable

(See **Probable**: JWT-05.)

### Needs Manual Review

None.

### Not Vulnerable

(See **Rejected** below for detail.)

---

## Rejected

### [NOT VULNERABLE] Algorithm confusion / `alg: none` on verify sites

- **File:** `backend/lib/auth.js:166`, `185`; `backend/node_modules/jsonwebtoken/verify.js:106-146`
- **Endpoint / function:** `requireAuth` (cookie + Bearer)
- **Reason:** `jwt.verify(token, secret)` with a symmetric secret: library requires a signature when a key is present; without explicit `algorithms` including `none`, unsigned tokens fail. Algorithms default to `HS256/384/512` for secret key type. App never verifies with an RSA public key, so RS256→HS256 public-key-as-HMAC confusion does not apply. Explicit `{ algorithms: ['HS256'] }` still recommended for defense in depth but not required to close a present exploit path on this stack.

### [NOT VULNERABLE] Weak / hardcoded HMAC secret

- **File:** `backend/lib/ensure-jwt-secret.js:1-28`; imported by `backend/lib/auth.js:1`
- **Endpoint / function:** Process boot / all JWT sign+verify
- **Reason:** Empty secret throws; placeholders (`changeme`, `devinsecurejwtsecret`, etc.) rejected; minimum length **32**. Secret comes from env (`JWT_SECRET`), not a hardcoded production value in app source. (Operator still must set a high-entropy value; bootstrap prevents common weak defaults.)

### [NOT VULNERABLE] `jwt.decode` / disabled signature verification

- **File:** `backend/lib/auth.js`
- **Reason:** Only `jwt.verify` is used for authentication; no `jwt.decode` auth path and no `verify_signature: false` optioning.

### [NOT VULNERABLE] Embedded JWK / JKU / X5U / `kid` injection

- **File:** `backend/lib/auth.js`
- **Reason:** Fixed env HMAC secret; token header key material is not consulted for verification; no `kid`-based DB/filesystem key lookup.

### [NOT VULNERABLE] Missing `exp` enforcement

- **File:** `backend/lib/auth.js:85-95`, `166`, `185`; jsonwebtoken verify defaults
- **Reason:** `jwt.sign(..., { expiresIn })` sets `exp`; `jwt.verify` validates `exp` unless `ignoreExpiration` (not set). Default lifetime 24h is a separate revocation concern (JWT-03), not missing expiry checks.

### [NOT VULNERABLE] Cookie baseline flags (HttpOnly / SameSite) under intended HTTPS edge

- **File:** `backend/lib/auth.js:39-46`
- **Reason:** Session cookie sets `httpOnly: true`, `sameSite: 'lax'`, `path: '/'`. CSRF cookie intentionally readable by JS (`httpOnly: false`) for double-submit. Residual Secure misconfiguration is tracked as JWT-05, not as a broken baseline implementation of HttpOnly/SameSite.

### [NOT VULNERABLE] Cross-service `iss` / `aud` confusion (single-issuer app)

- **File:** `backend/lib/auth.js` issuance/verify
- **Reason:** Tokens are minted and consumed only by this Express app with shared `JWT_SECRET`; no multi-audience JWT ecosystem observed. Missing `iss`/`aud` is hardening debt, not a demonstrated cross-service accept path here.

---

## Coverage checklist (requested themes)

| Theme | Result |
|---|---|
| `ensure-jwt-secret.js` | Rejected (enforces strength) |
| `jsonwebtoken` verify/sign | Verified; algorithms option omitted but library HS defaults OK |
| `alg` none / confusion | Rejected for current HS-only secret usage |
| Legacy role-less → admin (`effectiveRoleFromPayload`) | **JWT-01** Confirmed (+ secondary admin fallbacks) |
| `passwordChangeGate` skip when `userId` null | **JWT-02** Confirmed |
| No session revocation on password reset | **JWT-03** Confirmed |
| `ALLOW_JWT_BEARER` bypasses `rbacHttpPolicy` + CSRF | **JWT-04** Confirmed (env-gated) |
| Cookie flags | Baseline OK (Rejected); Secure footgun **JWT-05** Probable |
