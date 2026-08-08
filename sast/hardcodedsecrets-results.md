# Hardcoded Secrets Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis only (no live credential use against deployed stacks)  
**Skill:** `sast-hardcodedsecrets` @ `db52227eab1043bf122cbff7206fac6708b4d6c9`  
**Scope note:** Skill baseline prioritizes **publicly accessible** (client-bundled) secrets. This assessment **expands** per brief to also cover tracked **backend/config** defaults and examples (`DEFAULT_ADMIN_PASSWORD`, Redis fallback, JWT placeholders, `.env.example`, compose defaults, provider keys in source). Values are **redacted** (type/location only). Placeholders vs usable secrets are distinguished; **public vs server-only** exposure is stated per finding.

## Executive Summary

- Candidates analyzed: **10**
- Vulnerable (Confirmed usable hardcoded/default secrets): **2**
- Likely Vulnerable: **0**
- Not Vulnerable (placeholders / env-only / tests / fail-closed): **8**
- Needs Manual Review: **0**
- Public frontend confirmed secrets: **0** (no API keys/tokens/passwords hardcoded into `frontend/` client bundles)

| Bucket | Count | Finding IDs |
|---|---|---|
| Confirmed | 2 | SECRET-01, SECRET-02 |
| Probable | 0 | — |
| Rejected | 8 | SECRET-03 … SECRET-10 |
| Public frontend usable secrets | 0 | — |

---

## Confirmed

### [VULNERABLE] SECRET-01 — Clean-install default admin password constant

- **Finding ID:** SECRET-01
- **Severity:** High (on fresh installs before password change)
- **Confidence:** High
- **CWE:** CWE-798 (Use of Hard-coded Credentials); related CWE-1392 (Use of Default Credentials)
- **Secret type:** Application default password (usable, well-known)
- **Classification of value:** **Usable secret / default credential** — not a placeholder
- **Exposure:** **Server-only** (not shipped in frontend JS). Also documented in tracked ops docs / `.env.example` comment (knowledge disclosure, not browser-extractable bundle secret)
- **Files:lines:**
  - `backend/lib/defaultAdminBootstrap.js:3-4` (`DEFAULT_ADMIN_EMAIL`, `DEFAULT_ADMIN_PASSWORD`)
  - `backend/lib/defaultAdminBootstrap.js:71-76` (bcrypt hash + insert with `must_change_password=TRUE`)
  - Documented: `.env.example:12-13`, `docs/deployment.md` (default login pair), `docs/demo-runbook.md`
- **Variable/context:** `DEFAULT_ADMIN_PASSWORD` → bootstrap of `admin@talonhound.local`
- **Evidence (redacted):**
  ```
  export const DEFAULT_ADMIN_EMAIL = 'admin@****.local';
  export const DEFAULT_ADMIN_PASSWORD = '****';  // well-known short default (see docs)
  ```
- **Data flow:** Empty `users` + `default_admin_bootstrapped=false` → hash constant → INSERT → HTTP `POST /api/auth/login` until operator changes password
- **Prerequisites:** Clean install where bootstrap ran and admin has not completed forced password change (or operator left default in place if gate skipped/bypassed elsewhere — gate assumes change)
- **Impact:** Unauthenticated network attacker who can reach `/api/auth/login` may authenticate as the primary admin during the window before change (or if default remains). Full admin UI/API impact on that window.
- **Why reported despite must_change_password:** Constant is still a real, guessable credential embedded in source and published in docs; race/window and any gate bypass escalate to full admin.
- **Public vs server-only:** Not extractable from SPA bundles; exploitable via **login API**, not DevTools Sources.
- **Remediation direction:** Prefer interactive first-run setup without a published password; or generate a one-time random bootstrap secret printed once to operator console/logs-of-record; never document a fixed password in tree.
- **Regression tests later:** Yes

### [VULNERABLE] SECRET-02 — Redis AUTH default password fallback (`dev-insecure-redis`)

- **Finding ID:** SECRET-02
- **Severity:** High (if Redis is network-reachable; Medium if Redis stays compose-internal only)
- **Confidence:** High
- **CWE:** CWE-798; CWE-1392
- **Secret type:** Redis AUTH password (usable known default)
- **Classification of value:** **Usable secret / insecure default** — intentional compose/dev fallback, not `CHANGE_ME`-style inert placeholder
- **Exposure:** **Server-only / infrastructure** (compose + Node ensure scripts). Not present in frontend client bundles. Tracked in repo → anyone with source+default deploy knows Redis AUTH
- **Files:lines:**
  - `docker-compose.yml:33` — redis `--requirepass ${REDIS_PASSWORD:-****}`
  - `docker-compose.yml:48,116,161,239,271,298` — services get same compose default when unset
  - `backend/lib/ensure-redis-password.js:3-9` — non-production: if unset, assigns same default string
  - `integration/ensure-redis-password.js:3-9` — same pattern
  - Documented: `.env.example:3`, `docs/container-operations-and-tuning.md:45`
- **Evidence (redacted):**
  ```
  // docker-compose.yml
  command: ["redis-server", "--requirepass", "${REDIS_PASSWORD:-****}"]

  // backend/lib/ensure-redis-password.js (NODE_ENV !== production)
  process.env.REDIS_PASSWORD = '****';  // fixed known default
  ```
- **Nuance:** Backend `ensure-redis-password.js` **throws in `NODE_ENV=production`** if password unset (fail-closed for bare Node). **Compose still injects the default** whenever `REDIS_PASSWORD` is unset in the host `.env`, including production compose deploys — app containers then receive the known password via env, so the production throw path may never run.
- **Impact:** Anyone who can reach Redis with the known AUTH can read/write BullMQ queues (job injection / data tampering), undermine workers, potentially pivot into application side-effects depending on job payloads.
- **Public vs server-only:** Not browser-exposed; risk is **deploy + network trust boundary** to Redis / shared default across docs and compose.
- **Remediation direction:** Remove compose default; require strong `REDIS_PASSWORD` at compose up (`:?` like `JWT_SECRET`); never assign a fixed string in application code.
- **Regression tests later:** Yes

---

## Probable

None.

---

## Rejected

### [NOT VULNERABLE] SECRET-03 — `.env.example` DB/Redis placeholders (`CHANGE_ME`)

- **Finding ID:** SECRET-03
- **Secret type:** Env template placeholders
- **Classification of value:** **Placeholder** (not usable as-shipped production secret)
- **Exposure:** Tracked example file only; intended to be copied to gitignored `.env`
- **Files:** `.env.example:2,4` — `DB_PASSWORD=CHANGE_ME`, `REDIS_PASSWORD=CHANGE_ME`
- **Reason:** Explicit placeholder pattern; `ensure-jwt-secret` and operator docs treat `CHANGE_ME`-class values as something to replace. No live credential in tree. Note: if an operator deploys with literal `CHANGE_ME` unchanged, that becomes an operational misconfiguration (weak password), not a hardcoded production secret in application source beyond the example template.
- **Public vs server-only:** Not frontend-bundled.

### [NOT VULNERABLE] SECRET-04 — JWT secret: empty example + placeholder rejection (no hardcoded signing key)

- **Finding ID:** SECRET-04
- **Secret type:** JWT HMAC signing secret
- **Classification of value:** **No hardcoded usable JWT secret** in source; fail-closed validation
- **Exposure:** Server-only (`backend/lib/ensure-jwt-secret.js` imported from `backend/lib/auth.js`); compose requires `${JWT_SECRET:?…}`
- **Files:** `.env.example:6` (`JWT_SECRET=` empty); `backend/lib/ensure-jwt-secret.js:1-28`; `docker-compose.yml:40`
- **Evidence (redacted):** Rejects empty and normalized placeholders such as `changeme` / `replaceme` / `placeholder` / `yoursecrethere` / `devinsecurejwtsecret`; requires length ≥ 32. No default JWT string is assigned.
- **Reason:** Opposite of a hardcoded secret — boot fails without a strong operator-supplied value.

### [NOT VULNERABLE] SECRET-05 — Frontend API key / curl placeholders

- **Finding ID:** SECRET-05
- **Secret type:** Documentation strings in SPA
- **Classification of value:** **Placeholder**
- **Exposure:** **Public** (bundled in `frontend/src/main.jsx`) — but not a secret
- **Files:** `frontend/src/main.jsx` (~5709–5714, ~6818–6823) — `{API_KEY}`, `YOUR_API_KEY`, `YOUR_KEY`
- **Reason:** Instructional placeholders for operators to substitute; skill false-positive list (YOUR_*, example patterns). Empty controlled inputs for provider keys in Enrichment UI — no literal provider credentials.

### [NOT VULNERABLE] SECRET-06 — Enrichment / TI provider keys in application source

- **Finding ID:** SECRET-06
- **Secret type:** Third-party API keys (VirusTotal, AbuseIPDB, IPinfo, URLhaus, MalwareBazaar, ThreatFox, AlienVault OTX, etc.)
- **Classification of value:** **Env/DB only** — no usable key literals in production source
- **Exposure would be:** Server-only if hardcoded (they are not)
- **Evidence:** `.env.example` comments with empty / `<URLHAUS_AUTH_KEY>`-style tokens; runtime via `process.env.*` or DB `threat_intel_provider_configs.api_key` / feed credentials; frontend forms start with `api_key: ''` and placeholders like “Paste … key”
- **Reason:** No production provider API key string literals found outside tests.

### [NOT VULNERABLE] SECRET-07 — Test fixture credentials

- **Finding ID:** SECRET-07
- **Secret type:** Fake keys/passwords in unit tests
- **Classification of value:** Non-production fixtures (`test-token`, `vt-key`, `sk-live-abc` truncated fake, `th_ioc_not-a-real-key`, basic_auth `pass`/`secret`)
- **Exposure:** Test files not shipped to browser; not compose runtime
- **Files (examples):** `backend/services/*.test.js`, `backend/lib/*Auth*.test.js`, `backend/lib/auditRedaction.test.js`, `frontend/src/lib/createUserForm.test.js`
- **Reason:** Skill excludes test fixtures unless shipped to clients; values are clearly synthetic.

### [NOT VULNERABLE] SECRET-08 — Redis URL builder (env password interpolation)

- **Finding ID:** SECRET-08
- **Files:** `backend/lib/redis-url.js`, `integration/redis-url.js`
- **Reason:** Constructs `redis://:…@host:port` from `process.env.REDIS_PASSWORD` — env reference, not a hardcoded password. Coupled risk is SECRET-02 when that env is the known default.

### [NOT VULNERABLE] SECRET-09 — Documented default admin username (identity, not a secret alone)

- **Finding ID:** SECRET-09
- **Files:** `DEFAULT_ADMIN_EMAIL` in `defaultAdminBootstrap.js`; docs / `.env.example`
- **Reason:** Username/email alone is not a credential secret. Reported together with SECRET-01 for password; standalone email disclosure is low/informational inventory only — classified Rejected as independent finding.

### [NOT VULNERABLE] SECRET-10 — High-confidence cloud/token regex scan (AWS/Google/GitHub/Slack/Stripe/OpenAI/private keys)

- **Finding ID:** SECRET-10
- **Reason:** No matches for `AKIA…`, `AIza…`, `ghp_`/`github_pat_`, Slack `xox*`, `sk_live_`/`sk_test_` production patterns, `sk-ant-`, `-----BEGIN … PRIVATE KEY-----`, or password-bearing DB URIs with embedded credentials in tracked app/config source (excluding lockfile integrity hashes and test fakes). No tracked private key PEM material.

---

## Public frontend summary

| Surface | Usable hardcoded secrets found |
|---|---|
| `frontend/src/**` (Vite client bundle) | **0** |
| `frontend/nginx.conf` / static | API key log redaction pattern only — no secrets |
| HTML templates | N/A (SPA) |

External attackers **cannot** extract JWT signing secrets, Redis AUTH, DB passwords, or provider API keys from the shipped frontend bundle based on this static review. Remaining confirmed issues are **server/install defaults** (SECRET-01, SECRET-02).

---

## Inventory cross-check (assessment brief)

| Brief item | Result |
|---|---|
| `DEFAULT_ADMIN_PASSWORD` | **SECRET-01** Confirmed (usable; server-only + docs) |
| Redis default fallback | **SECRET-02** Confirmed (usable; compose + non-prod Node) |
| JWT placeholders | **SECRET-04** Rejected (empty example + rejector; no hardcoded JWT) |
| `.env.example` | **SECRET-03** Rejected placeholders; documents default admin (ties to SECRET-01) |
| Compose defaults | Covered under **SECRET-02**; `JWT_SECRET` required (`:?`); `DB_PASSWORD` from env (no compose default password string) |
| Provider keys in source | **SECRET-06** none hardcoded in prod paths |

---

## Counts (for rollup)

| Metric | Count |
|---|---|
| Candidates analyzed | 10 |
| Confirmed (SECRET-*) | 2 |
| Probable | 0 |
| Rejected | 8 |
| Needs Manual Review | 0 |
| Public-frontend usable secrets | 0 |
