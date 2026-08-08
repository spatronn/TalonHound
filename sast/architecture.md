# Architecture: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67` (`main`)  
**Skill toolkit:** `utkusen/sast-skills` @ `db52227eab1043bf122cbff7206fac6708b4d6c9`

This document is reconnaissance only (sast-analysis). Vulnerability claims belong in per-class `*-results.md` files.

---

## Technology Stack

| Category | Details |
|---|---|
| Languages | JavaScript (ESM) — Node.js backend/workers; React 18 frontend (JSX) |
| Frameworks | Express 4 (`backend/server.js`); Vite 5 + React Router 6 (`frontend/`) |
| Databases | PostgreSQL 16 (`pg` Pool); Redis (`ioredis`) + BullMQ job queues |
| Auth mechanism | HttpOnly JWT cookie (`demo_session`); CSRF double-submit cookie; optional `X-Api-Ingest-Token`; optional JWT Bearer if `ALLOW_JWT_BEARER=1`; API keys (`th_pf_` / `th_ioc_` / legacy) for `/api/v1` and published feeds |
| Roles | App roles: `admin`, `analyst`, `readonly` (`backend/lib/rbac.js`). `is_system_admin` is a DB flag protecting the primary admin account — not a separate HTTP role |
| Infrastructure | Docker Compose (`docker-compose.yml`): db, redis, backend, integration-scheduler/worker, ioc-expiration/search-export/deep-search/backup workers, frontend, edge proxy. Only ports 80/443 published |
| External services | Built-in TI feeds (URLhaus, USOM, ThreatFox, MalwareBazaar, PhishTank, AlienVault OTX, Spamhaus DROP); enrichment (VirusTotal, IPinfo Lite, AbuseIPDB, RDAP/IANA, DNSMania via env); custom threat feed HTTP(S) URLs |
| Package managers | npm — `backend/package.json`, `frontend/package.json`, `integration/package.json` |

---

## Architecture Overview

TalonHound is a **monolithic threat-intelligence platform**:

1. **Browser (React SPA)** → edge **nginx** (`proxy/nginx.conf`) → **frontend nginx** (static + reverse-proxy `/api` and `/public` to backend:3000) → **Express API**.
2. **Express** owns HTTP auth, RBAC, IOC CRUD/search, enrichment admin, published feeds, backups metadata, user admin.
3. **Integration worker/scheduler** (BullMQ) imports built-in and custom feeds into PostgreSQL.
4. **Async workers** handle IOC expiration, search exports, deep searches, encrypted backups (local filesystem volumes).
5. **PostgreSQL** is the system of record; **Redis** is queue/broker only.

Trust is layered: unauthenticated browser/API clients, authenticated UI sessions (roles), machine ingest token, scoped API keys, and operator-controlled env secrets.

---

## Data Flow

### Primary UI session flow

1. `POST /api/auth/login` (public) → bcrypt verify → `signUserToken` → HttpOnly JWT + CSRF cookies.
2. Subsequent `/api/*` calls: `apiAuthGate` → `requireAuth` (cookie) → `csrfProtection` (mutating) → `passwordChangeGate` → `rbacHttpPolicy` → route handler (`requireRole` where applied).
3. Reads/writes go through `pg` parameterized queries; responses return JSON to React (default escaping; no `dangerouslySetInnerHTML` found).

### Machine API key flow

1. Client `Authorization: Bearer th_*` → `/api/v1/*` skipped by session gate → route `authenticateApiKey` + scope check → `apiIocService` / published feed pull.
2. Published feed: `GET /api/published-feeds/:slug?api_key=` or legacy `GET /public/feeds/:token/feed.txt`.

### Feed / enrichment outbound flow

1. Admin configures custom feed URL (validated hostname literals) or enrichment provider settings (IPinfo allows configurable `base_url`).
2. Worker or on-demand enrich/test issues `fetch()` to external HTTP(S).
3. Parsed indicators written to IOC tables / enrichment tables.

### Export / backup flow

1. Authenticated user (admin/analyst depending on route) creates export/backup job → Redis queue → worker writes under volume dirs (`/data/ioc-search-exports`, `/data/backups`) with path-safety helpers → download via authenticated stream.

---

## Privilege Levels

| Principal | Preconditions | Typical capabilities |
|---|---|---|
| Unauthenticated | Network reachability | Health, setup (until configured), login/logout, OpenAPI/Swagger static, published feed with valid `api_key` / path token |
| `readonly` | Valid session JWT | GET/HEAD; self profile/preferences PUT only |
| `analyst` | Valid session JWT | Triage + many mutations (feeds sync/test, some enrichment provider config unless `requireRole(ADMIN)`); blocked where admin-only middleware applied |
| `admin` | Valid session JWT | User admin, API keys, published feeds, backups, hard deletes, taxonomy, most `/api/admin/*` |
| System admin flag | `users.is_system_admin` | Cannot be deleted/demoted/renamed/deactivated via normal admin ops |
| Ingest token | Matching env secret | Synthetic admin user; bypasses CSRF + readonly policy; blocked by `requireRole` checks |
| JWT Bearer (`ALLOW_JWT_BEARER=1`) | Valid JWT in Authorization | Same as cookie user; also bypasses CSRF + `rbacHttpPolicy` |
| `published_feed` API key | Bearer or `?api_key=` | Read published feeds (feed-agnostic for modern keys) |
| `ioc_management` API key | Bearer on `/api/v1/iocs` | Create/update IOCs within scope |

**Important assessment assumption:** Do **not** treat “admin-only”, “analyst”, or “internal worker” as free of impact. Privilege required must be stated per finding.

---

## Entry Points

| Entry Point | Type | Auth Required | Description |
|---|---|---|---|
| `GET /healthz`, `/readyz`, `/health` | HTTP | No | Liveness/readiness |
| `POST /api/auth/login`, `/logout` | HTTP | No | Session bootstrap/teardown |
| `GET /api/auth/me`, `POST /api/auth/change-password` | HTTP | Session | Identity + forced password change |
| `GET/POST /api/setup/*`, timezone | HTTP | Setup gate rules | First-run configuration |
| `GET /api/docs`, `/api/openapi.json`, `/api/docs/static/*` | HTTP | No | Public OpenAPI + Swagger UI assets |
| Most `/api/*` (IOC, users, integrations, enrichment, audit, …) | HTTP | Session JWT (+ CSRF on mutate) | Core product API |
| `/api/v1/iocs` | HTTP | Bearer API key + scopes | Machine IOC management |
| `GET /api/published-feeds/:slug?api_key=` | HTTP | Query API key | Public feed pull |
| `GET /public/feeds/:token/feed.txt` | HTTP | Path token | Legacy feed-bound key |
| Integration scheduler/worker jobs | Queue | Internal Redis | Built-in + custom feed sync |
| `ioc-*-worker`, `backup-worker` | Queue | Internal | Export, deep search, expiration, backup |
| Backup/restore CLI | CLI / host | Operator shell | Restore not exposed via HTTP |
| Off-path: scripts import CSV via API | CLI | Operator | Not an upload endpoint |

### Middleware stack (backend)

```382:389:backend/server.js
app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.use(createSetupGate(pool));
app.use(apiAuthGate);
app.use(csrfProtection);
app.use(createPasswordChangeGate(pool));
app.use(rbacHttpPolicy);
```

### Auth gate exclusions (`apiAuthGate`)

- OPTIONS
- login / logout
- setup status/preview/complete
- `/api/docs*`, `/api/openapi.json`
- entire `/api/v1*`
- `GET /api/published-feeds/{slug}` when `?api_key=` present (not `source-options`)
- Non-`/api` paths (health, `/public/feeds/...`)

---

## Route authorization matrix (security-relevant)

`method | path | auth required | role required | object-level check | evidence | concern`

| method | path | auth | role | object-level | evidence | concern |
|---|---|---|---|---|---|---|
| POST | `/api/auth/login` | No | — | — | `auth.js` gate + `server.js` login | Brute force / default creds on fresh install |
| POST | `/api/auth/change-password` | Yes | self | `req.user.id` only | `authPassword.js` | Check bypass if `userId` missing (see password gate) |
| * | `/api/admin/users/*`, reset-password | Session | admin (`requireRole`) | system-admin invariants | `users.js` | Stateless JWT not revoked on reset |
| GET/POST/PATCH/DELETE | `/api/api-keys*` | Session | list any auth; mutate/reveal admin | key id | `apiKeys.js` | Reveal must stay no-store; list not admin-only |
| GET | `/api/published-feeds/:slug?api_key=` | API key | feed key type | slug + rate limit; **not** feed-scoped for modern keys | `publicFeeds.js` | Any `th_pf_` key reads all feeds |
| GET | `/public/feeds/:token/feed.txt` | Path token | — | feed-bound hash | `publicFeeds.js` | Token-in-URL logging risk (nginx redacts some) |
| POST/PATCH | `/api/v1/iocs` | Bearer API key | scopes | strips provenance fields | `apiV1Iocs.js` | Scope confusion if middleware skipped |
| POST/PUT | `/api/custom-threat-feeds` | Session | admin | — | `customThreatFeeds.js` | SSRF via URL (+ incomplete private checks) |
| POST | `.../test-fetch`, sync | Session | admin/analyst | — | `customThreatFeeds.js` | Analyst can trigger outbound once URL set |
| PUT | `/api/admin/enrichment-providers/ipinfo-lite` | Session | **no requireRole(ADMIN)** | — | `ipEnrichment.js` ~454 | `base_url` unvalidated → SSRF + token leak |
| PUT | `/api/admin/enrichment-providers/virustotal` | Session | **no requireRole(ADMIN)** | — | `server.js` VT admin | Analyst can set VT API key |
| PUT | AbuseIPDB / Spamhaus admin | Session | admin | — | enrichment routes | Consistent admin gate |
| GET | `/api/iocs/search-exports/:id/download` | Session | (module policy) | path resolve by id/basename | `iocSearchExports.js` | Ownership/IDOR check needed in detection |
| GET | `/api/backups/:id/download` | Session | admin | pathSafety | `backups.js` | Admin-only download of archives |
| GET | `/api/docs`, openapi | No | — | — | `apiDocs.js` | Info disclosure of API surface |
| * | `/api/v1*` | API key on route | scopes | — | gate skips session | Must not inherit cookie roles |

---

## Trust Boundaries

1. **Internet/LAN browser → edge nginx → app**  
   Attacker-controlled HTTP(S), cookies, headers (`x-forwarded-*`, CSRF, Authorization). CORS defaults to allow-all on Express.

2. **SPA → backend API**  
   Same-origin via frontend nginx proxy in production; CSRF required for cookie mutations.

3. **Backend → PostgreSQL**  
   Privileged data plane; SQL must remain parameterized; dynamic identifiers must be allowlisted.

4. **Backend/workers → Redis**  
   Internal queue; compromise of Redis ≈ job injection. Default insecure Redis password fallback exists if unset.

5. **Workers → external HTTP**  
   Feed URLs, enrichment bases, IANA RDAP. User/admin-controlled URLs cross into network trust.

6. **Backend → filesystem volumes**  
   Exports/backups under `/data/*`; path traversal defenses in `pathSafety` / `exportConfig`.

7. **API keys / feed tokens → feed content**  
   Lower trust than admin session; possession grants IOC feed data.

8. **Env secrets / compose → runtime**  
   `JWT_SECRET`, DB/Redis passwords, encryption keys, provider tokens, `DNSMANIA_BASE_URL`.

### Attacker-controlled / lower-trust inputs

- HTTP bodies/query/path/headers on all public and authenticated routes
- Custom feed URLs and credentials (admin-set; fetch by admin/analyst/worker)
- IPinfo `base_url` / tokens (UI-configured)
- IOC values, search DSL, notes, tags, classifications, enrichment refresh targets
- Published feed `api_key` query / path tokens
- Uploaded-via-API JSON (no multipart upload middleware)
- CSV/text responses from remote feeds (content injection into DB → UI rendering)
- Job payloads in Redis (if Redis reachable)

---

## Sensitive Data Inventory

| Data Type | Where Stored | How Accessed | Protection |
|---|---|---|---|
| Password hashes | `users.password_hash` | Login / change / reset | bcrypt cost 12 |
| Session JWT | Cookie `demo_session` | Every `/api` session call | HttpOnly, SameSite=lax, Secure when HTTPS/`x-forwarded-proto` |
| CSRF token | Cookie `demo_csrf` | Header match | Not HttpOnly (intentional) |
| JWT signing secret | Env `JWT_SECRET` | Process boot | Rejected if missing/weak (`ensure-jwt-secret.js`) |
| Ingest token | Env | Header compare | timingSafeEqual |
| API key material | Hash + optional AES-GCM ciphertext | Create/reveal (admin) | Prefix keys; reveal audited; Soft-delete |
| Provider API keys | `threat_intel_provider_configs.api_key` **plaintext TEXT** + env fallbacks | Admin UI / enrich | Masked in API responses |
| Custom feed credentials | `integration_feeds.credentials` JSONB | Feed fetch auth headers | Masked summaries |
| API key encryption key | Env `API_KEY_ENCRYPTION_KEY` | Reveal path | Required for reveal |
| Backup archives | `/data/backups` | Admin download; CLI restore | Optional encryption key file |
| Export CSV | `/data/ioc-search-exports` | Authenticated download | Path resolve guards |
| Default admin password constant | `DEFAULT_ADMIN_PASSWORD = 'admin'` in bootstrap code | Clean install only | Documented; `must_change_password` |

---

## Subsystem Notes (assessment focus)

### Authentication / password flows

- Forced change via `must_change_password` + `passwordChangeGate` allowlist.
- Gate skips when no `req.user`, ingest auth, or **missing `userId` on JWT**.
- Password reset issues temporary password once; JWT sessions not server-revoked (documented).

### API keys / published feeds

- Profiles: `published_feed` → `published_feeds:read`; `ioc_management` → `ioc:create`+`ioc:update`.
- Soft-delete / disable must reject auth (`apiKeyAuth` — verify in detection).
- Modern published feed keys are **not feed-scoped**.

### SSRF-relevant outbound

- Custom feeds: `validateFeedUrl` blocks literal private/loopback hosts; **no DNS pin**; `redirect: 'follow'` then validate final URL; IPv4-mapped IPv6 incompletely covered.
- IPinfo: configurable `base_url` with **no URL allowlist**; token in query string on that base.
- DNSMania: env-only base URL; domain `localhost` blocked for domain lookups; IP private not fully blocked for IP lookups.
- Built-in feeds: env/code fixed hosts.

### SQL

- Primary pattern: parameterized `$n` via `pg`.
- IOC Search DSL: user values bound; operators/columns whitelisted (`iocSearchDsl/queryBuilder.js`).
- ORDER BY user influence mapped to fixed literals where present (`server.js` sort).

### RCE

- `child_process` used in backup path (`pg_dump`, `tar`, `git rev-parse`) with fixed argv patterns.
- No `eval`/`Function`/`vm`/XML/`multer` dependencies observed in app packages.

### XSS

- React SPA; **no** `dangerouslySetInnerHTML` in frontend.
- Server may emit HTML for Swagger UI (`apiDocs.js`) — review for reflected injection.
- Stored IOC/provider text rendered as React text nodes (default escape).

### Path traversal / upload

- No multipart upload handlers.
- Export/backup downloads resolve under fixed dirs with escape rejection.
- Feed sync fetches remote content into memory/DB, not arbitrary local path write from client filenames.

### GraphQL / XXE / SSTI

- **GraphQL:** no dependency, schema, or route — expect `N/A` with this evidence.
- **XXE:** no XML parser libraries; feeds are txt/csv/json — expect `N/A`.
- **SSTI:** no server template engine; Express JSON/HTML string builders only — verify OpenAPI HTML is static.

### Business logic

- API key reveal/disable/delete races; published feed advisory locks; job stale states; system-admin invariants; IOC suppression/reimport; concurrent update/delete; UI vs backend privilege mismatch (IPinfo/VT).

### Infra

- Compose publishes only 80/443.
- `cors()` unrestricted.
- Redis default password fallback `dev-insecure-redis` if unset.
- Nginx redacts `api_key` in access logs; HSTS/XFO/X-CTO headers on edge.

---

## Detection Guidance for Subsequent Skills

Prioritize:

1. SSRF (custom feed DNS/rebinding/redirect/IPv4-mapped; IPinfo `base_url` + missing admin role).
2. Missing/broken authz (analyst vs admin enrichment; ingest/bearer RBAC bypass; export IDOR).
3. JWT/session (legacy role-less → admin; password-change gate + missing `userId`; no revocation).
4. Hardcoded/default secrets (bootstrap `admin` password, compose Redis default, `.env.example` placeholders vs real).
5. SQL injection only if dynamic identifier paths escape whitelist.
6. Mark GraphQL/XXE/SSTI/file-upload classically `N/A` only after confirming no alternate surfaces (e.g., HTML template injection ≠ SSTI engine).

Do not assume safety from “admin-only” or “feed-populated” alone. Trace full source → sink with privilege prerequisites.
