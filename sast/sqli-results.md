# SQLi Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis only (no live DB exploitation / sqlmap against running services)  
**Stack:** Node.js + `pg` (PostgreSQL); primary pattern is `$n` placeholders. Dynamic SQL is limited to allowlisted identifiers/`ORDER BY` fragments and DSL compilation.

## Executive Summary

- Construction sites analyzed: **12**
- Vulnerable (Confirmed): **0**
- Likely Vulnerable (Probable): **0**
- Not Vulnerable (Rejected): **12**
- Needs Manual Review: **0**

| Bucket | Count | Finding IDs |
|---|---|---|
| Confirmed | 0 | — |
| Probable | 0 | — |
| Rejected | 12 | SQLI-01 … SQLI-12 |
| N/A | 0 | class applies; sinks exist but are defended |

**Verdict:** No SQL injection confirmed. High-interest paths (DSL `queryBuilder`, published-feed SQL, suppressions `ORDER BY` sort map) were reachability-traced and rejected.

---

## Confirmed

None.

---

## Probable

None.

---

## Findings (skill classification order)

### Vulnerable

None.

### Likely Vulnerable

None.

### Needs Manual Review

None.

### Not Vulnerable

#### [NOT VULNERABLE] SQLI-01 — IOC suppressions `ORDER BY` via request `sort` map

- **Finding ID:** SQLI-01
- **File:** `backend/server.js` (lines ~4984–4996)
- **Endpoint / function:** `GET /api/ioc-suppressions` (authenticated; list path)
- **Construction:** `` ORDER BY ${orderBy} `` where `orderBy` is selected from a ternary map keyed on `req.query.sort`
- **Taint / reachability:** `req.query.sort` is user-controlled, **but** only three exact string matches map to fixed SQL literals (`s.created_at ASC`, `s.expires_at ASC NULLS LAST`, `s.ioc_value ASC`); any other value falls through to fixed `'s.created_at DESC'`. The raw `sort` string is never concatenated into SQL.
- **Filter clauses:** `search` / `ioc_type` / `scope` / `created_by` values are pushed into `params` and referenced as `$n` (`ILIKE` / equality). Status branches push boolean literals as fixed SQL or bind active flags.
- **Reason:** Effective allowlist for dynamic `ORDER BY` identifiers; no attacker-controlled SQL fragment.
- **Remediation (hygiene only):** Optional explicit `ALLOWED_SORT` Set for readability; not required for safety.

#### [NOT VULNERABLE] SQLI-02 — IOC Search DSL `queryBuilder` (template SQL + bound values)

- **Finding ID:** SQLI-02
- **Files:**
  - `backend/lib/iocSearchDsl/queryBuilder.js` (`buildWhereClause`, `Builder`)
  - `backend/lib/iocSearchDsl/fields.js` (`FIELD_REGISTRY` field/operator whitelist)
  - `backend/lib/iocSearchDsl/index.js` / `parser.js` (`parseSearchQuery`)
  - Callers: interactive search in `backend/server.js`, export/deep-search workers, `searchPageSql.js`
- **Endpoint / function:** Authenticated IOC advanced search / export / deep search (DSL query text from request body/query or job payload)
- **Construction:** Template literals assemble boolean SQL (`ILIKE`, `EXISTS`, `IN (...)` membership). User **values** go through `this.bind()` → `$n` parameters. Field names and operators come only from the validated AST after registry checks; hash/attr type strings interpolated as identifiers are from hardcoded maps (`HASH_TYPE_LITERAL`, `ATTR_TYPE_LITERAL`) keyed by whitelisted field names—not from raw user text.
- **Taint / reachability:** User DSL text **is** reachable into the builder, but only after `parseSearchQuery` rejects unknown fields/operators/values. Bound parameters cover all search literals (including dates + timezone via `dateExpr`).
- **Reason:** Whitelist AST + parameterized values; architecture note confirmed. Not SQLi.

#### [NOT VULNERABLE] SQLI-03 — `feedPublisherService` query-mode `advanced_query` → DSL SQL

- **Finding ID:** SQLI-03
- **Files:**
  - `backend/lib/feedPublisherService.js` (`compileAdvancedQuery`, `buildQueryModeWhereSql`, `fetchQueryModeIocRows`)
  - `backend/routes/publishedFeeds.js` (`validateAdvancedQuery` via `parseSearchQuery` on create/update)
- **Endpoint / function:** Admin published-feed CRUD stores `advanced_query`; snapshot generation / public feed pull executes compiled SQL server-side
- **Construction:** `` WHERE ${whereSql} `` where `whereSql` is DSL output (same as SQLI-02) plus fixed safety `AND` fragments; tag filters bind arrays as `$n::text[]`
- **Taint / reachability:** Second-order: admin-controlled query stored in DB, later executed. Still compiled through `parseSearchQuery` + `buildWhereClause` at generation time (and validated on write). Values remain bound.
- **Reason:** Second-order DSL input does not escape parameterization/whitelist; reject.

#### [NOT VULNERABLE] SQLI-04 — `feedPublisherService` `FROM ${table}` partition watermark

- **Finding ID:** SQLI-04
- **File:** `backend/lib/feedPublisherService.js` (`FEED_IOC_PARTITION_TABLE`, `fetchCheapIocWatermark`, ~547–617)
- **Construction:** `` FROM ${table} `` with `table = FEED_IOC_PARTITION_TABLE[feedType]`
- **Taint / reachability:** `feedType` comes from `resolveFeedIocTypes(feed)` (normalized published-feed IOC categories). Only keys `ip|domain|url|hash` map to fixed partition names (`ioc_ip`, `ioc_domain`, `ioc_url`, `ioc_file_hash`). Unknown keys `continue` and skip the query. Observable types for `WHERE` are bound as `$n`.
- **Reason:** Identifier allowlist map; not user-freeform table names.

#### [NOT VULNERABLE] SQLI-05 — `feedPublisherService` inlined `min_confidence` numeric fragment

- **Finding ID:** SQLI-05
- **File:** `backend/lib/feedPublisherService.js` (`buildFeedFilterSql`, ~281–289)
- **Construction:** `` ) >= ${Number(feed.min_confidence)} `` gated by `Number.isFinite(Number(feed.min_confidence))`
- **Taint / reachability:** `min_confidence` is set from admin feed body (`publishedFeeds.js`) and persisted. Only finite numbers pass the gate; non-numeric strings become `NaN` and skip the clause. Interpolated value is a JS number, not raw string.
- **Reason:** Type-gated numeric literal interpolation cannot carry SQL metacharacters; reject as SQLi (prefer `$n` later for style only).

#### [NOT VULNERABLE] SQLI-06 — `buildFeedKeySourceSql` / window filters

- **Finding ID:** SQLI-06
- **Files:** `backend/lib/publishedFeedSources.js` (`buildFeedKeySourceSql`); `feedPublisherService.js` (`WINDOW_INTERVALS` + interval `$n::interval`)
- **Construction:** Dynamic `AND (`…`)` assembled from feed keys; each comparison uses `$n` (exact/prefix/ILIKE/custom `ANY`/manual `ANY` bigint). Window strings map through `WINDOW_INTERVALS` then bind as interval parameters—never interpolate raw user window text.
- **Taint / reachability:** `include_feed_keys` are admin-set and filtered against known keys; even if unexpected, string values are still bound, not concatenated as SQL.
- **Reason:** Parameterized predicates + allowlisted window keys.

#### [NOT VULNERABLE] SQLI-07 — Integration queue window `intervalSql`

- **Finding ID:** SQLI-07
- **File:** `backend/server.js` (~640–695)
- **Construction:** `` q.queued_at >= ${intervalSql} `` where `intervalSql` is one of fixed string literals (`NOW() - INTERVAL '24 hours'|'7 days'|'30 days'`). Custom range uses **timestamptz binds** after `Date.parse` validation—not string concat of `queue_from`/`queue_to` into SQL.
- **Taint / reachability:** `queue_window` query param only selects among fixed branches; invalid/custom handled separately with parameters.
- **Reason:** Allowlisted fixed interval SQL; custom path parameterized.

#### [NOT VULNERABLE] SQLI-08 — IOC list `FROM ${partitionTable}`

- **Finding ID:** SQLI-08
- **File:** `backend/server.js` (~4067–4075)
- **Construction:** `` FROM ${partitionTable} `` with map `{ ip, ipv6, domain, url } → ioc_*` keyed by resolved `obsType`
- **Taint / reachability:** Only mapped types yield a table; fragment is code constant. Status predicates via `iocStatusSqlClause` compare `mode` and emit fixed SQL (mode string never interpolated).
- **Reason:** Allowlisted partition identifiers.

#### [NOT VULNERABLE] SQLI-09 — `iocActiveSources` `FROM ${table}`

- **Finding ID:** SQLI-09
- **File:** `backend/lib/iocActiveSources.js` (`IOC_LIST_PARTITION_BY_TYPE`, `resolveIocPartitionRows`, ~439–477)
- **Construction:** Same pattern: type → fixed partition name; IDs/types bound as `$1`/`$2`
- **Reason:** Allowlist map; reject.

#### [NOT VULNERABLE] SQLI-10 — `SET LOCAL statement_timeout` numeric interpolation

- **Finding ID:** SQLI-10
- **Files:**
  - `backend/server.js` (~4534–4538): `safeTimeout = Math.max(100, Math.min(Math.trunc(timeoutMs), 120000))`
  - `backend/ioc-deep-search-worker.js` (~158): `Math.trunc(cfg.queryTimeoutMs)`
- **Construction:** `` SET LOCAL statement_timeout = ${safeTimeout|truncatedMs} ``
- **Taint / reachability:** Interactive timeout from `getQueryTimeoutMs()` (env integer clamps in `iocSearchDsl/config.js`). Worker timeout from worker config (numeric). No request string reaches the SET fragment.
- **Reason:** Integer-only server config; not SQLi.

#### [NOT VULNERABLE] SQLI-11 — `SET TIME ZONE` with IANA validation + quote escape

- **Finding ID:** SQLI-11
- **File:** `backend/lib/systemTime.js` (`assertValidIanaTimezone`, `setClientSessionTimezone`, ~49–65, 585–588)
- **Construction:** `` SET TIME ZONE '${tz.replace(/'/g, "''")}' ``
- **Taint / reachability:** Timezone originates from setup/admin-configured system setting. Before use, `assertValidIanaTimezone` requires non-empty IANA validation via `Intl.DateTimeFormat(..., { timeZone: tz })` and rejects fixed offset forms. Only validated zones are interpolated; quote doubling is defense-in-depth.
- **Reason:** Effective allowlist (valid IANA IDs only), not free-form SQL. (Note: quote-escaping alone would be insufficient per skill; validation is what rejects.)

#### [NOT VULNERABLE] SQLI-12 — Misc dynamic identifier helpers (constants / sanitized)

- **Finding ID:** SQLI-12
- **Sites:**
  - `backend/routes/threatClassifications.js`: `` ORDER BY ${ADMIN_LIST_ORDER_SQL} `` — module-constant SQL including fixed `UNKNOWN_THREAT_CLASSIFICATION` slug
  - `backend/lib/fileArtifacts/txSavepoint.js`: `` SAVEPOINT ${sp} `` — name regex-sanitized to `[A-Za-z0-9_]` / callers pass hardcoded names (`fa_hash_ins`)
  - `backend/lib/iocSearchDsl/searchPageSql.js`: `` LIMIT ${probeLimit} `` — integer from env-clamped preview limit (+1)
  - `backend/lib/fileArtifacts/canonicalListSql.js`: `${fromAlias}` / `${itemAlias}` — caller-supplied SQL aliases with defaults (`ann`, `i`, `f`); not HTTP path params
- **Reason:** No attacker-controlled unvalidated identifier reaches these sinks.

---

## Rejected (summary table)

| ID | Site | Why rejected |
|---|---|---|
| SQLI-01 | suppressions `ORDER BY` sort map | Exact-match → fixed ORDER BY literals |
| SQLI-02 | DSL `queryBuilder` | Field/op whitelist + `$n` binds |
| SQLI-03 | feedPublisher advanced_query | Same DSL compiler; second-order still safe |
| SQLI-04 | feedPublisher `FROM ${table}` | Partition name allowlist |
| SQLI-05 | `min_confidence` Number() | Finite-number gate only |
| SQLI-06 | feed key / window SQL | Params + window allowlist |
| SQLI-07 | queue `intervalSql` | Fixed INTERVAL literals / bound custom range |
| SQLI-08 | IOC list partition `FROM` | Type→table map |
| SQLI-09 | iocActiveSources partition `FROM` | Type→table map |
| SQLI-10 | `statement_timeout` SET | Clamped integers from config |
| SQLI-11 | `SET TIME ZONE` | IANA allowlist validation |
| SQLI-12 | classifications / SAVEPOINT / LIMIT / aliases | Constants or sanitized non-HTTP identifiers |

---

## Coverage notes

- Broader codebase overwhelmingly uses `pool.query(staticOrPlaceholderSql, [params])`. Dynamic `WHERE ${joinedClauses}` patterns observed in audit/tags/export paths compose **parameterized** clause fragments (`col = $n`), not raw user strings into SQL text.
- No classic `"SELECT … '" + user + "'"` / `` `…${req.query.x}…` `` value-injection sinks were found in production backend paths after recon of template-literal and `ORDER BY`/`FROM ${…}` sites.
- Privilege note: admin/analyst ability to author DSL or feed configs does not create SQLi when compilation remains parameterized.

## Intermediate artifacts

No `sast/sqli-recon.md` / `sast/sqli-batch-*.md` retained (recon + taint performed in-session; final merge only).
