# File Artifacts

Exact file-hash IOCs (`md5`, `sha1`, `sha256`) remain stored as `ioc_items` rows. A **File Artifact** is an additive identity layer that groups sibling exact hashes of the same physical file without deleting IOC UUIDs or rewriting correlation/audit FKs.

## Schema

Migration: `backend/migrations/131_file_artifacts.sql`

| Table | Purpose |
|-------|---------|
| `file_artifacts` | One logical file (`status`: `active` \| `merged`) |
| `file_artifact_hashes` | Exact identity hashes only (global unique per type+value) |
| `file_artifact_ioc_links` | Links legacy `ioc_items` → artifact (preserves `public_id`) |
| `file_artifact_source_observations` | **Observed-as** attribution per source |
| `file_artifact_non_identity_attrs` | IMPHASH / TLSH / SSDEEP (never auto-merge evidence) |
| `file_artifact_merge_conflicts` | Conflicting mappings that block auto-merge |

Primary hash priority: **SHA256 > SHA1 > MD5**. SHA512 is not supported in TalonHound.

No additive list index migration (`132_*`) is shipped yet. Fixture-scale `EXPLAIN (ANALYZE, BUFFERS)` on the disposable harness did not justify a new index; re-measure at 1–5k identities before production.

## Feature flags

| Env | Default | Effect |
|-----|---------|--------|
| `FILE_ARTIFACTS_DUAL_WRITE_ENABLED` | off | Importers/manual/custom/VT write artifact rows |
| `FILE_ARTIFACTS_READ_ENABLED` | off | Detail `file_artifact` block, **canonical list/search/export**, `/api/file-artifacts/:id` |

Flags are independent. Dual-write can run while read stays off (populate tables without changing UI grain).

## Canonical list / export semantics (read flag **on**)

Identity key:

- Linked file artifact → `a:<resolved_artifact_id>` (follows one `merged_into` hop)
- Else legacy → `o:<type>:<lower(value)>`

Pagination and totals use this identity **before** `LIMIT` / keyset (browse, exact/hash/partition, CTE, DSL search). Post-LIMIT JS collapse is not the source of truth when read is on.

### Active browse (SQL-before-pagination)

When `FILE_ARTIFACTS_READ_ENABLED` is on, `fetchActiveIocListPage` uses `buildCanonicalActiveBrowsePageSql()`:

1. Candidate index walk (`ORDER BY created_at DESC LIMIT candidate`) — bound only for planner cost
2. Active membership / manual `ioc_source_id` filter
3. Annotate `identity_key` + primary hash
4. `GROUP BY identity_key` (canonical row; platform time = `MIN(created_at)`)
5. Cap to `browseCap` identities
6. **`LIMIT $3 OFFSET $4` on canonical rows**

JS `canonicalizeRowsByIdentity` is **not** used for browse page slicing when read is on. READ off keeps the legacy oversample + `(type|value)` JS path.

Sort: `platform_imported_at DESC`, tie-breaker `identity_key ASC`.

| Field | Meaning |
|-------|---------|
| List timestamp | Platform import = `MIN(ioc_items.created_at)` across linked IOCs |
| Display value / type | Primary hash (`file_artifact_hashes.is_primary`), else representative IOC |
| Export grain | **1 artifact = 1 CSV row** (same identity as list) |
| Additive export columns | `artifact_id`, `primary_hash_type`, `primary_hash_value`, `known_hashes`, `linked_ioc_public_ids` |

When read flag is **off**: list/export keep legacy `(type,value)` / raw `ioc_items` contracts.

## Concurrent attach (orphan-safe)

`attachExactHash` (shared by dual-write + backfill):

1. Opens a transaction when given a Pool (caller Client keeps outer tx)
2. `pg_advisory_xact_lock(hashtext(type), hashtext(value))` on normalized hash identity
3. Re-read hash → reuse artifact if present
4. Else create artifact + hash under the lock
5. On unique violation: delete **only** this-tx empty orphan (no hashes/links/observations/attrs), then attach to winner

Do **not** run global empty-artifact deletes. Hash uniqueness remains source of truth.

## Orphan invariant

```sql
SELECT fa.id
FROM file_artifacts fa
LEFT JOIN file_artifact_hashes fah ON fah.artifact_id = fa.id
LEFT JOIN file_artifact_ioc_links fail ON fail.artifact_id = fa.id
LEFT JOIN file_artifact_source_observations faso ON faso.artifact_id = fa.id
WHERE fah.id IS NULL
  AND fail.id IS NULL
  AND faso.id IS NULL;
```

Expected: **0**. Enforced in backfill `validate` phase and disposable harness.

## Automatic merge trust rules

Auto-merge / attach sibling hashes only when:

1. Same MalwareBazaar source record note contains exact hash set (`md5=` / `sha1=` + primary sha256)
2. VirusTotal `raw_response.data.attributes` contains exact md5/sha1/sha256 together
3. Manual merge (service ready; UI is Phase 2)

**Never** auto-merge from: file name, size, MIME, family, tags, IMPHASH, TLSH, SSDEEP, timestamps alone.

## Source attribution

- Custom feed sending only MD5 → observation `observed_as=md5` (`direct_source_observation`)
- MalwareBazaar sending SHA256 → `observed_as=sha256`; sibling hashes get `provider_hash_mapping`
- Never attribute a hash a source did not send as a direct observation

Observations are stored in `file_artifact_source_observations` for dual-write / merge integrity.
They are not rendered as a dedicated IOC Details "Source Evidence" UI section.

## Backfill

```bash
# Dry-run (must not mutate)
FILE_ARTIFACT_BACKFILL_DRY_RUN=1 npm run backfill-file-artifacts --prefix integration

# Seed only
FILE_ARTIFACT_BACKFILL_PHASE=seed FILE_ARTIFACT_BACKFILL_BATCH_SIZE=500 npm run backfill-file-artifacts --prefix integration

# Provider mapping (MB + VT)
FILE_ARTIFACT_BACKFILL_PHASE=provider npm run backfill-file-artifacts --prefix integration

# Validate invariants
FILE_ARTIFACT_BACKFILL_PHASE=validate npm run backfill-file-artifacts --prefix integration
```

Idempotent. Does not delete IOCs. Resume via `FILE_ARTIFACT_BACKFILL_RESUME_PUBLIC_ID`.

## Full rollout (forward)

1. Deploy migration `131` (additive only; safe with flags off)
2. Enable **`FILE_ARTIFACTS_DUAL_WRITE_ENABLED=1`** — new imports populate artifact tables; UI still legacy
3. Dry-run backfill → confirm no mutation → execute `seed` → `provider` → `validate`
4. Spot-check operational SQL (below)
5. Enable **`FILE_ARTIFACTS_READ_ENABLED=1`** — detail + canonical list/search/export
6. Monitor list totals, page sizes, export row counts vs identity count

## Rollback (both directions)

### A. Read rollback (immediate UI/API legacy)

1. Set `FILE_ARTIFACTS_READ_ENABLED=0` (or unset)
2. List/search/export return legacy grain; detail omits `file_artifact` block
3. Artifact tables and dual-write data remain intact

### B. Dual-write rollback (stop writing artifacts)

1. Set `FILE_ARTIFACTS_DUAL_WRITE_ENABLED=0`
2. Prefer also setting read off if tables will go stale
3. **Do not** drop tables in this phase; no destructive migration

### C. Combined “full off”

1. Read off → dual-write off
2. Leave schema in place for a later re-enable

## Operational SQL checks

```sql
-- Empty orphan artifacts (must be 0)
SELECT COUNT(*) FROM file_artifacts fa
LEFT JOIN file_artifact_hashes fah ON fah.artifact_id = fa.id
LEFT JOIN file_artifact_ioc_links fail ON fail.artifact_id = fa.id
LEFT JOIN file_artifact_source_observations faso ON faso.artifact_id = fa.id
WHERE fah.id IS NULL AND fail.id IS NULL AND faso.id IS NULL;

-- Orphan links (should be 0)
SELECT COUNT(*) FROM file_artifact_ioc_links l
LEFT JOIN ioc_items i ON i.id = l.ioc_item_id AND i.observable_type = l.ioc_observable_type
WHERE i.id IS NULL;

-- Multiple primaries per artifact (should be 0; enforced by unique index)
SELECT artifact_id, COUNT(*) FROM file_artifact_hashes
WHERE is_primary GROUP BY artifact_id HAVING COUNT(*) > 1;

-- Open merge conflicts
SELECT conflicting_hash_type, conflicting_hash_value, reason, created_at
FROM file_artifact_merge_conflicts WHERE status = 'open'
ORDER BY created_at DESC LIMIT 50;

-- Identity count vs raw hash IOC count (read-on expectation: identities ≤ raw)
SELECT
  (SELECT COUNT(*) FROM ioc_items WHERE observable_type IN ('md5','sha1','sha256')) AS raw_hash_iocs,
  (SELECT COUNT(*) FROM file_artifacts WHERE status = 'active') AS active_artifacts;
```

## Disposable DB tests (repo-real)

Hard fail unless `ALLOW_FILE_ARTIFACT_DB_TESTS=1`, `DB_NAME` contains `_test`, host is `127.0.0.1`/`localhost`, and `NODE_ENV` is not `production`.

```bash
# Linux/macOS
ALLOW_FILE_ARTIFACT_DB_TESTS=1 ./scripts/file-artifact-db-tests.sh

# Windows / cross-platform (starts postgres:16-alpine on :55432 when Docker is available)
cd backend
set ALLOW_FILE_ARTIFACT_DB_TESTS=1
set NODE_ENV=test
set DB_HOST=127.0.0.1
set DB_PORT=55432
set DB_USER=demo
set DB_PASSWORD=test
set DB_NAME=talonhound_file_artifact_test
npm run test:file-artifacts-db
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | PASS — all migration/backfill/list/export/concurrency/EXPLAIN checks |
| `1` | FAIL — assertion or migration error |
| `2` | SKIP/BLOCKED — Docker/guard unavailable (**not** a pass; not commit-ready for DB acceptance) |

Flow: migrate all → assert `131` → seed fixture → dry-run (no mutation) → backfill → validate → second backfill idempotent → concurrent attach ×10 → orphan=0 → SQL browse pages → list/export → EXPLAIN → cleanup.

Use existing DB without Docker: `FILE_ARTIFACT_DB_SKIP_DOCKER=1` (still requires the guard).

### EXPLAIN (on disposable DB)

Harness runs `EXPLAIN (ANALYZE, BUFFERS)` for canonical browse + CTE list. Re-run manually:

```sql
-- bind: candidate, browseCap, limit, offset
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
-- paste buildCanonicalActiveBrowsePageSql() body
```

Add `132_*` indexes only with a real plan justification; do not rewrite `131` if any environment may have applied it.

## API

- `GET /api/ioc/details?public_id=` — additive `file_artifact` when read flag on
- `GET /api/file-artifacts/:artifactId` — artifact payload when read flag on
- `GET /api/ioc/list`, `POST /api/iocs/search`, DSL CSV export — canonical identity when read flag on

## Conflict handling

If MD5 X maps to two different SHA256 artifacts via trusted providers, a row is written to `file_artifact_merge_conflicts` and automatic merge is skipped.
