/**
 * SQL builders for POST /api/iocs/search page + probe queries.
 *
 * FILE_ARTIFACTS_READ_ENABLED page path must:
 *   1) filter matching ioc_items (DSL whereSql — indexable predicates stay on i.*)
 *   2) resolve canonical identity_key (artifact or o:type:value)
 *   3) aggregate platform_imported_at = MIN(created_at) per identity
 *   4) pick a stable representative row (primary-hash preference)
 *   5) keyset-paginate the canonical set: ORDER BY platform_imported_at DESC, id DESC
 *
 * The previous FA page CTE materialised every matching row, then HashAggregated
 * multi-column ARRAY_AGGs across the full set before LIMIT — that allocation
 * blows past Docker's default 64MiB /dev/shm when parallel workers kick in
 * (root cause of HTTP 500 "Search failed" for source contains "USOM").
 *
 * Exact semantics are preserved; memory is reduced by:
 *   - light bounds (MIN/MAX + single-column status agg) separate from representative pick
 *   - DISTINCT ON for the representative instead of ARRAY_AGG of every display column
 *   - projecting page rows only after keyset + LIMIT on the canonical set
 */

export const HASH_TYPE_RANK_SQL = `CASE LOWER(observable_type) WHEN 'sha256' THEN 0 WHEN 'sha1' THEN 1 WHEN 'md5' THEN 2 ELSE 9 END`;

export const PRIMARY_MATCH_RANK_SQL = `CASE WHEN primary_hash_value IS NOT NULL
  AND LOWER(observable) = LOWER(primary_hash_value)
  AND LOWER(observable_type) = LOWER(primary_hash_type) THEN 0 ELSE 1 END`;

function artifactIdExpr(itemAlias = 'i') {
  return `CASE
    WHEN fa.id IS NULL THEN NULL
    WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL THEN fa.merged_into_artifact_id
    ELSE fa.id
  END`;
}

function identityKeyExpr(itemAlias = 'i') {
  return `CASE
    WHEN fa.id IS NULL THEN 'o:' || ${itemAlias}.observable_type || ':' || LOWER(${itemAlias}.observable)
    WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
      THEN 'a:' || fa.merged_into_artifact_id::text
    ELSE 'a:' || fa.id::text
  END`;
}

function artifactAnnotateJoins(itemAlias = 'i') {
  return `
  LEFT JOIN file_artifact_ioc_links fal
    ON fal.ioc_item_id = ${itemAlias}.id AND fal.ioc_observable_type = ${itemAlias}.observable_type
  LEFT JOIN file_artifacts fa ON fa.id = fal.artifact_id
  LEFT JOIN file_artifact_hashes faph
    ON faph.artifact_id = COALESCE(
         CASE WHEN fa.status = 'merged' THEN fa.merged_into_artifact_id ELSE fa.id END,
         fa.id
       )
   AND faph.is_primary = TRUE`;
}

/**
 * Legacy FA page SQL (pre-fix): LIMIT only after full multi-column GROUP BY.
 * Exported for EXPLAIN / equivalence harnesses — not used by the API.
 */
export function buildLegacyFileArtifactSearchPageSql({
  whereSql,
  cursorParamStart = null,
  limitParamIdx
}) {
  const cursorClause = cursorParamStart != null
    ? ` AND (platform_imported_at, id) < ($${cursorParamStart}::timestamptz, $${cursorParamStart + 1}::bigint)`
    : '';
  return `
    WITH matched AS (
      SELECT i.id, i.public_id, i.observable, i.observable_type,
             COALESCE(i.status, 'active') AS status,
             i.first_seen_at, i.last_seen_at, i.created_at,
             i.source_name, i.confidence, i.category,
             i.threat_classification, i.threat_actor_id
      FROM ioc_items i
      WHERE ${whereSql}
    ),
    ann AS (
      SELECT m.*,
             ${artifactIdExpr('m')} AS artifact_id,
             faph.hash_type AS primary_hash_type,
             faph.normalized_hash_value AS primary_hash_value,
             ${identityKeyExpr('m')} AS identity_key
      FROM matched m
      ${artifactAnnotateJoins('m')}
    ),
    grouped AS (
      SELECT
        identity_key,
        MIN(created_at) AS platform_imported_at,
        (ARRAY_AGG(id ORDER BY
          ${PRIMARY_MATCH_RANK_SQL},
          ${HASH_TYPE_RANK_SQL},
          created_at ASC, id ASC
        ))[1]::bigint AS id,
        (ARRAY_AGG(public_id::text ORDER BY
          ${PRIMARY_MATCH_RANK_SQL},
          ${HASH_TYPE_RANK_SQL},
          created_at ASC, id ASC
        ))[1] AS public_id,
        COALESCE(
          (ARRAY_AGG(primary_hash_value) FILTER (WHERE primary_hash_value IS NOT NULL))[1],
          (ARRAY_AGG(observable ORDER BY created_at ASC, id ASC))[1]
        ) AS observable,
        COALESCE(
          (ARRAY_AGG(primary_hash_type) FILTER (WHERE primary_hash_type IS NOT NULL))[1],
          (ARRAY_AGG(observable_type ORDER BY created_at ASC, id ASC))[1]
        ) AS observable_type,
        (ARRAY_AGG(status ORDER BY created_at DESC))[1] AS status,
        MIN(first_seen_at) AS first_seen_at,
        MAX(last_seen_at) AS last_seen_at,
        (ARRAY_AGG(artifact_id) FILTER (WHERE artifact_id IS NOT NULL))[1] AS artifact_id
      FROM ann
      GROUP BY identity_key
    )
    SELECT id, public_id, observable, observable_type, status,
           first_seen_at, last_seen_at, platform_imported_at AS created_at, artifact_id, identity_key
    FROM grouped
    WHERE TRUE${cursorClause}
    ORDER BY platform_imported_at DESC, id DESC
    LIMIT $${limitParamIdx}`;
}

/**
 * Exact-semantics FA page SQL: aggregate bounds first, DISTINCT ON representative,
 * then keyset + LIMIT on the canonical set before any wide page projection.
 */
export function buildFileArtifactSearchPageSql({
  whereSql,
  cursorParamStart = null,
  limitParamIdx
}) {
  const cursorClause = cursorParamStart != null
    ? ` AND (c.platform_imported_at, c.id) < ($${cursorParamStart}::timestamptz, $${cursorParamStart + 1}::bigint)`
    : '';

  return `
    WITH annotated AS (
      SELECT
        i.id,
        i.public_id,
        i.observable,
        i.observable_type,
        COALESCE(i.status, 'active') AS status,
        i.first_seen_at,
        i.last_seen_at,
        i.created_at,
        ${artifactIdExpr('i')} AS artifact_id,
        faph.hash_type AS primary_hash_type,
        faph.normalized_hash_value AS primary_hash_value,
        ${identityKeyExpr('i')} AS identity_key
      FROM ioc_items i
      ${artifactAnnotateJoins('i')}
      WHERE ${whereSql}
    ),
    bounds AS (
      SELECT
        identity_key,
        MIN(created_at) AS platform_imported_at,
        MIN(first_seen_at) AS first_seen_at,
        MAX(last_seen_at) AS last_seen_at,
        (ARRAY_AGG(status ORDER BY created_at DESC))[1] AS status,
        (ARRAY_AGG(artifact_id) FILTER (WHERE artifact_id IS NOT NULL))[1] AS artifact_id
      FROM annotated
      GROUP BY identity_key
    ),
    reps AS (
      SELECT DISTINCT ON (identity_key)
        identity_key,
        id,
        public_id,
        observable,
        observable_type,
        primary_hash_type,
        primary_hash_value
      FROM annotated
      ORDER BY
        identity_key,
        ${PRIMARY_MATCH_RANK_SQL},
        ${HASH_TYPE_RANK_SQL},
        created_at ASC,
        id ASC
    ),
    canonical AS (
      SELECT
        b.identity_key,
        b.platform_imported_at,
        b.first_seen_at,
        b.last_seen_at,
        b.status,
        b.artifact_id,
        r.id,
        r.public_id,
        COALESCE(r.primary_hash_value, r.observable) AS observable,
        COALESCE(r.primary_hash_type, r.observable_type) AS observable_type
      FROM bounds b
      JOIN reps r ON r.identity_key = b.identity_key
    )
    SELECT
      c.id,
      c.public_id,
      c.observable,
      c.observable_type,
      c.status,
      c.first_seen_at,
      c.last_seen_at,
      c.platform_imported_at AS created_at,
      c.artifact_id,
      c.identity_key
    FROM canonical c
    WHERE TRUE${cursorClause}
    ORDER BY c.platform_imported_at DESC, c.id DESC
    LIMIT $${limitParamIdx}`;
}

export function buildPlainSearchPageSql({
  whereSql,
  keysetClause = '',
  limitParamIdx
}) {
  return `
    SELECT i.id, i.public_id, i.observable, i.observable_type,
           COALESCE(i.status, 'active') AS status,
           i.first_seen_at, i.last_seen_at, i.created_at
    FROM ioc_items i
    WHERE ${whereSql}${keysetClause}
    ORDER BY i.created_at DESC, i.id DESC
    LIMIT $${limitParamIdx}`;
}

export function buildSearchPageSql({
  fileArtifactsReadEnabled,
  whereSql,
  keysetClause = '',
  cursorParamStart = null,
  limitParamIdx
}) {
  if (fileArtifactsReadEnabled) {
    return buildFileArtifactSearchPageSql({
      whereSql,
      cursorParamStart,
      limitParamIdx
    });
  }
  return buildPlainSearchPageSql({ whereSql, keysetClause, limitParamIdx });
}

/**
 * Canonical result SELECT with no pagination, for Deep Search spool materialization.
 *
 * Produces exactly the same canonical rows (same identity dedup, same representative pick,
 * same ORDER BY platform_imported_at DESC, id DESC) as the interactive page SQL, but
 * without a cursor/keyset or LIMIT — so it can be wrapped by a single database-native
 * INSERT ... SELECT that materializes the whole (bounded) result set once. Reusing the
 * interactive projection guarantees Deep Search browsing shows byte-for-byte the same rows
 * the interactive path would have shown.
 *
 * Columns: id, public_id, observable, observable_type, status, first_seen_at, created_at,
 * artifact_id. (created_at is platform_imported_at in the FA path.)
 */
export function buildCanonicalResultSelectSql({ fileArtifactsReadEnabled, whereSql }) {
  if (fileArtifactsReadEnabled) {
    return `
    WITH annotated AS (
      SELECT
        i.id, i.public_id, i.observable, i.observable_type,
        COALESCE(i.status, 'active') AS status,
        i.first_seen_at, i.last_seen_at, i.created_at,
        ${artifactIdExpr('i')} AS artifact_id,
        faph.hash_type AS primary_hash_type,
        faph.normalized_hash_value AS primary_hash_value,
        ${identityKeyExpr('i')} AS identity_key
      FROM ioc_items i
      ${artifactAnnotateJoins('i')}
      WHERE ${whereSql}
    ),
    bounds AS (
      SELECT
        identity_key,
        MIN(created_at) AS platform_imported_at,
        MIN(first_seen_at) AS first_seen_at,
        (ARRAY_AGG(status ORDER BY created_at DESC))[1] AS status,
        (ARRAY_AGG(artifact_id) FILTER (WHERE artifact_id IS NOT NULL))[1] AS artifact_id
      FROM annotated
      GROUP BY identity_key
    ),
    reps AS (
      SELECT DISTINCT ON (identity_key)
        identity_key, id, public_id, observable, observable_type,
        primary_hash_type, primary_hash_value
      FROM annotated
      ORDER BY identity_key, ${PRIMARY_MATCH_RANK_SQL}, ${HASH_TYPE_RANK_SQL}, created_at ASC, id ASC
    )
    SELECT
      r.id,
      r.public_id,
      COALESCE(r.primary_hash_value, r.observable) AS observable,
      COALESCE(r.primary_hash_type, r.observable_type) AS observable_type,
      b.status,
      b.first_seen_at,
      b.platform_imported_at AS created_at,
      b.artifact_id
    FROM bounds b
    JOIN reps r ON r.identity_key = b.identity_key`;
  }
  return `
    SELECT i.id, i.public_id, i.observable, i.observable_type,
           COALESCE(i.status, 'active') AS status,
           i.first_seen_at, i.created_at,
           NULL::uuid AS artifact_id
    FROM ioc_items i
    WHERE ${whereSql}`;
}

/**
 * Full INSERT ... SELECT that materializes a Deep Search result set into the spool table.
 *
 *   whereSql/params : compiled DSL predicate (references alias i) — already includes the
 *                     snapshot cutoff bound appended by the caller.
 *   deepSearchIdIdx : $ index of the deep_search_id parameter
 *
 * There is deliberately NO LIMIT: a completed Deep Search materializes the COMPLETE matching
 * set. The only bound is the background statement_timeout the caller sets (a real, named
 * config) — if the set cannot be materialized within it, the statement is cancelled (57014)
 * and the search fails honestly rather than silently truncating.
 *
 * position is a dense 1-based rank in the canonical ORDER BY, so the spool is keyset-
 * browsable by (created_at DESC, ioc_item_id DESC) — the same order the interactive list
 * uses. No result rows are ever loaded into Node.
 */
export function buildDeepSearchSpoolInsertSql({ fileArtifactsReadEnabled, whereSql, deepSearchIdIdx }) {
  const canonical = buildCanonicalResultSelectSql({ fileArtifactsReadEnabled, whereSql });
  return `
    INSERT INTO ioc_deep_search_results
      (deep_search_id, position, ioc_item_id, ioc_observable_type, public_id,
       observable, status, created_at, first_seen_at, artifact_id)
    SELECT
      $${deepSearchIdIdx}::uuid,
      ROW_NUMBER() OVER (ORDER BY c.created_at DESC, c.id DESC),
      c.id,
      c.observable_type,
      c.public_id,
      c.observable,
      c.status,
      c.created_at,
      c.first_seen_at,
      c.artifact_id
    FROM (${canonical}) c`;
}

export function buildFileArtifactSearchProbeSql({ whereSql, probeLimit }) {
  const matchedLimit = Math.max(probeLimit * 5, probeLimit);
  return `
    WITH matched AS (
      SELECT i.id, i.observable, i.observable_type
      FROM ioc_items i
      WHERE ${whereSql}
      LIMIT ${matchedLimit}
    ),
    ann AS (
      SELECT m.*,
             CASE
               WHEN fa.id IS NULL THEN 'o:' || m.observable_type || ':' || LOWER(m.observable)
               WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
                 THEN 'a:' || fa.merged_into_artifact_id::text
               ELSE 'a:' || fa.id::text
             END AS identity_key
      FROM matched m
      LEFT JOIN file_artifact_ioc_links fal
        ON fal.ioc_item_id = m.id AND fal.ioc_observable_type = m.observable_type
      LEFT JOIN file_artifacts fa ON fa.id = fal.artifact_id
    )
    SELECT 1 FROM (SELECT DISTINCT identity_key FROM ann) d LIMIT ${probeLimit}`;
}

export function buildPlainSearchProbeSql({ whereSql, probeLimit }) {
  return `SELECT 1 FROM ioc_items i WHERE ${whereSql} LIMIT ${probeLimit}`;
}

export function buildSearchProbeSql({
  fileArtifactsReadEnabled,
  whereSql,
  probeLimit
}) {
  if (fileArtifactsReadEnabled) {
    return buildFileArtifactSearchProbeSql({ whereSql, probeLimit });
  }
  return buildPlainSearchProbeSql({ whereSql, probeLimit });
}

/**
 * In-memory canonical page used by equivalence tests.
 * Mirrors SQL: identity_key → MIN(created_at), representative order, then
 * keyset on (platform_imported_at, id) DESC.
 */
export function canonicalSearchPageFromRows(rows, { limit, cursor = null } = {}) {
  const groups = new Map();
  const hashRank = (t) => {
    const x = String(t || '').toLowerCase();
    if (x === 'sha256') return 0;
    if (x === 'sha1') return 1;
    if (x === 'md5') return 2;
    return 9;
  };
  const primaryRank = (row) => (
    row.primary_hash_value
    && String(row.observable).toLowerCase() === String(row.primary_hash_value).toLowerCase()
    && String(row.observable_type).toLowerCase() === String(row.primary_hash_type).toLowerCase()
      ? 0 : 1
  );
  const identityKey = (row) => {
    if (row.identity_key) return row.identity_key;
    if (row.artifact_id) return `a:${row.artifact_id}`;
    return `o:${row.observable_type}:${String(row.observable || '').toLowerCase()}`;
  };

  for (const row of rows) {
    const key = identityKey(row);
    let g = groups.get(key);
    if (!g) {
      g = { key, members: [] };
      groups.set(key, g);
    }
    g.members.push(row);
  }

  const canonical = [];
  for (const g of groups.values()) {
    const sorted = [...g.members].sort((a, b) => {
      const pr = primaryRank(a) - primaryRank(b);
      if (pr) return pr;
      const hr = hashRank(a.observable_type) - hashRank(b.observable_type);
      if (hr) return hr;
      const ta = new Date(a.created_at).getTime();
      const tb = new Date(b.created_at).getTime();
      if (ta !== tb) return ta - tb;
      return Number(a.id) - Number(b.id);
    });
    const byNewestStatus = [...g.members].sort((a, b) => {
      const ta = new Date(a.created_at).getTime();
      const tb = new Date(b.created_at).getTime();
      if (tb !== ta) return tb - ta;
      return Number(b.id) - Number(a.id);
    });
    const rep = sorted[0];
    const primary = g.members.find((m) => m.primary_hash_value) || null;
    const platform_imported_at = g.members.reduce(
      (min, m) => (!min || new Date(m.created_at) < new Date(min) ? m.created_at : min),
      null
    );
    const first_seen_at = g.members.reduce(
      (min, m) => (!min || new Date(m.first_seen_at) < new Date(min) ? m.first_seen_at : min),
      null
    );
    const last_seen_at = g.members.reduce(
      (max, m) => (!max || new Date(m.last_seen_at) > new Date(max) ? m.last_seen_at : max),
      null
    );
    const artifact_id = g.members.map((m) => m.artifact_id).find(Boolean) || null;
    canonical.push({
      identity_key: g.key,
      id: Number(rep.id),
      public_id: String(rep.public_id),
      observable: primary?.primary_hash_value || rep.observable,
      observable_type: primary?.primary_hash_type || rep.observable_type,
      status: byNewestStatus[0].status || 'active',
      first_seen_at,
      last_seen_at,
      created_at: platform_imported_at,
      artifact_id
    });
  }

  canonical.sort((a, b) => {
    const ta = new Date(a.created_at).getTime();
    const tb = new Date(b.created_at).getTime();
    if (tb !== ta) return tb - ta;
    return Number(b.id) - Number(a.id);
  });

  let filtered = canonical;
  if (cursor) {
    const ct = new Date(cursor.t).getTime();
    const cid = Number(cursor.id);
    filtered = canonical.filter((row) => {
      const rt = new Date(row.created_at).getTime();
      if (rt < ct) return true;
      if (rt > ct) return false;
      return Number(row.id) < cid;
    });
  }
  return filtered.slice(0, limit);
}
