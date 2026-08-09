import crypto from 'crypto';
import {
  FEED_WINDOWS,
  FEED_IOC_TYPES,
  buildPlainTextFeed,
  selectFeedItems,
  confidenceToScore,
  feedIocTypesKey,
  normalizeFeedIocTypes,
  observableTypesForFeedIocTypes
} from './feedFormatter.js';
import { JsonFeedWriter, normalizePublishedIoc } from './publishedFeedJson.js';
import { fetchPublishedFeedItemMetadata, metaKey } from './publishedFeedJsonData.js';
import {
  buildFeedKeySourceSql,
  extractManualFeedSourceIds,
  isCustomFeedKey,
  isManualFeedKey,
  resolveKnownFeedKeysForSnapshot
} from './publishedFeedSources.js';
import { isFileArtifactsReadEnabled } from './fileArtifacts/flags.js';
import {
  getPublishedFeedArtifactConfig,
  removeFileQuiet,
  resolveStoredArtifactPath
} from './publishedFeedArtifact/store.js';
import { createServiceLogger } from './appLogger.js';
import { parseSearchQuery, buildWhereClause } from './iocSearchDsl/index.js';

export { buildFeedKeySourceSql };

/**
 * Published Feed content is defined by exactly one of two mutually-exclusive modes:
 *   'basic' — IOC Types + Default Window + Threat Feeds (legacy Basic Filters)
 *   'query' — an Advanced Query using the IOC List DSL
 * Safety Filters and Delivery apply in BOTH modes.
 */
export const FEED_FILTER_MODES = { BASIC: 'basic', QUERY: 'query' };

/** Snapshot ioc_type identity key used for query-mode feeds (no ioc_types partitioning). */
export const QUERY_FEED_SNAPSHOT_KEY = 'query';

/**
 * Resolve the effective filter mode. Only 'query' with a non-empty advanced_query is a
 * query feed; everything else (including legacy rows without filter_mode) is 'basic'.
 * The inactive mode's fields never influence the active mode's base IOC set.
 */
export function resolveFeedFilterMode(feed) {
  const mode = String(feed?.filter_mode || '').trim().toLowerCase();
  if (mode === FEED_FILTER_MODES.QUERY && String(feed?.advanced_query || '').trim()) {
    return FEED_FILTER_MODES.QUERY;
  }
  return FEED_FILTER_MODES.BASIC;
}

export function isQueryModeFeed(feed) {
  return resolveFeedFilterMode(feed) === FEED_FILTER_MODES.QUERY;
}

const FEED_IOC_EXPIRY_DAYS = Math.max(Number(process.env.FEED_IOC_EXPIRY_DAYS || 90), 1);
const FEED_EXPORT_MAX_LIMIT = Math.max(Number(process.env.FEED_EXPORT_MAX_LIMIT || 100000), 1);
const feedLog = createServiceLogger('published-feeds');

/**
 * Dedicated two-key advisory-lock namespace for Published Feed generation.
 * key1 = class (never shared with backup/bootstrap single-arg locks),
 * key2 = feed id.
 */
export const PUBLISHED_FEED_GEN_LOCK_CLASS = 874290151;

export function publishedFeedGenerationLockKeys(feedId) {
  const id = Number(feedId);
  return {
    classId: PUBLISHED_FEED_GEN_LOCK_CLASS,
    objId: Number.isFinite(id) && id > 0 ? Math.floor(id) : 0
  };
}

export { FEED_EXPORT_MAX_LIMIT };

const WINDOW_INTERVALS = {
  '1d': '1 day',
  '3d': '3 days',
  '7d': '7 days',
  all: null
};

/** Exact file hashes that participate in File Artifact identity. */
const ARTIFACT_HASH_TYPES_SQL = `'md5','sha1','sha256'`;

/**
 * Hash published feeds collapse MD5/SHA1 siblings onto primary (usually SHA256)
 * when File Artifact read path is enabled.
 */
export function shouldCanonicalizePublishedHashFeed(feed) {
  if (!isFileArtifactsReadEnabled()) return false;
  // Query-mode feeds select an arbitrary IOC population by DSL predicate and format
  // each row by its own observable type; hash-artifact canonicalization is a
  // Basic-Filters hash-feed concern only.
  if (isQueryModeFeed(feed)) return false;
  const types = resolveFeedIocTypes(feed);
  return types.includes('hash');
}

/** Prefer ioc_types[]; fall back to legacy scalar ioc_type during rollout. */
export function resolveFeedIocTypes(feed) {
  if (Array.isArray(feed?.ioc_types) && feed.ioc_types.length) {
    const norm = normalizeFeedIocTypes(feed.ioc_types);
    if (norm.ok) return norm.value;
  }
  if (feed?.ioc_type != null && String(feed.ioc_type).trim() !== '') {
    const norm = normalizeFeedIocTypes(feed.ioc_type);
    if (norm.ok) return norm.value;
  }
  return [];
}

/** Supported output formats. TXT is the default / backward-compatible behavior. */
export const FEED_OUTPUT_FORMATS = { TXT: 'txt', JSON: 'json' };

/** Resolve a feed's output format; anything other than 'json' is 'txt'. */
export function resolvePublishedFeedFormat(feed) {
  return String(feed?.format || '').trim().toLowerCase() === FEED_OUTPUT_FORMATS.JSON
    ? FEED_OUTPUT_FORMATS.JSON
    : FEED_OUTPUT_FORMATS.TXT;
}

export function isJsonFormatFeed(feed) {
  return resolvePublishedFeedFormat(feed) === FEED_OUTPUT_FORMATS.JSON;
}

/**
 * Phase-1 streaming/file-artifact generation gate. Default OFF so existing in-memory
 * generation + DB-backed snapshots are unchanged until an operator opts in
 * (PUBLISHED_FEED_STREAMING_ENABLED=true). Serving auto-detects file-backed rows regardless.
 */
export function isPublishedFeedStreamingEnabled() {
  const v = String(process.env.PUBLISHED_FEED_STREAMING_ENABLED ?? 'false').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/**
 * Whether this feed uses the bounded-memory streaming/file-artifact path.
 * When the feature flag is on, ALL supported generation modes stream (including
 * canonical hash/file-artifact feeds, which use a dedicated cursor SQL shape).
 */
export function shouldStreamPublishedFeed(feed) {
  if (!isPublishedFeedStreamingEnabled()) return false;
  void feed;
  return true;
}

/** JSON include flags, honoring the documented defaults (metadata+classification on, enrichment off). */
export function resolveJsonIncludeFlags(feed) {
  return {
    includeSourceMetadata: feed?.include_source_metadata !== false,
    includeClassification: feed?.include_classification !== false,
    includeEnrichment: feed?.include_enrichment === true
  };
}

/**
 * Build the snapshot content for a feed in its configured output format.
 * TXT is byte-for-byte identical to the legacy path. JSON serializes the public contract
 * incrementally and fetches per-item metadata in bounded batches (no N+1, no giant object).
 * @returns {Promise<{ content: string, content_hash: string, item_count: number }>}
 */
export async function buildFeedContent(db, feed, iocRows, formatTypes, maxItems) {
  if (!isJsonFormatFeed(feed)) {
    return buildPlainTextFeed(iocRows, formatTypes, maxItems);
  }
  const items = selectFeedItems(iocRows, formatTypes, maxItems);
  const flags = resolveJsonIncludeFlags(feed);
  const metaByKey = await fetchPublishedFeedItemMetadata(db, items, flags);
  const writer = new JsonFeedWriter({ name: feed.name, ...flags });
  for (const it of items) {
    const meta = metaByKey.get(metaKey(it.observable_type, it.value)) || {};
    const base = {
      value: it.value,
      observable_type: it.observable_type,
      category: it.row?.category,
      confidence: it.row?.confidence
    };
    writer.addItem(normalizePublishedIoc(base, meta, flags));
  }
  return writer.finish();
}

function parseJsonArray(val) {
  if (val == null) return null;
  if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
  if (typeof val === 'string') {
    try {
      const parsed = JSON.parse(val);
      if (Array.isArray(parsed)) return parsed.map((x) => String(x).trim()).filter(Boolean);
    } catch {
      return val.split(',').map((x) => x.trim()).filter(Boolean);
    }
  }
  return null;
}

function normalizeTimeWindow(value) {
  const v = String(value || 'all').trim().toLowerCase();
  if (v === 'last_1_day' || v === '1d') return '1d';
  if (v === 'last_3_days' || v === '3d') return '3d';
  if (v === 'last_7_days' || v === '7d') return '7d';
  if (v === 'all') return 'all';
  return null;
}

export function normalizeFeedConfig(row) {
  if (!row) return null;
  const ioc_types = resolveFeedIocTypes({
    ioc_types: parseJsonArray(row.ioc_types) || row.ioc_types,
    ioc_type: row.ioc_type
  });
  return {
    ...row,
    id: Number(row.id),
    time_window: normalizeTimeWindow(row.time_window) || 'all',
    ioc_types,
    filter_mode: resolveFeedFilterMode(row),
    format: resolvePublishedFeedFormat(row),
    include_source_metadata: row.include_source_metadata !== false,
    include_classification: row.include_classification !== false,
    include_enrichment: row.include_enrichment === true,
    advanced_query: row.advanced_query != null ? String(row.advanced_query) : null,
    include_feed_keys: parseJsonArray(row.include_feed_keys),
    include_tags: parseJsonArray(row.include_tags),
    exclude_tags: parseJsonArray(row.exclude_tags)
  };
}

export function filtersHash(feed, window) {
  const queryMode = isQueryModeFeed(feed);
  const jsonFeed = isJsonFormatFeed(feed);
  const payload = {
    filter_mode: resolveFeedFilterMode(feed),
    // JSON output + include flags change the artifact bytes, so a change must force
    // regeneration even when the underlying IOC set is unchanged. These keys are only
    // added for JSON feeds so a TXT feed's hash stays byte-identical to the legacy value
    // (no regeneration churn for existing feeds on upgrade).
    ...(jsonFeed ? { output_format: 'json', json_include: resolveJsonIncludeFlags(feed) } : {}),
    // Base-set inputs depend on the active mode only.
    ...(queryMode
      ? { advanced_query: String(feed.advanced_query || '').trim() }
      : {
        ioc_types: resolveFeedIocTypes(feed),
        window,
        min_confidence: feed.min_confidence,
        include_feed_keys: feed.include_feed_keys
      }),
    // Safety + delivery apply in both modes.
    include_tags: feed.include_tags,
    exclude_tags: feed.exclude_tags,
    exclude_false_positive: feed.exclude_false_positive,
    exclude_expired: feed.exclude_expired,
    max_items: feed.max_items,
    // Bump hash-feed snapshots when artifact canonicalization is active.
    artifact_canonical: shouldCanonicalizePublishedHashFeed(feed) ? 1 : 0
  };
  return crypto.createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex').slice(0, 16);
}

async function fetchLatestIntegrationFinishedAt(db, feed = null) {
  const includeCustom = (feed?.include_feed_keys || []).some((k) => isCustomFeedKey(k));
  const manualSourceIds = extractManualFeedSourceIds(feed?.include_feed_keys);
  // Sequential queries: generation holds a single session client; pg Clients
  // cannot safely run concurrent queries on the same connection.
  const timestamps = [];
  {
    const { rows } = await db.query(
      `SELECT MAX(finished_at) AS latest_finished_at
       FROM integration_runs
       WHERE status = 'success' AND finished_at IS NOT NULL`
    );
    if (rows[0]?.latest_finished_at) timestamps.push(rows[0].latest_finished_at);
  }
  if (includeCustom) {
    const { rows } = await db.query(
      `SELECT MAX(finished_at) AS latest_finished_at
       FROM custom_threat_feed_runs
       WHERE status = 'success' AND finished_at IS NOT NULL`
    );
    if (rows[0]?.latest_finished_at) timestamps.push(rows[0].latest_finished_at);
  }
  if (manualSourceIds.length) {
    const { rows } = await db.query(
      `SELECT MAX(COALESCE(last_seen_log, last_seen_at, created_at)) AS latest_finished_at
       FROM ioc_items
       WHERE ioc_source_id = ANY($1::bigint[])`,
      [manualSourceIds]
    );
    if (rows[0]?.latest_finished_at) timestamps.push(rows[0].latest_finished_at);
  }
  const normalized = timestamps
    .filter(Boolean)
    .map((ts) => (ts instanceof Date ? ts.toISOString() : String(ts)));
  if (!normalized.length) return null;
  return normalized.sort().at(-1) || null;
}

/**
 * Safety Filter SQL fragments shared by BOTH Basic Filters and Advanced Query modes.
 * These are intentionally common post-filters: exclude false positives, exclude expired,
 * Include Tags, Exclude Tags. Their semantics are identical in both modes (mutates params).
 * @returns {string} SQL AND-clauses (may be empty string)
 */
function buildSafetyFilterSql(feed, params) {
  let sql = '';

  if (feed.exclude_false_positive) {
    sql += `
      AND COALESCE(i.category, '') NOT ILIKE '%false%positive%'
      AND lower(COALESCE(i.category, '')) <> 'fp'
    `;
  }

  if (feed.exclude_expired !== false) {
    sql += ` AND COALESCE(i.status, 'active') = 'active' `;
  }

  if (feed.include_tags?.length) {
    params.push(feed.include_tags.map((t) => t.toLowerCase()));
    sql += `
      AND EXISTS (
        SELECT 1
        FROM ioc_tags it
        JOIN tags tg ON tg.id = it.tag_id
        WHERE it.ioc_id = i.id
          AND it.ioc_observable_type = i.observable_type
          AND tg.enabled = TRUE
          AND lower(tg.name) = ANY($${params.length}::text[])
      )
    `;
  }

  if (feed.exclude_tags?.length) {
    params.push(feed.exclude_tags.map((t) => t.toLowerCase()));
    sql += `
      AND NOT EXISTS (
        SELECT 1
        FROM ioc_tags it
        JOIN tags tg ON tg.id = it.tag_id
        WHERE it.ioc_id = i.id
          AND it.ioc_observable_type = i.observable_type
          AND lower(tg.name) = ANY($${params.length}::text[])
      )
    `;
  }

  return sql;
}

/**
 * Append Basic Filters SQL fragments (mutates params): Default Window, min_confidence,
 * Threat Feeds (include_feed_keys), then the shared Safety Filters. Used only when the
 * feed is in Basic Filters mode.
 * @returns {string} SQL AND-clauses (may be empty string)
 */
function buildFeedFilterSql(feed, window, params) {
  let sql = '';
  const interval = WINDOW_INTERVALS[window];
  if (interval) {
    params.push(interval);
    sql += ` AND COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) >= NOW() - $${params.length}::interval `;
  }

  if (feed.min_confidence != null && Number.isFinite(Number(feed.min_confidence))) {
    sql += ` AND (
      CASE LOWER(COALESCE(i.confidence, ''))
        WHEN 'high' THEN 100
        WHEN 'medium' THEN 50
        WHEN 'low' THEN 25
        ELSE 0
      END
    ) >= ${Number(feed.min_confidence)} `;
  }

  sql += buildFeedKeySourceSql(feed.include_feed_keys, params);

  sql += buildSafetyFilterSql(feed, params);

  return sql;
}

/**
 * Parse + compile the feed's Advanced Query using the SAME canonical IOC List DSL
 * (parseSearchQuery + buildWhereClause). Throws DslError on invalid syntax / fields /
 * operators — never invents a Published-Feed-only query language.
 * @returns {{ whereSql: string, whereParams: any[] }}
 */
function compileAdvancedQuery(feed) {
  const { ast } = parseSearchQuery(feed.advanced_query);
  const { sql, params } = buildWhereClause(ast);
  return { whereSql: sql, whereParams: params };
}

/**
 * Query-mode base predicate: (advanced query) AND (safety filters), with suppressed
 * IOCs always excluded — mirrors the Basic-mode non-canonical WHERE exactly except the
 * base set comes from the DSL instead of ioc_types/window/source selectors.
 * `params` starts with the compiled DSL params (positional $1..$n from buildWhereClause);
 * safety filters push additional params after them.
 */
function buildQueryModeWhereSql(feed) {
  const { whereSql, whereParams } = compileAdvancedQuery(feed);
  const params = [...whereParams];
  const safetySql = buildSafetyFilterSql(feed, params);
  const sql = `(${whereSql})
      AND COALESCE(i.status, 'active') <> 'suppressed'
      ${safetySql}`;
  return { sql, params };
}

/** Rows for a query-mode feed. Same projection + dedup as the Basic non-canonical path. */
export async function fetchQueryModeIocRows(pool, feed) {
  const { sql: whereSql, params } = buildQueryModeWhereSql(feed);
  const sql = `
    SELECT DISTINCT ON (lower(i.observable))
      i.observable,
      i.observable_type,
      i.confidence,
      i.category,
      i.source_name,
      COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) AS recency_ts
    FROM ioc_items i
    WHERE ${whereSql}
    ORDER BY lower(i.observable),
      COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) DESC,
      CASE LOWER(COALESCE(i.confidence, '')) WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
      i.observable ASC
  `;
  const { rows } = await pool.query(sql, params);
  return rows.filter((r) => confidenceToScore(r.confidence) >= (feed.min_confidence ?? 0) || feed.min_confidence == null);
}

/** Cheap fingerprint for a query-mode feed (distinct observable count + max recency). */
export async function fetchQueryModeFingerprint(pool, feed) {
  const { sql: whereSql, params } = buildQueryModeWhereSql(feed);
  const sql = `
    SELECT COUNT(DISTINCT lower(i.observable))::bigint AS item_count,
           MAX(COALESCE(i.last_seen_log, i.last_seen_at, i.created_at)) AS max_recency
    FROM ioc_items i
    WHERE ${whereSql}
  `;
  const { rows } = await pool.query(sql, params);
  const maxRecency = rows[0]?.max_recency;
  return {
    itemCount: Number(rows[0]?.item_count || 0),
    maxRecency: maxRecency instanceof Date ? maxRecency.toISOString() : (maxRecency ? String(maxRecency) : null),
    filtersHash: filtersHash(feed, 'all')
  };
}

const ARTIFACT_IDENTITY_SQL = `
      CASE
        WHEN i.observable_type IN (${ARTIFACT_HASH_TYPES_SQL}) AND fa.id IS NOT NULL THEN
          'a:' || COALESCE(
            CASE
              WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
                THEN fa.merged_into_artifact_id
              ELSE fa.id
            END,
            fa.id
          )::text
        ELSE 'o:' || i.observable_type || ':' || LOWER(i.observable)
      END
`;

const ARTIFACT_ANNOTATE_JOINS = `
      LEFT JOIN file_artifact_ioc_links fal
        ON fal.ioc_item_id = i.id
       AND fal.ioc_observable_type = i.observable_type
       AND i.observable_type IN (${ARTIFACT_HASH_TYPES_SQL})
      LEFT JOIN file_artifacts fa ON fa.id = fal.artifact_id
      LEFT JOIN file_artifact_hashes faph
        ON faph.artifact_id = COALESCE(
             CASE
               WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
                 THEN fa.merged_into_artifact_id
               ELSE fa.id
             END,
             fa.id
           )
       AND faph.is_primary = TRUE
`;

export async function fetchIocRows(pool, feed, window) {
  const types = observableTypesForFeedIocTypes(resolveFeedIocTypes(feed));
  if (!types.length) return [];

  const params = [];
  const typePlaceholders = types.map((t) => {
    params.push(t);
    return `$${params.length}`;
  });
  const filterSql = buildFeedFilterSql(feed, window, params);
  const canonicalize = shouldCanonicalizePublishedHashFeed(feed);

  let sql;
  if (canonicalize) {
    sql = `
    WITH matched AS (
      SELECT
        i.observable,
        i.observable_type,
        i.confidence,
        i.category,
        i.source_name,
        COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) AS recency_ts,
        (${ARTIFACT_IDENTITY_SQL}) AS identity_key,
        faph.hash_type AS primary_hash_type,
        faph.normalized_hash_value AS primary_hash_value,
        CASE
          WHEN i.observable_type IN (${ARTIFACT_HASH_TYPES_SQL}) AND fa.id IS NOT NULL THEN TRUE
          ELSE FALSE
        END AS has_artifact
      FROM ioc_items i
      ${ARTIFACT_ANNOTATE_JOINS}
      WHERE i.observable_type IN (${typePlaceholders.join(', ')})
        AND COALESCE(i.status, 'active') <> 'suppressed'
        ${filterSql}
    ),
    picked AS (
      SELECT DISTINCT ON (identity_key)
        COALESCE(
          CASE WHEN has_artifact THEN primary_hash_value END,
          observable
        ) AS observable,
        COALESCE(
          CASE WHEN has_artifact THEN primary_hash_type END,
          observable_type
        ) AS observable_type,
        confidence,
        category,
        source_name,
        recency_ts
      FROM matched
      ORDER BY identity_key,
        CASE
          WHEN has_artifact
            AND primary_hash_value IS NOT NULL
            AND LOWER(observable) = LOWER(primary_hash_value)
            AND LOWER(observable_type) = LOWER(primary_hash_type)
            THEN 0 ELSE 1
        END,
        CASE LOWER(observable_type)
          WHEN 'sha256' THEN 0 WHEN 'sha1' THEN 1 WHEN 'md5' THEN 2 ELSE 9
        END,
        recency_ts DESC NULLS LAST,
        observable ASC
    )
    SELECT observable, observable_type, confidence, category, source_name, recency_ts
    FROM picked
    `;
  } else {
    sql = `
    SELECT DISTINCT ON (lower(i.observable))
      i.observable,
      i.observable_type,
      i.confidence,
      i.category,
      i.source_name,
      COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) AS recency_ts
    FROM ioc_items i
    WHERE i.observable_type IN (${typePlaceholders.join(', ')})
      AND COALESCE(i.status, 'active') <> 'suppressed'
      ${filterSql}
    ORDER BY lower(i.observable),
      COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) DESC,
      CASE LOWER(COALESCE(i.confidence, '')) WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
      i.observable ASC
    `;
  }

  const { rows } = await pool.query(sql, params);
  return rows.filter((r) => confidenceToScore(r.confidence) >= (feed.min_confidence ?? 0) || feed.min_confidence == null);
}

/** SQL confidence-rank expression shared by the streaming base query's ORDER BYs. */
const CONF_RANK_SQL = (col) =>
  `CASE LOWER(COALESCE(${col}, '')) WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`;

/**
 * Streaming cursor SQL for Basic hash feeds when File Artifact read/canonicalization is
 * on. Mirrors fetchIocRows' matched→picked CTE (identity_key collapse onto primary hash)
 * but projects the stable ioc id + provenance columns and applies the same outer
 * sortFeedRows order so the server-side cursor can stream without materializing in Node.
 * @param {{ lowerValues?: string[], types?: string[] }} [restrict]
 * @returns {{ sql: string, params: any[] }}
 */
export function buildStreamingHashBaseSql(feed, window, restrict = null) {
  const types = observableTypesForFeedIocTypes(resolveFeedIocTypes(feed));
  const params = [];
  const typePlaceholders = types.map((t) => {
    params.push(t);
    return `$${params.length}`;
  });
  const filterSql = buildFeedFilterSql(feed, window, params);
  let restrictSql = '';
  if (restrict?.lowerValues?.length && restrict?.types?.length) {
    params.push(restrict.lowerValues);
    const lv = `$${params.length}`;
    params.push(restrict.types);
    const ty = `$${params.length}`;
    restrictSql = ` AND lower(i.observable) = ANY(${lv}::text[]) AND i.observable_type = ANY(${ty}::text[]) `;
  }

  const sql = `
    WITH matched AS (
      SELECT
        i.id,
        i.observable,
        i.observable_type,
        i.confidence,
        i.category,
        i.source_name,
        i.created_at,
        i.ioc_source_id,
        COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) AS recency_ts,
        (${ARTIFACT_IDENTITY_SQL}) AS identity_key,
        faph.hash_type AS primary_hash_type,
        faph.normalized_hash_value AS primary_hash_value,
        CASE
          WHEN i.observable_type IN (${ARTIFACT_HASH_TYPES_SQL}) AND fa.id IS NOT NULL THEN TRUE
          ELSE FALSE
        END AS has_artifact
      FROM ioc_items i
      ${ARTIFACT_ANNOTATE_JOINS}
      WHERE i.observable_type IN (${typePlaceholders.join(', ')})
        AND COALESCE(i.status, 'active') <> 'suppressed'
        ${filterSql}
        ${restrictSql}
    ),
    picked AS (
      SELECT DISTINCT ON (identity_key)
        id,
        COALESCE(
          CASE WHEN has_artifact THEN primary_hash_value END,
          observable
        ) AS observable,
        COALESCE(
          CASE WHEN has_artifact THEN primary_hash_type END,
          observable_type
        ) AS observable_type,
        confidence,
        category,
        source_name,
        created_at,
        ioc_source_id,
        recency_ts
      FROM matched
      ORDER BY identity_key,
        CASE
          WHEN has_artifact
            AND primary_hash_value IS NOT NULL
            AND LOWER(observable) = LOWER(primary_hash_value)
            AND LOWER(observable_type) = LOWER(primary_hash_type)
            THEN 0 ELSE 1
        END,
        CASE LOWER(observable_type)
          WHEN 'sha256' THEN 0 WHEN 'sha1' THEN 1 WHEN 'md5' THEN 2 ELSE 9
        END,
        recency_ts DESC NULLS LAST,
        observable ASC
    )
    SELECT d.id, d.observable, d.observable_type, d.confidence, d.category,
           d.created_at, d.ioc_source_id, d.source_name, d.recency_ts
    FROM picked d
    ORDER BY d.recency_ts DESC, ${CONF_RANK_SQL('d.confidence')} DESC, d.observable ASC`;

  return { sql, params };
}

/**
 * Base query for the bounded-memory STREAMING generator. Produces one row per distinct
 * output identity (lower(observable) for non-hash; file-artifact identity_key for
 * canonical hash feeds), in the same canonical output order as sortFeedRows
 * (recency DESC, confidence DESC, observable ASC), and carries the stable ioc id +
 * provenance columns needed for sibling-aware enrichment.
 *
 * Executed via a server-side cursor so the dedup/recency sort happens ONCE in PostgreSQL
 * (spilling to DB temp, not Node) and rows stream in bounded batches. No client keyset,
 * no per-page rescan. Canonical hash feeds use buildStreamingHashBaseSql.
 * @param {{ lowerValues?: string[], types?: string[] }} [restrict] optional identity scope
 * @returns {{ sql: string, params: any[] }}
 */
export function buildStreamingBaseSql(feed, window, restrict = null) {
  if (shouldCanonicalizePublishedHashFeed(feed)) {
    return buildStreamingHashBaseSql(feed, window, restrict);
  }

  const queryMode = isQueryModeFeed(feed);
  let innerWhere;
  let params;
  if (queryMode) {
    const q = buildQueryModeWhereSql(feed);
    innerWhere = q.sql;
    params = q.params;
  } else {
    const types = observableTypesForFeedIocTypes(resolveFeedIocTypes(feed));
    params = [];
    const typePlaceholders = types.map((t) => {
      params.push(t);
      return `$${params.length}`;
    });
    const filterSql = buildFeedFilterSql(feed, window, params);
    innerWhere = `i.observable_type IN (${typePlaceholders.join(', ')})
      AND COALESCE(i.status, 'active') <> 'suppressed'
      ${filterSql}`;
  }
  if (restrict?.lowerValues?.length && restrict?.types?.length) {
    params.push(restrict.lowerValues);
    const lv = `$${params.length}`;
    params.push(restrict.types);
    const ty = `$${params.length}`;
    innerWhere += ` AND lower(i.observable) = ANY(${lv}::text[]) AND i.observable_type = ANY(${ty}::text[])`;
  }

  const sql = `
    SELECT d.id, d.observable, d.observable_type, d.confidence, d.category,
           d.created_at, d.ioc_source_id, d.source_name, d.recency_ts
    FROM (
      SELECT DISTINCT ON (lower(i.observable))
        i.id, i.observable, i.observable_type, i.confidence, i.category,
        i.created_at, i.ioc_source_id, i.source_name,
        COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) AS recency_ts
      FROM ioc_items i
      WHERE ${innerWhere}
      ORDER BY lower(i.observable),
        COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) DESC,
        ${CONF_RANK_SQL('i.confidence')} DESC,
        i.observable ASC
    ) d
    ORDER BY d.recency_ts DESC, ${CONF_RANK_SQL('d.confidence')} DESC, d.observable ASC`;

  return { sql, params };
}

/** Conservative export fingerprint — same filters as fetchIocRows without DISTINCT ON sort cost. */
export async function fetchIocExportFingerprint(pool, feed, window) {
  const types = observableTypesForFeedIocTypes(resolveFeedIocTypes(feed));
  if (!types.length) {
    return { itemCount: 0, maxRecency: null, filtersHash: filtersHash(feed, window) };
  }

  const params = [];
  const typePlaceholders = types.map((t) => {
    params.push(t);
    return `$${params.length}`;
  });
  const filterSql = buildFeedFilterSql(feed, window, params);
  const canonicalize = shouldCanonicalizePublishedHashFeed(feed);

  let sql;
  if (canonicalize) {
    sql = `
    SELECT COUNT(DISTINCT (${ARTIFACT_IDENTITY_SQL}))::bigint AS item_count,
           MAX(COALESCE(i.last_seen_log, i.last_seen_at, i.created_at)) AS max_recency
    FROM ioc_items i
    ${ARTIFACT_ANNOTATE_JOINS}
    WHERE i.observable_type IN (${typePlaceholders.join(', ')})
      AND COALESCE(i.status, 'active') <> 'suppressed'
      ${filterSql}
    `;
  } else {
    sql = `
    SELECT COUNT(DISTINCT lower(i.observable))::bigint AS item_count,
           MAX(COALESCE(i.last_seen_log, i.last_seen_at, i.created_at)) AS max_recency
    FROM ioc_items i
    WHERE i.observable_type IN (${typePlaceholders.join(', ')})
      AND COALESCE(i.status, 'active') <> 'suppressed'
      ${filterSql}
    `;
  }

  const { rows } = await pool.query(sql, params);
  const maxRecency = rows[0]?.max_recency;
  return {
    itemCount: Number(rows[0]?.item_count || 0),
    maxRecency: maxRecency instanceof Date ? maxRecency.toISOString() : (maxRecency ? String(maxRecency) : null),
    filtersHash: filtersHash(feed, window)
  };
}

function exportFingerprintKey(fingerprint) {
  return JSON.stringify({
    itemCount: fingerprint?.itemCount ?? 0,
    maxRecency: fingerprint?.maxRecency ?? null,
    filtersHash: fingerprint?.filtersHash ?? null
  });
}

const FEED_IOC_PARTITION_TABLE = {
  ip: 'ioc_ip',
  domain: 'ioc_domain',
  url: 'ioc_url',
  hash: 'ioc_file_hash'
};

function feedHasSourceFilters(feed) {
  // Query-mode feeds can select from arbitrary joined tables, so the cheap partition
  // watermark is not a sufficient change signal — force the full fingerprint path.
  if (isQueryModeFeed(feed)) return true;
  return Boolean(
    feed.include_feed_keys?.length
    || feed.include_tags?.length
    || feed.exclude_tags?.length
    || (feed.min_confidence != null && Number.isFinite(Number(feed.min_confidence)))
  );
}

function normalizeWatermarkTs(value) {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export function watermarkKey(watermark) {
  if (!watermark) return null;
  return JSON.stringify({
    max_id: Number(watermark.max_id || 0),
    max_ts: normalizeWatermarkTs(watermark.max_ts),
    active_count: Number(watermark.active_count || 0)
  });
}

/**
 * Cheap partition-level watermark — one query per selected feed IOC category
 * (still partition tables only; no parent ioc_items scan). Results are merged.
 */
export async function fetchCheapIocWatermark(pool, feed) {
  const feedTypes = resolveFeedIocTypes(feed);
  if (!feedTypes.length) {
    return { max_id: 0, max_ts: null, active_count: 0 };
  }

  let maxId = 0;
  let maxTs = null;
  let activeCount = 0;

  for (const feedType of feedTypes) {
    const table = FEED_IOC_PARTITION_TABLE[feedType];
    if (!table) continue;

    const types = observableTypesForFeedIocTypes([feedType]);
    const params = [];
    let typeClause = '';
    if (types.length === 1) {
      params.push(types[0]);
      typeClause = `AND observable_type = $${params.length}`;
    } else if (types.length > 1) {
      params.push(types);
      typeClause = `AND observable_type = ANY($${params.length}::text[])`;
    }

    const { rows } = await pool.query(
      `SELECT COALESCE(MAX(id), 0)::bigint AS max_id,
              MAX(COALESCE(last_seen_log, last_seen_at, created_at)) AS max_ts,
              COUNT(*)::bigint AS active_count
       FROM ${table}
       WHERE COALESCE(status, 'active') = 'active'
         ${typeClause}`,
      params
    );

    maxId = Math.max(maxId, Number(rows[0]?.max_id || 0));
    activeCount += Number(rows[0]?.active_count || 0);
    const ts = normalizeWatermarkTs(rows[0]?.max_ts);
    if (ts && (!maxTs || ts > maxTs)) maxTs = ts;
  }

  return {
    max_id: maxId,
    max_ts: maxTs,
    active_count: activeCount
  };
}

export function canSkipPublishedFeedRegeneration({
  feed,
  window,
  latestSnapshot,
  watermark,
  latestIntegrationFinishedAt,
  force = false
}) {
  if (force || !latestSnapshot?.content_hash) return { skip: false };

  const filters_hash = filtersHash(feed, window);
  if (latestSnapshot.params?.filters_hash !== filters_hash) return { skip: false };

  const feedUpdatedAt = feed.updated_at instanceof Date
    ? feed.updated_at.toISOString()
    : (feed.updated_at ? String(feed.updated_at) : null);
  if (latestSnapshot.params?.feed_updated_at !== feedUpdatedAt) return { skip: false };

  if (feedHasSourceFilters(feed)) return { skip: false };

  if (watermarkKey(latestSnapshot.params?.ioc_watermark) !== watermarkKey(watermark)) {
    return { skip: false };
  }

  const snapshotGeneratedAt = latestSnapshot.generated_at instanceof Date
    ? latestSnapshot.generated_at.toISOString()
    : (latestSnapshot.generated_at ? String(latestSnapshot.generated_at) : null);
  if (latestIntegrationFinishedAt && snapshotGeneratedAt
    && latestIntegrationFinishedAt > snapshotGeneratedAt) {
    return { skip: false };
  }

  return { skip: true, reason: 'unchanged_watermark' };
}

/**
 * Run fn inside BEGIN/COMMIT.
 * - Pool (has .connect, no .release): checkout, release in finally.
 * - Already-checked-out client (has .release): reuse session; do not release.
 *   Important: pg Clients also expose .connect(), so we must not use that alone.
 */
async function withTransaction(db, fn) {
  const isCheckedOutClient = typeof db.release === 'function';
  if (!isCheckedOutClient && typeof db.connect === 'function') {
    const client = await db.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // ignore rollback failures; preserve original error
      }
      throw err;
    } finally {
      client.release();
    }
  }

  await db.query('BEGIN');
  try {
    const result = await fn(db);
    await db.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await db.query('ROLLBACK');
    } catch {
      // ignore
    }
    throw err;
  }
}

export async function tryAcquirePublishedFeedGenerationLock(client, feedId) {
  const { classId, objId } = publishedFeedGenerationLockKeys(feedId);
  const { rows } = await client.query(
    'SELECT pg_try_advisory_lock($1::int, $2::int) AS ok',
    [classId, objId]
  );
  return Boolean(rows[0]?.ok);
}

export async function releasePublishedFeedGenerationLock(client, feedId) {
  const { classId, objId } = publishedFeedGenerationLockKeys(feedId);
  await client.query('SELECT pg_advisory_unlock($1::int, $2::int)', [classId, objId]);
}

export async function persistPublishedFeedSnapshot(pool, snapshot) {
  const feedId = Number(snapshot.feedId);
  const paramsJson = snapshot.paramsJson || {};
  const iocTypeKey = String(
    paramsJson.ioc_type
    || feedIocTypesKey(paramsJson.ioc_types)
    || ''
  );
  const window = String(paramsJson.window || '');
  const status = String(snapshot.status || 'success');
  const paramsText = JSON.stringify(paramsJson);

  return withTransaction(pool, async (client) => {
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtext($1)::bigint)',
      [`published_feed_snapshots:${feedId}:${iocTypeKey}:${window}`]
    );

    if (status !== 'success') {
      const { rows } = await client.query(
        `SELECT id
         FROM published_feed_snapshots
         WHERE feed_id = $1
           AND status = 'failed'
           AND params->>'ioc_type' = $2
           AND params->>'window' = $3
         ORDER BY generated_at DESC
         LIMIT 1
         FOR UPDATE`,
        [feedId, iocTypeKey, window]
      );

      if (rows[0]?.id) {
        await client.query(
          `UPDATE published_feed_snapshots
           SET generated_at = NOW(),
               item_count = 0,
               content_hash = NULL,
               content = '',
               status = 'failed',
               error_message = $2,
               params = $3::jsonb
           WHERE id = $1`,
          [rows[0].id, snapshot.errorMessage || null, paramsText]
        );
        return;
      }

      await client.query(
        `INSERT INTO published_feed_snapshots
           (feed_id, item_count, content_hash, content, status, error_message, params)
         VALUES ($1, 0, NULL, '', 'failed', $2, $3::jsonb)`,
        [feedId, snapshot.errorMessage || null, paramsText]
      );
      return;
    }

    const { rows } = await client.query(
      `SELECT id, content_hash
       FROM published_feed_snapshots
       WHERE feed_id = $1
         AND status = 'success'
         AND params->>'ioc_type' = $2
         AND params->>'window' = $3
       ORDER BY generated_at DESC
       LIMIT 1
       FOR UPDATE`,
      [feedId, iocTypeKey, window]
    );

    if (!rows[0]?.id) {
      await client.query(
        `INSERT INTO published_feed_snapshots
           (feed_id, item_count, content_hash, content, status, error_message, params)
         VALUES ($1, $2, $3, $4, 'success', NULL, $5::jsonb)`,
        [feedId, snapshot.itemCount, snapshot.contentHash, snapshot.content, paramsText]
      );
      return;
    }

    if (rows[0].content_hash === snapshot.contentHash) {
      // Content identical — still refresh params so config watermarks (feed_updated_at,
      // export_fingerprint, filters_hash) stay aligned for the next skip/incremental check.
      await client.query(
        `UPDATE published_feed_snapshots
         SET params = $2::jsonb
         WHERE id = $1`,
        [rows[0].id, paramsText]
      );
      return { skipped: true, reason: 'unchanged_hash' };
    }

    await client.query(
      `UPDATE published_feed_snapshots
       SET generated_at = NOW(),
           item_count = $2,
           content_hash = $3,
           content = $4,
           status = 'success',
           error_message = NULL,
           params = $5::jsonb
       WHERE id = $1`,
      [rows[0].id, snapshot.itemCount, snapshot.contentHash, snapshot.content, paramsText]
    );
  });
}

/**
 * Persist a FILE-BACKED snapshot (content NULL, storage_path set). Mirrors the success path
 * of persistPublishedFeedSnapshot: xact-locked per (feed, ioc_type, window); dedups on
 * content_hash. Returns which artifact files the caller must clean up:
 *   - redundantStoragePath: the just-written artifact is identical → delete it, keep old.
 *   - previousStoragePath:  the row was repointed → delete the superseded old artifact.
 */
export async function persistPublishedFeedArtifactSnapshot(pool, snapshot) {
  const feedId = Number(snapshot.feedId);
  const paramsJson = snapshot.paramsJson || {};
  const iocTypeKey = String(paramsJson.ioc_type || feedIocTypesKey(paramsJson.ioc_types) || '');
  const window = String(paramsJson.window || '');
  const paramsText = JSON.stringify(paramsJson);

  return withTransaction(pool, async (client) => {
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtext($1)::bigint)',
      [`published_feed_snapshots:${feedId}:${iocTypeKey}:${window}`]
    );

    const { rows } = await client.query(
      `SELECT id, content_hash, storage_path
       FROM published_feed_snapshots
       WHERE feed_id = $1 AND status = 'success'
         AND params->>'ioc_type' = $2 AND params->>'window' = $3
       ORDER BY generated_at DESC LIMIT 1 FOR UPDATE`,
      [feedId, iocTypeKey, window]
    );
    const prev = rows[0];

    if (!prev?.id) {
      await client.query(
        `INSERT INTO published_feed_snapshots
           (feed_id, item_count, content_hash, content, status, error_message, params,
            storage_path, file_size, artifact_format, generation_id)
         VALUES ($1, $2, $3, NULL, 'success', NULL, $4::jsonb, $5, $6, $7, $8)`,
        [feedId, snapshot.itemCount, snapshot.contentHash, paramsText,
          snapshot.storagePath, snapshot.fileSize, snapshot.artifactFormat, snapshot.generationId]
      );
      return { inserted: true };
    }

    if (prev.content_hash === snapshot.contentHash) {
      // Identical logical content → keep the existing artifact; the new one is redundant.
      // Still refresh params so feed_updated_at / fingerprints stay current.
      await client.query(
        `UPDATE published_feed_snapshots
         SET params = $2::jsonb,
             item_count = COALESCE($3, item_count),
             file_size = COALESCE($4, file_size)
         WHERE id = $1`,
        [prev.id, paramsText, snapshot.itemCount ?? null, snapshot.fileSize ?? null]
      );
      return { skipped: true, reason: 'unchanged_hash', redundantStoragePath: snapshot.storagePath };
    }

    await client.query(
      `UPDATE published_feed_snapshots
       SET generated_at = NOW(), item_count = $2, content_hash = $3, content = NULL,
           status = 'success', error_message = NULL, params = $4::jsonb,
           storage_path = $5, file_size = $6, artifact_format = $7, generation_id = $8
       WHERE id = $1`,
      [prev.id, snapshot.itemCount, snapshot.contentHash, paramsText,
        snapshot.storagePath, snapshot.fileSize, snapshot.artifactFormat, snapshot.generationId]
    );
    // Old artifact is now superseded; caller deletes it after this commit.
    return { updated: true, previousStoragePath: prev.storage_path || null };
  });
}

export async function generatePublishedFeedSnapshot(pool, feedId, options = {}) {
  const id = Number(feedId);
  if (!Number.isFinite(id) || id <= 0) {
    throw new Error('Invalid feed id');
  }

  const force = Boolean(options.force);
  const startedAt = Date.now();

  // Dedicated client so session advisory lock covers the entire generation.
  if (typeof pool.connect !== 'function') {
    return runPublishedFeedGeneration(pool, id, { ...options, force, startedAt });
  }

  const client = await pool.connect();
  let locked = false;
  try {
    locked = await tryAcquirePublishedFeedGenerationLock(client, id);
    if (!locked) {
      const result = {
        feed_id: id,
        results: [],
        last_status: 'skipped',
        last_error: null,
        skipped: true,
        reason: 'generation_in_progress'
      };
      feedLog.info('published feed generation', {
        feed_id: id,
        feed_name: null,
        windows: options.window ? [options.window] : FEED_WINDOWS,
        generation_ms: Date.now() - startedAt,
        item_count: null,
        snapshot_bytes: null,
        result: 'generation_in_progress',
        skip_reason: 'generation_in_progress',
        force
      });
      return result;
    }
    return await runPublishedFeedGeneration(client, id, { ...options, force, startedAt });
  } finally {
    if (locked) {
      try {
        await releasePublishedFeedGenerationLock(client, id);
      } catch (err) {
        feedLog.warn('published feed generation unlock failed', {
          feed_id: id,
          error: String(err?.message || err)
        });
      }
    }
    client.release();
  }
}

/**
 * Heavy generation work — must run on the same DB client that holds the
 * session advisory lock (or a mock queryable without connect).
 */
async function runPublishedFeedGeneration(db, id, options = {}) {
  const force = Boolean(options.force);
  const startedAt = options.startedAt || Date.now();
  let queryMs = 0;
  let snapshotBytes = null;
  let maxItemCount = 0;

  const { rows: feedRows } = await db.query('SELECT * FROM published_feeds WHERE id = $1', [id]);
  if (!feedRows.length) throw new Error('Feed not found');
  const feedBase = normalizeFeedConfig(feedRows[0]);
  const feedName = feedBase.name || null;
  const queryMode = isQueryModeFeed(feedBase);
  const configuredKeys = feedBase.include_feed_keys || [];
  // Threat Feeds (include_feed_keys) is a Basic-Filters selector — it must not influence
  // a query-mode feed, so only resolve it (and gate on staleness) in Basic mode.
  const resolvedFeedKeys = queryMode ? [] : await resolveKnownFeedKeysForSnapshot(db, configuredKeys);
  const allKeysStale = !queryMode && configuredKeys.length > 0 && resolvedFeedKeys.length === 0;
  const feed = {
    ...feedBase,
    include_feed_keys: resolvedFeedKeys.length ? resolvedFeedKeys : (configuredKeys.length ? [] : null)
  };

  // Query-mode feeds produce a single window-agnostic snapshot keyed by QUERY_FEED_SNAPSHOT_KEY;
  // the base set is the Advanced Query alone (Default Window never applies).
  const windows = queryMode
    ? ['all']
    : (options.window ? [normalizeTimeWindow(options.window)].filter(Boolean) : FEED_WINDOWS);
  const results = [];
  const latestIntegrationFinishedAt = force
    ? null
    : await fetchLatestIntegrationFinishedAt(db, feed);
  const cheapWatermark = force ? null : await fetchCheapIocWatermark(db, feed);
  const feedUpdatedAt = feed.updated_at instanceof Date
    ? feed.updated_at.toISOString()
    : (feed.updated_at ? String(feed.updated_at) : null);
  const iocTypes = resolveFeedIocTypes(feed);
  // Formatting hint: Basic uses the configured feed types; Query formats each row by its
  // own observable type (pass all categories so buildPlainTextFeed normalizes per-row).
  const formatTypes = queryMode ? FEED_IOC_TYPES : iocTypes;
  const iocTypeKey = queryMode ? QUERY_FEED_SNAPSHOT_KEY : feedIocTypesKey(iocTypes);

  // Phase 2: when projection incremental applies, skip the legacy export-fingerprint
  // pre-check (it scans the full matching IOC set and defeats cheap no-op).
  let incrementalPreferDirtyPath = false;
  let canUseIncrementalRefreshFn = null;
  if (!force && shouldStreamPublishedFeed(feed)) {
    const proj = await import('./publishedFeedProjection.js');
    incrementalPreferDirtyPath = proj.isIncrementalEnabledForFeed(id) && proj.isProjectionReady(feed);
    canUseIncrementalRefreshFn = proj.canUseIncrementalRefresh;
  }

  for (const window of windows) {
    try {
      const filters_hash = filtersHash(feed, window);
      const useIncrementalDirtyPath = Boolean(
        incrementalPreferDirtyPath
        && canUseIncrementalRefreshFn?.(feed, { force: false, filtersChanged: false, snapshotWindow: window })
      );

      if (!force && !useIncrementalDirtyPath) {
        const latest = await getLatestSnapshotMeta(db, id, iocTypeKey, window);
        const skipCheck = canSkipPublishedFeedRegeneration({
          feed,
          window,
          latestSnapshot: latest,
          watermark: cheapWatermark,
          latestIntegrationFinishedAt,
          force
        });
        if (skipCheck.skip) {
          results.push({
            window,
            status: 'success',
            item_count: latest?.item_count ?? 0,
            skipped: true,
            reason: skipCheck.reason
          });
          maxItemCount = Math.max(maxItemCount, Number(latest?.item_count || 0));
          continue;
        }
      }

      let fingerprint;
      let fingerprintKey;
      if (useIncrementalDirtyPath) {
        // Reuse prior snapshot fingerprint metadata; dirty detection decides rewrite.
        const latest = await getLatestSnapshotMeta(db, id, iocTypeKey, window);
        fingerprintKey = latest?.params?.export_fingerprint
          || exportFingerprintKey({
            itemCount: Number(latest?.item_count || 0),
            maxRecency: null,
            filtersHash: filters_hash
          });
        fingerprint = {
          itemCount: Number(latest?.item_count || 0),
          maxRecency: null,
          filtersHash: filters_hash
        };
      } else if (allKeysStale) {
        fingerprint = { itemCount: 0, maxRecency: null, filtersHash: filtersHash(feed, window) };
        fingerprintKey = exportFingerprintKey(fingerprint);
      } else {
        const t0 = Date.now();
        fingerprint = queryMode
          ? await fetchQueryModeFingerprint(db, feed)
          : await fetchIocExportFingerprint(db, feed, window);
        queryMs += Date.now() - t0;
        fingerprintKey = exportFingerprintKey(fingerprint);
      }

      if (!force && !useIncrementalDirtyPath) {
        const latest = await getLatestSnapshotMeta(db, id, iocTypeKey, window);
        const prevKey = latest?.params?.export_fingerprint;
        if (latest?.content_hash && latest.params?.filters_hash === filters_hash && prevKey === fingerprintKey) {
          results.push({
            window,
            status: 'success',
            item_count: latest.item_count,
            skipped: true,
            reason: 'unchanged_fingerprint'
          });
          maxItemCount = Math.max(maxItemCount, Number(latest.item_count || 0));
          if (latest.content_bytes != null) {
            snapshotBytes = Math.max(snapshotBytes || 0, Number(latest.content_bytes));
          }
          continue;
        }
      }

      const genMax = feed.max_items != null ? Math.min(Number(feed.max_items), FEED_EXPORT_MAX_LIMIT) : null;
      const paramsJson = {
        ioc_type: iocTypeKey,
        ioc_types: iocTypes,
        filter_mode: resolveFeedFilterMode(feed),
        output_format: resolvePublishedFeedFormat(feed),
        window,
        filters_hash,
        export_fingerprint: fingerprintKey,
        feed_updated_at: feedUpdatedAt,
        ioc_watermark: cheapWatermark || await fetchCheapIocWatermark(db, feed)
      };

      if (shouldStreamPublishedFeed(feed)) {
        // Phase 1 streaming + Phase 2 incremental/projection (when enabled + ready).
        const artifactCfg = getPublishedFeedArtifactConfig();
        const {
          generateFeedArtifact,
          generateEmptyFeedArtifact,
          generateFeedArtifactFromProjection
        } = await import('./publishedFeedStreamGenerator.js');
        const {
          decideRefreshMode,
          collectDirtyIocIds,
          applyIncrementalProjectionUpdate,
          captureCutoffNow,
          touchFeedRefreshChecked,
          setFeedProjectionState,
          clearFeedProjection,
          PROJECTION_STATUS,
          logRefreshMetrics,
          isIncrementalEnabledForFeed
        } = await import('./publishedFeedIncremental.js');

        const latestMeta = await getLatestSnapshotMeta(db, id, iocTypeKey, window);
        // filters_hash is the generation config watermark. Do not use feed_updated_at here:
        // identical-content snapshot dedupe historically left feed_updated_at stale and
        // forced permanent full rebuilds. Config edits that affect membership change filters_hash.
        const filtersChanged = Boolean(
          force
          || (latestMeta?.params?.filters_hash && latestMeta.params.filters_hash !== filters_hash)
        );

        const incrementalForFeed = isIncrementalEnabledForFeed(id);
        const mode = decideRefreshMode(feed, {
          force: force || filtersChanged,
          filtersChanged,
          incrementalEnabled: incrementalForFeed,
          streamingEnabled: true,
          snapshotWindow: window
        });

        const t0 = Date.now();
        let art;
        let refreshMode = mode;
        let changedCount = 0;

        if (allKeysStale) {
          art = await generateEmptyFeedArtifact(feed, { cfg: artifactCfg });
          refreshMode = 'full';
          await clearFeedProjection(db, id).catch(() => {});
          await setFeedProjectionState(db, id, {
            projection_status: PROJECTION_STATUS.READY,
            projection_cutoff: captureCutoffNow(),
            projection_built_at: new Date()
          }).catch(() => {});
        } else if (mode === 'incremental') {
          const cutoff = feed.projection_cutoff ? new Date(feed.projection_cutoff) : null;
          const W = captureCutoffNow();
          const dirty = await collectDirtyIocIds(db, feed, cutoff);
          if (!dirty.ids.length && !dirty.forceFull) {
            // True no-op: no artifact rewrite, do not bump published_feeds.updated_at.
            await touchFeedRefreshChecked(db, id, { mode: 'noop', ms: Date.now() - t0, changed: 0 });
            logRefreshMetrics({
              feed_id: id,
              refresh_mode: 'noop',
              changed_candidates: 0,
              total_duration_ms: Date.now() - t0,
              watermark_from: cutoff ? cutoff.toISOString() : null,
              watermark_to: W.toISOString()
            });
            results.push({
              window,
              status: 'success',
              item_count: latestMeta?.item_count ?? 0,
              skipped: true,
              reason: 'noop_incremental'
            });
            maxItemCount = Math.max(maxItemCount, Number(latestMeta?.item_count || 0));
            continue;
          }
          const delta = await applyIncrementalProjectionUpdate(db, feed, window, formatTypes, dirty);
          if (delta.forceFull) {
            refreshMode = 'full';
            await setFeedProjectionState(db, id, { projection_status: PROJECTION_STATUS.BOOTSTRAPPING });
            await clearFeedProjection(db, id);
            art = await generateFeedArtifact(db, feed, window, {
              formatTypes, maxItems: genMax, cfg: artifactCfg,
              populateProjection: true, projectionWindow: window
            });
            await setFeedProjectionState(db, id, {
              projection_status: PROJECTION_STATUS.READY,
              projection_cutoff: W,
              projection_built_at: new Date()
            });
            changedCount = art.itemCount;
          } else if (!delta.artifactDirty) {
            await setFeedProjectionState(db, id, { projection_cutoff: W });
            await touchFeedRefreshChecked(db, id, {
              mode: 'noop',
              ms: Date.now() - t0,
              changed: 0
            });
            logRefreshMetrics({
              feed_id: id,
              refresh_mode: 'noop',
              changed_candidates: dirty.ids.length,
              entered_count: delta.entered,
              updated_count: delta.updated,
              removed_count: delta.removed,
              unchanged_count: delta.unchanged,
              total_duration_ms: Date.now() - t0
            });
            results.push({
              window,
              status: 'success',
              item_count: latestMeta?.item_count ?? 0,
              skipped: true,
              reason: 'noop_incremental'
            });
            maxItemCount = Math.max(maxItemCount, Number(latestMeta?.item_count || 0));
            continue;
          } else {
            art = await generateFeedArtifactFromProjection(db, feed, window, {
              maxItems: genMax, cfg: artifactCfg
            });
            changedCount = delta.entered + delta.updated + delta.removed;
            await setFeedProjectionState(db, id, { projection_cutoff: W });
            logRefreshMetrics({
              feed_id: id,
              refresh_mode: 'incremental',
              changed_candidates: dirty.ids.length,
              entered_count: delta.entered,
              updated_count: delta.updated,
              removed_count: delta.removed,
              unchanged_count: delta.unchanged,
              artifact_bytes: art.fileSize,
              artifact_duration_ms: Date.now() - t0,
              total_duration_ms: Date.now() - t0,
              watermark_from: cutoff ? cutoff.toISOString() : null,
              watermark_to: W.toISOString()
            });
          }
        } else {
          // full or bootstrap — streaming rebuild.
          // Only clear/populate projection for the durable `all` window. Sliding-window
          // full rebuilds must not wipe published_feed_items (that destroyed the all
          // projection during Domain delta testing).
          const W = captureCutoffNow();
          const populate = Boolean(
            incrementalForFeed
            && String(window) === 'all'
            && (mode === 'bootstrap' || mode === 'full')
          );
          if (populate) {
            await setFeedProjectionState(db, id, { projection_status: PROJECTION_STATUS.BOOTSTRAPPING });
            await clearFeedProjection(db, id);
          }
          art = await generateFeedArtifact(db, feed, window, {
            formatTypes, maxItems: genMax, cfg: artifactCfg,
            populateProjection: populate, projectionWindow: window
          });
          if (populate) {
            await setFeedProjectionState(db, id, {
              projection_status: PROJECTION_STATUS.READY,
              projection_cutoff: W,
              projection_built_at: new Date()
            });
          }
          refreshMode = mode === 'bootstrap' ? 'bootstrap' : 'full';
          changedCount = art.itemCount;
          logRefreshMetrics({
            feed_id: id,
            refresh_mode: refreshMode,
            changed_candidates: null,
            artifact_bytes: art.fileSize,
            total_duration_ms: Date.now() - t0
          });
        }

        queryMs += Date.now() - t0;
        snapshotBytes = Math.max(snapshotBytes || 0, art.fileSize);
        maxItemCount = Math.max(maxItemCount, art.itemCount);

        let persistRes;
        try {
          persistRes = await persistPublishedFeedArtifactSnapshot(db, {
            feedId: id,
            itemCount: art.itemCount,
            contentHash: art.contentHash,
            storagePath: art.storagePath,
            fileSize: art.fileSize,
            artifactFormat: art.format,
            generationId: art.generationId,
            paramsJson
          });
        } catch (persistErr) {
          await removeFileQuiet(resolveStoredArtifactPath(artifactCfg.storageDir, art.storagePath)).catch(() => {});
          throw persistErr;
        }
        const stale = persistRes?.redundantStoragePath || persistRes?.previousStoragePath;
        if (stale) {
          await removeFileQuiet(resolveStoredArtifactPath(artifactCfg.storageDir, stale)).catch(() => {});
        }
        await db.query(
          `UPDATE published_feeds
           SET last_refresh_mode = $2, last_refresh_ms = $3, last_changed_count = $4,
               last_refresh_checked_at = NOW()
           WHERE id = $1`,
          [id, refreshMode, Date.now() - t0, changedCount]
        ).catch(() => {});
        results.push({ window, status: 'success', item_count: art.itemCount, refresh_mode: refreshMode });
      } else {
        let iocRows = [];
        if (!allKeysStale) {
          const t0 = Date.now();
          iocRows = queryMode
            ? await fetchQueryModeIocRows(db, feed)
            : await fetchIocRows(db, feed, window);
          queryMs += Date.now() - t0;
        }
        const { content, content_hash, item_count } = await buildFeedContent(db, feed, iocRows, formatTypes, genMax);
        const bytes = Buffer.byteLength(content, 'utf8');
        snapshotBytes = Math.max(snapshotBytes || 0, bytes);
        maxItemCount = Math.max(maxItemCount, item_count);

        await persistPublishedFeedSnapshot(db, {
          feedId: id,
          itemCount: item_count,
          contentHash: content_hash,
          content,
          status: 'success',
          paramsJson
        });

        results.push({ window, status: 'success', item_count });
      }
    } catch (err) {
      const msg = String(err?.message || err);
      const paramsJson = {
        ioc_type: iocTypeKey,
        ioc_types: iocTypes,
        window,
        filters_hash: filtersHash(feed, window)
      };
      await persistPublishedFeedSnapshot(db, {
        feedId: id,
        itemCount: 0,
        contentHash: null,
        content: '',
        status: 'failed',
        errorMessage: msg,
        paramsJson
      });
      results.push({ window, status: 'failed', error: msg });
    }
  }

  const failed = results.filter((r) => r.status === 'failed');
  const lastStatus = failed.length === results.length ? 'failed' : failed.length ? 'partial' : 'success';
  const lastError = failed.length ? failed.map((f) => `${f.window}: ${f.error}`).join('; ') : null;
  const allSkipped = results.length > 0 && results.every((r) => r.skipped);
  const anyGenerated = results.some((r) => r.status === 'success' && !r.skipped);

  if (!allSkipped) {
    // Do NOT bump updated_at on generation — that column is a config watermark.
    // Bumping it made the next cycle see filtersChanged and forced full rebuilds,
    // defeating incremental/no-op even when projection was ready.
    await db.query(
      `UPDATE published_feeds
       SET last_generated_at = NOW(),
           last_status = $2,
           last_error = $3
       WHERE id = $1`,
      [id, lastStatus, lastError]
    );
  } else {
    // No-op ticks must NOT bump updated_at — that previously defeated the next
    // watermark/filtersHash skip by making feed_updated_at look dirty.
    await db.query(
      `UPDATE published_feeds
       SET last_generated_at = NOW(),
           last_status = COALESCE(last_status, 'success'),
           last_refresh_checked_at = NOW(),
           last_refresh_mode = COALESCE(last_refresh_mode, 'noop')
       WHERE id = $1`,
      [id]
    );
  }

  const resultLabel = failed.length === results.length && results.length
    ? 'failed'
    : anyGenerated
      ? 'generated'
      : allSkipped
        ? 'unchanged'
        : lastStatus === 'partial'
          ? 'generated'
          : 'failed';
  const skipReason = allSkipped
    ? (results.find((r) => r.reason)?.reason || 'unchanged')
    : null;

  feedLog.info('published feed generation', {
    feed_id: id,
    feed_name: feedName,
    windows,
    generation_ms: Date.now() - startedAt,
    query_ms: queryMs,
    item_count: maxItemCount,
    snapshot_bytes: snapshotBytes,
    result: resultLabel,
    skip_reason: skipReason,
    force
  });

  return { feed_id: id, results, last_status: lastStatus, last_error: lastError };
}

/** Default scheduler poll cadence (ms). Overridable via PUBLISHED_FEED_TICK_MS. */
export const PUBLISHED_FEED_TICK_MS_DEFAULT = 60 * 1000;
/** Floor for tick resolution — avoid sub-15s busy loops. */
export const PUBLISHED_FEED_TICK_MS_MIN = 15 * 1000;

/**
 * Resolve Published Feed scheduler poll interval from env/config.
 * Invalid/empty values fall back to the 60s default; values below the floor are clamped.
 */
export function resolvePublishedFeedTickMs(envValue = process.env.PUBLISHED_FEED_TICK_MS) {
  if (envValue == null || envValue === '') return PUBLISHED_FEED_TICK_MS_DEFAULT;
  const n = Number(envValue);
  if (!Number.isFinite(n)) return PUBLISHED_FEED_TICK_MS_DEFAULT;
  return Math.max(n, PUBLISHED_FEED_TICK_MS_MIN);
}

/**
 * Cheap due check for scheduled Published Feed refresh.
 *
 * Cadence is start-anchored: `last_generated_at` is completion time, so we subtract
 * `last_refresh_ms` (last window duration) to approximate the previous start. That way a
 * 5m feed that starts at T and finishes at T+45s becomes due again near T+5m, not T+5m45s
 * (and not T+10m when the poll interval equals the refresh interval).
 *
 * Long jobs (> interval): after completion the feed is immediately due once — no backlog
 * queue; advisory lock still prevents overlap while a run is in progress.
 */
export function isPublishedFeedDue(row, nowMs = Date.now()) {
  if (row?.enabled === false) return false;
  const intervalMs = Math.max(Number(row?.refresh_interval_minutes || 15), 5) * 60 * 1000;
  if (!row?.last_generated_at) return true;
  const completedAt = new Date(row.last_generated_at).getTime();
  if (!Number.isFinite(completedAt)) return true;
  const durationMs = Math.max(0, Number(row.last_refresh_ms) || 0);
  const cappedDuration = Math.min(durationMs, intervalMs);
  const anchorMs = completedAt - cappedDuration;
  return nowMs - anchorMs >= intervalMs;
}

/**
 * Scheduler tick: cheap SELECT of scheduling columns, filter due feeds in-process,
 * then run generation only for due ids (advisory lock prevents overlap).
 */
export async function regenerateAllEnabledFeeds(pool, options = {}) {
  const nowMs = Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  const { rows } = await pool.query(
    `SELECT id, name, refresh_interval_minutes, last_generated_at, last_refresh_ms, enabled
     FROM published_feeds
     WHERE enabled = TRUE`
  );
  const due = rows.filter((r) => isPublishedFeedDue(r, nowMs));

  for (const row of due) {
    try {
      const result = await generatePublishedFeedSnapshot(pool, row.id);
      if (result?.reason === 'generation_in_progress') {
        // Structured log already emitted by generatePublishedFeedSnapshot.
        continue;
      }
      // Per-run structured log is emitted inside runPublishedFeedGeneration.
    } catch (err) {
      feedLog.error('published feed scheduled regenerate failed', {
        feed_id: row.id,
        error: String(err?.message || err)
      });
    }
  }
  return { checked: rows.length, due: due.length, due_ids: due.map((r) => Number(r.id)) };
}

/** Metadata only — never SELECT content (used for 304 / skip checks). */
export async function getLatestSnapshotMeta(db, feedId, iocTypeKey, window) {
  const { rows } = await db.query(
    `SELECT id, content_hash, item_count, generated_at, params,
            storage_path, artifact_format,
            COALESCE(octet_length(content), file_size) AS content_bytes
     FROM published_feed_snapshots
     WHERE feed_id = $1
       AND status = 'success'
       AND params->>'ioc_type' = $2
       AND params->>'window' = $3
     ORDER BY generated_at DESC
     LIMIT 1`,
    [Number(feedId), String(iocTypeKey), String(window)]
  );
  return rows[0] || null;
}

/** Load the file-artifact pointer pinned to snapshot id + content_hash (publish-race safe). */
export async function getSnapshotArtifactByIdAndHash(db, snapshotId, contentHash) {
  const { rows } = await db.query(
    `SELECT id, storage_path, file_size, artifact_format, content_hash, generated_at
     FROM published_feed_snapshots
     WHERE id = $1 AND content_hash = $2 AND status = 'success' AND storage_path IS NOT NULL
     LIMIT 1`,
    [Number(snapshotId), String(contentHash)]
  );
  return rows[0] || null;
}

/** Load content pinned to snapshot id + content_hash (publish-race safe). */
export async function getSnapshotContentByIdAndHash(db, snapshotId, contentHash) {
  const { rows } = await db.query(
    `SELECT id, content, content_hash, item_count, generated_at, params
     FROM published_feed_snapshots
     WHERE id = $1
       AND content_hash = $2
       AND status = 'success'
     LIMIT 1`,
    [Number(snapshotId), String(contentHash)]
  );
  return rows[0] || null;
}

export async function getLatestSnapshot(db, feedId, iocTypeKey, window) {
  const { rows } = await db.query(
    `SELECT id, content, content_hash, item_count, generated_at, params
     FROM published_feed_snapshots
     WHERE feed_id = $1
       AND status = 'success'
       AND params->>'ioc_type' = $2
       AND params->>'window' = $3
     ORDER BY generated_at DESC
     LIMIT 1`,
    [Number(feedId), String(iocTypeKey), String(window)]
  );
  return rows[0] || null;
}
