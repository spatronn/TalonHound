// Sliding-window eligibility for Published Feed incremental projection.
//
// One base projection row per identity is stored under snapshot_window='all'.
// The row's recency_ts matches full-generation semantics:
//   COALESCE(last_seen_log, last_seen_at, created_at)
//
// Sliding-window artifacts (1d/3d/7d) filter that base projection at read time.
// Time-only departures (no IOC write) are detected via indexed boundary range scans.

export const BASE_PROJECTION_WINDOW = 'all';

export const SLIDING_WINDOWS = ['1d', '3d', '7d'];

const WINDOW_INTERVALS = {
  '1d': '1 day',
  '3d': '3 days',
  '7d': '7 days',
  all: null
};

export function isSlidingWindow(window) {
  return SLIDING_WINDOWS.includes(String(window || '').toLowerCase());
}

export function windowIntervalSql(window) {
  return WINDOW_INTERVALS[String(window || '').toLowerCase()] ?? null;
}

/** Feature gate for sliding-window incremental artifact generation. */
export function isSlidingWindowIncrementalEnabled() {
  const v = String(process.env.PUBLISHED_FEED_SLIDING_WINDOW_INCREMENTAL_ENABLED ?? 'true').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/**
 * Whether an item with recency_ts is visible in a sliding window at `at`.
 * Matches SQL: recency_ts >= at - interval (inclusive lower bound).
 */
export function isRecencyVisibleInWindow(recencyTs, window, at = new Date()) {
  const interval = windowIntervalSql(window);
  if (!interval) return true;
  if (!recencyTs) return false;
  const ms = intervalToMs(interval);
  if (!ms) return true;
  return new Date(recencyTs).getTime() >= at.getTime() - ms;
}

function intervalToMs(interval) {
  const m = String(interval).match(/^(\d+)\s+(day|days|hour|hours)$/i);
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  if (unit.startsWith('day')) return n * 24 * 60 * 60 * 1000;
  if (unit.startsWith('hour')) return n * 60 * 60 * 1000;
  return null;
}

/**
 * Items that leave a sliding window purely because time advanced between cutoffs.
 * Was eligible at prevCutoff: recency_ts >= prevCutoff - interval
 * Not eligible at curCutoff:   recency_ts <  curCutoff - interval
 */
export async function collectBoundaryDepartures(db, feedId, prevCutoff, curCutoff, window) {
  const interval = windowIntervalSql(window);
  if (!interval || !prevCutoff || !curCutoff) return [];
  const { rows } = await db.query(
    `SELECT identity_key, chunk_key, ioc_item_id, recency_ts
     FROM published_feed_items
     WHERE feed_id = $1
       AND snapshot_window = $2
       AND recency_ts >= $3::timestamptz - $5::interval
       AND recency_ts < $4::timestamptz - $5::interval`,
    [feedId, BASE_PROJECTION_WINDOW, prevCutoff, curCutoff, interval]
  );
  return rows;
}

/**
 * Normalize a generation bound to an ISO timestamptz string for SQL params.
 * @param {Date|string|number|null|undefined} asOf
 * @returns {string|null}
 */
export function normalizeGenerationAsOf(asOf) {
  if (asOf == null || asOf === '') return null;
  if (asOf instanceof Date) {
    if (Number.isNaN(asOf.getTime())) return null;
    return asOf.toISOString();
  }
  const d = new Date(asOf);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

/**
 * SQL fragment + params for sliding-window filter on base projection reads.
 *
 * When `asOf` is provided, the lower bound is frozen to that instant
 * (`recency_ts >= asOf - interval`) so count and chunk streaming share one
 * membership set. Callers MUST pass the generation candidateCutoff for any
 * multi-statement generation; bare NOW() is only for ad-hoc diagnostics.
 */
export function projectionWindowFilter(artifactWindow, paramIndex, asOf = null) {
  const interval = windowIntervalSql(artifactWindow);
  if (!interval || String(artifactWindow).toLowerCase() === 'all') {
    return { sql: '', params: [] };
  }
  const bound = normalizeGenerationAsOf(asOf);
  if (bound) {
    return {
      sql: ` AND recency_ts >= $${paramIndex}::timestamptz - $${paramIndex + 1}::interval`,
      params: [bound, interval]
    };
  }
  return {
    sql: ` AND recency_ts >= NOW() - $${paramIndex}::interval`,
    params: [interval]
  };
}

/**
 * Ordered projection scan for artifact generation.
 * Reads base projection (snapshot_window='all') and applies sliding-window filter when needed.
 */
export function buildProjectionScanSql(feedId, artifactWindow, asOf = null) {
  const base = BASE_PROJECTION_WINDOW;
  const filter = projectionWindowFilter(artifactWindow, 3, asOf);
  return {
    sql: `
      SELECT identity_key, ioc_item_id, observable, observable_type, recency_ts,
             confidence, category, txt_value, item_json, content_fingerprint, chunk_key
      FROM published_feed_items
      WHERE feed_id = $1 AND snapshot_window = $2${filter.sql}
      ORDER BY recency_ts DESC NULLS LAST, confidence_rank DESC, observable ASC, identity_key ASC`,
    params: [feedId, base, ...filter.params]
  };
}

/** Count projection rows visible in an artifact window at an optional frozen bound. */
export async function countProjectionItemsForWindow(db, feedId, artifactWindow, asOf = null) {
  const base = BASE_PROJECTION_WINDOW;
  const filter = projectionWindowFilter(artifactWindow, 3, asOf);
  const { rows } = await db.query(
    `SELECT COUNT(*)::bigint AS n
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2${filter.sql}`,
    [feedId, base, ...filter.params]
  );
  return Number(rows[0]?.n || 0);
}

/**
 * Resolve expected visible projection size for chunk manifests.
 * For snapshot_window=all, prefers durable projection_item_count and only COUNT(*) when
 * verify=true or the counter is unset.
 */
export async function resolveExpectedProjectionItemCount(db, feed, artifactWindow, asOf = null, {
  verify = false
} = {}) {
  const window = String(artifactWindow || BASE_PROJECTION_WINDOW).toLowerCase();
  const cached = feed?.projection_item_count;
  const canUseCache = window === 'all'
    && !verify
    && cached != null
    && Number.isFinite(Number(cached));
  if (canUseCache) return Number(cached);

  const n = await countProjectionItemsForWindow(db, feed.id, window, asOf);
  if (window === 'all' && feed?.id != null) {
    const { setFeedProjectionState } = await import('./publishedFeedProjection.js');
    await setFeedProjectionState(db, feed.id, { projection_item_count: n });
    feed.projection_item_count = n;
  }
  return n;
}

/**
 * Count window-visible projection rows whose chunk_key is IN `chunkKeys`.
 * Cheap when the key set is small (affected chunks) vs counting the complement.
 */
export async function countProjectionItemsInChunks(
  db,
  feedId,
  artifactWindow,
  asOf,
  chunkKeys = []
) {
  const base = BASE_PROJECTION_WINDOW;
  const keys = [...new Set((chunkKeys || []).map(Number).filter(Number.isFinite))];
  if (!keys.length) return 0;
  const filter = projectionWindowFilter(artifactWindow, 3, asOf);
  const keysIdx = 3 + filter.params.length;
  const { rows } = await db.query(
    `SELECT COUNT(*)::bigint AS n
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2${filter.sql}
       AND chunk_key = ANY($${keysIdx}::integer[])`,
    [feedId, base, ...filter.params, keys]
  );
  return Number(rows[0]?.n || 0);
}

/**
 * Count window-visible projection rows whose chunk_key is NOT in `excludeChunkKeys`.
 * Used to verify that unaffected (reused) parent chunks still match projection membership.
 */
export async function countProjectionItemsOutsideChunks(
  db,
  feedId,
  artifactWindow,
  asOf,
  excludeChunkKeys = []
) {
  const exclude = [...new Set((excludeChunkKeys || []).map(Number).filter(Number.isFinite))];
  const filter = projectionWindowFilter(artifactWindow, 3, asOf);
  // For base window with no sliding filter: count the small affected set and subtract
  // from total instead of scanning millions of unaffected rows.
  if (String(artifactWindow || '').toLowerCase() === 'all' && !filter.sql && exclude.length) {
    const { rows: totalRows } = await db.query(
      `SELECT COUNT(*)::bigint AS n
       FROM published_feed_items
       WHERE feed_id = $1 AND snapshot_window = $2`,
      [feedId, BASE_PROJECTION_WINDOW]
    );
    const total = Number(totalRows[0]?.n || 0);
    const inside = await countProjectionItemsInChunks(db, feedId, artifactWindow, asOf, exclude);
    return Math.max(0, total - inside);
  }
  const base = BASE_PROJECTION_WINDOW;
  const excludeIdx = 3 + filter.params.length;
  const { rows } = await db.query(
    `SELECT COUNT(*)::bigint AS n
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2${filter.sql}
       AND NOT (chunk_key = ANY($${excludeIdx}::integer[]))`,
    [feedId, base, ...filter.params, exclude]
  );
  return Number(rows[0]?.n || 0);
}

/**
 * Sum item_count for parent-generation chunks whose keys are NOT being regenerated.
 * Empty exclude list sums the entire generation (all chunks reused).
 */
export async function sumGenerationChunkItemsOutside(
  db,
  generationId,
  format,
  excludeChunkKeys = []
) {
  const exclude = [...new Set((excludeChunkKeys || []).map(Number).filter(Number.isFinite))];
  const { rows } = await db.query(
    `SELECT COALESCE(SUM(c.item_count), 0)::bigint AS n
     FROM published_feed_generation_chunks gc
     JOIN published_feed_chunks c ON c.id = gc.chunk_id
     WHERE gc.generation_id = $1
       AND gc.format = $2
       AND NOT (gc.chunk_key = ANY($3::integer[]))`,
    [String(generationId), String(format), exclude]
  );
  return Number(rows[0]?.n || 0);
}

/**
 * Incremental chunk reuse is only safe when projection membership for unaffected
 * chunk keys equals the parent generation's stored item counts for those keys.
 *
 * When a prior sliding-window generation under-counted (or a full projection refresh
 * changed recency without rebuilding every window artifact), dirty-only regeneration
 * leaves unreused keys underfilled → CHUNK_MANIFEST_COUNT_MISMATCH (actual << expected)
 * and the failed transaction never heals the active generation.
 */
export async function canReuseUnaffectedChunks(db, {
  feedId,
  artifactWindow,
  asOf,
  parentGenerationId,
  format = 'txt',
  excludeChunkKeys = [],
  expectedTotal = null
} = {}) {
  const exclude = [...new Set((excludeChunkKeys || []).map(Number).filter(Number.isFinite))];
  if (!parentGenerationId || !exclude.length) {
    return {
      reusable: false,
      reason: !parentGenerationId ? 'no_parent' : 'no_exclude_keys',
      projection_reused: null,
      parent_reused: null
    };
  }
  const parentReused = await sumGenerationChunkItemsOutside(db, parentGenerationId, format, exclude);
  let projectionReused;
  // Prefer: cached/known total − small in-chunk COUNT (avoids full-table complement scan).
  if (
    String(artifactWindow || '').toLowerCase() === 'all'
    && expectedTotal != null
    && Number.isFinite(Number(expectedTotal))
  ) {
    const inside = await countProjectionItemsInChunks(db, feedId, artifactWindow, asOf, exclude);
    projectionReused = Math.max(0, Number(expectedTotal) - inside);
  } else {
    projectionReused = await countProjectionItemsOutsideChunks(
      db, feedId, artifactWindow, asOf, exclude
    );
  }
  return {
    reusable: projectionReused === parentReused,
    reason: projectionReused === parentReused ? null : 'reused_chunk_membership_drift',
    projection_reused: projectionReused,
    parent_reused: parentReused
  };
}

/**
 * Chunk cursor SQL: reads base projection, filters by window eligibility and chunk keys.
 * `chunkKeysParamIndex` is the 1-based position of the chunk_key ANY() parameter after
 * feed_id ($1) and snapshot_window ($2) and any window-filter params.
 */
export function buildChunkCursorSql(feedId, artifactWindow, chunkKeysParamIndex, asOf = null) {
  const base = BASE_PROJECTION_WINDOW;
  const filter = projectionWindowFilter(artifactWindow, 3, asOf);
  const keysIdx = chunkKeysParamIndex ?? (3 + filter.params.length);
  const chunkFilter = ` AND chunk_key = ANY($${keysIdx}::integer[])`;
  return {
    sql: `
      SELECT identity_key, chunk_key, txt_value, item_json
      FROM published_feed_items
      WHERE feed_id = $1 AND snapshot_window = $2${filter.sql}${chunkFilter}
      ORDER BY chunk_key, recency_ts DESC NULLS LAST,
               confidence_rank DESC, observable ASC, identity_key ASC`,
    params: [feedId, base, ...filter.params]
  };
}

/**
 * Compute dirty chunk keys per artifact window from projection delta + boundary departures.
 */
export function computeAffectedChunksByWindow(delta, boundaries, touchedRows = [], at = new Date()) {
  const out = {
    all: new Set(delta?.affectedChunkKeys || []),
    '1d': new Set(),
    '3d': new Set(),
    '7d': new Set()
  };

  for (const w of SLIDING_WINDOWS) {
    for (const row of boundaries[w] || []) {
      if (row.chunk_key != null) out[w].add(Number(row.chunk_key));
    }
    for (const row of touchedRows) {
      const chunk = row.chunk_key != null ? Number(row.chunk_key) : null;
      if (chunk == null) continue;
      const prevVisible = row.prev_recency_ts != null
        ? isRecencyVisibleInWindow(row.prev_recency_ts, w, at)
        : false;
      const nowVisible = isRecencyVisibleInWindow(row.recency_ts, w, at);
      if (prevVisible || nowVisible) out[w].add(chunk);
    }
  }

  return Object.fromEntries(
    Object.entries(out).map(([k, set]) => [k, [...set].sort((a, b) => a - b)])
  );
}

/**
 * Whether an artifact window needs regeneration this tick.
 */
export function windowNeedsArtifactRefresh(window, delta, boundaries, affectedChunksByWindow) {
  const w = String(window).toLowerCase();
  if (w === 'all') {
    return Boolean(delta?.artifactDirty);
  }
  if (!isSlidingWindow(w)) return Boolean(delta?.artifactDirty);
  if ((boundaries[w]?.length || 0) > 0) return true;
  return (affectedChunksByWindow[w]?.length || 0) > 0;
}
