/**
 * Canonical IOC list/search/export timestamp resolver.
 *
 * Aggregate (multi-membership), shared by list + export SQL:
 *   first_seen_in_source   = MIN(first_seen_in_feed)
 *   last_changed_raw       = MAX(COALESCE(last_changed_in_source, first_seen_in_feed))
 *                            — never uses technical last_seen_in_feed alone as "last changed"
 *
 * Display / API fallback for the "Last changed in source" column:
 *   1. last_changed_raw (membership aggregate above)
 *   2. first_seen_in_source aggregate
 *   3. ioc_items.created_at
 *
 * last_seen_at is a backward-compat alias of the same display value.
 */

/** Shared SQL fragment for membership aggregate (alias `m`). */
export const CANONICAL_FIRST_SEEN_AGG_SQL = 'MIN(m.first_seen_in_feed)';
export const CANONICAL_LAST_CHANGED_AGG_SQL =
  'MAX(COALESCE(m.last_changed_in_source, m.first_seen_in_feed))';

/**
 * Pure resolver used by tests and callers that already have membership aggregates.
 * @param {{
 *   first_seen_in_source?: Date|string|null,
 *   last_changed_in_source?: Date|string|null,
 *   item_created_at?: Date|string|null
 * }} input
 */
export function resolveCanonicalIocTimestamps(input = {}) {
  const created = input.item_created_at || null;
  const firstSeenInSource = input.first_seen_in_source || null;
  // Aggregate already coalesces per-membership last_changed → first_seen_in_feed.
  const lastChangedInSource = input.last_changed_in_source || null;

  const displayTimestamp = lastChangedInSource || firstSeenInSource || created || null;
  let displayField = 'created_at';
  if (lastChangedInSource) displayField = 'last_changed_in_source';
  else if (firstSeenInSource) displayField = 'first_seen_in_feed';
  else if (created) displayField = 'created_at';
  else displayField = null;

  return {
    first_seen_in_source: firstSeenInSource || created || null,
    // Canonical column value after fallback (may equal first_seen or created).
    last_changed_in_source: displayTimestamp,
    last_changed_in_source_raw: lastChangedInSource,
    first_seen_at: firstSeenInSource || created || null,
    last_seen_at: displayTimestamp,
    display_timestamp: displayTimestamp,
    display_timestamp_field: displayField
  };
}

/**
 * Batch-attach canonical timestamps onto IOC list/search page items.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {Array<object>} items
 */
export async function attachCanonicalIocListTimestamps(db, items = []) {
  if (!items.length) return items;
  const ids = [...new Set(items.map((it) => Number(it.id)).filter((id) => Number.isFinite(id) && id > 0))];
  /** @type {Map<number, { first_seen_in_source: any, last_changed_in_source: any }>} */
  const tsMap = new Map();

  if (ids.length) {
    const { rows } = await db.query(
      `SELECT m.ioc_item_id,
              ${CANONICAL_FIRST_SEEN_AGG_SQL} AS first_seen_in_source,
              ${CANONICAL_LAST_CHANGED_AGG_SQL} AS last_changed_in_source
         FROM ioc_feed_memberships m
        WHERE m.ioc_item_id = ANY($1::bigint[])
        GROUP BY m.ioc_item_id`,
      [ids]
    );
    for (const row of rows) {
      tsMap.set(Number(row.ioc_item_id), {
        first_seen_in_source: row.first_seen_in_source,
        last_changed_in_source: row.last_changed_in_source
      });
    }
  }

  return items.map((it) => {
    const agg = tsMap.get(Number(it.id)) || {};
    const resolved = resolveCanonicalIocTimestamps({
      first_seen_in_source: agg.first_seen_in_source,
      last_changed_in_source: agg.last_changed_in_source,
      item_created_at: it.created_at || it.item_created_at
    });
    return {
      ...it,
      ...resolved
    };
  });
}

export const IOC_LIST_TIMESTAMP_COLUMN = Object.freeze({
  apiField: 'last_seen_at',
  canonicalField: 'last_changed_in_source',
  label: 'Last changed in source',
  description:
    'Latest time source content actually changed for this IOC (not feed poll presence). Falls back to first_seen_in_feed, then created_at.',
  aggregateSql: CANONICAL_LAST_CHANGED_AGG_SQL,
  fallback: Object.freeze([
    'ioc_feed_memberships.last_changed_in_source',
    'ioc_feed_memberships.first_seen_in_feed',
    'ioc_items.created_at'
  ])
});
