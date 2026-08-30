/**
 * IOC list Timestamp = platform first-import time (`ioc_items.created_at`).
 *
 * This is set once on INSERT (DEFAULT NOW / omitted column) and is never rewritten
 * on re-import, re-sync, or additional feed memberships.
 *
 * Source-change aggregates (first_seen / last_changed in source) remain available for
 * IOC detail, DSL filters, and export columns — they must NOT drive the list Timestamp.
 */

/** Shared SQL fragment for membership aggregate (alias `m`) — source semantics only. */
export const CANONICAL_FIRST_SEEN_AGG_SQL = 'MIN(m.first_seen_in_feed)';
export const CANONICAL_LAST_CHANGED_AGG_SQL =
  'MAX(COALESCE(m.last_changed_in_source, m.first_seen_in_feed))';

/**
 * Platform import / IOC List Timestamp resolver.
 * @param {{ item_created_at?: Date|string|null, created_at?: Date|string|null }} input
 */
export function resolvePlatformImportTimestamp(input = {}) {
  const created = input.item_created_at || input.created_at || null;
  return {
    created_at: created,
    imported_at: created,
    // Legacy list field name still emitted for older clients — same value as imported_at.
    last_seen_at: created,
    list_timestamp: created,
    list_timestamp_field: created ? 'created_at' : null
  };
}

/**
 * Source-change timestamps for detail / DSL / export (not the list Timestamp column).
 * last_changed falls back to first_seen_in_feed only — never to created_at or last_seen_in_feed alone.
 * @param {{
 *   first_seen_in_source?: Date|string|null,
 *   last_changed_in_source?: Date|string|null,
 *   item_created_at?: Date|string|null,
 *   created_at?: Date|string|null
 * }} input
 */
export function resolveSourceChangeTimestamps(input = {}) {
  const created = input.item_created_at || input.created_at || null;
  const firstSeenInSource = input.first_seen_in_source || null;
  const lastChangedRaw = input.last_changed_in_source || null;
  const lastChangedDisplay = lastChangedRaw || firstSeenInSource || null;

  return {
    first_seen_in_source: firstSeenInSource || null,
    last_changed_in_source: lastChangedDisplay,
    last_changed_in_source_raw: lastChangedRaw,
    // Item-level first_seen_at is not the list Timestamp; keep for consumers that need it.
    first_seen_at: firstSeenInSource || created || null
  };
}

/**
 * Combined resolver (list import + source-change fields). Prefer the specific helpers.
 * @deprecated Prefer resolvePlatformImportTimestamp / resolveSourceChangeTimestamps
 */
export function resolveCanonicalIocTimestamps(input = {}) {
  const platform = resolvePlatformImportTimestamp(input);
  const source = resolveSourceChangeTimestamps(input);
  return {
    ...source,
    ...platform,
    // Keep an explicit display_timestamp aligned with list Timestamp (platform import).
    display_timestamp: platform.imported_at,
    display_timestamp_field: platform.list_timestamp_field
  };
}

/**
 * Attach platform import Timestamp (+ optional source-change fields) onto list/search items.
 * Ensures created_at is loaded from DB when page builders omitted it.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {Array<object>} items
 */
export async function attachCanonicalIocListTimestamps(db, items = []) {
  if (!items.length) return items;
  const ids = [...new Set(items.map((it) => Number(it.id)).filter((id) => Number.isFinite(id) && id > 0))];

  /** @type {Map<number, Date|string>} */
  const createdMap = new Map();
  /** @type {Map<number, { first_seen_in_source: any, last_changed_in_source: any }>} */
  const sourceTsMap = new Map();

  if (ids.length) {
    const needCreated = items.some((it) => !(it.created_at || it.item_created_at));
    const queries = [
      db.query(
        `SELECT m.ioc_item_id,
                ${CANONICAL_FIRST_SEEN_AGG_SQL} AS first_seen_in_source,
                ${CANONICAL_LAST_CHANGED_AGG_SQL} AS last_changed_in_source
           FROM ioc_feed_memberships m
          WHERE m.ioc_item_id = ANY($1::bigint[])
          GROUP BY m.ioc_item_id`,
        [ids]
      )
    ];
    if (needCreated) {
      queries.push(
        db.query(
          `SELECT id, created_at FROM ioc_items WHERE id = ANY($1::bigint[])`,
          [ids]
        )
      );
    }

    const results = await Promise.all(queries);
    for (const row of results[0].rows) {
      sourceTsMap.set(Number(row.ioc_item_id), {
        first_seen_in_source: row.first_seen_in_source,
        last_changed_in_source: row.last_changed_in_source
      });
    }
    if (needCreated && results[1]) {
      for (const row of results[1].rows) {
        createdMap.set(Number(row.id), row.created_at);
      }
    }
  }

  return items.map((it) => {
    const id = Number(it.id);
    const created = it.created_at || it.item_created_at || createdMap.get(id) || null;
    const agg = sourceTsMap.get(id) || {};
    const platform = resolvePlatformImportTimestamp({ item_created_at: created });
    const source = resolveSourceChangeTimestamps({
      first_seen_in_source: agg.first_seen_in_source,
      last_changed_in_source: agg.last_changed_in_source,
      item_created_at: created
    });
    return {
      ...it,
      ...source,
      ...platform
    };
  });
}

export const IOC_LIST_TIMESTAMP_COLUMN = Object.freeze({
  apiField: 'imported_at',
  canonicalField: 'created_at',
  label: 'Timestamp',
  description:
    'When this IOC was first added to TalonHound (ioc_items.created_at). Stable across re-syncs and extra feed memberships.',
  orderBySql: 'ioc_items.created_at DESC',
  fallback: Object.freeze(['ioc_items.created_at'])
});

/**
 * IOC detail platform insert time = earliest ioc_items.created_at across related rows.
 * Never invents a value from source/membership timestamps.
 * @param {Array<{ created_at?: Date|string|null }>} rows
 */
export function resolveDetailPlatformImportTimestamp(rows = []) {
  const createdDates = (Array.isArray(rows) ? rows : [])
    .map((r) => r?.created_at)
    .filter((d) => d != null && d !== '');
  if (!createdDates.length) {
    return resolvePlatformImportTimestamp({});
  }
  const earliest = createdDates.reduce((min, d) => (new Date(d) < new Date(min) ? d : min));
  return resolvePlatformImportTimestamp({ created_at: earliest });
}

/**
 * Presence / last-confirmed across feed memberships (`last_seen_in_feed`).
 * Returns null when unavailable — does not fall back to last_changed or created_at.
 * @param {Array<{ last_seen_in_feed?: Date|string|null }>} membershipRows
 */
export function resolveDetailLastConfirmedAt(membershipRows = []) {
  const dates = (Array.isArray(membershipRows) ? membershipRows : [])
    .map((m) => m?.last_seen_in_feed)
    .filter((d) => d != null && d !== '');
  if (!dates.length) return null;
  return dates.reduce((max, d) => (new Date(d) > new Date(max) ? d : max));
}
