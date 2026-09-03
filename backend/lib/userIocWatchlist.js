/**
 * Per-user IOC Watchlist (Favorites) data access.
 *
 * Membership lives in the relationship table user_ioc_watchlist and is ALWAYS
 * scoped to a single user_id. No function here accepts a caller-supplied user id
 * for another user — the route layer derives user_id from the authenticated
 * session and passes it in. There is no code path that returns or mutates another
 * user's rows.
 *
 * ioc_items is LIST-partitioned by observable_type with a composite primary key
 * (observable_type, id); public_id is only indexed. So a watchlist row stores
 * (observable_type, ioc_id) and we resolve the external public_id to that pair.
 */

import { IOC_LIST_ALLOWED_PAGE_SIZES, IOC_LIST_DEFAULT_PAGE_SIZE } from './iocListPagination.js';

export const WATCHLIST_UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const WATCHLIST_LIST_MAX_PAGE_SIZE = 100;

/** @param {unknown} raw @returns {string|null} lowercased uuid or null */
export function parseWatchlistPublicId(raw) {
  const v = String(raw ?? '').trim().toLowerCase();
  return WATCHLIST_UUID_RE.test(v) ? v : null;
}

/**
 * Positive-integer user id (bigint). Machine principals (id null) are rejected by
 * the route layer before reaching the store; this guards against 0/NaN too.
 * @param {unknown} raw
 */
export function normalizeUserId(raw) {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} publicId validated uuid
 * @returns {Promise<{ ioc_id: number, observable_type: string } | null>}
 */
export async function resolveIocRefByPublicId(pool, publicId) {
  const { rows } = await pool.query(
    `SELECT id AS ioc_id, observable_type
       FROM ioc_items
      WHERE public_id = $1::uuid
      LIMIT 1`,
    [publicId]
  );
  if (!rows.length) return null;
  return { ioc_id: Number(rows[0].ioc_id), observable_type: String(rows[0].observable_type) };
}

/**
 * Idempotent add. Duplicate stars are a no-op (ON CONFLICT DO NOTHING); the unique
 * primary key (user_id, observable_type, ioc_id) is the source of truth, not the
 * client. Returns { created } where created is false when the row already existed.
 * @param {import('pg').Pool} pool
 * @param {number} userId
 * @param {{ ioc_id: number, observable_type: string }} ref
 */
export async function addToWatchlist(pool, userId, ref) {
  const { rowCount } = await pool.query(
    `INSERT INTO user_ioc_watchlist (user_id, observable_type, ioc_id)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id, observable_type, ioc_id) DO NOTHING`,
    [userId, ref.observable_type, ref.ioc_id]
  );
  return { created: rowCount > 0 };
}

/**
 * Idempotent remove. Removing an absent row is a no-op. Only ever affects the
 * caller's own row.
 * @param {import('pg').Pool} pool
 * @param {number} userId
 * @param {{ ioc_id: number, observable_type: string }} ref
 */
export async function removeFromWatchlist(pool, userId, ref) {
  const { rowCount } = await pool.query(
    `DELETE FROM user_ioc_watchlist
      WHERE user_id = $1 AND observable_type = $2 AND ioc_id = $3`,
    [userId, ref.observable_type, ref.ioc_id]
  );
  return { removed: rowCount > 0 };
}

/**
 * @param {import('pg').Pool} pool
 * @param {number} userId
 * @param {{ ioc_id: number, observable_type: string }} ref
 * @returns {Promise<boolean>}
 */
export async function isWatchlisted(pool, userId, ref) {
  const { rowCount } = await pool.query(
    `SELECT 1 FROM user_ioc_watchlist
      WHERE user_id = $1 AND observable_type = $2 AND ioc_id = $3
      LIMIT 1`,
    [userId, ref.observable_type, ref.ioc_id]
  );
  return rowCount > 0;
}

/**
 * @param {import('pg').Pool} pool
 * @param {number} userId
 * @returns {Promise<number>}
 */
export async function countWatchlist(pool, userId) {
  const { rows } = await pool.query(
    `SELECT count(*)::bigint AS n FROM user_ioc_watchlist WHERE user_id = $1`,
    [userId]
  );
  return Number(rows[0]?.n || 0);
}

/**
 * A page of the caller's watchlist refs, newest star first.
 * @param {import('pg').Pool} pool
 * @param {number} userId
 * @param {{ limit: number, offset: number }} page
 * @returns {Promise<Array<{ observable_type: string, ioc_id: number, created_at: string }>>}
 */
export async function listWatchlistRefs(pool, userId, { limit, offset }) {
  const { rows } = await pool.query(
    `SELECT observable_type, ioc_id, created_at
       FROM user_ioc_watchlist
      WHERE user_id = $1
      ORDER BY created_at DESC, ioc_id DESC
      LIMIT $2 OFFSET $3`,
    [userId, limit, offset]
  );
  return rows.map((r) => ({
    observable_type: String(r.observable_type),
    ioc_id: Number(r.ioc_id),
    created_at: r.created_at
  }));
}

/**
 * Load the ioc_items rows for a page of watchlist refs. The join carries
 * observable_type so Postgres prunes to the right partitions and uses the
 * composite primary key — no full ioc_items scan.
 * @param {import('pg').Pool} pool
 * @param {Array<{ observable_type: string, ioc_id: number }>} refs
 */
export async function loadIocRowsForRefs(pool, refs) {
  if (!refs.length) return [];
  const types = refs.map((r) => r.observable_type);
  const ids = refs.map((r) => r.ioc_id);
  const { rows } = await pool.query(
    `SELECT i.id, i.public_id, i.observable, i.observable_type,
            i.source_name, i.source_url, i.confidence, i.category, i.note,
            i.created_at, i.first_seen_at, i.last_seen_at, i.status
       FROM ioc_items i
       JOIN unnest($1::text[], $2::bigint[]) AS w(observable_type, ioc_id)
         ON i.observable_type = w.observable_type AND i.id = w.ioc_id`,
    [types, ids]
  );
  return rows;
}

/**
 * Shape an ioc_items row into the pageItem the IOC-list enrichment pipeline
 * (mapIocListPageItems) expects. Mirrors the exact-observable list path so a
 * watchlist row renders identically to a normal IOC-list row.
 * @param {object} row
 */
export function iocRowToPageItem(row) {
  return {
    id: Number(row.id),
    public_id: row.public_id,
    observable: row.observable,
    observable_type: row.observable_type,
    ip: row.observable,
    status: row.status || 'active',
    created_at: row.created_at,
    imported_at: row.created_at,
    first_seen_at: row.first_seen_at || row.created_at,
    last_seen_at: row.last_seen_at || row.created_at,
    source_count: 0,
    source_names: [],
    confidence_set: [],
    category_set: []
  };
}

/**
 * Per-user membership for a page of already-built IOC list items. ONE query,
 * scoped to the viewer, keyed by the globally-unique ioc id. Mutates each item,
 * setting item.watchlisted (boolean). Safe to call with an empty/invalid viewer
 * (annotates everything false without a query).
 * @param {import('pg').Pool} pool
 * @param {number|null} userId
 * @param {Array<object>} items
 */
export async function annotateItemsWatchlisted(pool, userId, items) {
  if (!Array.isArray(items) || items.length === 0) return items;
  const uid = normalizeUserId(userId);
  if (!uid) {
    for (const it of items) it.watchlisted = false;
    return items;
  }
  const ids = [];
  for (const it of items) {
    const n = Number(it?.id);
    if (Number.isInteger(n) && n > 0) ids.push(n);
  }
  let starred = new Set();
  if (ids.length) {
    const { rows } = await pool.query(
      `SELECT ioc_id FROM user_ioc_watchlist
        WHERE user_id = $1 AND ioc_id = ANY($2::bigint[])`,
      [uid, ids]
    );
    starred = new Set(rows.map((r) => Number(r.ioc_id)));
  }
  for (const it of items) {
    it.watchlisted = starred.has(Number(it?.id));
  }
  return items;
}

/**
 * @param {Record<string, unknown>} query express req.query
 */
export function parseWatchlistListParams(query = {}) {
  const page = Math.max(Number(query.page) || 1, 1);
  const rawSize = Number(query.page_size);
  const pageSize = IOC_LIST_ALLOWED_PAGE_SIZES.includes(rawSize)
    ? rawSize
    : IOC_LIST_DEFAULT_PAGE_SIZE;
  return { page, pageSize, limit: pageSize, offset: (page - 1) * pageSize };
}

/**
 * Pagination envelope compatible with the IOC-list shape the frontend already
 * consumes. Watchlist totals are exact (cheap per-user COUNT), so no cap here.
 * @param {{ page: number, pageSize: number, total: number }} opts
 */
export function buildWatchlistPagination({ page, pageSize, total }) {
  const size = Math.max(Number(pageSize) || IOC_LIST_DEFAULT_PAGE_SIZE, 1);
  const t = Math.max(Number(total) || 0, 0);
  const pageCount = t === 0 ? 1 : Math.max(Math.ceil(t / size), 1);
  return {
    page: Math.max(Number(page) || 1, 1),
    page_size: size,
    global_total: t,
    listed_items: t,
    page_count: pageCount,
    mode: 'watchlist',
    status_filter: 'all',
    total: t,
    total_pages: pageCount
  };
}
