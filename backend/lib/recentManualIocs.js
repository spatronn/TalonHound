// Recent manually-added IOCs for the "Add IOC" page table.
//
// "Manual" is determined ONLY by the authoritative origin marker
// ioc_items.created_origin = 'manual_add', written exclusively by
// createManualIoc(). Feed imports, scheduled jobs, background workers,
// migrations/backfills and external API ingestion never set it, so they are
// excluded at the query level (never fetched-then-filtered in the client).

export const MANUAL_IOC_ORIGIN = 'manual_add';
export const RECENT_MANUAL_IOC_DEFAULT_LIMIT = 10;
export const RECENT_MANUAL_IOC_MAX_LIMIT = 10;

export function clampRecentManualIocLimit(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return RECENT_MANUAL_IOC_DEFAULT_LIMIT;
  const floored = Math.floor(n);
  if (floored < 1) return 1;
  if (floored > RECENT_MANUAL_IOC_MAX_LIMIT) return RECENT_MANUAL_IOC_MAX_LIMIT;
  return floored;
}

export function buildRecentManualIocsQuery(limit) {
  const safeLimit = clampRecentManualIocLimit(limit);
  const text = `
    SELECT
      i.id,
      i.public_id,
      i.observable,
      i.observable_type,
      i.created_at,
      i.created_by_user_id,
      u.username AS added_by
    FROM ioc_items i
    LEFT JOIN users u ON u.public_id = i.created_by_user_id
    WHERE i.created_origin = $1
    ORDER BY i.created_at DESC, i.id DESC
    LIMIT $2
  `;
  return { text, values: [MANUAL_IOC_ORIGIN, safeLimit] };
}

export function mapRecentManualIocRow(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    public_id: row.public_id || null,
    observable: row.observable,
    observable_type: row.observable_type || null,
    added_by: row.added_by || null,
    created_at: row.created_at || null
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ limit?: number|string }} [opts]
 * @returns {Promise<Array<object>>} newest-first, at most 10 manual IOCs
 */
export async function fetchRecentManualIocs(pool, opts = {}) {
  const { text, values } = buildRecentManualIocsQuery(opts.limit);
  const { rows } = await pool.query(text, values);
  return (rows || []).map(mapRecentManualIocRow);
}
