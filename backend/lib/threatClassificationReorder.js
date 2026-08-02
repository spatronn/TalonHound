/** Plan and apply deterministic threat classification sort_order values. */

import { UNKNOWN_THREAT_CLASSIFICATION } from './threatClassification.js';

export const THREAT_CLASSIFICATION_SORT_STEP = 10;

/**
 * @param {string} slug
 * @param {boolean} active
 * @returns {[number, number]}
 */
export function threatClassificationListRank(slug, active) {
  const unknownRank = slug === UNKNOWN_THREAT_CLASSIFICATION ? 0 : 1;
  const activeRank = active ? 0 : 1;
  return [unknownRank, activeRank];
}

/**
 * Display / management list order: Unknown first, then active by sort_order, then inactive by sort_order.
 * @template {{ id?: string, slug: string, active?: boolean, sort_order?: number, name?: string }} T
 * @param {T[]} rows
 * @returns {T[]}
 */
export function sortThreatClassificationsForDisplay(rows) {
  return [...(rows || [])].sort((a, b) => {
    const [au, aa] = threatClassificationListRank(a.slug, a.active !== false);
    const [bu, ba] = threatClassificationListRank(b.slug, b.active !== false);
    if (au !== bu) return au - bu;
    if (aa !== ba) return aa - ba;
    const so = (Number(a.sort_order) || 0) - (Number(b.sort_order) || 0);
    if (so) return so;
    return String(a.name || a.slug || '').localeCompare(String(b.name || b.slug || ''));
  });
}

/**
 * Build compact id→order snapshots for audit metadata (avoid full row payloads).
 * @param {Array<{ id: string, sort_order?: number }>} rows
 * @returns {Array<{ id: string, sort_order: number }>}
 */
export function threatClassificationOrderSnapshot(rows) {
  return sortThreatClassificationsForDisplay(rows).map((row) => ({
    id: String(row.id),
    sort_order: Number(row.sort_order) || 0
  }));
}

/**
 * Validate ordered_ids and produce unique, deterministic sort_order assignments (0, 10, 20, …).
 * Unknown is always forced first. Active rows come before inactive while preserving relative order
 * from the client list within each group.
 *
 * @param {Array<{ id: string, slug: string, active?: boolean, sort_order?: number, name?: string }>} rows
 * @param {unknown} orderedIdsRaw
 * @returns {{ ok: true, assignments: Array<{ id: string, sort_order: number }>, orderedIds: string[] }
 *   | { ok: false, status: number, error: string }}
 */
export function planThreatClassificationReorder(rows, orderedIdsRaw) {
  if (!Array.isArray(orderedIdsRaw)) {
    return { ok: false, status: 400, error: 'ordered_ids must be an array of classification ids' };
  }
  if (!orderedIdsRaw.length) {
    return { ok: false, status: 400, error: 'ordered_ids cannot be empty' };
  }

  const orderedIds = orderedIdsRaw.map((id) => String(id || '').trim());
  if (orderedIds.some((id) => !id)) {
    return { ok: false, status: 400, error: 'ordered_ids contains an invalid id' };
  }

  const seen = new Set();
  for (const id of orderedIds) {
    if (seen.has(id)) {
      return { ok: false, status: 400, error: 'ordered_ids contains duplicate ids' };
    }
    seen.add(id);
  }

  const byId = new Map((rows || []).map((row) => [String(row.id), row]));
  if (!byId.size) {
    return { ok: false, status: 500, error: 'No threat classifications found' };
  }

  for (const id of orderedIds) {
    if (!byId.has(id)) {
      return { ok: false, status: 400, error: `ordered_ids contains unknown id: ${id}` };
    }
  }
  for (const id of byId.keys()) {
    if (!seen.has(id)) {
      return { ok: false, status: 400, error: 'ordered_ids must include every classification id' };
    }
  }

  const unknown = [...byId.values()].find((row) => row.slug === UNKNOWN_THREAT_CLASSIFICATION);
  if (!unknown) {
    return { ok: false, status: 500, error: 'Unknown classification is missing' };
  }

  const unknownId = String(unknown.id);
  const rest = orderedIds.filter((id) => id !== unknownId);
  const activeOrdered = [];
  const inactiveOrdered = [];
  for (const id of rest) {
    const row = byId.get(id);
    if (row.active !== false) activeOrdered.push(row);
    else inactiveOrdered.push(row);
  }

  const orderedRows = [unknown, ...activeOrdered, ...inactiveOrdered];
  const assignments = orderedRows.map((row, index) => ({
    id: String(row.id),
    sort_order: index * THREAT_CLASSIFICATION_SORT_STEP
  }));

  return {
    ok: true,
    assignments,
    orderedIds: assignments.map((a) => a.id)
  };
}

/**
 * Assign sort_order values in a single statement to avoid temporary unique collisions.
 * @param {{ query: Function }} client
 * @param {Array<{ id: string, sort_order: number }>} assignments
 * @param {string | null} actor
 */
export async function applyThreatClassificationSortOrders(client, assignments, actor = null) {
  if (!assignments?.length) return;
  const ids = assignments.map((a) => a.id);
  const orders = assignments.map((a) => a.sort_order);
  await client.query(
    `UPDATE threat_classifications AS tc
     SET sort_order = v.sort_order,
         updated_by = $3,
         updated_at = NOW()
     FROM UNNEST($1::uuid[], $2::int[]) AS v(id, sort_order)
     WHERE tc.id = v.id`,
    [ids, orders, actor]
  );
}
