/**
 * IOC Details "First seen in source" / "Last seen in source" for Threat
 * Library evidence.
 *
 * Those cards mean source observation time: a feed membership contributes the
 * provider's own date (first_seen_in_feed from URLhaus dateAdded, ThreatFox
 * first_seen …), never TalonHound's import time. A Threat Library IOC is an
 * ioc_items row of the Threat_Library source whose first/last_seen_at are the
 * moment an analyst pressed Create IOCs — an import time. The report's own
 * observation of the value is:
 *
 *   1. the publisher observation of its indicator row (candidate
 *      evidence.source_observation: First / Last Seen, date precision), else
 *   2. the report publication date (the publisher reported it by then),
 *
 * so those replace the import time of Threat_Library rows in the source
 * observation aggregate. Read-time only: ioc_items timestamps, lifecycle,
 * expiration and feed recency are unchanged.
 */

import { IOC_SOURCE_NAME } from './constants.js';

/** Claims that make a report an evidence source of the IOC (same gate as Threat Context + approved). */
const CLAIMS_SQL = `
  SELECT c.matched_ioc_id,
         c.evidence->'source_observation' AS source_observation,
         r.public_id AS report_public_id,
         r.title AS report_title,
         r.published_at
  FROM threat_report_candidates c
  JOIN threat_reports r ON r.id = c.report_id
  WHERE c.matched_ioc_id = ANY($1::bigint[])
    AND r.deleted_at IS NULL
    AND r.import_status IN ('ready', 'imported', 'review_required')
    AND c.review_status IN ('approved', 'created_ioc')
    AND c.assessment IN ('malicious', 'suspicious')
`;

/**
 * @param {import('pg').Pool} pool
 * @param {Array<number|string>} iocIds ioc_items ids of the IOC identity
 */
export async function loadThreatLibraryObservationClaims(pool, iocIds) {
  const ids = [...new Set((iocIds || []).map(Number).filter((n) => Number.isFinite(n) && n > 0))];
  if (!ids.length) return [];
  const { rows } = await pool.query(CLAIMS_SQL, [ids]);
  return rows;
}

function dayOf(value) {
  if (!value) return null;
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) return value;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

/**
 * Earliest / latest report-side observation over the claims.
 * @param {object[]} claims rows of loadThreatLibraryObservationClaims
 * @returns {{ first: object, last: object }|null} each end:
 *   { date: 'YYYY-MM-DD', basis: 'publisher_observation'|'report_publication', report_id, report_title }
 */
export function resolveThreatLibraryObservationWindow(claims) {
  let first = null;
  let last = null;
  for (const c of claims || []) {
    const obs = c?.source_observation && typeof c.source_observation === 'object' ? c.source_observation : null;
    const report = { report_id: c.report_public_id || null, report_title: c.report_title || null };
    let lo = null;
    let hi = null;
    let basis = null;
    if (obs && (obs.earliest || obs.first_seen || obs.latest || obs.last_seen)) {
      lo = dayOf(obs.first_seen || obs.earliest || obs.latest);
      hi = dayOf(obs.last_seen || obs.latest || obs.earliest);
      basis = 'publisher_observation';
    } else {
      lo = dayOf(c.published_at);
      hi = lo;
      basis = 'report_publication';
    }
    if (lo && (!first || lo < first.date)) first = { date: lo, basis, ...report };
    if (hi && (!last || hi > last.date)) last = { date: hi, basis, ...report };
  }
  return first && last ? { first, last } : null;
}

const toInstant = (day) => `${day}T00:00:00.000Z`;
const ms = (v) => (v == null ? NaN : new Date(v).getTime());

/**
 * Source observation aggregate for the IOC Details summary.
 * Feed memberships keep their own (provider) dates; manual / custom item rows
 * keep theirs; Threat_Library item rows are replaced by the report-side
 * window when one exists (their own timestamps are import time).
 * @param {{
 *   membershipRows: Array<{ first_seen_in_feed?: any, last_seen_in_feed?: any }>,
 *   itemRows: Array<{ source_name?: string, item_first_seen_at?: any, item_last_seen_at?: any, created_at?: any }>,
 *   window: ReturnType<typeof resolveThreatLibraryObservationWindow>
 * }} input
 * @returns {{ first_seen_at: any, last_seen_in_source: any, first_seen_provenance: object|null, last_seen_provenance: object|null }}
 */
export function resolveSourceObservationTimestamps({ membershipRows = [], itemRows = [], window = null } = {}) {
  const isThreatLibraryRow = (r) => String(r?.source_name || '') === IOC_SOURCE_NAME;
  const items = window ? itemRows.filter((r) => !isThreatLibraryRow(r)) : itemRows;

  // Same precedence as before for non-Threat-Library evidence: feed memberships
  // when present, otherwise item rows.
  const memberFirst = membershipRows.map((m) => m.first_seen_in_feed).filter(Boolean);
  const memberLast = membershipRows.map((m) => m.last_seen_in_feed).filter(Boolean);
  const baseFirst = memberFirst.length ? memberFirst : items.map((r) => r.item_first_seen_at || r.created_at).filter(Boolean);
  const baseLast = memberLast.length ? memberLast : items.map((r) => r.item_last_seen_at).filter(Boolean);

  const pickMin = (list) => list.reduce((min, d) => (min == null || ms(d) < ms(min) ? d : min), null);
  const pickMax = (list) => list.reduce((max, d) => (max == null || ms(d) > ms(max) ? d : max), null);

  let firstSeen = pickMin(baseFirst);
  let lastSeen = pickMax(baseLast);
  let firstProv = null;
  let lastProv = null;
  if (window) {
    const wFirst = toInstant(window.first.date);
    const wLast = toInstant(window.last.date);
    if (firstSeen == null || ms(wFirst) < ms(firstSeen)) {
      firstSeen = wFirst;
      firstProv = { ...window.first, precision: 'date', source: 'threat_library' };
    }
    if (lastSeen == null || ms(wLast) > ms(lastSeen)) {
      lastSeen = wLast;
      lastProv = { ...window.last, precision: 'date', source: 'threat_library' };
    }
  }
  return {
    first_seen_at: firstSeen,
    last_seen_in_source: lastSeen,
    first_seen_provenance: firstProv,
    last_seen_provenance: lastProv
  };
}
