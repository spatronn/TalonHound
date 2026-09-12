/**
 * Bulk match Threat Library candidates against canonical ioc_items.
 * Uses the same unnest(type, value) pattern as mcpBulkLookupIocs — no N+1.
 */

import { normalizeObservable } from '../observable-normalization.js';
import { deriveMatchState } from './constants.js';

const IOC_TYPES = new Set(['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);

/**
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {Array<{ candidate_type: string, normalized_value: string, assessment?: string, confidence?: number|null, is_ioc?: boolean }>} candidates
 */
export async function bulkMatchCandidates(pool, candidates) {
  const iocCandidates = candidates.filter(
    (c) => c.is_ioc !== false && IOC_TYPES.has(String(c.candidate_type || '').toLowerCase())
  );

  /** @type {Map<string, { id: number, public_id: string, observable: string, observable_type: string, status: string }>} */
  const byKey = new Map();

  // Chunk to keep parameter arrays bounded
  const CHUNK = 500;
  for (let i = 0; i < iocCandidates.length; i += CHUNK) {
    const slice = iocCandidates.slice(i, i + CHUNK);
    const types = slice.map((c) => String(c.candidate_type).toLowerCase());
    const values = slice.map((c) => normalizeObservable(c.candidate_type, c.normalized_value) || c.normalized_value);
    const { rows } = await pool.query(
      `SELECT DISTINCT ON (observable_type, observable)
              id, public_id, observable, observable_type, status
       FROM ioc_items
       WHERE (observable_type, observable) IN (
         SELECT * FROM unnest($1::text[], $2::text[]) AS t(observable_type, observable)
       )
       ORDER BY observable_type, observable, created_at ASC, id ASC`,
      [types, values]
    );
    for (const r of rows) {
      byKey.set(`${r.observable_type}\0${r.observable}`, r);
    }
  }

  const matched = [];
  let counts = { existing: 0, new: 0, context_only: 0, needs_review: 0, invalid: 0 };

  for (const c of candidates) {
    const type = String(c.candidate_type || '').toLowerCase();
    const isIoc = c.is_ioc !== false && IOC_TYPES.has(type);
    let hit = null;
    if (isIoc) {
      const norm = normalizeObservable(type, c.normalized_value) || c.normalized_value;
      hit = byKey.get(`${type}\0${norm}`) || null;
    }
    const matchState = deriveMatchState({
      assessment: c.assessment || 'unknown',
      confidence: c.confidence ?? null,
      matchedIocId: hit ? Number(hit.id) : null,
      valid: c.assessment !== 'invalid' && (isIoc || type === 'cve' || type === 'attack_technique')
    });
    if (counts[matchState] != null) counts[matchState] += 1;
    else counts.needs_review += 1;

    matched.push({
      ...c,
      match_state: matchState,
      matched_ioc_id: hit ? Number(hit.id) : null,
      matched_ioc_public_id: hit?.public_id || null,
      matched_ioc_observable_type: hit?.observable_type || null,
      matched_ioc_status: hit?.status || null
    });
  }

  return {
    candidates: matched,
    summary: {
      total: candidates.length,
      ...counts
    }
  };
}
