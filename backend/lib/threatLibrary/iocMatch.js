/**
 * Bulk match Threat Library candidates against canonical ioc_items.
 * Uses the same unnest(type, value) pattern as mcpBulkLookupIocs — no N+1.
 */

import { normalizeObservable } from '../observable-normalization.js';
import { parseNetworkObservable } from '../networkObservable.js';
import { deriveMatchState } from './constants.js';

const MATCHABLE_IOC_TYPES = new Set(['ip', 'ipv6', 'cidr', 'domain', 'url', 'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);
const IOC_TYPES = MATCHABLE_IOC_TYPES;
const NETWORK_TYPES = new Set(['ip', 'ipv6', 'cidr']);

/**
 * ioc_items (observable_type, observable) a candidate is looked up by. Network
 * values use the IOC layer's canonical identity: a CIDR is the ip / ipv6
 * network IOC with its prefix (never a host), an IPv6 address an ipv6 IOC.
 * @returns {{ type: string, value: string } | null}
 */
export function catalogLookupIdentity(candidateType, normalizedValue) {
  const type = String(candidateType || '').toLowerCase();
  const value = String(normalizedValue || '');
  if (NETWORK_TYPES.has(type)) {
    const network = parseNetworkObservable(value);
    if (!network || !network.ok || (type === 'cidr') !== (network.kind === 'cidr')) return null;
    return { type: network.type, value: network.value };
  }
  return { type, value: normalizeObservable(type, value) || value };
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {Array<{ candidate_type: string, normalized_value: string, assessment?: string, confidence?: number|null, is_ioc?: boolean }>} candidates
 */
export async function bulkMatchCandidates(pool, candidates) {
  const iocCandidates = candidates.filter(
    (c) => c.is_ioc !== false &&
      MATCHABLE_IOC_TYPES.has(String(c.candidate_type || '').toLowerCase()) &&
      catalogLookupIdentity(c.candidate_type, c.normalized_value)
  );

  /** @type {Map<string, { id: number, public_id: string, observable: string, observable_type: string, status: string }>} */
  const byKey = new Map();

  // Chunk to keep parameter arrays bounded
  const CHUNK = 500;
  for (let i = 0; i < iocCandidates.length; i += CHUNK) {
    const slice = iocCandidates.slice(i, i + CHUNK);
    const identities = slice.map((c) => catalogLookupIdentity(c.candidate_type, c.normalized_value));
    const types = identities.map((i) => i.type);
    const values = identities.map((i) => i.value);
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
    const identity = isIoc ? catalogLookupIdentity(type, c.normalized_value) : null;
    if (identity) hit = byKey.get(`${identity.type}\0${identity.value}`) || null;
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

/**
 * Keep the stored global-IOC link of identities the catalog lookup skipped.
 *
 * bulkMatchCandidates only looks up candidates that are still IOC-typed
 * (is_ioc !== false). When a contract fix re-reads a previously matched or
 * created identity as non-IOC (an incomplete URL prefix, a provider service),
 * the lookup is skipped and the row would be written back with
 * matched_ioc_id = NULL: the global IOC would silently lose its link to this
 * report. The link is a fact about the identity, not a membership claim, so
 * it is carried over when the stored IOC record still exists. A lookup that
 * RAN and missed is a real catalog change and is left as matched (the refresh
 * guard reports it as an IOC link change).
 *
 * The carried link must still describe this identity: the stored IOC record
 * must exist with the candidate's observable type and normalized value. A
 * stale or mismatched id (record deleted, re-typed, or pointing at another
 * value) is NOT carried; the row is written unlinked and the refresh guard
 * reports that as a protected IOC link change.
 *
 * Reads only. Returns new candidate objects (inputs are not mutated).
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {object[]} candidates matched candidates (matchCandidateSet output)
 * @param {object[]} previousRows persisted rows of the report
 * @returns {Promise<{ candidates: object[], preserved: { identity: string, matched_ioc_id: number }[] }>}
 */
export async function preserveStoredIocLinks(pool, candidates, previousRows) {
  const priorByKey = new Map((previousRows || []).map((r) => [`${r.candidate_type}\0${r.normalized_value}`, r]));
  const pending = [];
  for (const c of candidates || []) {
    if (c.matched_ioc_id != null) continue;
    const prior = priorByKey.get(`${c.candidate_type}\0${c.normalized_value}`);
    if (prior?.matched_ioc_id == null) continue;
    const lookedUp = c.is_ioc !== false &&
      MATCHABLE_IOC_TYPES.has(String(c.candidate_type || '').toLowerCase()) &&
      Boolean(catalogLookupIdentity(c.candidate_type, c.normalized_value));
    if (lookedUp) continue;
    pending.push({ c, prior });
  }
  if (!pending.length) return { candidates: candidates || [], preserved: [] };
  const ids = [...new Set(pending.map((p) => Number(p.prior.matched_ioc_id)).filter(Number.isFinite))];
  const { rows } = await pool.query(
    `SELECT id, observable_type, observable FROM ioc_items WHERE id = ANY($1::bigint[])`,
    [ids]
  );
  // ioc_items is keyed (observable_type, id): an id alone is not an identity.
  const live = new Map(rows.map((r) => [`${r.observable_type}\0${r.id}`, r]));
  const carried = new Map();
  const preserved = [];
  for (const { c, prior } of pending) {
    const type = String(c.candidate_type || '').toLowerCase();
    if (!MATCHABLE_IOC_TYPES.has(type)) continue;
    const identity = catalogLookupIdentity(type, c.normalized_value);
    if (!identity) continue;
    const storedType = String(prior.matched_ioc_observable_type || identity.type).toLowerCase();
    if (storedType !== identity.type) continue;
    const hit = live.get(`${identity.type}\0${Number(prior.matched_ioc_id)}`);
    if (!hit) continue;
    const value = String(c.normalized_value || '');
    if (hit.observable !== identity.value && hit.observable !== value) continue;
    const matchedIocId = Number(hit.id);
    carried.set(c, {
      ...c,
      matched_ioc_id: matchedIocId,
      matched_ioc_observable_type: prior.matched_ioc_observable_type || hit.observable_type || null,
      match_state: deriveMatchState({
        assessment: c.assessment,
        confidence: c.confidence,
        matchedIocId,
        valid: c.assessment !== 'invalid'
      })
    });
    preserved.push({ identity: `${c.candidate_type}:${c.normalized_value}`, matched_ioc_id: matchedIocId });
  }
  return { candidates: (candidates || []).map((c) => carried.get(c) || c), preserved };
}
