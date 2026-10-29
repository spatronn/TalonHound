/**
 * File-identity source provenance.
 *
 * A verified MD5/SHA1/SHA256 alias shares one logical file, but each source
 * membership stays on the IOC row whose hash that source actually published.
 * IOC Details and the observable-sources API read this summary so a canonical
 * SHA256 page still shows an MD5-only feed as that feed's MD5 observation.
 *
 * VirusTotal (and any other enrichment provider) is not a threat-intelligence
 * source here. Enrichment evidence lives on file_artifact_source_observations
 * and ioc_enrichments, not in this membership list.
 *
 * List active-source counts (enrichItemsWithActiveSourceCounts) use the same
 * definition: distinct providers with an active membership or active manual
 * source on any proven alias. Historical providers are not part of that count.
 */

import { isFileArtifactsReadEnabled } from './fileArtifacts/flags.js';
import { resolveArtifactScopedIocIds } from './fileArtifacts/read.js';
import {
  fetchObservableMembershipSummary,
  isActiveFeedMembership,
  isHistoricalFeedMembership
} from './iocActiveSources.js';

export const SOURCE_RELATIONSHIP = Object.freeze({
  DIRECT: 'direct',
  VERIFIED_FILE_IDENTITY: 'verified_file_identity'
});

function sourceNameOf(src) {
  return String(src?.name || '').trim() || 'Unknown source';
}

function annotateSource(src, row, relationship) {
  return {
    ...src,
    ioc_item_id: src.ioc_item_id != null ? Number(src.ioc_item_id) : Number(row.ioc_id),
    publisher_ioc_id: Number(row.ioc_id),
    publisher_public_id: row.public_id || null,
    publisher_observable_type: row.observable_type || null,
    publisher_observable: row.observable || null,
    relationship
  };
}

function observationOf(src, row, relationship, active) {
  return {
    membership_id: src.membership_id != null ? Number(src.membership_id) : null,
    ioc_source_id: src.ioc_source_id != null ? Number(src.ioc_source_id) : null,
    ioc_item_id: Number(row.ioc_id),
    public_id: row.public_id || null,
    observable_type: row.observable_type || null,
    observable: row.observable || null,
    relationship,
    status: src.status || (active ? 'active' : 'expired'),
    source_type: src.source_type || null,
    active: Boolean(active)
  };
}

function labelDirectPublisher(summary, row) {
  const stamp = (src) => annotateSource(src, row, SOURCE_RELATIONSHIP.DIRECT);
  return {
    ...summary,
    activeSources: (summary.activeSources || []).map(stamp),
    historicalSources: (summary.historicalSources || []).map(stamp),
    identityScoped: false
  };
}

function prefers(candidate, current) {
  if (!current) return true;
  if (candidate.relationship === SOURCE_RELATIONSHIP.DIRECT
    && current.relationship !== SOURCE_RELATIONSHIP.DIRECT) {
    return true;
  }
  return false;
}

/**
 * Collapse per-alias membership summaries into one logical source list.
 * An active provider is never also listed as historical. An expired-only
 * provider stays historical and is not reactivated. One card per provider
 * name; every publisher hash is kept on `observations`.
 *
 * @param {Array<{ ioc_id: number, public_id?: string|null, observable: string, observable_type: string, summary: object }>} rows
 * @param {{ canonicalIocId?: number|string|null }} [opts]
 */
export function assembleFileIdentitySources(rows = [], opts = {}) {
  const canonicalId = Number(opts.canonicalIocId);
  const byName = new Map();

  for (const row of rows || []) {
    const relationship = Number(row.ioc_id) === canonicalId
      ? SOURCE_RELATIONSHIP.DIRECT
      : SOURCE_RELATIONSHIP.VERIFIED_FILE_IDENTITY;
    const summary = row.summary || {};
    const push = (src, active) => {
      const name = sourceNameOf(src);
      if (!byName.has(name)) {
        byName.set(name, { active: null, historical: null, observations: [] });
      }
      const bucket = byName.get(name);
      bucket.observations.push(observationOf(src, row, relationship, active));
      const annotated = annotateSource(src, row, relationship);
      if (active) {
        if (prefers(annotated, bucket.active)) bucket.active = annotated;
      } else if (prefers(annotated, bucket.historical)) {
        bucket.historical = annotated;
      }
    };
    for (const src of summary.activeSources || []) push(src, true);
    for (const src of summary.historicalSources || []) push(src, false);
  }

  const activeSources = [];
  const historicalSources = [];
  for (const bucket of byName.values()) {
    const observations = bucket.observations;
    if (bucket.active) {
      activeSources.push({ ...bucket.active, observations });
    } else if (bucket.historical) {
      historicalSources.push({ ...bucket.historical, observations });
    }
  }

  const byLabel = (a, b) => String(a.name || '').localeCompare(String(b.name || ''));
  activeSources.sort(byLabel);
  historicalSources.sort(byLabel);

  const membershipRows = [];
  const seenMembership = new Set();
  for (const row of rows || []) {
    for (const membership of row.summary?.membershipRows || []) {
      const id = Number(membership.id);
      if (Number.isFinite(id) && seenMembership.has(id)) continue;
      if (Number.isFinite(id)) seenMembership.add(id);
      membershipRows.push(membership);
    }
  }

  const activeMemberships = membershipRows.filter(isActiveFeedMembership);
  const historicalMemberships = membershipRows.filter(isHistoricalFeedMembership);
  const activeSourceNames = activeSources.map((s) => s.name).filter(Boolean);

  return {
    membershipRows,
    activeMemberships,
    historicalMemberships,
    activeSources,
    historicalSources,
    activeSourceCount: activeSourceNames.length,
    activeSourceNames,
    historicalSourceCount: historicalSources.length,
    // Timestamp aggregates for the canonical page follow active memberships so an
    // expired alias observation cannot move "last seen". Empty active set falls
    // back to the full identity (all-historical IOC).
    timingMembershipRows: activeMemberships.length ? activeMemberships : membershipRows,
    identityScoped: true
  };
}

/**
 * Membership summary for one IOC, expanded across proven file-hash aliases
 * when artifact reads are enabled. Falls back to the single-observable summary
 * otherwise, including when the IOC has no artifact link.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {{ observable: string, observableType: string, iocItemIds?: number[], seedIocId?: number|string|null }} opts
 */
export async function fetchFileIdentityMembershipSummary(pool, {
  observable,
  observableType,
  iocItemIds = [],
  seedIocId = null
} = {}) {
  const seedId = Number(seedIocId || iocItemIds?.[0]);
  const single = () => fetchObservableMembershipSummary(pool, {
    observable,
    observableType,
    iocItemIds
  });

  if (!isFileArtifactsReadEnabled() || !Number.isFinite(seedId) || seedId <= 0) {
    return single();
  }

  let scopeIds = [seedId];
  try {
    const resolved = await resolveArtifactScopedIocIds(pool, seedId);
    if (resolved?.length) scopeIds = resolved;
  } catch (err) {
    if (!(err && (err.code === '42P01' || String(err.message || '').includes('file_artifact')))) {
      throw err;
    }
  }

  if (scopeIds.length === 1) {
    // No proven alias. Keep the existing single-observable summary, including
    // its timestamp rows, and only label the publisher observable.
    const summary = await single();
    return labelDirectPublisher(summary, {
      ioc_id: seedId,
      observable,
      observable_type: observableType
    });
  }

  const { rows } = await pool.query(
    `SELECT id, public_id, observable, observable_type
     FROM ioc_items
     WHERE id = ANY($1::bigint[])
     ORDER BY id ASC`,
    [scopeIds]
  );
  const byId = new Map(rows.map((row) => [Number(row.id), row]));
  if (!byId.has(seedId)) {
    byId.set(seedId, {
      id: seedId,
      public_id: null,
      observable,
      observable_type: observableType
    });
  }

  const assembledRows = [];
  for (const id of scopeIds) {
    const row = byId.get(Number(id));
    if (!row) continue;
    const summary = await fetchObservableMembershipSummary(pool, {
      observable: row.observable,
      observableType: row.observable_type,
      iocItemIds: [Number(row.id)]
    });
    assembledRows.push({
      ioc_id: Number(row.id),
      public_id: row.public_id || null,
      observable: row.observable,
      observable_type: row.observable_type,
      summary
    });
  }

  if (!assembledRows.length) return single();
  return assembleFileIdentitySources(assembledRows, { canonicalIocId: seedId });
}
