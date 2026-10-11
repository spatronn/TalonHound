/**
 * Source-aware IOC attribution (Threat Actors + Malware Families).
 *
 * Analyst associations remain in ioc_threat_actors / ioc_malware_families.
 * Feed/source assertions live here with independent Pulse (or other) provenance.
 */

import { normalizeTagSlug } from './tagHelpers.js';

export const ENTITY_KIND = Object.freeze({
  THREAT_ACTOR: 'threat_actor',
  MALWARE_FAMILY: 'malware_family'
});

export const ASSOCIATION_KIND = Object.freeze({
  ASSOCIATED_VIA_SOURCE_PULSE: 'associated_via_source_pulse',
  DIRECTLY_ATTRIBUTED_TO: 'directly_attributed_to',
  MALWARE_SAMPLE_OF: 'malware_sample_of'
});

export const ASSERTION_STATUS = Object.freeze({
  CURRENT: 'current',
  WITHDRAWN: 'withdrawn',
  STALE: 'stale'
});

export const RESOLUTION_STATUS = Object.freeze({
  RESOLVED: 'resolved',
  UNRESOLVED: 'unresolved',
  AMBIGUOUS: 'ambiguous'
});

export const ATTRIBUTION_PROVENANCE = Object.freeze({
  ANALYST: 'analyst',
  SOURCE_REPORTED: 'source_reported',
  MIXED: 'mixed'
});

export const MAX_SOURCE_LABEL_LENGTH = 128;
export const MAX_ATTRIBUTION_LABELS_PER_KIND = 32;

export function normalizeAttributionLabel(raw) {
  const trimmed = String(raw ?? '').trim().replace(/\s+/g, ' ');
  if (!trimmed) return null;
  if (trimmed.length > MAX_SOURCE_LABEL_LENGTH) return trimmed.slice(0, MAX_SOURCE_LABEL_LENGTH);
  return trimmed;
}

export function normalizeAttributionLabelKey(raw) {
  const label = normalizeAttributionLabel(raw);
  if (!label) return null;
  return label.toLowerCase();
}

/** Normalize adversary field: string, array of strings, or empty. */
export function normalizeAdversaryLabels(raw) {
  if (raw == null) return [];
  const items = Array.isArray(raw) ? raw : [raw];
  const out = [];
  const seen = new Set();
  for (const item of items) {
    if (typeof item === 'object' && item != null) {
      const candidate = item.name ?? item.value ?? item.adversary ?? null;
      const label = normalizeAttributionLabel(candidate);
      const key = normalizeAttributionLabelKey(candidate);
      if (!label || !key || seen.has(key)) continue;
      seen.add(key);
      out.push(label);
      if (out.length >= MAX_ATTRIBUTION_LABELS_PER_KIND) break;
      continue;
    }
    const label = normalizeAttributionLabel(item);
    const key = normalizeAttributionLabelKey(item);
    if (!label || !key || seen.has(key)) continue;
    seen.add(key);
    out.push(label);
    if (out.length >= MAX_ATTRIBUTION_LABELS_PER_KIND) break;
  }
  return out;
}

/** Normalize malware_families: array of strings/objects, or single string. */
export function normalizeMalwareFamilyLabels(raw) {
  return normalizeAdversaryLabels(raw);
}

function iocPairKey(iocId, observableType) {
  return `${Number(iocId)}|${String(observableType || '')}`;
}

function entityGroupKey(entityKind, entityId, labelKey) {
  if (entityId) return `${entityKind}|id:${String(entityId).toLowerCase()}`;
  return `${entityKind}|label:${labelKey}`;
}

/**
 * Exact catalog resolution: case-insensitive name or alias match.
 * Multiple matches → ambiguous (no arbitrary merge).
 */
export async function resolveCatalogEntity(client, entityKind, label) {
  const key = normalizeAttributionLabelKey(label);
  if (!key) {
    return { status: RESOLUTION_STATUS.UNRESOLVED, entityId: null, matches: [] };
  }

  if (entityKind === ENTITY_KIND.THREAT_ACTOR) {
    const { rows } = await client.query(
      `SELECT id, name, slug, aliases, active
       FROM threat_actors
       WHERE active IS DISTINCT FROM false
         AND (
           lower(name) = $1
           OR EXISTS (
             SELECT 1 FROM unnest(COALESCE(aliases, '{}'::text[])) a
             WHERE lower(a) = $1
           )
         )
       ORDER BY name ASC
       LIMIT 5`,
      [key]
    );
    if (rows.length === 1) {
      return { status: RESOLUTION_STATUS.RESOLVED, entityId: rows[0].id, matches: rows };
    }
    if (rows.length > 1) {
      return { status: RESOLUTION_STATUS.AMBIGUOUS, entityId: null, matches: rows };
    }
    return { status: RESOLUTION_STATUS.UNRESOLVED, entityId: null, matches: [] };
  }

  if (entityKind === ENTITY_KIND.MALWARE_FAMILY) {
    const { rows } = await client.query(
      `SELECT id, name, slug, aliases, active
       FROM malware_families
       WHERE active IS DISTINCT FROM false
         AND (
           lower(name) = $1
           OR EXISTS (
             SELECT 1 FROM unnest(COALESCE(aliases, '{}'::text[])) a
             WHERE lower(a) = $1
           )
         )
       ORDER BY name ASC
       LIMIT 5`,
      [key]
    );
    if (rows.length === 1) {
      return { status: RESOLUTION_STATUS.RESOLVED, entityId: rows[0].id, matches: rows };
    }
    if (rows.length > 1) {
      return { status: RESOLUTION_STATUS.AMBIGUOUS, entityId: null, matches: rows };
    }
    return { status: RESOLUTION_STATUS.UNRESOLVED, entityId: null, matches: [] };
  }

  return { status: RESOLUTION_STATUS.UNRESOLVED, entityId: null, matches: [] };
}

/**
 * Upsert one source assertion. Idempotent for identical content.
 * @returns {'inserted'|'updated'|'unchanged'}
 */
export async function upsertSourceAttribution(client, {
  iocId,
  observableType,
  entityKind,
  sourceLabel,
  feedKey,
  sourceName,
  evidenceRefType,
  evidenceRefId,
  evidenceUrl = null,
  evidenceTitle = null,
  associationKind = ASSOCIATION_KIND.ASSOCIATED_VIA_SOURCE_PULSE,
  observedAt = null,
  isBackfill = false,
  providerMetadata = null,
  entityId = null,
  resolutionStatus = null
}) {
  const label = normalizeAttributionLabel(sourceLabel);
  const labelKey = normalizeAttributionLabelKey(sourceLabel);
  if (!iocId || !observableType || !entityKind || !label || !labelKey) return 'unchanged';
  if (!feedKey || !sourceName || !evidenceRefType || !evidenceRefId) return 'unchanged';

  let resolvedEntityId = entityId;
  let resolvedStatus = resolutionStatus;
  if (resolvedStatus == null || (resolvedEntityId == null && resolvedStatus === RESOLUTION_STATUS.RESOLVED)) {
    const resolution = await resolveCatalogEntity(client, entityKind, label);
    resolvedEntityId = resolution.entityId;
    resolvedStatus = resolution.status;
  }

  const metaJson = providerMetadata == null ? '{}' : JSON.stringify(providerMetadata);
  const { rows } = await client.query(
    `INSERT INTO ioc_source_attributions (
       ioc_id, ioc_observable_type, entity_kind,
       source_label, source_label_normalized, entity_id, resolution_status,
       feed_key, source_name, evidence_ref_type, evidence_ref_id,
       evidence_url, evidence_title, association_kind, assertion_status,
       observed_at, first_ingested_at, last_ingested_at, is_backfill, provider_metadata
     ) VALUES (
       $1, $2, $3,
       $4, $5, $6::uuid, $7,
       $8, $9, $10, $11,
       $12, $13, $14, 'current',
       $15, NOW(), NOW(), $16, $17::jsonb
     )
     ON CONFLICT (ioc_id, ioc_observable_type, entity_kind, feed_key,
                  evidence_ref_type, evidence_ref_id, source_label_normalized)
     DO UPDATE SET
       source_label = EXCLUDED.source_label,
       entity_id = EXCLUDED.entity_id,
       resolution_status = EXCLUDED.resolution_status,
       source_name = EXCLUDED.source_name,
       evidence_url = EXCLUDED.evidence_url,
       evidence_title = EXCLUDED.evidence_title,
       association_kind = EXCLUDED.association_kind,
       assertion_status = 'current',
       observed_at = COALESCE(EXCLUDED.observed_at, ioc_source_attributions.observed_at),
       last_ingested_at = CASE
         WHEN ioc_source_attributions.assertion_status IS DISTINCT FROM 'current'
           OR ioc_source_attributions.source_label IS DISTINCT FROM EXCLUDED.source_label
           OR ioc_source_attributions.entity_id IS DISTINCT FROM EXCLUDED.entity_id
           OR ioc_source_attributions.resolution_status IS DISTINCT FROM EXCLUDED.resolution_status
           OR ioc_source_attributions.evidence_url IS DISTINCT FROM EXCLUDED.evidence_url
           OR ioc_source_attributions.evidence_title IS DISTINCT FROM EXCLUDED.evidence_title
           OR ioc_source_attributions.association_kind IS DISTINCT FROM EXCLUDED.association_kind
           OR ioc_source_attributions.provider_metadata IS DISTINCT FROM EXCLUDED.provider_metadata
         THEN NOW()
         ELSE ioc_source_attributions.last_ingested_at
       END,
       withdrawn_at = NULL,
       is_backfill = ioc_source_attributions.is_backfill OR EXCLUDED.is_backfill,
       provider_metadata = EXCLUDED.provider_metadata,
       updated_at = CASE
         WHEN ioc_source_attributions.assertion_status IS DISTINCT FROM 'current'
           OR ioc_source_attributions.source_label IS DISTINCT FROM EXCLUDED.source_label
           OR ioc_source_attributions.entity_id IS DISTINCT FROM EXCLUDED.entity_id
           OR ioc_source_attributions.resolution_status IS DISTINCT FROM EXCLUDED.resolution_status
           OR ioc_source_attributions.evidence_url IS DISTINCT FROM EXCLUDED.evidence_url
           OR ioc_source_attributions.evidence_title IS DISTINCT FROM EXCLUDED.evidence_title
           OR ioc_source_attributions.association_kind IS DISTINCT FROM EXCLUDED.association_kind
           OR ioc_source_attributions.provider_metadata IS DISTINCT FROM EXCLUDED.provider_metadata
         THEN NOW()
         ELSE ioc_source_attributions.updated_at
       END
     RETURNING
       (xmax = 0) AS inserted,
       (assertion_status = 'current'
        AND updated_at = first_ingested_at) AS trivial`,
    [
      iocId,
      observableType,
      entityKind,
      label,
      labelKey,
      resolvedEntityId,
      resolvedStatus,
      feedKey,
      sourceName,
      evidenceRefType,
      String(evidenceRefId),
      evidenceUrl,
      evidenceTitle,
      associationKind,
      observedAt,
      Boolean(isBackfill),
      metaJson
    ]
  );

  const row = rows[0];
  if (!row) return 'unchanged';
  if (row.inserted) return 'inserted';
  // Detect true no-op via xmax + whether updated_at moved is hard in RETURNING;
  // treat conflict path as updated when we got a row (idempotent re-confirm is ok).
  return 'updated';
}

/**
 * Authoritative complete observation for one (IOC, evidence ref): withdraw
 * current assertions of the given kinds that are absent from `keepLabelKeys`.
 * Incomplete syncs must NOT call this.
 */
export async function reconcileSourceAttributionsForEvidence(client, {
  iocId,
  observableType,
  feedKey,
  evidenceRefType,
  evidenceRefId,
  entityKinds = [ENTITY_KIND.THREAT_ACTOR, ENTITY_KIND.MALWARE_FAMILY],
  keepLabelKeysByKind = {}
}) {
  if (!iocId || !observableType || !feedKey || !evidenceRefType || !evidenceRefId) {
    return { withdrawn: 0 };
  }

  let withdrawn = 0;
  for (const kind of entityKinds) {
    const keep = new Set(
      (keepLabelKeysByKind[kind] || [])
        .map((k) => normalizeAttributionLabelKey(k))
        .filter(Boolean)
    );
    const { rowCount } = await client.query(
      `UPDATE ioc_source_attributions
       SET assertion_status = 'withdrawn',
           withdrawn_at = COALESCE(withdrawn_at, NOW()),
           updated_at = NOW()
       WHERE ioc_id = $1
         AND ioc_observable_type = $2
         AND feed_key = $3
         AND evidence_ref_type = $4
         AND evidence_ref_id = $5
         AND entity_kind = $6
         AND assertion_status = 'current'
         AND NOT (source_label_normalized = ANY($7::text[]))`,
      [
        iocId,
        observableType,
        feedKey,
        evidenceRefType,
        String(evidenceRefId),
        kind,
        [...keep]
      ]
    );
    withdrawn += rowCount || 0;
  }
  return { withdrawn };
}

export async function upsertOtxPulseSnapshot(client, {
  pulseId,
  pulseName = null,
  adversary = null,
  malwareFamilies = [],
  tags = [],
  tlp = null,
  authorName = null,
  pulseCreated = null,
  pulseModified = null,
  pulseUrl = null,
  isBackfill = false
}) {
  const id = String(pulseId || '').trim();
  if (!id) return null;
  const families = normalizeMalwareFamilyLabels(malwareFamilies);
  const tagList = Array.isArray(tags)
    ? tags.map((t) => String(t || '').trim()).filter(Boolean).slice(0, 64)
    : [];
  const adversaryLabel = normalizeAdversaryLabels(adversary)[0] || null;

  await client.query(
    `INSERT INTO otx_pulse_snapshots (
       pulse_id, pulse_name, adversary, malware_families, tags, tlp, author_name,
       pulse_created, pulse_modified, pulse_url, first_fetched_at, last_fetched_at, is_backfill
     ) VALUES (
       $1, $2, $3, $4::text[], $5::text[], $6, $7,
       $8, $9, $10, NOW(), NOW(), $11
     )
     ON CONFLICT (pulse_id) DO UPDATE SET
       pulse_name = COALESCE(EXCLUDED.pulse_name, otx_pulse_snapshots.pulse_name),
       adversary = EXCLUDED.adversary,
       malware_families = EXCLUDED.malware_families,
       tags = EXCLUDED.tags,
       tlp = COALESCE(EXCLUDED.tlp, otx_pulse_snapshots.tlp),
       author_name = COALESCE(EXCLUDED.author_name, otx_pulse_snapshots.author_name),
       pulse_created = COALESCE(EXCLUDED.pulse_created, otx_pulse_snapshots.pulse_created),
       pulse_modified = COALESCE(EXCLUDED.pulse_modified, otx_pulse_snapshots.pulse_modified),
       pulse_url = COALESCE(EXCLUDED.pulse_url, otx_pulse_snapshots.pulse_url),
       last_fetched_at = NOW(),
       is_backfill = otx_pulse_snapshots.is_backfill OR EXCLUDED.is_backfill`,
    [
      id,
      pulseName,
      adversaryLabel,
      families,
      tagList,
      tlp,
      authorName,
      pulseCreated,
      pulseModified,
      pulseUrl,
      Boolean(isBackfill)
    ]
  );
  return id;
}

/**
 * Apply complete OTX pulse attribution for one IOC.
 * Upserts actor + family assertions and reconciles withdrawn labels for this pulse.
 */
export async function applyOtxPulseAttributions(client, {
  iocId,
  observableType,
  pulseId,
  pulseName = null,
  pulseUrl = null,
  adversary = null,
  malwareFamilies = [],
  observedAt = null,
  isBackfill = false,
  feedKey = 'alienvault-otx',
  sourceName = 'AlienVault OTX',
  completeObservation = true
}) {
  const actors = normalizeAdversaryLabels(adversary);
  const families = normalizeMalwareFamilyLabels(malwareFamilies);
  const evidenceRefType = 'otx_pulse';
  const evidenceRefId = String(pulseId || '').trim();
  if (!iocId || !observableType || !evidenceRefId) {
    return { actors: 0, families: 0, withdrawn: 0 };
  }

  let actorCount = 0;
  let familyCount = 0;

  for (const label of actors) {
    const result = await upsertSourceAttribution(client, {
      iocId,
      observableType,
      entityKind: ENTITY_KIND.THREAT_ACTOR,
      sourceLabel: label,
      feedKey,
      sourceName,
      evidenceRefType,
      evidenceRefId,
      evidenceUrl: pulseUrl,
      evidenceTitle: pulseName,
      associationKind: ASSOCIATION_KIND.ASSOCIATED_VIA_SOURCE_PULSE,
      observedAt,
      isBackfill,
      providerMetadata: {
        provider: 'alienvault_otx',
        pulse_id: evidenceRefId,
        field: 'adversary'
      }
    });
    if (result === 'inserted' || result === 'updated') actorCount += 1;
  }

  for (const label of families) {
    const result = await upsertSourceAttribution(client, {
      iocId,
      observableType,
      entityKind: ENTITY_KIND.MALWARE_FAMILY,
      sourceLabel: label,
      feedKey,
      sourceName,
      evidenceRefType,
      evidenceRefId,
      evidenceUrl: pulseUrl,
      evidenceTitle: pulseName,
      associationKind: ASSOCIATION_KIND.ASSOCIATED_VIA_SOURCE_PULSE,
      observedAt,
      isBackfill,
      providerMetadata: {
        provider: 'alienvault_otx',
        pulse_id: evidenceRefId,
        field: 'malware_families'
      }
    });
    if (result === 'inserted' || result === 'updated') familyCount += 1;
  }

  let withdrawn = 0;
  if (completeObservation) {
    const recon = await reconcileSourceAttributionsForEvidence(client, {
      iocId,
      observableType,
      feedKey,
      evidenceRefType,
      evidenceRefId,
      keepLabelKeysByKind: {
        [ENTITY_KIND.THREAT_ACTOR]: actors.map(normalizeAttributionLabelKey).filter(Boolean),
        [ENTITY_KIND.MALWARE_FAMILY]: families.map(normalizeAttributionLabelKey).filter(Boolean)
      }
    });
    withdrawn = recon.withdrawn;
  }

  return { actors: actorCount, families: familyCount, withdrawn };
}

async function loadAnalystThreatActors(client, pairs) {
  if (!pairs.length) return new Map();
  const values = pairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
  const params = pairs.flatMap((p) => [p.id, p.observable_type]);
  const { rows } = await client.query(
    `SELECT ita.ioc_id, ita.ioc_observable_type, ita.threat_actor_id AS entity_id,
            ita.source_type, ita.source_name,
            ta.name, ta.slug, ta.aliases, ta.active
     FROM ioc_threat_actors ita
     JOIN threat_actors ta ON ta.id = ita.threat_actor_id
     WHERE (ita.ioc_id, ita.ioc_observable_type) IN (VALUES ${values})
     ORDER BY ta.name ASC`,
    params
  );
  const map = new Map();
  for (const row of rows) {
    const key = iocPairKey(row.ioc_id, row.ioc_observable_type);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(row);
  }
  return map;
}

async function loadAnalystMalwareFamilies(client, pairs) {
  if (!pairs.length) return new Map();
  const values = pairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
  const params = pairs.flatMap((p) => [p.id, p.observable_type]);
  let rows;
  try {
    ({ rows } = await client.query(
      `SELECT imf.ioc_id, imf.ioc_observable_type, imf.malware_family_id AS entity_id,
              imf.source_type, imf.source_name,
              mf.name, mf.slug, mf.aliases, mf.active
       FROM ioc_malware_families imf
       JOIN malware_families mf ON mf.id = imf.malware_family_id
       WHERE (imf.ioc_id, imf.ioc_observable_type) IN (VALUES ${values})
       ORDER BY mf.name ASC`,
      params
    ));
  } catch (err) {
    if (String(err?.message || '').includes('ioc_malware_families')
      || String(err?.message || '').includes('malware_families')) {
      return new Map();
    }
    throw err;
  }
  const map = new Map();
  for (const row of rows) {
    const key = iocPairKey(row.ioc_id, row.ioc_observable_type);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(row);
  }
  return map;
}

async function loadSourceAttributions(client, pairs, { includeWithdrawn = false } = {}) {
  if (!pairs.length) return new Map();
  const values = pairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
  const params = pairs.flatMap((p) => [p.id, p.observable_type]);
  let rows;
  try {
    ({ rows } = await client.query(
      `SELECT a.ioc_id, a.ioc_observable_type, a.entity_kind, a.source_label,
              a.source_label_normalized, a.entity_id, a.resolution_status,
              a.feed_key, a.source_name, a.evidence_ref_type, a.evidence_ref_id,
              a.evidence_url, a.evidence_title, a.association_kind, a.assertion_status,
              a.observed_at, a.first_ingested_at, a.last_ingested_at, a.withdrawn_at,
              a.is_backfill,
              CASE
                WHEN a.entity_kind = 'threat_actor' THEN ta.name
                WHEN a.entity_kind = 'malware_family' THEN mf.name
                ELSE NULL
              END AS resolved_name,
              CASE
                WHEN a.entity_kind = 'threat_actor' THEN ta.slug
                WHEN a.entity_kind = 'malware_family' THEN mf.slug
                ELSE NULL
              END AS resolved_slug,
              CASE
                WHEN a.entity_kind = 'threat_actor' THEN ta.aliases
                WHEN a.entity_kind = 'malware_family' THEN mf.aliases
                ELSE NULL
              END AS resolved_aliases,
              CASE
                WHEN a.entity_kind = 'threat_actor' THEN ta.active
                WHEN a.entity_kind = 'malware_family' THEN mf.active
                ELSE NULL
              END AS resolved_active
       FROM ioc_source_attributions a
       LEFT JOIN threat_actors ta
         ON a.entity_kind = 'threat_actor' AND ta.id = a.entity_id
       LEFT JOIN malware_families mf
         ON a.entity_kind = 'malware_family' AND mf.id = a.entity_id
       WHERE (a.ioc_id, a.ioc_observable_type) IN (VALUES ${values})
         AND ($3::boolean OR a.assertion_status = 'current')
       ORDER BY a.source_label ASC, a.evidence_ref_id ASC`,
      [...params, includeWithdrawn]
    ));
  } catch (err) {
    if (String(err?.message || '').includes('ioc_source_attributions')) return new Map();
    throw err;
  }
  const map = new Map();
  for (const row of rows) {
    const key = iocPairKey(row.ioc_id, row.ioc_observable_type);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(row);
  }
  return map;
}

async function loadActiveSuppressions(client, pairs) {
  if (!pairs.length) return new Map();
  const values = pairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
  const params = pairs.flatMap((p) => [p.id, p.observable_type]);
  let rows;
  try {
    ({ rows } = await client.query(
      `SELECT ioc_id, ioc_observable_type, entity_kind, entity_id,
              source_label_normalized, feed_key, evidence_ref_type, evidence_ref_id
       FROM ioc_attribution_overrides
       WHERE cleared_at IS NULL
         AND action = 'suppress'
         AND (ioc_id, ioc_observable_type) IN (VALUES ${values})`,
      params
    ));
  } catch (err) {
    if (String(err?.message || '').includes('ioc_attribution_overrides')) return new Map();
    throw err;
  }
  const map = new Map();
  for (const row of rows) {
    const key = iocPairKey(row.ioc_id, row.ioc_observable_type);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(row);
  }
  return map;
}

function isSuppressed(suppressions, assertion) {
  for (const s of suppressions || []) {
    if (s.entity_kind !== assertion.entity_kind) continue;
    if (s.feed_key && s.feed_key !== assertion.feed_key) continue;
    if (s.evidence_ref_type && s.evidence_ref_type !== assertion.evidence_ref_type) continue;
    if (s.evidence_ref_id && s.evidence_ref_id !== assertion.evidence_ref_id) continue;
    if (s.entity_id && assertion.entity_id
      && String(s.entity_id).toLowerCase() === String(assertion.entity_id).toLowerCase()) {
      return true;
    }
    if (s.source_label_normalized
      && s.source_label_normalized === assertion.source_label_normalized) {
      return true;
    }
  }
  return false;
}

function buildSourceProvenance(row) {
  return {
    source_name: row.source_name,
    feed_key: row.feed_key,
    association_kind: row.association_kind,
    assertion_status: row.assertion_status,
    evidence_ref_type: row.evidence_ref_type,
    evidence_ref_id: row.evidence_ref_id,
    evidence_url: row.evidence_url || null,
    evidence_title: row.evidence_title || null,
    source_label: row.source_label,
    resolution_status: row.resolution_status,
    observed_at: row.observed_at || null,
    first_ingested_at: row.first_ingested_at || null,
    last_ingested_at: row.last_ingested_at || null,
    withdrawn_at: row.withdrawn_at || null,
    is_backfill: Boolean(row.is_backfill),
    attribution: ATTRIBUTION_PROVENANCE.SOURCE_REPORTED
  };
}

function mergeEntityGroup({ entityKind, analystRows = [], sourceRows = [] }) {
  const groups = new Map();

  for (const row of analystRows) {
    const key = entityGroupKey(entityKind, row.entity_id, normalizeAttributionLabelKey(row.name));
    if (!groups.has(key)) {
      groups.set(key, {
        id: row.entity_id,
        name: row.name,
        slug: row.slug || null,
        aliases: row.aliases || [],
        active: row.active != null ? Boolean(row.active) : true,
        analyst: true,
        sources: []
      });
    } else {
      groups.get(key).analyst = true;
    }
  }

  for (const row of sourceRows) {
    const displayName = row.resolved_name || row.source_label;
    const key = entityGroupKey(
      entityKind,
      row.entity_id,
      row.source_label_normalized || normalizeAttributionLabelKey(displayName)
    );
    if (!groups.has(key)) {
      groups.set(key, {
        id: row.entity_id || null,
        name: displayName,
        slug: row.resolved_slug || (row.entity_id ? null : normalizeTagSlug(row.source_label)),
        aliases: row.resolved_aliases || [],
        active: row.resolved_active != null ? Boolean(row.resolved_active) : true,
        analyst: false,
        sources: []
      });
    }
    const g = groups.get(key);
    if (!g.id && row.entity_id) g.id = row.entity_id;
    if (row.resolved_name) g.name = row.resolved_name;
    g.sources.push(buildSourceProvenance(row));
  }

  const list = [...groups.values()].map((g) => {
    const currentSources = g.sources.filter((s) => s.assertion_status === 'current');
    const attribution = g.analyst && currentSources.length
      ? ATTRIBUTION_PROVENANCE.MIXED
      : g.analyst
        ? ATTRIBUTION_PROVENANCE.ANALYST
        : ATTRIBUTION_PROVENANCE.SOURCE_REPORTED;
    return {
      id: g.id,
      name: g.name,
      slug: g.slug,
      aliases: g.aliases,
      active: g.active,
      attribution,
      association_kind: currentSources[0]?.association_kind
        || (g.analyst ? null : ASSOCIATION_KIND.ASSOCIATED_VIA_SOURCE_PULSE),
      sources: g.sources
    };
  });

  list.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
  return list;
}

/**
 * Effective Threat Actors + Malware Families for IOC Overview / details API.
 * Deduplicates logical entities while preserving independent Pulse provenance.
 * @param {{ includeWithdrawn?: boolean, compact?: boolean }} [opts]
 *   compact=true omits per-source provenance arrays (list views).
 */
export async function loadEffectiveIocAttributions(pool, pairs, { includeWithdrawn = false, compact = false } = {}) {
  const validPairs = (pairs || [])
    .map((p) => ({
      id: Number(p?.id ?? p?.ioc_id),
      observable_type: String(p?.observable_type ?? p?.ioc_observable_type ?? '').trim()
    }))
    .filter((p) => Number.isFinite(p.id) && p.id > 0 && p.observable_type);

  const empty = new Map();
  if (!validPairs.length) return empty;

  const [analystActors, analystFamilies, sourceMap, suppressMap] = await Promise.all([
    loadAnalystThreatActors(pool, validPairs),
    loadAnalystMalwareFamilies(pool, validPairs),
    loadSourceAttributions(pool, validPairs, { includeWithdrawn }),
    loadActiveSuppressions(pool, validPairs)
  ]);

  const out = new Map();
  for (const p of validPairs) {
    const key = iocPairKey(p.id, p.observable_type);
    const suppressions = suppressMap.get(key) || [];
    const sourceRows = (sourceMap.get(key) || []).filter((row) => {
      if (row.assertion_status !== 'current' && !includeWithdrawn) return false;
      if (row.assertion_status === 'current' && isSuppressed(suppressions, row)) return false;
      return true;
    });

    const threatActors = mergeEntityGroup({
      entityKind: ENTITY_KIND.THREAT_ACTOR,
      analystRows: analystActors.get(key) || [],
      sourceRows: sourceRows.filter((r) => r.entity_kind === ENTITY_KIND.THREAT_ACTOR)
    });

    const malwareFamilies = mergeEntityGroup({
      entityKind: ENTITY_KIND.MALWARE_FAMILY,
      analystRows: analystFamilies.get(key) || [],
      sourceRows: sourceRows.filter((r) => r.entity_kind === ENTITY_KIND.MALWARE_FAMILY)
    });

    const analystActorIds = (analystActors.get(key) || [])
      .map((r) => r.entity_id)
      .filter(Boolean);
    const analystFamilyIds = (analystFamilies.get(key) || [])
      .map((r) => r.entity_id)
      .filter(Boolean);

    const shapeList = (list) => (compact
      ? list.map(({ sources, ...rest }) => rest)
      : list);

    const primaryActor = threatActors.find((a) => a.id) || threatActors[0] || null;
    out.set(key, {
      threat_actors: shapeList(threatActors),
      threat_actor_ids: threatActors.filter((a) => a.id).map((a) => a.id),
      threat_actor_id: primaryActor?.id || null,
      threat_actor_name: primaryActor?.name || null,
      analyst_threat_actor_ids: analystActorIds,
      malware_families: shapeList(malwareFamilies),
      malware_family_ids: malwareFamilies.filter((a) => a.id).map((a) => a.id),
      analyst_malware_family_ids: analystFamilyIds
    });
  }
  return out;
}

export function emptyAttributionResponseFields() {
  return {
    threat_actors: [],
    threat_actor_ids: [],
    threat_actor_id: null,
    threat_actor_name: null,
    analyst_threat_actor_ids: [],
    malware_families: [],
    malware_family_ids: [],
    analyst_malware_family_ids: []
  };
}

export async function fetchEffectiveIocAttributions(pool, iocId, observableType) {
  const map = await loadEffectiveIocAttributions(pool, [{ id: iocId, observable_type: observableType }]);
  return map.get(iocPairKey(iocId, observableType)) || emptyAttributionResponseFields();
}

/** Resolve IOC id for an observable (oldest row), used by feed import. */
export async function resolveIocIdForObservable(client, observable, observableType) {
  const { rows } = await client.query(
    `SELECT id, observable_type
     FROM ioc_items
     WHERE observable = $1 AND observable_type = $2
     ORDER BY created_at ASC
     LIMIT 1`,
    [observable, observableType]
  );
  return rows[0] || null;
}
