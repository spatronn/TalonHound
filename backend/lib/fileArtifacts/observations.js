/**
 * Source observation helpers — preserve observed-as attribution.
 */

import { normalizeExactHash } from './hashNormalize.js';

export const OBSERVATION_TYPE = Object.freeze({
  DIRECT: 'direct_source_observation',
  PROVIDER_MAPPING: 'provider_hash_mapping',
  ENRICHMENT: 'enrichment_derived',
  MANUAL: 'manual_verified',
  BACKFILL: 'migration_backfill'
});

export const RELATION_METHOD = Object.freeze({
  SAME_SOURCE_RECORD: 'same_source_record',
  PROVIDER_EXACT_HASH_SET: 'provider_exact_hash_set',
  ENRICHMENT_RESULT: 'enrichment_result',
  MANUAL_MERGE: 'manual_merge',
  MIGRATION_SEED: 'migration_seed'
});

/**
 * Upsert a source observation without advancing last_changed when content unchanged.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {object} input
 */
export async function upsertSourceObservation(db, input) {
  const hash = normalizeExactHash(input.observed_hash_type, input.observed_hash_value);
  if (!hash) {
    return { skipped: true, reason: 'invalid_hash' };
  }
  const artifactId = input.artifact_id;
  const sourceName = String(input.source_name || '').trim();
  if (!artifactId || !sourceName) {
    return { skipped: true, reason: 'missing_identity' };
  }

  const observationType = input.observation_type || OBSERVATION_TYPE.DIRECT;
  const relationMethod = input.relation_method || RELATION_METHOD.SAME_SOURCE_RECORD;
  const now = input.last_seen_in_source || new Date().toISOString();
  const firstSeen = input.first_seen_in_source || now;
  const rawRef = input.raw_ref && typeof input.raw_ref === 'object' ? input.raw_ref : {};

  const existing = await db.query(
    `SELECT id, last_seen_in_source, last_changed_in_source, raw_ref
     FROM file_artifact_source_observations
     WHERE artifact_id = $1
       AND source_name = $2
       AND observed_hash_type = $3
       AND observed_hash_value = $4
       AND observation_type = $5
       AND COALESCE(feed_id::text, '') = COALESCE($6::text, '')
     ORDER BY id ASC
     LIMIT 1`,
    [
      artifactId,
      sourceName,
      hash.hash_type,
      hash.normalized_hash_value,
      observationType,
      input.feed_id || null
    ]
  );

  if (existing.rowCount) {
    const row = existing.rows[0];
    const prevRaw = JSON.stringify(row.raw_ref || {});
    const nextRaw = JSON.stringify(rawRef);
    const contentChanged = prevRaw !== nextRaw;
    await db.query(
      `UPDATE file_artifact_source_observations
       SET last_seen_in_source = GREATEST(COALESCE(last_seen_in_source, $2::timestamptz), $2::timestamptz),
           last_changed_in_source = CASE
             WHEN $3::boolean THEN $2::timestamptz
             ELSE last_changed_in_source
           END,
           observed_hash_id = COALESCE($4::uuid, observed_hash_id),
           confidence = COALESCE($5, confidence),
           raw_ref = CASE WHEN $3::boolean THEN $6::jsonb ELSE raw_ref END,
           updated_at = NOW()
       WHERE id = $1`,
      [
        row.id,
        now,
        contentChanged,
        input.observed_hash_id || null,
        input.confidence || null,
        nextRaw
      ]
    );
    return { id: row.id, created: false, content_changed: contentChanged };
  }

  const ins = await db.query(
    `INSERT INTO file_artifact_source_observations (
       artifact_id, source_name, feed_id, source_membership_id, source_record_id,
       observed_hash_id, observed_hash_type, observed_hash_value,
       observation_type, relation_method, confidence,
       first_seen_in_source, last_seen_in_source, last_changed_in_source, raw_ref
     ) VALUES (
       $1, $2, $3, $4, $5,
       $6, $7, $8,
       $9, $10, $11,
       $12::timestamptz, $13::timestamptz, $13::timestamptz, $14::jsonb
     )
     RETURNING id`,
    [
      artifactId,
      sourceName,
      input.feed_id || null,
      input.source_membership_id || null,
      input.source_record_id || null,
      input.observed_hash_id || null,
      hash.hash_type,
      hash.normalized_hash_value,
      observationType,
      relationMethod,
      input.confidence || null,
      firstSeen,
      now,
      JSON.stringify(rawRef)
    ]
  );
  return { id: ins.rows[0].id, created: true, content_changed: true };
}

/**
 * Format observation for API/UI (Observed As semantics).
 * @param {object} row
 */
export function formatObservationForApi(row) {
  if (!row) return null;
  return {
    id: row.id,
    artifact_id: row.artifact_id,
    source_name: row.source_name,
    feed_id: row.feed_id || null,
    observed_as: row.observed_hash_type,
    observed_hash_type: row.observed_hash_type,
    observed_hash_value: row.observed_hash_value,
    observation_type: row.observation_type,
    relation_method: row.relation_method,
    evidence_label: evidenceLabel(row.observation_type, row.relation_method),
    confidence: row.confidence || null,
    first_seen_in_source: row.first_seen_in_source || null,
    last_seen_in_source: row.last_seen_in_source || null,
    last_changed_in_source: row.last_changed_in_source || null
  };
}

function evidenceLabel(observationType, relationMethod) {
  if (observationType === OBSERVATION_TYPE.DIRECT) return 'Direct source observation';
  if (observationType === OBSERVATION_TYPE.PROVIDER_MAPPING) return 'Provider exact hash mapping';
  if (observationType === OBSERVATION_TYPE.ENRICHMENT) return 'Enrichment-derived mapping';
  if (observationType === OBSERVATION_TYPE.MANUAL) return 'Manual verification';
  if (observationType === OBSERVATION_TYPE.BACKFILL) return 'Migration backfill';
  return relationMethod || observationType || 'Observation';
}
