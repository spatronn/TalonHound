/**
 * Merge two file artifacts into a canonical one. Idempotent and lock-ordered.
 */

import { mergeArtifactMetadata } from './metadataPolicy.js';
import { recomputePrimaryHash, syncCanonicalIocFlag } from './attach.js';

/**
 * @param {import('pg').PoolClient} client
 * @param {{
 *   canonicalArtifactId: string,
 *   duplicateArtifactId: string,
 *   evidence?: object,
 *   method?: string
 * }} input
 */
export async function mergeFileArtifacts(client, input) {
  const canonicalId = String(input.canonicalArtifactId || '');
  const duplicateId = String(input.duplicateArtifactId || '');
  if (!canonicalId || !duplicateId) {
    return { ok: false, reason: 'missing_ids' };
  }
  if (canonicalId === duplicateId) {
    return { ok: true, noop: true, reason: 'same_artifact' };
  }

  // Deterministic lock order to reduce deadlock risk
  const [firstId, secondId] = [canonicalId, duplicateId].sort();
  await client.query(
    `SELECT id FROM file_artifacts WHERE id = ANY($1::uuid[]) FOR UPDATE`,
    [[firstId, secondId]]
  );

  const { rows: arts } = await client.query(
    `SELECT id, status, merged_into_artifact_id, file_name, file_type, mime_type, size_bytes,
            first_seen_at, last_seen_at, metadata, created_at
     FROM file_artifacts
     WHERE id = ANY($1::uuid[])`,
    [[canonicalId, duplicateId]]
  );
  const byId = new Map(arts.map((r) => [r.id, r]));
  let canonical = byId.get(canonicalId);
  let duplicate = byId.get(duplicateId);
  if (!canonical || !duplicate) {
    return { ok: false, reason: 'artifact_not_found' };
  }

  // Follow tombstones
  if (canonical.status === 'merged' && canonical.merged_into_artifact_id) {
    return mergeFileArtifacts(client, {
      ...input,
      canonicalArtifactId: canonical.merged_into_artifact_id
    });
  }
  if (duplicate.status === 'merged') {
    if (duplicate.merged_into_artifact_id === canonicalId) {
      return { ok: true, noop: true, reason: 'already_merged' };
    }
    if (duplicate.merged_into_artifact_id) {
      return mergeFileArtifacts(client, {
        ...input,
        duplicateArtifactId: duplicate.merged_into_artifact_id
      });
    }
  }

  // Move hashes (handle unique conflicts by keeping canonical)
  const { rows: dupHashes } = await client.query(
    `SELECT id, hash_type, normalized_hash_value FROM file_artifact_hashes WHERE artifact_id = $1`,
    [duplicateId]
  );
  for (const h of dupHashes) {
    const existing = await client.query(
      `SELECT id, artifact_id FROM file_artifact_hashes
       WHERE hash_type = $1 AND normalized_hash_value = $2`,
      [h.hash_type, h.normalized_hash_value]
    );
    if (existing.rowCount && existing.rows[0].artifact_id === canonicalId) {
      // Drop duplicate hash row after remapping FKs that point at it
      await client.query(
        `UPDATE file_artifact_ioc_links SET linked_hash_id = $2 WHERE linked_hash_id = $1`,
        [h.id, existing.rows[0].id]
      );
      await client.query(
        `UPDATE file_artifact_source_observations SET observed_hash_id = $2 WHERE observed_hash_id = $1`,
        [h.id, existing.rows[0].id]
      );
      await client.query(`DELETE FROM file_artifact_hashes WHERE id = $1`, [h.id]);
      continue;
    }
    if (existing.rowCount && existing.rows[0].artifact_id !== canonicalId) {
      // Should not happen under global unique; skip
      continue;
    }
    await client.query(
      `UPDATE file_artifact_hashes
       SET artifact_id = $2, is_primary = FALSE, updated_at = NOW()
       WHERE id = $1`,
      [h.id, canonicalId]
    );
  }

  // Move IOC links
  const { rows: dupLinks } = await client.query(
    `SELECT id, ioc_item_id, ioc_observable_type FROM file_artifact_ioc_links WHERE artifact_id = $1`,
    [duplicateId]
  );
  for (const link of dupLinks) {
    const existing = await client.query(
      `SELECT id, artifact_id FROM file_artifact_ioc_links
       WHERE ioc_observable_type = $1 AND ioc_item_id = $2`,
      [link.ioc_observable_type, link.ioc_item_id]
    );
    if (existing.rowCount) {
      if (existing.rows[0].artifact_id === canonicalId) {
        await client.query(`DELETE FROM file_artifact_ioc_links WHERE id = $1`, [link.id]);
      }
      continue;
    }
    await client.query(
      `UPDATE file_artifact_ioc_links
       SET artifact_id = $2, is_canonical_ioc = FALSE WHERE id = $1`,
      [link.id, canonicalId]
    );
  }

  // Move observations
  await client.query(
    `UPDATE file_artifact_source_observations SET artifact_id = $2, updated_at = NOW()
     WHERE artifact_id = $1`,
    [duplicateId, canonicalId]
  );

  // Move non-identity attrs (ON CONFLICT ignore)
  const { rows: attrs } = await client.query(
    `SELECT attr_type, attr_value, source_name FROM file_artifact_non_identity_attrs WHERE artifact_id = $1`,
    [duplicateId]
  );
  for (const a of attrs) {
    await client.query(
      `INSERT INTO file_artifact_non_identity_attrs (artifact_id, attr_type, attr_value, source_name)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (artifact_id, attr_type, attr_value) DO NOTHING`,
      [canonicalId, a.attr_type, a.attr_value, a.source_name]
    );
  }
  await client.query(
    `DELETE FROM file_artifact_non_identity_attrs WHERE artifact_id = $1`,
    [duplicateId]
  );

  const meta = mergeArtifactMetadata(canonical, duplicate);
  await client.query(
    `UPDATE file_artifacts SET
       file_name = $2,
       file_type = $3,
       mime_type = $4,
       size_bytes = $5,
       first_seen_at = $6::timestamptz,
       last_seen_at = $7::timestamptz,
       metadata = $8::jsonb,
       updated_at = NOW()
     WHERE id = $1`,
    [
      canonicalId,
      meta.file_name,
      meta.file_type,
      meta.mime_type,
      meta.size_bytes,
      meta.first_seen_at,
      meta.last_seen_at,
      JSON.stringify(meta.metadata || {})
    ]
  );

  await client.query(
    `UPDATE file_artifacts SET
       status = 'merged',
       merged_into_artifact_id = $2,
       primary_hash_id = NULL,
       updated_at = NOW(),
       metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb
     WHERE id = $1`,
    [
      duplicateId,
      canonicalId,
      JSON.stringify({
        merged_at: new Date().toISOString(),
        merge_method: input.method || 'automatic',
        merge_evidence: input.evidence || {}
      })
    ]
  );

  const primary = await recomputePrimaryHash(client, canonicalId);
  await syncCanonicalIocFlag(client, canonicalId);

  return {
    ok: true,
    noop: false,
    canonical_artifact_id: canonicalId,
    duplicate_artifact_id: duplicateId,
    primary: primary.primary,
    promoted: primary.promoted
  };
}
