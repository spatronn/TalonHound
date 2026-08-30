/**
 * Post-process list items: collapse rows that share a file artifact.
 */

import { isFileArtifactsReadEnabled } from './flags.js';
import { mapPublicIdsToArtifactIds, dedupeListItemsByArtifact } from './read.js';

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {Array<object>} items
 */
export async function applyFileArtifactListDedupe(db, items) {
  if (!isFileArtifactsReadEnabled() || !items?.length) return items;
  const publicIds = items.map((i) => i.public_id).filter(Boolean);
  const map = await mapPublicIdsToArtifactIds(db, publicIds);
  if (!map.size) return items;

  const deduped = dedupeListItemsByArtifact(
    items.map((i) => ({
      ...i,
      sources: i.source_names || i.sources || []
    })),
    map
  );

  const artifactIds = [...new Set(deduped.map((d) => d._artifact_id).filter(Boolean))];
  const primaryByArtifact = new Map();
  if (artifactIds.length) {
    const { rows } = await db.query(
      `SELECT h.artifact_id, h.hash_type, h.normalized_hash_value,
              cl.ioc_public_id AS canonical_public_id,
              cl.ioc_item_id AS canonical_ioc_id
       FROM file_artifact_hashes h
       LEFT JOIN LATERAL (
         SELECT l.ioc_public_id, l.ioc_item_id
         FROM file_artifact_ioc_links l
         WHERE l.artifact_id = h.artifact_id
         ORDER BY l.is_canonical_ioc DESC NULLS LAST,
           CASE l.ioc_observable_type
             WHEN 'sha256' THEN 0 WHEN 'sha1' THEN 1 WHEN 'md5' THEN 2 ELSE 9
           END,
           l.ioc_item_id ASC
         LIMIT 1
       ) cl ON TRUE
       WHERE h.artifact_id = ANY($1::uuid[]) AND h.is_primary = TRUE`,
      [artifactIds]
    );
    for (const r of rows) {
      primaryByArtifact.set(String(r.artifact_id), r);
    }
  }

  return deduped.map((item) => {
    const artId = item._artifact_id;
    const primary = artId ? primaryByArtifact.get(String(artId)) : null;
    const sourceNames = Array.isArray(item.sources)
      ? item.sources
      : (item.source_names || []);
    const out = {
      ...item,
      source_names: [...sourceNames].sort(),
      source_count: sourceNames.length || item.source_count || 0,
      artifact_id: artId || null,
      known_hash_types: item.known_hash_types || null
    };
    delete out.sources;
    delete out._artifact_id;
    if (primary) {
      out.observable = primary.normalized_hash_value;
      out.observable_type = primary.hash_type;
      out.ip = primary.normalized_hash_value;
      if (primary.canonical_public_id) out.public_id = String(primary.canonical_public_id);
      if (primary.canonical_ioc_id != null) out.id = Number(primary.canonical_ioc_id);
    }
    return out;
  });
}
