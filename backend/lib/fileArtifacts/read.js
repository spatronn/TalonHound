/**
 * Read-path helpers for artifact-aware IOC detail / list.
 */

import { formatObservationForApi } from './observations.js';
import { selectPrimaryHash } from './hashNormalize.js';
import { isFileArtifactsReadEnabled } from './flags.js';

/**
 * Resolve artifact for an IOC public_id (follows merged tombstones).
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} publicId
 */
export async function findArtifactByIocPublicId(db, publicId) {
  const { rows } = await db.query(
    `SELECT l.artifact_id, l.ioc_public_id, l.ioc_item_id, l.ioc_observable_type,
            l.is_canonical_ioc, l.linked_hash_id,
            a.status, a.merged_into_artifact_id
     FROM file_artifact_ioc_links l
     JOIN file_artifacts a ON a.id = l.artifact_id
     WHERE l.ioc_public_id = $1::uuid
     LIMIT 1`,
    [publicId]
  );
  if (!rows.length) return null;
  let row = rows[0];
  let guard = 0;
  while (row.status === 'merged' && row.merged_into_artifact_id && guard < 5) {
    const next = await db.query(
      `SELECT id AS artifact_id, status, merged_into_artifact_id FROM file_artifacts WHERE id = $1`,
      [row.merged_into_artifact_id]
    );
    if (!next.rowCount) break;
    row = { ...row, artifact_id: next.rows[0].artifact_id, status: next.rows[0].status, merged_into_artifact_id: next.rows[0].merged_into_artifact_id };
    guard += 1;
  }
  return row;
}

/**
 * Load full artifact payload for API.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} artifactId
 * @param {{ requested_public_id?: string|null }} opts
 */
export async function loadArtifactDetail(db, artifactId, opts = {}) {
  const { rows: arts } = await db.query(
    `SELECT id, primary_hash_id, status, merged_into_artifact_id,
            file_name, file_type, mime_type, size_bytes,
            first_seen_at, last_seen_at, created_at, updated_at, metadata
     FROM file_artifacts WHERE id = $1`,
    [artifactId]
  );
  if (!arts.length) return null;
  const artifact = arts[0];
  if (artifact.status === 'merged' && artifact.merged_into_artifact_id) {
    return loadArtifactDetail(db, artifact.merged_into_artifact_id, opts);
  }

  const { rows: hashes } = await db.query(
    `SELECT id, hash_type, normalized_hash_value, is_primary, first_seen_at, last_seen_at, verification_source
     FROM file_artifact_hashes
     WHERE artifact_id = $1
     ORDER BY CASE hash_type WHEN 'sha256' THEN 0 WHEN 'sha1' THEN 1 WHEN 'md5' THEN 2 ELSE 9 END`,
    [artifactId]
  );
  const primary = hashes.find((h) => h.is_primary) || selectPrimaryHash(hashes);

  const { rows: links } = await db.query(
    `SELECT ioc_item_id, ioc_observable_type, ioc_public_id, linked_hash_id, is_canonical_ioc
     FROM file_artifact_ioc_links
     WHERE artifact_id = $1
     ORDER BY is_canonical_ioc DESC, ioc_observable_type`,
    [artifactId]
  );
  const canonicalLink = links.find((l) => l.is_canonical_ioc) || links[0] || null;

  const { rows: observations } = await db.query(
    `SELECT * FROM file_artifact_source_observations
     WHERE artifact_id = $1
     ORDER BY source_name, observed_hash_type`,
    [artifactId]
  );

  const { rows: nonIdentity } = await db.query(
    `SELECT attr_type, attr_value, source_name
     FROM file_artifact_non_identity_attrs
     WHERE artifact_id = $1
     ORDER BY attr_type`,
    [artifactId]
  );

  const requested = opts.requested_public_id ? String(opts.requested_public_id) : null;
  const canonicalPublicId = canonicalLink?.ioc_public_id || null;
  const isLegacyAlias = Boolean(
    requested && canonicalPublicId && requested !== String(canonicalPublicId)
  );

  const knownHashes = hashes.map((h) => ({
    hash_type: h.hash_type,
    value: h.normalized_hash_value,
    is_primary: Boolean(h.is_primary),
    hash_id: h.id
  }));

  return {
    artifact_id: artifact.id,
    status: artifact.status,
    primary_hash: primary
      ? { hash_type: primary.hash_type, value: primary.normalized_hash_value, hash_id: primary.id }
      : null,
    known_hashes: knownHashes,
    linked_ioc_ids: links.map((l) => Number(l.ioc_item_id)),
    linked_ioc_public_ids: links.map((l) => String(l.ioc_public_id)),
    canonical_ioc_id: canonicalLink ? Number(canonicalLink.ioc_item_id) : null,
    canonical_ioc_public_id: canonicalPublicId,
    is_canonical_ioc: canonicalLink
      ? Boolean(requested && String(canonicalLink.ioc_public_id) === requested)
      : false,
    is_legacy_alias: isLegacyAlias,
    redirected_from_ioc_id: isLegacyAlias ? requested : null,
    redirected_from_public_id: isLegacyAlias ? requested : null,
    file_name: artifact.file_name,
    file_type: artifact.file_type,
    mime_type: artifact.mime_type,
    size_bytes: artifact.size_bytes,
    first_seen_at: artifact.first_seen_at,
    last_seen_at: artifact.last_seen_at,
    non_identity_attrs: nonIdentity,
    source_observations: observations.map(formatObservationForApi),
    metadata: artifact.metadata || {}
  };
}

/**
 * Build additive file_artifact block for IOC detail response when flag enabled.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} publicId
 */
export async function buildFileArtifactDetailBlock(db, publicId) {
  if (!isFileArtifactsReadEnabled()) return null;
  try {
    const link = await findArtifactByIocPublicId(db, publicId);
    if (!link?.artifact_id) return null;
    return loadArtifactDetail(db, link.artifact_id, { requested_public_id: publicId });
  } catch (err) {
    // Schema may not be migrated yet — fail soft
    if (err && (err.code === '42P01' || String(err.message || '').includes('file_artifact'))) {
      return null;
    }
    throw err;
  }
}

/**
 * Map of public_id → artifact_id for list dedupe.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string[]} publicIds
 */
export async function mapPublicIdsToArtifactIds(db, publicIds) {
  const ids = [...new Set((publicIds || []).filter(Boolean))];
  if (!ids.length || !isFileArtifactsReadEnabled()) return new Map();
  try {
    const { rows } = await db.query(
      `SELECT l.ioc_public_id::text AS public_id,
              CASE WHEN a.status = 'merged' AND a.merged_into_artifact_id IS NOT NULL
                   THEN a.merged_into_artifact_id ELSE a.id END AS artifact_id
       FROM file_artifact_ioc_links l
       JOIN file_artifacts a ON a.id = l.artifact_id
       WHERE l.ioc_public_id = ANY($1::uuid[])`,
      [ids]
    );
    const map = new Map();
    for (const r of rows) map.set(String(r.public_id), String(r.artifact_id));
    return map;
  } catch (err) {
    if (err && err.code === '42P01') return new Map();
    throw err;
  }
}

/**
 * Dedupe list rows by artifact_id when present; keep canonical-preferring row.
 * Falls back to type::value grouping key for non-linked rows.
 *
 * @param {Array<object>} items
 * @param {Map<string,string>} artifactByPublicId
 * @param {{ getGroupKey?: (item: object) => string }} opts
 */
export function dedupeListItemsByArtifact(items, artifactByPublicId, opts = {}) {
  const getGroupKey = opts.getGroupKey || ((item) => {
    const pid = String(item.public_id || '');
    const artifactId = artifactByPublicId?.get(pid);
    if (artifactId) return `artifact:${artifactId}`;
    return `${item.observable_type}::${item.observable}`;
  });

  const rankType = (t) => {
    const x = String(t || '').toLowerCase();
    if (x === 'sha256') return 0;
    if (x === 'sha1') return 1;
    if (x === 'md5') return 2;
    return 9;
  };

  const groups = new Map();
  for (const item of items || []) {
    const key = getGroupKey(item);
    const prev = groups.get(key);
    if (!prev) {
      groups.set(key, { ...item, _artifact_id: artifactByPublicId?.get(String(item.public_id || '')) || null });
      continue;
    }
    // Prefer higher-priority hash type as display row
    if (rankType(item.observable_type) < rankType(prev.observable_type)) {
      const merged = {
        ...item,
        sources: mergeSets(prev.sources, item.sources),
        _artifact_id: prev._artifact_id || artifactByPublicId?.get(String(item.public_id || '')) || null,
        known_hash_types: mergeSets(prev.known_hash_types, item.observable_type, prev.observable_type)
      };
      groups.set(key, merged);
    } else {
      prev.sources = mergeSets(prev.sources, item.sources);
      prev.known_hash_types = mergeSets(prev.known_hash_types, item.observable_type, prev.observable_type);
    }
  }
  return [...groups.values()];
}

function mergeSets(a, b, c) {
  const out = new Set();
  const add = (v) => {
    if (v == null) return;
    if (Array.isArray(v) || v instanceof Set) {
      for (const x of v) if (x != null && x !== '') out.add(x);
      return;
    }
    if (v !== '') out.add(v);
  };
  add(a);
  add(b);
  add(c);
  return [...out];
}
