/**
 * Attach exact hashes / IOC links to file artifacts (idempotent).
 */

import {
  EXACT_HASH_TYPE_SET,
  normalizeExactHash,
  normalizeHashType,
  selectPrimaryHash,
  shouldPromotePrimary,
  extractNonIdentityAttrsFromNote,
  extractExactHashesFromNote
} from './hashNormalize.js';
import { upsertSourceObservation, OBSERVATION_TYPE, RELATION_METHOD } from './observations.js';
import { recordMergeConflict, detectMultiArtifactConflict } from './conflicts.js';

/**
 * Recompute and persist primary hash for an artifact.
 * @param {import('pg').PoolClient} client
 * @param {string} artifactId
 */
export async function recomputePrimaryHash(client, artifactId) {
  const { rows } = await client.query(
    `SELECT id, hash_type, normalized_hash_value, is_primary
     FROM file_artifact_hashes
     WHERE artifact_id = $1`,
    [artifactId]
  );
  const primary = selectPrimaryHash(rows);
  if (!primary) {
    await client.query(
      `UPDATE file_artifacts SET primary_hash_id = NULL, updated_at = NOW() WHERE id = $1`,
      [artifactId]
    );
    return { primary: null, promoted: false };
  }

  const prev = rows.find((r) => r.is_primary);
  const promoted = !prev || prev.id !== primary.id;

  await client.query(
    `UPDATE file_artifact_hashes SET is_primary = FALSE, updated_at = NOW()
     WHERE artifact_id = $1 AND is_primary = TRUE`,
    [artifactId]
  );
  await client.query(
    `UPDATE file_artifact_hashes SET is_primary = TRUE, updated_at = NOW() WHERE id = $1`,
    [primary.id]
  );
  await client.query(
    `UPDATE file_artifacts SET primary_hash_id = $2, updated_at = NOW() WHERE id = $1`,
    [artifactId, primary.id]
  );

  // Keep canonical IOC flag in sync with primary hash type preference
  await syncCanonicalIocFlag(client, artifactId);

  return {
    primary: {
      id: primary.id,
      hash_type: primary.hash_type,
      normalized_hash_value: primary.normalized_hash_value
    },
    promoted,
    previous_primary_id: prev?.id || null
  };
}

/**
 * Prefer canonical IOC link matching primary hash type, else SHA256>SHA1>MD5 among links.
 * @param {import('pg').PoolClient} client
 * @param {string} artifactId
 */
export async function syncCanonicalIocFlag(client, artifactId) {
  const { rows } = await client.query(
    `SELECT l.id, l.ioc_observable_type, h.hash_type AS linked_hash_type, h.is_primary
     FROM file_artifact_ioc_links l
     LEFT JOIN file_artifact_hashes h ON h.id = l.linked_hash_id
     WHERE l.artifact_id = $1`,
    [artifactId]
  );
  if (!rows.length) return null;

  const rank = (type) => {
    const t = normalizeHashType(type);
    if (t === 'sha256') return 0;
    if (t === 'sha1') return 1;
    if (t === 'md5') return 2;
    return 9;
  };

  const sorted = [...rows].sort((a, b) => {
    const aPrimary = a.is_primary ? 0 : 1;
    const bPrimary = b.is_primary ? 0 : 1;
    if (aPrimary !== bPrimary) return aPrimary - bPrimary;
    return rank(a.linked_hash_type || a.ioc_observable_type)
      - rank(b.linked_hash_type || b.ioc_observable_type);
  });
  const canonicalId = sorted[0].id;

  await client.query(
    `UPDATE file_artifact_ioc_links SET is_canonical_ioc = FALSE WHERE artifact_id = $1`,
    [artifactId]
  );
  await client.query(
    `UPDATE file_artifact_ioc_links SET is_canonical_ioc = TRUE WHERE id = $1`,
    [canonicalId]
  );
  return canonicalId;
}

/**
 * Find active artifact by exact hash.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} hashType
 * @param {string} hashValue
 */
export async function findArtifactByHash(db, hashType, hashValue) {
  const hash = normalizeExactHash(hashType, hashValue);
  if (!hash) return null;
  const { rows } = await db.query(
    `SELECT a.id AS artifact_id, a.status, a.merged_into_artifact_id,
            h.id AS hash_id, h.hash_type, h.normalized_hash_value, h.is_primary
     FROM file_artifact_hashes h
     JOIN file_artifacts a ON a.id = h.artifact_id
     WHERE h.hash_type = $1 AND h.normalized_hash_value = $2
     LIMIT 1`,
    [hash.hash_type, hash.normalized_hash_value]
  );
  if (!rows.length) return null;
  const row = rows[0];
  if (row.status === 'merged' && row.merged_into_artifact_id) {
    const active = await findActiveArtifact(db, row.merged_into_artifact_id);
    if (!active?.artifact_id) return null;
    return {
      artifact_id: active.artifact_id,
      status: active.status,
      merged_into_artifact_id: active.merged_into_artifact_id || null,
      hash_id: row.hash_id,
      hash_type: row.hash_type,
      normalized_hash_value: row.normalized_hash_value,
      is_primary: row.is_primary,
      // Physical row may still sit on a tombstone until merge heal moves it
      hash_artifact_id: row.artifact_id
    };
  }
  return row;
}

async function findActiveArtifact(db, artifactId) {
  const { rows } = await db.query(
    `SELECT id AS artifact_id, status, merged_into_artifact_id
     FROM file_artifacts WHERE id = $1`,
    [artifactId]
  );
  if (!rows.length) return null;
  const row = rows[0];
  if (row.status === 'merged' && row.merged_into_artifact_id) {
    return findActiveArtifact(db, row.merged_into_artifact_id);
  }
  return row;
}

/**
 * Deterministic advisory lock key pair for an exact hash (transaction-scoped).
 * Uses two hashtext ints to reduce collision vs single-key lock.
 */
export function exactHashAdvisoryLockKeys(hashType, normalizedValue) {
  return [
    `fa_hash:${String(hashType || '').toLowerCase()}`,
    String(normalizedValue || '').toLowerCase()
  ];
}

/**
 * Delete artifact only if this tx created it and it has no hashes/links/observations.
 * @param {import('pg').PoolClient} client
 * @param {string} artifactId
 */
async function deleteEmptyOrphanArtifactIfSafe(client, artifactId) {
  if (!artifactId) return false;
  const { rows } = await client.query(
    `SELECT
       (SELECT COUNT(*)::int FROM file_artifact_hashes WHERE artifact_id = $1) AS h,
       (SELECT COUNT(*)::int FROM file_artifact_ioc_links WHERE artifact_id = $1) AS l,
       (SELECT COUNT(*)::int FROM file_artifact_source_observations WHERE artifact_id = $1) AS o,
       (SELECT COUNT(*)::int FROM file_artifact_non_identity_attrs WHERE artifact_id = $1) AS n`,
    [artifactId]
  );
  const r = rows[0];
  if (!r || r.h > 0 || r.l > 0 || r.o > 0 || r.n > 0) return false;
  await client.query(`DELETE FROM file_artifacts WHERE id = $1 AND status = 'active'`, [artifactId]);
  return true;
}

/**
 * Core attach inside an open transaction (caller holds tx).
 * Takes pg_advisory_xact_lock on hash identity before create.
 */
async function attachExactHashInTx(client, input) {
  const hash = normalizeExactHash(input.hash_type, input.hash_value);
  if (!hash) return { ok: false, reason: 'invalid_hash' };

  const [k1, k2] = exactHashAdvisoryLockKeys(hash.hash_type, hash.normalized_hash_value);
  await client.query(
    `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
    [k1, k2]
  );

  const existing = await findArtifactByHash(client, hash.hash_type, hash.normalized_hash_value);
  if (existing?.hash_id) {
    // Heal leftover hash rows on merged tombstones that already point at this artifact
    if (
      existing.hash_artifact_id
      && existing.hash_artifact_id !== existing.artifact_id
      && (!input.artifact_id || input.artifact_id === existing.artifact_id)
    ) {
      await client.query(
        `UPDATE file_artifact_hashes
         SET artifact_id = $2, is_primary = FALSE, updated_at = NOW(),
             last_seen_at = GREATEST(COALESCE(last_seen_at, $3::timestamptz), COALESCE($3::timestamptz, last_seen_at))
         WHERE id = $1`,
        [existing.hash_id, existing.artifact_id, input.last_seen_at || new Date().toISOString()]
      );
      await recomputePrimaryHash(client, existing.artifact_id);
      return {
        ok: true,
        created_artifact: false,
        created_hash: false,
        artifact_id: existing.artifact_id,
        hash_id: existing.hash_id,
        healed_from_merged: true
      };
    }
    if (input.artifact_id && existing.artifact_id !== input.artifact_id) {
      await recordMergeConflict(client, {
        conflicting_hash_type: hash.hash_type,
        conflicting_hash_value: hash.normalized_hash_value,
        candidate_artifact_ids: [existing.artifact_id, input.artifact_id],
        reason: 'exact_hash_already_bound_to_other_artifact',
        evidence: { existing_artifact_id: existing.artifact_id, requested_artifact_id: input.artifact_id }
      });
      return {
        ok: false,
        reason: 'conflict',
        artifact_id: existing.artifact_id,
        hash_id: existing.hash_id
      };
    }
    await client.query(
      `UPDATE file_artifact_hashes
       SET last_seen_at = GREATEST(COALESCE(last_seen_at, $2::timestamptz), COALESCE($2::timestamptz, last_seen_at)),
           updated_at = NOW()
       WHERE id = $1`,
      [existing.hash_id, input.last_seen_at || new Date().toISOString()]
    );
    return {
      ok: true,
      created_artifact: false,
      created_hash: false,
      artifact_id: existing.artifact_id,
      hash_id: existing.hash_id
    };
  }

  let artifactId = input.artifact_id || null;
  let createdArtifact = false;
  if (!artifactId) {
    const insA = await client.query(
      `INSERT INTO file_artifacts (
         file_name, file_type, mime_type, size_bytes,
         first_seen_at, last_seen_at, status
       ) VALUES ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz, 'active')
       RETURNING id`,
      [
        input.file_name || null,
        input.file_type || null,
        input.mime_type || null,
        input.size_bytes ?? null,
        input.first_seen_at || new Date().toISOString(),
        input.last_seen_at || input.first_seen_at || new Date().toISOString()
      ]
    );
    artifactId = insA.rows[0].id;
    createdArtifact = true;
  }

  let hashId;
  let createdHash = true;
  // SAVEPOINT: unique_violation aborts the subxact only — recovery queries must not see 25P02.
  const hashInsSp = 'fa_hash_ins';
  try {
    await client.query(`SAVEPOINT ${hashInsSp}`);
    const insH = await client.query(
      `INSERT INTO file_artifact_hashes (
         artifact_id, hash_type, normalized_hash_value, is_primary,
         first_seen_at, last_seen_at, verification_source
       ) VALUES ($1, $2, $3, FALSE, $4::timestamptz, $5::timestamptz, $6)
       RETURNING id`,
      [
        artifactId,
        hash.hash_type,
        hash.normalized_hash_value,
        input.first_seen_at || new Date().toISOString(),
        input.last_seen_at || input.first_seen_at || new Date().toISOString(),
        input.verification_source || null
      ]
    );
    hashId = insH.rows[0].id;
    await client.query(`RELEASE SAVEPOINT ${hashInsSp}`);
  } catch (err) {
    await client.query(`ROLLBACK TO SAVEPOINT ${hashInsSp}`).catch(() => {});
    const isUnique =
      err
      && (err.code === '23505' || String(err.message || '').includes('uq_file_artifact_hashes'));
    if (isUnique) {
      let cleaned = false;
      if (createdArtifact) {
        cleaned = await deleteEmptyOrphanArtifactIfSafe(client, artifactId);
      }
      const again = await findArtifactByHash(client, hash.hash_type, hash.normalized_hash_value);
      if (again?.hash_id) {
        if (input.artifact_id && again.artifact_id !== input.artifact_id) {
          await recordMergeConflict(client, {
            conflicting_hash_type: hash.hash_type,
            conflicting_hash_value: hash.normalized_hash_value,
            candidate_artifact_ids: [again.artifact_id, input.artifact_id],
            reason: 'exact_hash_already_bound_to_other_artifact',
            evidence: {
              existing_artifact_id: again.artifact_id,
              requested_artifact_id: input.artifact_id,
              raced: true
            }
          });
          return {
            ok: false,
            reason: 'conflict',
            artifact_id: again.artifact_id,
            hash_id: again.hash_id,
            raced: true,
            orphan_cleaned: cleaned
          };
        }
        return {
          ok: true,
          created_artifact: false,
          created_hash: false,
          artifact_id: again.artifact_id,
          hash_id: again.hash_id,
          raced: true,
          orphan_cleaned: cleaned
        };
      }
      if (createdArtifact) {
        await deleteEmptyOrphanArtifactIfSafe(client, artifactId);
      }
      return {
        ok: false,
        reason: 'unique_violation',
        code: '23505',
        message: err.message,
        orphan_cleaned: cleaned
      };
    }
    if (createdArtifact) {
      await deleteEmptyOrphanArtifactIfSafe(client, artifactId);
    }
    throw err;
  }

  const primaryResult = await recomputePrimaryHash(client, artifactId);

  return {
    ok: true,
    created_artifact: createdArtifact,
    created_hash: createdHash,
    artifact_id: artifactId,
    hash_id: hashId,
    primary: primaryResult.primary,
    promoted: primaryResult.promoted
  };
}

/**
 * Attach a single exact hash to an artifact (or create artifact). Idempotent.
 * Opens a short transaction when given a Pool so advisory_xact_lock spans the race window.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {{
 *   hash_type: string,
 *   hash_value: string,
 *   artifact_id?: string|null,
 *   verification_source?: string|null,
 *   first_seen_at?: string|Date|null,
 *   last_seen_at?: string|Date|null,
 *   file_name?: string|null,
 *   file_type?: string|null,
 *   mime_type?: string|null,
 *   size_bytes?: number|null
 * }} input
 */
export async function attachExactHash(db, input) {
  // pg.Client also has .connect(); only Pool needs a new checkout + transaction wrapper.
  const isPool = Boolean(
    db
    && typeof db.connect === 'function'
    && typeof db.query === 'function'
    && typeof db.release !== 'function'
    && (db.totalCount != null || db.options?.max != null || db.constructor?.name === 'Pool')
  );
  if (isPool) {
    const client = await db.connect();
    try {
      await client.query('BEGIN');
      const result = await attachExactHashInTx(client, input);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }
  return attachExactHashInTx(db, input);
}

/**
 * Link an ioc_items row to an artifact. Idempotent.
 *
 * @param {import('pg').PoolClient} client
 * @param {{
 *   artifact_id: string,
 *   ioc_item_id: number|string,
 *   ioc_observable_type: string,
 *   ioc_public_id: string,
 *   linked_hash_id?: string|null,
 *   is_canonical_ioc?: boolean
 * }} input
 */
export async function linkIocToArtifact(client, input) {
  const type = normalizeHashType(input.ioc_observable_type);
  if (!EXACT_HASH_TYPE_SET.has(type)) {
    return { ok: false, reason: 'not_exact_hash_ioc' };
  }

  const existing = await client.query(
    `SELECT id, artifact_id FROM file_artifact_ioc_links
     WHERE ioc_observable_type = $1 AND ioc_item_id = $2`,
    [type, input.ioc_item_id]
  );
  if (existing.rowCount) {
    const row = existing.rows[0];
    if (row.artifact_id !== input.artifact_id) {
      await recordMergeConflict(client, {
        conflicting_hash_type: type,
        conflicting_hash_value: String(input.ioc_public_id),
        candidate_artifact_ids: [row.artifact_id, input.artifact_id],
        reason: 'ioc_already_linked_to_other_artifact',
        evidence: { ioc_item_id: input.ioc_item_id, ioc_observable_type: type }
      });
      return { ok: false, reason: 'conflict', link_id: row.id, artifact_id: row.artifact_id };
    }
    if (input.linked_hash_id) {
      await client.query(
        `UPDATE file_artifact_ioc_links SET linked_hash_id = COALESCE(linked_hash_id, $2) WHERE id = $1`,
        [row.id, input.linked_hash_id]
      );
    }
    await syncCanonicalIocFlag(client, input.artifact_id);
    return { ok: true, created: false, link_id: row.id, artifact_id: row.artifact_id };
  }

  const ins = await client.query(
    `INSERT INTO file_artifact_ioc_links (
       artifact_id, ioc_item_id, ioc_observable_type, ioc_public_id,
       linked_hash_id, is_canonical_ioc
     ) VALUES ($1, $2, $3, $4, $5, FALSE)
     RETURNING id`,
    [
      input.artifact_id,
      input.ioc_item_id,
      type,
      input.ioc_public_id,
      input.linked_hash_id || null
    ]
  );
  await syncCanonicalIocFlag(client, input.artifact_id);
  return { ok: true, created: true, link_id: ins.rows[0].id, artifact_id: input.artifact_id };
}

/**
 * Upsert non-identity attrs (imphash/tlsh/ssdeep). Never triggers merge.
 * @param {import('pg').PoolClient} client
 * @param {string} artifactId
 * @param {Array<{ attr_type: string, attr_value: string }>} attrs
 * @param {string|null} sourceName
 */
export async function upsertNonIdentityAttrs(client, artifactId, attrs, sourceName = null) {
  let created = 0;
  for (const attr of attrs || []) {
    const r = await client.query(
      `INSERT INTO file_artifact_non_identity_attrs (artifact_id, attr_type, attr_value, source_name)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (artifact_id, attr_type, attr_value) DO UPDATE
         SET updated_at = NOW(),
             source_name = COALESCE(file_artifact_non_identity_attrs.source_name, EXCLUDED.source_name)
       RETURNING (xmax = 0) AS inserted`,
      [artifactId, attr.attr_type, attr.attr_value, sourceName]
    );
    if (r.rows[0]?.inserted) created += 1;
  }
  return { created };
}

/**
 * High-level: ensure file-hash IOC is represented as artifact + link + direct observation.
 * Used by dual-write and seed backfill.
 *
 * @param {import('pg').PoolClient} client
 * @param {{
 *   ioc_item_id: number|string,
 *   ioc_public_id: string,
 *   observable_type: string,
 *   observable: string,
 *   source_name?: string|null,
 *   feed_id?: string|null,
 *   note?: string|null,
 *   first_seen_at?: string|Date|null,
 *   last_seen_at?: string|Date|null,
 *   confidence?: string|null,
 *   observation_type?: string,
 *   relation_method?: string,
 *   attach_note_siblings?: boolean,
 *   provider_mapping?: boolean
 * }} input
 */
export async function ensureArtifactForFileHashIoc(client, input) {
  const primary = normalizeExactHash(input.observable_type, input.observable);
  if (!primary) {
    return { ok: false, reason: 'invalid_or_non_exact_hash' };
  }

  const attach = await attachExactHash(client, {
    hash_type: primary.hash_type,
    hash_value: primary.normalized_hash_value,
    first_seen_at: input.first_seen_at,
    last_seen_at: input.last_seen_at,
    verification_source: input.source_name || null
  });
  if (!attach.ok) return attach;

  const link = await linkIocToArtifact(client, {
    artifact_id: attach.artifact_id,
    ioc_item_id: input.ioc_item_id,
    ioc_observable_type: primary.hash_type,
    ioc_public_id: input.ioc_public_id,
    linked_hash_id: attach.hash_id
  });

  let observation = null;
  if (input.source_name) {
    observation = await upsertSourceObservation(client, {
      artifact_id: attach.artifact_id,
      source_name: input.source_name,
      feed_id: input.feed_id || null,
      observed_hash_id: attach.hash_id,
      observed_hash_type: primary.hash_type,
      observed_hash_value: primary.normalized_hash_value,
      observation_type: input.observation_type || OBSERVATION_TYPE.DIRECT,
      relation_method: input.relation_method || RELATION_METHOD.SAME_SOURCE_RECORD,
      confidence: input.confidence || null,
      first_seen_in_source: input.first_seen_at,
      last_seen_in_source: input.last_seen_at || input.first_seen_at,
      raw_ref: { ioc_public_id: input.ioc_public_id, ioc_item_id: input.ioc_item_id }
    });
  }

  const nonIdentity = extractNonIdentityAttrsFromNote(input.note);
  if (nonIdentity.length) {
    await upsertNonIdentityAttrs(client, attach.artifact_id, nonIdentity, input.source_name || null);
  }

  // Sibling exact hashes from the same source record (MB note) — attach only, do not invent source attribution for siblings as "direct"
  let siblingResults = [];
  if (input.attach_note_siblings || input.provider_mapping) {
    siblingResults = await attachProviderExactHashSet(client, {
      artifact_id: attach.artifact_id,
      primary_hash: primary,
      note: input.note,
      source_name: input.source_name,
      feed_id: input.feed_id,
      provider_mapping: Boolean(input.provider_mapping)
    });
  }

  return {
    ok: true,
    artifact_id: attach.artifact_id,
    hash_id: attach.hash_id,
    created_artifact: attach.created_artifact,
    created_hash: attach.created_hash,
    link,
    observation,
    siblings: siblingResults,
    primary: attach.primary,
    promoted: attach.promoted
  };
}

/**
 * Attach additional exact hashes from a trusted same-record provider set.
 * Records provider_hash_mapping observations for sibling hashes (not as if source sent them as primary).
 *
 * @param {import('pg').PoolClient} client
 * @param {object} input
 */
export async function attachProviderExactHashSet(client, input) {
  const hashes = extractExactHashesFromNote({
    observableType: input.primary_hash?.hash_type,
    observable: input.primary_hash?.normalized_hash_value,
    note: input.note
  });

  // Look up artifacts for each hash; detect multi-artifact conflict before merging
  const hits = [];
  for (const h of hashes) {
    const found = await findArtifactByHash(client, h.hash_type, h.normalized_hash_value);
    if (found?.artifact_id) hits.push({ ...h, artifact_id: found.artifact_id, hash_id: found.hash_id });
  }
  const multi = detectMultiArtifactConflict(
    hits.filter((h) => h.artifact_id && h.artifact_id !== input.artifact_id)
      .concat(input.artifact_id ? [{ artifact_id: input.artifact_id }] : [])
  );

  // Sibling hashes already bound to other artifact(s): signal merge (caller / dual-write /
  // backfill choose canonical). Trusted provider exact-hash sets may span N artifacts
  // (e.g. ThreatFox published md5/sha1/sha256 as separate IOCs) — that is merge evidence,
  // not a blocking conflict. True unsafe multi-mapping is recorded via
  // detectMultiArtifactConflict + attachExactHash unique binding conflicts.
  const otherArtifactIds = [...new Set(
    hits.map((h) => h.artifact_id).filter((id) => id && id !== input.artifact_id)
  )];
  if (otherArtifactIds.length >= 1) {
    return {
      ok: true,
      needs_merge_with: otherArtifactIds[0],
      needs_merge_with_ids: otherArtifactIds,
      results: hits
    };
  }

  const results = [];
  for (const h of hashes) {
    const attached = await attachExactHash(client, {
      artifact_id: input.artifact_id,
      hash_type: h.hash_type,
      hash_value: h.normalized_hash_value,
      verification_source: input.source_name || 'provider_exact_hash_set'
    });
    results.push(attached);

    const isPrimary =
      h.hash_type === input.primary_hash?.hash_type
      && h.normalized_hash_value === input.primary_hash?.normalized_hash_value;

    // Direct observation only for the hash the source actually submitted as primary.
    // Sibling mappings get provider_hash_mapping.
    if (input.source_name && attached.ok && attached.hash_id) {
      if (!isPrimary && input.provider_mapping) {
        await upsertSourceObservation(client, {
          artifact_id: input.artifact_id,
          source_name: input.source_name,
          feed_id: input.feed_id || null,
          observed_hash_id: attached.hash_id,
          observed_hash_type: h.hash_type,
          observed_hash_value: h.normalized_hash_value,
          observation_type: OBSERVATION_TYPE.PROVIDER_MAPPING,
          relation_method: RELATION_METHOD.PROVIDER_EXACT_HASH_SET,
          raw_ref: { role: 'sibling_in_provider_record' }
        });
      }
    }

    // Link any existing IOC for this sibling hash
    if (attached.ok) {
      const iocRows = await client.query(
        `SELECT id, public_id, observable_type, observable
         FROM ioc_items
         WHERE observable_type = $1 AND observable = $2`,
        [h.hash_type, h.normalized_hash_value]
      );
      for (const ioc of iocRows.rows) {
        await linkIocToArtifact(client, {
          artifact_id: input.artifact_id,
          ioc_item_id: ioc.id,
          ioc_observable_type: ioc.observable_type,
          ioc_public_id: ioc.public_id,
          linked_hash_id: attached.hash_id
        });
      }
    }
  }

  await recomputePrimaryHash(client, input.artifact_id);
  return { ok: true, results, conflict: multi.conflict };
}

// re-export shouldPromotePrimary for tests
export { shouldPromotePrimary };
