/**
 * Suppress an existing IOC by id.
 *
 * Hash scope (hash_scope / suppression_scope):
 *   - omitted / 'file': when the IOC is a proven exact file-hash member of a
 *     file_artifact, set file_artifact_id so all proven aliases are covered
 *   - 'exact': suppress only this (type, value) even if a canonical file exists
 *
 * Non-file IOCs (and file hashes with no artifact link) remain exact-only.
 * Manual Suppressions-screen creation defaults to exact in createManualSuppression.
 *
 * Note: uq_ioc_suppressions_one_active_value_type allows only one active row per
 * (value, type). Exact and file for the *same* hash cannot coexist; overlapping
 * coverage uses different observables (e.g. file on MD5 + exact on SHA1).
 */

import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { parseRequiredReason } from './reasonValidation.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';
import {
  resolveSurvivorArtifactIdForIoc,
  loadProvenHashesForArtifact,
  loadLinkedIocsForArtifact,
  describeSuppressionScope,
  normalizeHashScopePreference
} from './iocSuppressionFileScope.js';
import { parseSuppressionExpiration, SUPPRESSION_REASON_MIN, SUPPRESSION_REASON_MAX } from './manualSuppressionCreate.js';

/**
 * @param {import('pg').Pool} pool
 * @param {number} iocId
 * @param {object} body { reason, expires_at?, scope?, hash_scope? }
 * @param {{ req?: object, user?: object, audit?: object }} [opts]
 * @returns {Promise<{ status: number, body: object }>}
 */
export async function createIocLinkedSuppression(pool, iocId, body = {}, opts = {}) {
  const id = Number(iocId);
  if (!Number.isFinite(id) || id <= 0) {
    return { status: 400, body: { message: 'Invalid IOC id' } };
  }

  const scope = String(body?.scope || 'global').trim().toLowerCase();
  if (scope !== 'global') {
    return { status: 400, body: { message: 'Only global scope is supported in phase-1' } };
  }

  const reasonCheck = parseRequiredReason(body?.reason, {
    field: 'reason',
    minLength: SUPPRESSION_REASON_MIN,
    maxLength: SUPPRESSION_REASON_MAX
  });
  if (!reasonCheck.ok) return { status: 400, body: { message: reasonCheck.message } };

  const expCheck = parseSuppressionExpiration(body?.expires_at);
  if (!expCheck.ok) return { status: 400, body: { message: expCheck.message } };

  const rawHashScope = body?.hash_scope ?? body?.suppression_scope ?? body?.identity_scope;
  if (rawHashScope != null && String(rawHashScope).trim() !== '' && normalizeHashScopePreference(rawHashScope) == null) {
    return { status: 400, body: { message: 'hash_scope must be "file" or "exact"' } };
  }
  const hashScopePref = normalizeHashScopePreference(rawHashScope); // null = default file when resolvable

  const reason = reasonCheck.reason;
  const expiresAt = expCheck.expiresAt;
  const createdBy = String(opts.user?.email || opts.user?.username || '').trim() || null;

  let inserted = null;
  let alreadyExisted = false;
  let artifactId = null;
  let iocValue = '';
  let iocType = '';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const iocQ = await client.query(
      `SELECT id, observable, observable_type, public_id
       FROM ioc_items WHERE id = $1 LIMIT 1`,
      [id]
    );
    if (!iocQ.rowCount) {
      await client.query('ROLLBACK');
      return { status: 404, body: { message: 'IOC not found' } };
    }
    const ioc = iocQ.rows[0];
    iocValue = String(ioc.observable || '').trim();
    iocType = String(ioc.observable_type || '').trim();

    const resolvedArtifactId = await resolveSurvivorArtifactIdForIoc(client, id);
    const wantFile = hashScopePref !== 'exact' && Boolean(resolvedArtifactId);
    artifactId = wantFile ? resolvedArtifactId : null;

    // Same (value, type) active row — unique index; resolve scope conflicts explicitly.
    const samePairQ = await client.query(
      `SELECT * FROM ioc_suppressions
       WHERE active = TRUE
         AND deleted_at IS NULL
         AND lower(ioc_value) = lower($1)
         AND lower(ioc_type) = lower($2)
       LIMIT 1`,
      [iocValue, iocType]
    );
    if (samePairQ.rowCount) {
      const existing = samePairQ.rows[0];
      const existingIsFile = Boolean(existing.file_artifact_id);
      if (!wantFile && existingIsFile) {
        await client.query('ROLLBACK');
        return {
          status: 409,
          body: {
            message: 'A file-level suppression already covers this hash. Disable or delete it before creating an exact-hash suppression for the same value.'
          }
        };
      }
      alreadyExisted = true;
      const upd = await client.query(
        `UPDATE ioc_suppressions
         SET reason = $2,
             created_by = COALESCE($3, created_by),
             expires_at = $4,
             file_artifact_id = CASE WHEN $5::uuid IS NOT NULL THEN $5::uuid ELSE file_artifact_id END,
             active = TRUE,
             deleted_at = NULL,
             deleted_by = NULL,
             updated_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [existing.id, reason, createdBy, expiresAt, artifactId]
      );
      inserted = upd.rows[0];
    } else if (artifactId) {
      // Another primary hash of the same file already has a file-scoped row.
      const fileDupQ = await client.query(
        `SELECT * FROM ioc_suppressions
         WHERE active = TRUE
           AND deleted_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW())
           AND file_artifact_id = $1::uuid
         ORDER BY created_at DESC
         LIMIT 1`,
        [artifactId]
      );
      if (fileDupQ.rowCount) {
        alreadyExisted = true;
        const upd = await client.query(
          `UPDATE ioc_suppressions
           SET reason = $2,
               created_by = COALESCE($3, created_by),
               expires_at = $4,
               active = TRUE,
               deleted_at = NULL,
               deleted_by = NULL,
               updated_at = NOW()
           WHERE id = $1
           RETURNING *`,
          [fileDupQ.rows[0].id, reason, createdBy, expiresAt]
        );
        inserted = upd.rows[0];
      }
    }

    if (!inserted) {
      try {
        const insertQ = await client.query(
          `INSERT INTO ioc_suppressions (
             ioc_value, ioc_type, scope, source_name, reason, created_by,
             expires_at, active, updated_at, file_artifact_id
           )
           VALUES ($1, $2, 'global', NULL, $3, $4, $5, TRUE, NOW(), $6::uuid)
           RETURNING *`,
          [iocValue, iocType, reason, createdBy, expiresAt, artifactId]
        );
        inserted = insertQ.rows[0];
      } catch (err) {
        if (err?.code === '23505') {
          await client.query('ROLLBACK');
          return { status: 409, body: { message: 'An active suppression already exists for this IOC.' } };
        }
        throw err;
      }
    }

    const recomputeTargets = new Map();
    recomputeTargets.set(`${iocType}\t${id}`, { id, observable_type: iocType });

    if (artifactId || inserted.file_artifact_id) {
      const linked = await loadLinkedIocsForArtifact(client, artifactId || inserted.file_artifact_id);
      for (const row of linked) {
        recomputeTargets.set(`${row.observable_type}\t${row.id}`, row);
      }
    } else {
      const samePair = await client.query(
        `SELECT id, observable_type FROM ioc_items
         WHERE lower(observable) = lower($1) AND lower(observable_type) = lower($2)`,
        [iocValue, iocType]
      );
      for (const row of samePair.rows || []) {
        recomputeTargets.set(`${row.observable_type}\t${row.id}`, row);
      }
    }

    for (const row of recomputeTargets.values()) {
      await recomputeIocGlobalStatus(client, row.id, row.observable_type, {
        audit: opts.audit,
        actor: { actor_type: 'user', source: 'web' }
      }).catch(() => {});
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return { status: 500, body: { message: 'Failed to suppress IOC', detail: err.message } };
  } finally {
    client.release();
  }

  const effectiveArtifactId = inserted.file_artifact_id || artifactId;
  let knownHashes = [];
  try {
    knownHashes = effectiveArtifactId ? await loadProvenHashesForArtifact(pool, effectiveArtifactId) : [];
  } catch (err) {
    console.warn('[suppression] known-hash load after create failed', err?.message || err);
  }
  const scopeInfo = describeSuppressionScope(inserted, knownHashes.length || null);

  if (!alreadyExisted && opts.audit?.auditSuccess && opts.req) {
    await opts.audit.auditSuccess({
      req: opts.req,
      action: AUDIT_ACTION.IOC_SUPPRESSION_CREATED,
      entityType: AUDIT_ENTITY.IOC_SUPPRESSION,
      entityId: String(inserted.id),
      entityDisplay: `${iocValue} (${iocType})`,
      severity: AUDIT_SEVERITY.WARNING,
      after: {
        ioc_value: inserted.ioc_value,
        ioc_type: inserted.ioc_type,
        scope: inserted.scope,
        reason: inserted.reason,
        expires_at: inserted.expires_at,
        file_artifact_id: inserted.file_artifact_id || null,
        suppression_scope: scopeInfo.kind
      },
      metadata: {
        ioc_id: id,
        created_by: createdBy,
        file_artifact_id: inserted.file_artifact_id || null,
        suppression_scope: scopeInfo.kind,
        hash_scope: hashScopePref || (effectiveArtifactId ? 'file' : 'exact'),
        known_hash_count: knownHashes.length || 0,
        previous_status: null,
        new_status: 'active'
      }
    }).catch((e) => console.warn('[audit] ioc-linked suppression create log failed', e?.message || e));
  }

  return {
    status: 200,
    body: {
      status: 'suppressed',
      already_existed: alreadyExisted,
      suppression: {
        ...inserted,
        suppression_scope: scopeInfo,
        covered_hashes: knownHashes.length
          ? knownHashes.map((h) => ({ hash_type: h.hash_type, value: h.normalized_hash_value }))
          : [{ hash_type: iocType, value: iocValue }],
        covered_hash_count: knownHashes.length || 1,
        known_hashes: knownHashes.length
          ? knownHashes.map((h) => ({ hash_type: h.hash_type, value: h.normalized_hash_value }))
          : undefined
      }
    }
  };
}
