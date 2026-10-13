/**
 * Manual, IOC-optional global suppression creation.
 *
 * A user can suppress an indicator that does not yet exist in ioc_items. The
 * suppression row is always global (scope='global', source_name=NULL). If the
 * indicator is later imported from a feed, the normal import lifecycle creates
 * the ioc_items row + membership, and recomputeIocGlobalStatus (which treats an
 * active suppression as the top-priority state) keeps its effective status
 * 'suppressed'.
 *
 * Hash scope:
 *   - hash_scope='exact' (default for this manual path): only (type, value)
 *   - hash_scope='file': only when the hash uniquely resolves to a proven
 *     file_artifact; sets file_artifact_id so all proven aliases are covered.
 */

import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { normalizeSuppressionInput } from './suppressionInput.js';
import { parseRequiredReason } from './reasonValidation.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';
import {
  resolveSurvivorArtifactIdForHash,
  loadProvenHashesForArtifact,
  loadLinkedIocsForArtifact,
  describeSuppressionScope,
  normalizeHashScopePreference,
  isFileHashSuppressionType
} from './iocSuppressionFileScope.js';

export const SUPPRESSION_REASON_MIN = 3;
export const SUPPRESSION_REASON_MAX = 500;

/**
 * @returns {{ ok: true, expiresAt: string|null } | { ok: false, message: string }}
 */
export function parseSuppressionExpiration(raw, now = new Date()) {
  if (raw == null || String(raw).trim() === '' || String(raw).trim().toLowerCase() === 'never') {
    return { ok: true, expiresAt: null };
  }
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return { ok: false, message: 'Invalid expiration date' };
  if (d.getTime() <= now.getTime()) return { ok: false, message: 'Expiration must be in the future' };
  return { ok: true, expiresAt: d.toISOString() };
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} body { ioc_value, ioc_type?, reason, expires_at?, active?, hash_scope? }
 * @param {{ req?: object, user?: object, audit?: object }} [opts]
 * @returns {Promise<{ status: number, body: object }>}
 */
export async function createManualSuppression(pool, body, opts = {}) {
  const normalized = normalizeSuppressionInput({
    ioc_value: body?.ioc_value ?? body?.observable,
    ioc_type: body?.ioc_type
  });
  if (!normalized.ok) return { status: 400, body: { message: normalized.message } };

  const reasonCheck = parseRequiredReason(body?.reason, {
    field: 'reason',
    minLength: SUPPRESSION_REASON_MIN,
    maxLength: SUPPRESSION_REASON_MAX
  });
  if (!reasonCheck.ok) return { status: 400, body: { message: reasonCheck.message } };

  const expCheck = parseSuppressionExpiration(body?.expires_at);
  if (!expCheck.ok) return { status: 400, body: { message: expCheck.message } };

  const rawScope = body?.hash_scope ?? body?.suppression_scope ?? body?.identity_scope;
  let hashScope = normalizeHashScopePreference(rawScope);
  if (hashScope == null) hashScope = 'exact'; // manual path default: never silent file expansion
  if (rawScope != null && String(rawScope).trim() !== '' && normalizeHashScopePreference(rawScope) == null) {
    return { status: 400, body: { message: 'hash_scope must be "file" or "exact"' } };
  }

  const { iocValue, iocType } = normalized;
  const reason = reasonCheck.reason;
  const expiresAt = expCheck.expiresAt;
  const createdBy = String(opts.user?.email || opts.user?.username || '').trim() || null;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    let artifactId = null;
    if (hashScope === 'file') {
      if (!isFileHashSuppressionType(iocType)) {
        await client.query('ROLLBACK');
        return { status: 400, body: { message: 'File scope is only valid for md5/sha1/sha256' } };
      }
      artifactId = await resolveSurvivorArtifactIdForHash(client, iocType, iocValue);
      if (!artifactId) {
        await client.query('ROLLBACK');
        return {
          status: 400,
          body: { message: 'Cannot resolve this hash to a verified canonical file. Use exact hash scope instead.' }
        };
      }
    }

    // Duplicate / scope-conflict guard (one active row per value+type).
    const samePairQ = await client.query(
      `SELECT id, file_artifact_id FROM ioc_suppressions
       WHERE active = TRUE
         AND deleted_at IS NULL
         AND lower(ioc_value) = lower($1)
         AND lower(ioc_type) = lower($2)
       LIMIT 1`,
      [iocValue, iocType]
    );
    if (samePairQ.rowCount) {
      await client.query('ROLLBACK');
      const existingIsFile = Boolean(samePairQ.rows[0].file_artifact_id);
      if (!artifactId && existingIsFile) {
        return {
          status: 409,
          body: {
            message: 'A file-level suppression already covers this hash. Disable or delete it before creating an exact-hash suppression for the same value.'
          }
        };
      }
      return { status: 409, body: { message: 'An active suppression already exists for this IOC.' } };
    }
    if (artifactId) {
      const fileDupQ = await client.query(
        `SELECT id FROM ioc_suppressions
         WHERE active = TRUE
           AND deleted_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW())
           AND file_artifact_id = $1::uuid
         LIMIT 1`,
        [artifactId]
      );
      if (fileDupQ.rowCount) {
        await client.query('ROLLBACK');
        return { status: 409, body: { message: 'An active file-level suppression already exists for this canonical file.' } };
      }
    }

    let inserted;
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

    const recomputeTargets = new Map();
    if (artifactId) {
      const linked = await loadLinkedIocsForArtifact(client, artifactId);
      for (const row of linked) {
        recomputeTargets.set(`${row.observable_type}\t${row.id}`, row);
      }
    }
    const iocQ = await client.query(
      `SELECT id, observable_type FROM ioc_items
       WHERE lower(observable) = lower($1) AND lower(observable_type) = lower($2)`,
      [iocValue, iocType]
    );
    for (const iocRow of iocQ.rows || []) {
      recomputeTargets.set(`${iocRow.observable_type}\t${iocRow.id}`, iocRow);
    }
    for (const iocRow of recomputeTargets.values()) {
      await recomputeIocGlobalStatus(client, iocRow.id, iocRow.observable_type, {
        audit: opts.audit,
        actor: { actor_type: 'user', source: 'web' }
      }).catch(() => {});
    }

    await client.query('COMMIT');

    let knownHashes = [];
    try {
      knownHashes = artifactId ? await loadProvenHashesForArtifact(pool, artifactId) : [];
    } catch {
      knownHashes = [];
    }
    const scopeInfo = describeSuppressionScope(inserted, knownHashes.length || null);

    if (opts.audit?.auditSuccess && opts.req) {
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
          reason: inserted.reason,
          expires_at: inserted.expires_at,
          status: 'active',
          file_artifact_id: inserted.file_artifact_id || null,
          suppression_scope: scopeInfo.kind
        },
        metadata: {
          manual_add: true,
          ioc_value: iocValue,
          ioc_type: iocType,
          reason,
          created_by: createdBy,
          previous_status: null,
          new_status: 'active',
          ioc_existed: (iocQ.rowCount || 0) > 0,
          hash_scope: hashScope,
          file_artifact_id: inserted.file_artifact_id || null,
          suppression_scope: scopeInfo.kind
        }
      }).catch((e) => console.warn('[audit] manual suppression create log failed', e?.message || e));
    }

    return {
      status: 201,
      body: {
        status: 'suppressed',
        suppression: {
          ...inserted,
          suppression_scope: scopeInfo,
          covered_hashes: knownHashes.length
            ? knownHashes.map((h) => ({ hash_type: h.hash_type, value: h.normalized_hash_value }))
            : [{ hash_type: iocType, value: iocValue }],
          covered_hash_count: knownHashes.length || 1
        }
      }
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return { status: 500, body: { message: 'Failed to create suppression', detail: err.message } };
  } finally {
    client.release();
  }
}
