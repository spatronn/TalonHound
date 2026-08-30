/**
 * Manual, IOC-optional global suppression creation.
 *
 * A user can suppress an indicator that does not yet exist in ioc_items. The
 * suppression row is always global (scope='global', source_name=NULL). If the
 * indicator is later imported from a feed, the normal import lifecycle creates
 * the ioc_items row + membership, and recomputeIocGlobalStatus (which treats an
 * active suppression as the top-priority state) keeps its effective status
 * 'suppressed'.
 */

import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { normalizeSuppressionInput } from './suppressionInput.js';
import { parseRequiredReason } from './reasonValidation.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';

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
 * @param {object} body { ioc_value, ioc_type?, reason, expires_at?, active? }
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

  const { iocValue, iocType } = normalized;
  const reason = reasonCheck.reason;
  const expiresAt = expCheck.expiresAt;
  const createdBy = String(opts.user?.email || opts.user?.username || '').trim() || null;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Duplicate guard (#8): reject if an active, non-deleted suppression already
    // exists for this normalized indicator (regardless of legacy scope).
    const dupQ = await client.query(
      `SELECT id FROM ioc_suppressions
       WHERE lower(ioc_value) = lower($1)
         AND lower(ioc_type) = lower($2)
         AND active = TRUE
         AND deleted_at IS NULL
         AND (expires_at IS NULL OR expires_at > NOW())
       LIMIT 1`,
      [iocValue, iocType]
    );
    if (dupQ.rowCount) {
      await client.query('ROLLBACK');
      return { status: 409, body: { message: 'An active suppression already exists for this IOC.' } };
    }

    // Insert a global suppression. If a disabled/expired global row exists (not
    // deleted), reactivate it in place via the scope unique index.
    let inserted;
    try {
      const insertQ = await client.query(
        `INSERT INTO ioc_suppressions (ioc_value, ioc_type, scope, source_name, reason, created_by, expires_at, active, updated_at)
         VALUES ($1, $2, 'global', NULL, $3, $4, $5, TRUE, NOW())
         ON CONFLICT (lower(ioc_value), lower(ioc_type), scope, COALESCE(lower(source_name), ''))
           WHERE deleted_at IS NULL
         DO UPDATE SET reason = EXCLUDED.reason,
                       created_by = COALESCE(EXCLUDED.created_by, ioc_suppressions.created_by),
                       expires_at = EXCLUDED.expires_at,
                       active = TRUE,
                       deleted_at = NULL,
                       deleted_by = NULL,
                       updated_at = NOW()
         RETURNING *`,
        [iocValue, iocType, reason, createdBy, expiresAt]
      );
      inserted = insertQ.rows[0];
    } catch (err) {
      // Unique violation from uq_ioc_suppressions_one_active_value_type (race).
      if (err?.code === '23505') {
        await client.query('ROLLBACK');
        return { status: 409, body: { message: 'An active suppression already exists for this IOC.' } };
      }
      throw err;
    }

    // If the indicator already exists as an IOC, recompute so its effective
    // status flips to 'suppressed' immediately.
    const iocQ = await client.query(
      `SELECT id, observable_type FROM ioc_items
       WHERE lower(observable) = lower($1) AND lower(observable_type) = lower($2)`,
      [iocValue, iocType]
    );
    for (const iocRow of iocQ.rows || []) {
      await recomputeIocGlobalStatus(client, iocRow.id, iocRow.observable_type, {
        audit: opts.audit,
        actor: { actor_type: 'user', source: 'web' }
      }).catch(() => {});
    }

    await client.query('COMMIT');

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
          status: 'active'
        },
        metadata: {
          manual_add: true,
          ioc_value: iocValue,
          ioc_type: iocType,
          reason,
          created_by: createdBy,
          previous_status: null,
          new_status: 'active',
          ioc_existed: (iocQ.rowCount || 0) > 0
        }
      }).catch((e) => console.warn('[audit] manual suppression create log failed', e?.message || e));
    }

    return { status: 201, body: { status: 'suppressed', suppression: inserted } };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return { status: 500, body: { message: 'Failed to create suppression', detail: err.message } };
  } finally {
    client.release();
  }
}
