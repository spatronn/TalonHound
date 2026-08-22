import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { API_SYSTEM_SOURCE_NAME } from './apiSystemSource.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';
import { formatIocEntityDisplay } from './auditIocContext.js';

/**
 * A manual/custom source can be detached from an IOC; a feed-managed source
 * cannot (feed lifecycle is owned by ingestion). Source capability is derived
 * from authoritative DB state (ioc_sources.source_type / name), never trusted
 * from the client. The REST system provenance source ("API") is also protected.
 *
 * @param {{ source_type?: string|null, name?: string|null }} sourceRow
 */
export function isManualRemovableSource(sourceRow) {
  if (!sourceRow) return false;
  if (String(sourceRow.source_type || '').toLowerCase() === 'feed') return false;
  if (String(sourceRow.name || '') === API_SYSTEM_SOURCE_NAME) return false;
  return true;
}

const REMOVAL_REASON = 'manually_removed';

function resolveActorUserId(user) {
  return user?.publicId && /^[0-9a-f-]{36}$/i.test(user.publicId) ? user.publicId : null;
}

/**
 * Remove a single manual/custom source membership from an IOC without deleting
 * the IOC entity or destroying source history. The removed membership is written
 * to ioc_manual_source_memberships as a 'removed' tombstone; the IOC's effective
 * status is recomputed via the canonical lifecycle calculator using a surviving
 * sibling row (manual siblings preferred so an active feed recompute never
 * clobbers a still-active manual source). Idempotent and concurrency-safe: the
 * target row is locked FOR UPDATE, so a replayed/concurrent request finds no
 * active association and performs no state transition and emits no audit event.
 *
 * @param {import('pg').Pool} pool
 * @param {{ publicId: string, sourceId: number }} params
 * @param {{ req?: object, user?: object, audit?: object }} [opts]
 * @returns {Promise<{ status: number, body: object }>}
 */
export async function removeIocManualSource(pool, { publicId, sourceId }, opts = {}) {
  const pubId = String(publicId || '').trim();
  if (!pubId) return { status: 400, body: { error: 'invalid_public_id', message: 'valid public_id is required' } };

  const numericSourceId = Number(sourceId);
  if (!Number.isFinite(numericSourceId) || numericSourceId <= 0) {
    return { status: 400, body: { error: 'invalid_source_id', message: 'valid source id is required' } };
  }

  // Resolve the observable from any ioc_items row carrying this public_id.
  const seedQ = await pool.query(
    `SELECT observable, observable_type FROM ioc_items WHERE public_id = $1::uuid LIMIT 1`,
    [pubId]
  );
  const seed = seedQ.rows[0];
  if (!seed) return { status: 404, body: { error: 'ioc_not_found', message: 'IOC not found' } };
  const observable = seed.observable;
  const observableType = seed.observable_type;

  // Authoritative source-type check (never trust the client on removability).
  const sourceQ = await pool.query(
    `SELECT id, name, source_type FROM ioc_sources WHERE id = $1`,
    [numericSourceId]
  );
  const sourceRow = sourceQ.rows[0];
  if (!sourceRow) return { status: 404, body: { error: 'source_not_found', message: 'IOC source not found' } };

  if (String(sourceRow.source_type || '').toLowerCase() === 'feed') {
    return {
      status: 400,
      body: {
        error: 'feed_source_not_removable',
        message: 'Feed-managed sources cannot be removed manually. Feed membership is controlled by the feed lifecycle.'
      }
    };
  }
  if (!isManualRemovableSource(sourceRow)) {
    return {
      status: 400,
      body: {
        error: 'source_not_removable',
        message: 'This source cannot be removed from an IOC.'
      }
    };
  }

  const userId = resolveActorUserId(opts.user);

  const client = await pool.connect();
  let removedRow = null;
  let canonicalPublicId = null;
  let recomputedStatus = null;
  try {
    await client.query('BEGIN');

    // Lock the manual membership row (if any) to serialize concurrent removals.
    const targetQ = await client.query(
      `SELECT id, public_id, observable, observable_type, source_name, status,
              confidence, confidence_source, confidence_source_name, manual_expires_at,
              created_at, last_seen_at
       FROM ioc_items
       WHERE observable = $1 AND observable_type = $2 AND ioc_source_id = $3
       ORDER BY id
       FOR UPDATE`,
      [observable, observableType, numericSourceId]
    );

    const target = targetQ.rows[0];
    if (!target) {
      // No live membership. Distinguish "already removed" (idempotent replay) from
      // "never associated" using the preserved history tombstone.
      const histQ = await client.query(
        `SELECT 1 FROM ioc_manual_source_memberships
         WHERE ioc_observable_type = $1 AND ioc_source_id = $2 AND status = 'removed'
           AND ioc_item_id IN (
             SELECT id FROM ioc_items WHERE observable = $3 AND observable_type = $1
           )
         LIMIT 1`,
        [observableType, numericSourceId, observable]
      );
      await client.query('ROLLBACK');
      if (histQ.rows.length) {
        return {
          status: 409,
          body: {
            error: 'source_already_removed',
            message: 'This source has already been removed from the IOC.'
          }
        };
      }
      return {
        status: 404,
        body: {
          error: 'association_not_found',
          message: 'This source is not associated with the IOC.'
        }
      };
    }

    if (String(target.status || 'active').toLowerCase() !== 'active') {
      await client.query('ROLLBACK');
      return {
        status: 409,
        body: {
          error: 'association_not_active',
          message: 'This source association is not currently active and cannot be removed.'
        }
      };
    }

    // Preserve a truthful history tombstone before detaching the membership.
    await client.query(
      `INSERT INTO ioc_manual_source_memberships (
         ioc_item_id, ioc_observable_type, ioc_source_id, source_name, status,
         confidence, confidence_source, confidence_source_name, manual_expires_at,
         moved_to_source_id, moved_at, moved_by, move_reason,
         first_seen_at, last_seen_at
       )
       VALUES (
         $1, $2, $3, COALESCE($4, $5), 'removed',
         $6, $7, $8, $9,
         NULL, NOW(), $10::uuid, $11,
         $12, COALESCE($13, $12)
       )
       ON CONFLICT (ioc_item_id, ioc_observable_type, ioc_source_id) DO UPDATE SET
         status = 'removed',
         moved_to_source_id = NULL,
         moved_at = NOW(),
         moved_by = EXCLUDED.moved_by,
         move_reason = EXCLUDED.move_reason,
         last_seen_at = EXCLUDED.last_seen_at`,
      [
        target.id,
        observableType,
        numericSourceId,
        target.source_name,
        sourceRow.name,
        target.confidence,
        target.confidence_source,
        target.confidence_source_name,
        target.manual_expires_at,
        userId,
        REMOVAL_REASON,
        target.created_at,
        target.last_seen_at
      ]
    );

    // Detach the manual membership. This removes only this (observable, source)
    // row; sibling rows (other manual sources, feed rows) and all history remain.
    await client.query(
      `DELETE FROM ioc_items WHERE id = $1 AND observable_type = $2`,
      [target.id, observableType]
    );

    // Pick a surviving sibling to recompute the IOC's effective status. Manual
    // (ioc_source_id NOT NULL) rows are preferred so the feed-branch blanket
    // status update never clobbers a still-active manual sibling.
    const survivorQ = await client.query(
      `SELECT id, public_id
       FROM ioc_items
       WHERE observable = $1 AND observable_type = $2
       ORDER BY (ioc_source_id IS NOT NULL) DESC, id ASC
       LIMIT 1`,
      [observable, observableType]
    );
    const survivor = survivorQ.rows[0] || null;
    canonicalPublicId = survivor?.public_id || null;

    if (survivor) {
      const recompute = await recomputeIocGlobalStatus(client, survivor.id, observableType, {
        audit: opts.audit,
        actor: { actor_type: 'user', source: 'web' }
      });
      recomputedStatus = recompute?.status ?? null;
    }

    removedRow = target;
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[ioc-source-removal] failed', {
      publicId: pubId,
      sourceId: numericSourceId,
      code: err.code,
      message: err.message
    });
    return {
      status: 500,
      body: { error: 'removal_failed', message: 'Failed to remove IOC from source', detail: err.message }
    };
  } finally {
    client.release();
  }

  // Audit only after a real state transition committed (never on a no-op).
  if (opts.audit?.auditSuccess && opts.req) {
    await opts.audit.auditSuccess({
      req: opts.req,
      action: AUDIT_ACTION.IOC_SOURCE_REMOVED,
      entityType: AUDIT_ENTITY.IOC,
      entityId: removedRow.public_id ? String(removedRow.public_id) : String(removedRow.id),
      entityDisplay: formatIocEntityDisplay(observableType, observable),
      subjectIocId: removedRow.id,
      subjectIocType: observableType,
      subjectIocValue: observable,
      severity: AUDIT_SEVERITY.WARNING,
      metadata: {
        ioc_id: removedRow.id,
        ioc_public_id: removedRow.public_id || null,
        observable,
        observable_type: observableType,
        source_id: numericSourceId,
        source_name: sourceRow.name,
        source_type: sourceRow.source_type || 'manual',
        action: REMOVAL_REASON,
        canonical_public_id: canonicalPublicId,
        recomputed_status: recomputedStatus
      }
    }).catch(() => {});
  }

  return {
    status: 200,
    body: {
      removed: true,
      ioc_id: removedRow.id,
      removed_public_id: removedRow.public_id || null,
      observable,
      observable_type: observableType,
      source_id: numericSourceId,
      source_name: sourceRow.name,
      source_type: sourceRow.source_type || 'manual',
      canonical_public_id: canonicalPublicId,
      status: recomputedStatus
    }
  };
}
