import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { resolveManualExpirationFromSource } from './manualIocCreate.js';
import { archiveIocSource, fetchIocSourceById, fetchIocSourceUsageCount } from './iocSourceLifecycle.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';

function normalizeScope() {
  return 'all';
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {number} sourceId
 * @param {number} targetSourceId
 */
async function fetchMoveCandidates(db, sourceId, targetSourceId) {
  const { rows } = await db.query(
    `SELECT i.id,
            i.observable,
            i.observable_type,
            i.status,
            i.confidence,
            i.confidence_source,
            i.confidence_source_name,
            i.manual_expires_at,
            i.source_name,
            i.created_at,
            i.last_seen_at,
            EXISTS (
              SELECT 1
              FROM ioc_items t
              WHERE t.observable = i.observable
                AND t.observable_type = i.observable_type
                AND t.ioc_source_id = $2
                AND t.id <> i.id
            ) AS target_exists
     FROM ioc_items i
     WHERE i.ioc_source_id = $1
     ORDER BY i.id`,
    [sourceId, targetSourceId]
  );
  return rows;
}

function summarizeMovePreview(sourceFrom, sourceTo, candidates) {
  let willMove = 0;
  let willMerge = 0;

  for (const row of candidates) {
    if (row.target_exists) willMerge += 1;
    else willMove += 1;
  }

  return {
    source_id: Number(sourceFrom.id),
    source_name: sourceFrom.name,
    target_source_id: Number(sourceTo.id),
    target_source_name: sourceTo.name,
    ioc_count: candidates.length,
    will_move: willMove,
    will_merge: willMerge,
    will_skip: 0,
    source_will_be_empty_after_move: candidates.length > 0
  };
}

function resolveApplyTargetDefaults(body) {
  if (body?.apply_target_defaults === undefined) return true;
  return Boolean(body.apply_target_defaults);
}

/**
 * @param {import('pg').Pool} pool
 * @param {number} sourceId
 * @param {object} body
 */
export async function previewIocSourceMove(pool, sourceId, body = {}) {
  const targetSourceId = Number(body.target_source_id);
  if (!Number.isFinite(targetSourceId) || targetSourceId <= 0) {
    return { status: 400, body: { message: 'target_source_id is required' } };
  }
  if (targetSourceId === sourceId) {
    return { status: 400, body: { message: 'Target source must differ from the source being moved' } };
  }

  const sourceFrom = await fetchIocSourceById(pool, sourceId);
  if (!sourceFrom) return { status: 404, body: { message: 'Source not found' } };

  const sourceTo = await fetchIocSourceById(pool, targetSourceId);
  if (!sourceTo) return { status: 400, body: { message: 'Target source not found' } };
  if (sourceTo.archived_at) {
    return { status: 400, body: { message: 'Target source is archived' } };
  }
  if (sourceTo.active === false) {
    return { status: 400, body: { message: 'Target source is disabled' } };
  }

  const candidates = await fetchMoveCandidates(pool, sourceId, targetSourceId);
  if (!candidates.length) {
    return { status: 400, body: { message: 'This source has no IOC records to move' } };
  }

  return { status: 200, body: summarizeMovePreview(sourceFrom, sourceTo, candidates) };
}

function buildTargetDefaults(targetSource, applyDefaults) {
  if (!applyDefaults) return null;
  const expiration = resolveManualExpirationFromSource(targetSource);
  if (!expiration.ok) return null;
  return {
    confidence: targetSource.default_confidence || 'medium',
    confidence_source: 'ioc_source_default',
    confidence_source_name: String(targetSource.name),
    default_threat_classification: targetSource.default_threat_classification || 'unknown',
    manual_expires_at: expiration.manual_expires_at,
    manual_override_reason: expiration.manual_override_reason
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {number} sourceId
 * @param {object} body
 * @param {{ req?: object, audit?: object, user?: object }} opts
 */
export async function executeIocSourceMove(pool, sourceId, body = {}, opts = {}) {
  const preview = await previewIocSourceMove(pool, sourceId, body);
  if (preview.status !== 200) return preview;

  const targetSourceId = Number(body.target_source_id);
  const applyDefaults = resolveApplyTargetDefaults(body);
  const archiveAfter = Boolean(body.archive_source_after_move);
  const userId = opts.user?.publicId && /^[0-9a-f-]{36}$/i.test(opts.user.publicId)
    ? opts.user.publicId
    : null;

  const sourceFrom = await fetchIocSourceById(pool, sourceId);
  const sourceTo = await fetchIocSourceById(pool, targetSourceId);
  const targetDefaults = buildTargetDefaults(sourceTo, applyDefaults);
  const candidates = await fetchMoveCandidates(pool, sourceId, targetSourceId);

  const client = await pool.connect();
  const affectedObservables = new Set();
  let moved = 0;
  let merged = 0;

  try {
    await client.query('BEGIN');

    await client.query(
      `INSERT INTO ioc_manual_source_memberships (
         ioc_item_id, ioc_observable_type, ioc_source_id, source_name, status,
         confidence, confidence_source, confidence_source_name, manual_expires_at,
         moved_to_source_id, moved_at, moved_by, move_reason,
         first_seen_at, last_seen_at
       )
       SELECT i.id,
              i.observable_type,
              i.ioc_source_id,
              COALESCE(i.source_name, $3),
              'moved',
              i.confidence,
              i.confidence_source,
              i.confidence_source_name,
              i.manual_expires_at,
              $2,
              NOW(),
              $4::uuid,
              'membership_reassigned',
              i.created_at,
              COALESCE(i.last_seen_at, i.created_at)
       FROM ioc_items i
       WHERE i.ioc_source_id = $1
       ON CONFLICT (ioc_item_id, ioc_observable_type, ioc_source_id) DO UPDATE SET
         status = EXCLUDED.status,
         moved_to_source_id = EXCLUDED.moved_to_source_id,
         moved_at = EXCLUDED.moved_at,
         moved_by = EXCLUDED.moved_by,
         move_reason = EXCLUDED.move_reason,
         last_seen_at = EXCLUDED.last_seen_at`,
      [sourceId, targetSourceId, sourceFrom.name, userId]
    );

    if (applyDefaults && targetDefaults) {
      const moveRes = await client.query(
        `UPDATE ioc_items i
         SET ioc_source_id = $2,
             source_name = $3,
             confidence = CASE
               WHEN i.confidence_source = 'analyst_override' THEN i.confidence
               ELSE $4
             END,
             confidence_source = CASE
               WHEN i.confidence_source = 'analyst_override' THEN i.confidence_source
               ELSE $5
             END,
             confidence_source_name = CASE
               WHEN i.confidence_source = 'analyst_override' THEN i.confidence_source_name
               ELSE $6
             END,
             threat_classification = CASE
               WHEN i.confidence_source = 'analyst_override' THEN i.threat_classification
               ELSE COALESCE($7, i.threat_classification)
             END,
             manual_expires_at = CASE
               WHEN i.confidence_source = 'analyst_override' THEN i.manual_expires_at
               ELSE $8
             END,
             manual_override_reason = CASE
               WHEN i.confidence_source = 'analyst_override' THEN i.manual_override_reason
               ELSE $9
             END,
             manual_status_override = TRUE,
             manual_status = 'active'
         WHERE i.ioc_source_id = $1
           AND NOT EXISTS (
             SELECT 1 FROM ioc_items t
             WHERE t.observable = i.observable
               AND t.observable_type = i.observable_type
               AND t.ioc_source_id = $2
               AND t.id <> i.id
           )
         RETURNING i.id, i.observable, i.observable_type`,
        [
          sourceId,
          targetSourceId,
          sourceTo.name,
          targetDefaults.confidence,
          targetDefaults.confidence_source,
          targetDefaults.confidence_source_name,
          targetDefaults.default_threat_classification,
          targetDefaults.manual_expires_at,
          targetDefaults.manual_override_reason
        ]
      );
      moved = moveRes.rowCount || 0;
      for (const row of moveRes.rows) {
        affectedObservables.add(`${row.observable_type}|${row.observable}`);
      }
    } else {
      const moveRes = await client.query(
        `UPDATE ioc_items i
         SET ioc_source_id = $2,
             source_name = $3
         WHERE i.ioc_source_id = $1
           AND NOT EXISTS (
             SELECT 1 FROM ioc_items t
             WHERE t.observable = i.observable
               AND t.observable_type = i.observable_type
               AND t.ioc_source_id = $2
               AND t.id <> i.id
           )
         RETURNING i.id, i.observable, i.observable_type`,
        [sourceId, targetSourceId, sourceTo.name]
      );
      moved = moveRes.rowCount || 0;
      for (const row of moveRes.rows) {
        affectedObservables.add(`${row.observable_type}|${row.observable}`);
      }
    }

    const mergeRes = await client.query(
      `WITH merged AS (
         SELECT s.id AS source_item_id,
                t.id AS target_item_id,
                GREATEST(
                  COALESCE(t.last_seen_at, t.created_at),
                  COALESCE(s.last_seen_at, s.created_at)
                ) AS merged_last_seen
         FROM ioc_items s
         INNER JOIN ioc_items t
           ON t.observable = s.observable
          AND t.observable_type = s.observable_type
          AND t.ioc_source_id = $2
          AND t.id <> s.id
         WHERE s.ioc_source_id = $1
       ),
       updated AS (
         UPDATE ioc_items t
         SET last_seen_at = m.merged_last_seen
         FROM merged m
         WHERE t.id = m.target_item_id
         RETURNING t.observable, t.observable_type
       ),
       deleted AS (
         DELETE FROM ioc_items s
         USING merged m
         WHERE s.id = m.source_item_id
         RETURNING s.observable, s.observable_type
       )
       SELECT (SELECT COUNT(*)::int FROM deleted) AS merged_sources`,
      [sourceId, targetSourceId]
    );
    merged = Number(mergeRes.rows[0]?.merged_sources || 0);

    for (const c of candidates) {
      affectedObservables.add(`${c.observable_type}|${c.observable}`);
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (opts.audit?.auditSuccess && opts.req) {
      await opts.audit.auditSuccess({
        req: opts.req,
        action: AUDIT_ACTION.IOC_SOURCE_MOVE_FAILED,
        entityType: AUDIT_ENTITY.IOC_SOURCE,
        entityId: String(sourceId),
        entityDisplay: sourceFrom.name,
        severity: AUDIT_SEVERITY.ERROR,
        metadata: {
          source_from_id: sourceId,
          source_from_name: sourceFrom.name,
          source_to_id: targetSourceId,
          source_to_name: sourceTo.name,
          error: err.message
        }
      });
    }
    return { status: 500, body: { message: 'Failed to move IOC records', detail: err.message } };
  } finally {
    client.release();
  }

  for (const key of affectedObservables) {
    const [observableType, observable] = key.split('|');
    const idRes = await pool.query(
      `SELECT id FROM ioc_items WHERE observable = $1 AND observable_type = $2 ORDER BY created_at DESC LIMIT 1`,
      [observable, observableType]
    );
    const iocId = idRes.rows[0]?.id;
    if (iocId) {
      await recomputeIocGlobalStatus(pool, iocId, observableType, {
        audit: opts.audit,
        actor: { actor_type: 'user', source: 'web' }
      }).catch(() => {});
    }
  }

  const sourceIocCountAfter = await fetchIocSourceUsageCount(pool, sourceId);
  const targetIocCountAfter = await fetchIocSourceUsageCount(pool, targetSourceId);

  let archivedSource = false;
  if (archiveAfter) {
    const archiveResult = await archiveIocSource(pool, sourceId, opts);
    archivedSource = archiveResult.status === 200;
    if (archivedSource && opts.audit?.auditSuccess && opts.req) {
      await opts.audit.auditSuccess({
        req: opts.req,
        action: AUDIT_ACTION.IOC_SOURCE_ARCHIVED_AFTER_MOVE,
        entityType: AUDIT_ENTITY.IOC_SOURCE,
        entityId: String(sourceId),
        entityDisplay: sourceFrom.name,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          source_id: sourceId,
          source_name: sourceFrom.name,
          target_source_id: targetSourceId,
          target_source_name: sourceTo.name
        }
      });
    }
  }

  const response = {
    source_id: sourceId,
    target_source_id: targetSourceId,
    matched: candidates.length,
    moved,
    merged,
    skipped: Math.max(0, candidates.length - moved - merged),
    source_ioc_count_after: sourceIocCountAfter,
    target_ioc_count_after: targetIocCountAfter,
    archived_source: archivedSource,
    errors: []
  };

  if (opts.audit?.auditSuccess && opts.req) {
    await opts.audit.auditSuccess({
      req: opts.req,
      action: AUDIT_ACTION.IOC_SOURCE_IOCS_MOVED,
      entityType: AUDIT_ENTITY.IOC_SOURCE,
      entityId: String(sourceId),
      entityDisplay: sourceFrom.name,
      severity: AUDIT_SEVERITY.INFO,
      metadata: {
        source_from_id: sourceId,
        source_from_name: sourceFrom.name,
        source_to_id: targetSourceId,
        source_to_name: sourceTo.name,
        ioc_count: candidates.length,
        apply_target_defaults: applyDefaults,
        archive_source_after_move: archiveAfter,
        matched: response.matched,
        moved: response.moved,
        merged: response.merged,
        skipped: response.skipped,
        source_ioc_count_after: sourceIocCountAfter,
        target_ioc_count_after: targetIocCountAfter,
        archived_source: archivedSource
      }
    });
  }

  return { status: 200, body: response };
}

export { normalizeScope, summarizeMovePreview, fetchMoveCandidates, resolveApplyTargetDefaults };
