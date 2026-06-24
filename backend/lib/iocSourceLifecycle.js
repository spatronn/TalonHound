import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';
import { pickSafeFields } from './auditRedaction.js';
import { serializeIocSourceRow } from './iocSourceValidation.js';

const SOURCE_AUDIT_FIELDS = [
  'name', 'description', 'default_confidence', 'default_threat_classification',
  'default_expire_policy', 'default_expire_days', 'active', 'state', 'archived_at'
];

export function resolveIocSourceState(row) {
  if (!row) return 'active';
  if (row.archived_at) return 'archived';
  if (row.active === false) return 'disabled';
  return 'active';
}

export function isIocSourceSelectable(row) {
  return resolveIocSourceState(row) === 'active';
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {number} sourceId
 */
export async function fetchIocSourceUsageCount(db, sourceId) {
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS ioc_count FROM ioc_items WHERE ioc_source_id = $1`,
    [sourceId]
  );
  return Number(rows[0]?.ioc_count || 0);
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {number} sourceId
 */
export async function fetchIocSourceById(db, sourceId) {
  const { rows } = await db.query(
    `SELECT s.*,
            (SELECT COUNT(*)::int FROM ioc_items i WHERE i.ioc_source_id = s.id) AS ioc_count
     FROM ioc_sources s
     WHERE s.id = $1`,
    [sourceId]
  );
  return rows[0] || null;
}

function serializeSourceWithUsage(row) {
  if (!row) return null;
  const serialized = serializeIocSourceRow(row);
  return {
    ...serialized,
    ioc_count: Number(row.ioc_count ?? serialized.ioc_count ?? 0),
    usage_count: Number(row.ioc_count ?? serialized.ioc_count ?? 0),
    state: resolveIocSourceState(row)
  };
}

const DELETE_BLOCKED_MESSAGE = 'This source contains IOC records. Move them to another source before deleting.';

/**
 * @param {import('pg').Pool} pool
 * @param {number} sourceId
 */
export async function previewIocSourceDelete(pool, sourceId) {
  const row = await fetchIocSourceById(pool, sourceId);
  if (!row) return { status: 404, body: { message: 'IOC source not found' } };

  const iocCount = Number(row.ioc_count || 0);
  const canDelete = iocCount === 0;

  return {
    status: 200,
    body: {
      source_id: Number(row.id),
      source_name: row.name,
      ioc_count: iocCount,
      can_delete: canDelete,
      blocked_reason: canDelete ? null : DELETE_BLOCKED_MESSAGE
    }
  };
}

async function auditSourceAction(audit, req, action, before, after, metadata = {}, severity = AUDIT_SEVERITY.INFO) {
  if (!audit?.auditSuccess || !req) return;
  await audit.auditSuccess({
    req,
    action,
    entityType: AUDIT_ENTITY.IOC_SOURCE,
    entityId: String(after?.id || before?.id),
    entityDisplay: after?.name || before?.name,
    severity,
    before: before ? pickSafeFields(before, SOURCE_AUDIT_FIELDS) : undefined,
    after: after ? pickSafeFields(after, SOURCE_AUDIT_FIELDS) : undefined,
    metadata
  });
}

/**
 * @param {import('pg').Pool} pool
 * @param {number} sourceId
 * @param {boolean} active
 * @param {{ req?: object, audit?: object }} opts
 */
export async function setIocSourceActive(pool, sourceId, active, opts = {}) {
  const row = await fetchIocSourceById(pool, sourceId);
  if (!row) return { status: 404, body: { message: 'IOC source not found' } };
  if (row.archived_at) {
    return { status: 409, body: { message: 'Archived sources cannot be enabled or disabled. Create a new source instead.' } };
  }

  const before = serializeSourceWithUsage(row);
  const { rows } = await pool.query(
    `UPDATE ioc_sources SET active = $2, updated_at = NOW() WHERE id = $1 RETURNING *,
      (SELECT COUNT(*)::int FROM ioc_items i WHERE i.ioc_source_id = ioc_sources.id) AS ioc_count`,
    [sourceId, Boolean(active)]
  );
  const after = serializeSourceWithUsage(rows[0]);
  const action = active ? AUDIT_ACTION.IOC_SOURCE_ENABLED : AUDIT_ACTION.IOC_SOURCE_DISABLED;
  const severity = active ? AUDIT_SEVERITY.INFO : AUDIT_SEVERITY.WARNING;

  await auditSourceAction(opts.audit, opts.req, action, before, after, {
    source_id: after.id,
    source_name: after.name,
    usage_count: after.usage_count,
    ioc_count: after.ioc_count,
    previous_state: before.state,
    new_state: after.state
  }, severity);

  return { status: 200, body: { source: after } };
}

/**
 * @param {import('pg').Pool} pool
 * @param {number} sourceId
 * @param {{ req?: object, audit?: object, user?: object }} opts
 */
export async function archiveIocSource(pool, sourceId, opts = {}) {
  const row = await fetchIocSourceById(pool, sourceId);
  if (!row) return { status: 404, body: { message: 'IOC source not found' } };
  if (row.archived_at) {
    return { status: 409, body: { message: 'IOC source is already archived' } };
  }

  const userId = opts.user?.publicId && /^[0-9a-f-]{36}$/i.test(opts.user.publicId)
    ? opts.user.publicId
    : null;
  const before = serializeSourceWithUsage(row);
  const { rows } = await pool.query(
    `UPDATE ioc_sources
     SET active = FALSE, archived_at = NOW(), archived_by = $2::uuid, updated_at = NOW()
     WHERE id = $1
     RETURNING *,
       (SELECT COUNT(*)::int FROM ioc_items i WHERE i.ioc_source_id = ioc_sources.id) AS ioc_count`,
    [sourceId, userId]
  );
  const after = serializeSourceWithUsage(rows[0]);

  await auditSourceAction(opts.audit, opts.req, AUDIT_ACTION.IOC_SOURCE_ARCHIVED, before, after, {
    source_id: after.id,
    source_name: after.name,
    usage_count: after.usage_count,
    ioc_count: after.ioc_count,
    previous_state: before.state,
    new_state: after.state
  }, AUDIT_SEVERITY.WARNING);

  return { status: 200, body: { source: after } };
}

/**
 * @param {import('pg').Pool} pool
 * @param {number} sourceId
 * @param {{ req?: object, audit?: object }} opts
 */
export async function deleteIocSource(pool, sourceId, opts = {}) {
  const row = await fetchIocSourceById(pool, sourceId);
  if (!row) return { status: 404, body: { message: 'IOC source not found' } };

  const iocCount = Number(row.ioc_count || 0);
  if (iocCount > 0) {
    await auditSourceAction(
      opts.audit,
      opts.req,
      AUDIT_ACTION.IOC_SOURCE_DELETE_BLOCKED_HAS_IOCS,
      serializeSourceWithUsage(row),
      serializeSourceWithUsage(row),
      {
        source_id: row.id,
        source_name: row.name,
        ioc_count: iocCount,
        usage_count: iocCount,
        previous_state: resolveIocSourceState(row),
        new_state: resolveIocSourceState(row)
      },
      AUDIT_SEVERITY.WARNING
    );
    return {
      status: 409,
      body: {
        message: DELETE_BLOCKED_MESSAGE,
        ioc_count: iocCount,
        usage_count: iocCount
      }
    };
  }

  const before = serializeSourceWithUsage(row);
  await pool.query('DELETE FROM ioc_sources WHERE id = $1', [sourceId]);

  await auditSourceAction(opts.audit, opts.req, AUDIT_ACTION.IOC_SOURCE_DELETED, before, null, {
    source_id: before.id,
    source_name: before.name,
    ioc_count: 0,
    usage_count: 0,
    previous_state: before.state,
    new_state: 'deleted'
  }, AUDIT_SEVERITY.WARNING);

  return { status: 200, body: { deleted: true, source_id: sourceId } };
}

export { serializeSourceWithUsage, SOURCE_AUDIT_FIELDS, DELETE_BLOCKED_MESSAGE };
