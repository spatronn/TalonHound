import { requireRole, ROLES } from '../lib/rbac.js';
import { auditActionLabel } from '../lib/auditConstants.js';

function toPublicAuditRow(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    created_at: row.created_at,
    actor_user_id: row.actor_user_id,
    actor_username: row.actor_username,
    actor_email: row.actor_email,
    actor_role: row.actor_role,
    action: row.action,
    action_label: auditActionLabel(row.action),
    entity_type: row.entity_type,
    entity_id: row.entity_id,
    entity_display: row.entity_display,
    severity: row.severity,
    status: row.status,
    ip_address: row.ip_address,
    user_agent: row.user_agent,
    request_id: row.request_id,
    source: row.source,
    before_data: row.before_data,
    after_data: row.after_data,
    metadata: row.metadata
  };
}

function csvEscape(value) {
  const s = value == null ? '' : String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 */
export function registerAuditLogRoutes(app, pool) {
  app.get('/api/audit-logs', requireRole(ROLES.ADMIN), async (req, res) => {
    const page = Math.max(1, Number(req.query?.page || 1));
    const pageSize = Math.min(100, Math.max(1, Number(req.query?.pageSize || 25)));
    const offset = (page - 1) * pageSize;

    const search = String(req.query?.search || '').trim();
    const action = String(req.query?.action || '').trim();
    const entityType = String(req.query?.entity_type || '').trim();
    const entityId = String(req.query?.entity_id || '').trim();
    const actorUserId = String(req.query?.actor_user_id || '').trim();
    const severity = String(req.query?.severity || '').trim();
    const status = String(req.query?.status || '').trim();
    const dateFrom = String(req.query?.date_from || '').trim();
    const dateTo = String(req.query?.date_to || '').trim();

    const where = ['1=1'];
    const params = [];

    if (search) {
      params.push(`%${search.toLowerCase()}%`);
      const i = params.length;
      where.push(`(
        lower(COALESCE(actor_username, '')) LIKE $${i}
        OR lower(COALESCE(actor_email, '')) LIKE $${i}
        OR lower(COALESCE(entity_display, '')) LIKE $${i}
        OR lower(COALESCE(entity_id, '')) LIKE $${i}
        OR lower(action) LIKE $${i}
        OR lower(entity_type) LIKE $${i}
      )`);
    }
    if (action) {
      params.push(action);
      where.push(`action = $${params.length}`);
    }
    if (entityType) {
      params.push(entityType);
      where.push(`entity_type = $${params.length}`);
    }
    if (entityId) {
      params.push(entityId);
      where.push(`entity_id = $${params.length}`);
    }
    if (actorUserId) {
      params.push(actorUserId);
      where.push(`actor_user_id = $${params.length}::uuid`);
    }
    if (severity) {
      params.push(severity);
      where.push(`severity = $${params.length}`);
    }
    if (status) {
      params.push(status);
      where.push(`status = $${params.length}`);
    }
    if (dateFrom) {
      params.push(dateFrom);
      where.push(`created_at >= $${params.length}::timestamptz`);
    }
    if (dateTo) {
      params.push(dateTo);
      where.push(`created_at <= $${params.length}::timestamptz`);
    }

    const baseWhere = where.join(' AND ');

    try {
      const countQ = await pool.query(
        `SELECT COUNT(*)::int AS total FROM audit_logs WHERE ${baseWhere}`,
        params
      );
      const total = Number(countQ.rows[0]?.total || 0);

      const listParams = [...params, pageSize, offset];
      const listQ = await pool.query(
        `SELECT *
         FROM audit_logs
         WHERE ${baseWhere}
         ORDER BY created_at DESC
         LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
        listParams
      );

      return res.json({
        items: listQ.rows.map(toPublicAuditRow),
        total,
        page,
        pageSize
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list audit logs', detail: err.message });
    }
  });

  app.get('/api/audit-logs/export.csv', requireRole(ROLES.ADMIN), async (req, res) => {
    const search = String(req.query?.search || '').trim();
    const action = String(req.query?.action || '').trim();
    const entityType = String(req.query?.entity_type || '').trim();
    const severity = String(req.query?.severity || '').trim();
    const status = String(req.query?.status || '').trim();
    const dateFrom = String(req.query?.date_from || '').trim();
    const dateTo = String(req.query?.date_to || '').trim();

    const where = ['1=1'];
    const params = [];
    if (search) {
      params.push(`%${search.toLowerCase()}%`);
      const i = params.length;
      where.push(`(
        lower(COALESCE(actor_username, '')) LIKE $${i}
        OR lower(COALESCE(entity_display, '')) LIKE $${i}
        OR lower(action) LIKE $${i}
      )`);
    }
    if (action) { params.push(action); where.push(`action = $${params.length}`); }
    if (entityType) { params.push(entityType); where.push(`entity_type = $${params.length}`); }
    if (severity) { params.push(severity); where.push(`severity = $${params.length}`); }
    if (status) { params.push(status); where.push(`status = $${params.length}`); }
    if (dateFrom) { params.push(dateFrom); where.push(`created_at >= $${params.length}::timestamptz`); }
    if (dateTo) { params.push(dateTo); where.push(`created_at <= $${params.length}::timestamptz`); }

    try {
      const { rows } = await pool.query(
        `SELECT id, created_at, actor_username, actor_email, actor_role, action, entity_type,
                entity_id, entity_display, severity, status, ip_address, source
         FROM audit_logs
         WHERE ${where.join(' AND ')}
         ORDER BY created_at DESC
         LIMIT 10000`,
        params
      );

      const header = [
        'id', 'created_at', 'actor_username', 'actor_email', 'actor_role',
        'action', 'entity_type', 'entity_id', 'entity_display', 'severity', 'status', 'ip_address', 'source'
      ];
      const lines = [header.join(',')];
      for (const row of rows) {
        lines.push(header.map((col) => csvEscape(row[col])).join(','));
      }

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="audit-logs.csv"');
      return res.send(lines.join('\n'));
    } catch (err) {
      return res.status(500).json({ message: 'Failed to export audit logs', detail: err.message });
    }
  });

  app.get('/api/audit-logs/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }

    try {
      const { rows } = await pool.query('SELECT * FROM audit_logs WHERE id = $1', [id]);
      if (!rows.length) return res.status(404).json({ message: 'Audit log not found' });
      return res.json({ item: toPublicAuditRow(rows[0]) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to fetch audit log', detail: err.message });
    }
  });
}
