import { requireRole, ROLES } from '../lib/rbac.js';
import { auditActionLabel } from '../lib/auditConstants.js';
import { buildIocAuditLogsWhere, buildIocAuditMatchContext, isUuid } from '../lib/iocAuditMatch.js';
import {
  parseAuditLimit,
  resolveAuditTimeRange,
  encodeAuditCursor,
  decodeAuditCursor,
  AuditQueryError
} from '../lib/auditLogQuery.js';

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
    subject_ioc_id: row.subject_ioc_id != null ? Number(row.subject_ioc_id) : null,
    subject_ioc_type: row.subject_ioc_type || null,
    subject_ioc_value: row.subject_ioc_value || null,
    target_type: row.target_type || null,
    target_value: row.target_value || null,
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
  app.get('/api/ioc/:id/audit-logs', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    const rawId = String(req.params?.id || '').trim();
    if (!rawId) return res.status(400).json({ message: 'IOC id is required' });

    const limit = Math.min(100, Math.max(1, Number(req.query?.limit || req.query?.pageSize || 50)));

    try {
      const lookupSql = isUuid(rawId)
        ? 'SELECT id, public_id, observable, observable_type FROM ioc_items WHERE public_id = $1::uuid LIMIT 1'
        : 'SELECT id, public_id, observable, observable_type FROM ioc_items WHERE id = $1::bigint LIMIT 1';
      const lookupParam = isUuid(rawId) ? rawId : Number(rawId);
      if (!isUuid(rawId) && (!Number.isFinite(lookupParam) || lookupParam <= 0)) {
        return res.status(400).json({ message: 'Invalid IOC id' });
      }

      const itemRes = await pool.query(lookupSql, [lookupParam]);
      if (!itemRes.rowCount) return res.status(404).json({ message: 'IOC not found' });

      const ctx = buildIocAuditMatchContext(itemRes.rows[0]);
      const { whereSql, params } = buildIocAuditLogsWhere(ctx);
      const listParams = [...params, limit];

      const listQ = await pool.query(
        `SELECT *
         FROM audit_logs
         WHERE ${whereSql}
         ORDER BY created_at DESC
         LIMIT $${listParams.length}`,
        listParams
      );

      return res.json({
        items: listQ.rows.map(toPublicAuditRow),
        total: listQ.rowCount,
        limit
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to fetch IOC audit history', detail: err.message });
    }
  });

  // Time-bounded, keyset-paginated audit log list.
  //
  // The window is enforced server-side: a missing range defaults to Last 24 hours
  // so the endpoint can never fall back to an unbounded history scan. Paging uses
  // a deterministic keyset cursor on (created_at DESC, id DESC) with LIMIT+1 to
  // derive `has_more` — no global COUNT(*) is ever run.
  app.get('/api/audit-logs', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    let range;
    let limit;
    let cursor;
    try {
      // Prefer new `from`/`to`/`limit`; fall back to legacy `date_from`/`date_to`/`pageSize`.
      range = resolveAuditTimeRange({
        from: req.query?.from ?? req.query?.date_from,
        to: req.query?.to ?? req.query?.date_to,
        now: new Date()
      });
      limit = parseAuditLimit(req.query?.limit ?? req.query?.pageSize);
      cursor = decodeAuditCursor(req.query?.cursor);
    } catch (err) {
      if (err instanceof AuditQueryError) {
        return res.status(400).json({ message: err.message });
      }
      return res.status(400).json({ message: 'Invalid audit query' });
    }

    const search = String(req.query?.search || '').trim();
    const action = String(req.query?.action || '').trim();
    const entityType = String(req.query?.entity_type || '').trim();
    const entityId = String(req.query?.entity_id || '').trim();
    const actorUserId = String(req.query?.actor_user_id || '').trim();
    const severity = String(req.query?.severity || '').trim();
    const status = String(req.query?.status || '').trim();

    const where = [];
    const params = [];

    // Enforced time window (lower bound always present).
    params.push(range.from.toISOString());
    where.push(`created_at >= $${params.length}::timestamptz`);
    if (range.to) {
      params.push(range.to.toISOString());
      where.push(`created_at <= $${params.length}::timestamptz`);
    }

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

    // Keyset cursor: rows strictly older than the last row of the previous page,
    // using the same deterministic ordering as ORDER BY (row-value comparison).
    if (cursor) {
      params.push(cursor.created_at);
      const ci = params.length;
      params.push(cursor.id);
      const ii = params.length;
      where.push(`(created_at, id) < ($${ci}::timestamptz, $${ii}::bigint)`);
    }

    const baseWhere = where.join(' AND ');
    // Fetch one extra row to detect a further page without a COUNT(*).
    params.push(limit + 1);

    try {
      const listQ = await pool.query(
        `SELECT *
         FROM audit_logs
         WHERE ${baseWhere}
         ORDER BY created_at DESC, id DESC
         LIMIT $${params.length}`,
        params
      );

      const rows = listQ.rows;
      const hasMore = rows.length > limit;
      const pageRows = hasMore ? rows.slice(0, limit) : rows;
      const last = pageRows[pageRows.length - 1];
      const nextCursor = hasMore && last
        ? encodeAuditCursor({ created_at: last.created_at, id: last.id })
        : null;

      return res.json({
        items: pageRows.map(toPublicAuditRow),
        next_cursor: nextCursor,
        has_more: hasMore,
        limit,
        range: {
          from: range.from.toISOString(),
          to: range.to ? range.to.toISOString() : null
        }
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
    // Accept new from/to aliases alongside the legacy date_from/date_to names.
    const dateFrom = String(req.query?.from ?? req.query?.date_from ?? '').trim();
    const dateTo = String(req.query?.to ?? req.query?.date_to ?? '').trim();

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

  app.get('/api/audit-logs/:id', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
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
