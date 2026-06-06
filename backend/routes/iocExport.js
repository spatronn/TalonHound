import { requireRole, ROLES } from '../lib/rbac.js';
import { csvEscape, parseIocExportQuery } from '../lib/iocExportHelpers.js';

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 */
export function registerIocExportRoutes(app, pool) {
  app.get('/api/iocs/export', requireRole(ROLES.ADMIN), async (req, res) => {
    const parsed = parseIocExportQuery(req.query);
    if (!parsed.ok) return res.status(400).json({ message: parsed.message });

    const { format, page, pageSize, offset, filters } = parsed;
    const where = [];
    const params = [];

    if (filters.type) {
      if (filters.type === 'file_hash') {
        where.push(`i.observable_type IN ('md5','sha1','sha256','ssdeep','imphash','tlsh')`);
      } else if (filters.type === 'ip') {
        where.push(`i.observable_type IN ('ip','ip6')`);
      } else {
        params.push(filters.type);
        where.push(`i.observable_type = $${params.length}`);
      }
    }

    if (filters.confidence) {
      params.push(filters.confidence);
      where.push(`LOWER(i.confidence) = $${params.length}`);
    }

    if (filters.source) {
      params.push(`%${filters.source}%`);
      where.push(`i.source_name ILIKE $${params.length}`);
    }

    if (filters.since) {
      params.push(filters.since);
      where.push(`i.last_seen_at >= $${params.length}::timestamptz`);
    }

    if (filters.q) {
      params.push(`%${filters.q}%`);
      where.push(`(i.observable ILIKE $${params.length} OR i.source_name ILIKE $${params.length})`);
    }

    if (filters.status === 'expired') {
      where.push(`COALESCE(i.status, 'active') = 'expired'`);
    } else if (filters.status === 'active') {
      where.push(`COALESCE(i.status, 'active') = 'active'`);
    } else if (filters.status === 'suppressed') {
      where.push(`EXISTS (
        SELECT 1 FROM ioc_suppressions s
        WHERE s.active = TRUE
          AND LOWER(s.ioc_value) = LOWER(i.observable)
          AND LOWER(s.ioc_type) = LOWER(i.observable_type)
      )`);
    } else if (!filters.include_expired) {
      where.push(`COALESCE(i.status, 'active') <> 'expired'`);
    }

    if (!filters.include_suppressed && filters.status !== 'suppressed') {
      where.push(`NOT EXISTS (
        SELECT 1 FROM ioc_suppressions s
        WHERE s.active = TRUE
          AND LOWER(s.ioc_value) = LOWER(i.observable)
          AND LOWER(s.ioc_type) = LOWER(i.observable_type)
      )`);
    }

    if (filters.tag) {
      params.push(filters.tag);
      where.push(`EXISTS (
        SELECT 1 FROM ioc_item_tags it
        JOIN ioc_tags t ON t.id = it.tag_id
        WHERE it.ioc_item_id = i.id AND LOWER(t.name) = LOWER($${params.length})
      )`);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    try {
      const countQ = await pool.query(`SELECT COUNT(*)::bigint AS total FROM ioc_items i ${whereSql}`, params);
      const total = Number(countQ.rows[0]?.total || 0);

      params.push(pageSize);
      const limitIdx = params.length;
      params.push(offset);
      const offsetIdx = params.length;

      const rowsQ = await pool.query(
        `SELECT
           i.observable AS ioc_value,
           i.observable_type AS ioc_type,
           i.confidence,
           COALESCE(i.status, 'active') AS status,
           i.source_name AS source,
           i.first_seen_at,
           i.last_seen_at,
           i.expires_at,
           COALESCE(tags.names, ARRAY[]::text[]) AS tags
         FROM ioc_items i
         LEFT JOIN LATERAL (
           SELECT ARRAY_AGG(DISTINCT t.name ORDER BY t.name) AS names
           FROM ioc_item_tags it
           JOIN ioc_tags t ON t.id = it.tag_id
           WHERE it.ioc_item_id = i.id
         ) tags ON TRUE
         ${whereSql}
         ORDER BY i.last_seen_at DESC NULLS LAST, i.id DESC
         LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
        params
      );

      const items = rowsQ.rows.map((row) => ({
        ioc_value: row.ioc_value,
        ioc_type: row.ioc_type,
        confidence: row.confidence,
        status: row.status,
        source: row.source,
        first_seen: row.first_seen_at,
        last_seen: row.last_seen_at,
        expires_at: row.expires_at,
        tags: row.tags || []
      }));

      const pagination = {
        page,
        page_size: pageSize,
        total,
        total_pages: Math.max(1, Math.ceil(total / pageSize))
      };

      if (format === 'json') {
        return res.json({ items, pagination, filters });
      }

      const header = ['ioc_value', 'ioc_type', 'confidence', 'status', 'source', 'first_seen', 'last_seen', 'expires_at', 'tags'];
      const lines = [header.join(',')];
      for (const item of items) {
        lines.push([
          csvEscape(item.ioc_value),
          csvEscape(item.ioc_type),
          csvEscape(item.confidence),
          csvEscape(item.status),
          csvEscape(item.source),
          csvEscape(item.first_seen),
          csvEscape(item.last_seen),
          csvEscape(item.expires_at),
          csvEscape((item.tags || []).join('|'))
        ].join(','));
      }
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="iocs-export.csv"');
      return res.send(`${lines.join('\n')}\n`);
    } catch (err) {
      return res.status(500).json({ message: 'Failed to export IOCs', detail: err.message });
    }
  });
}
