import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import {
  UNKNOWN_THREAT_CLASSIFICATION,
  invalidateThreatClassificationRegistry,
  listActiveThreatClassifications,
  normalizeThreatClassificationSlugInput,
  loadThreatClassificationRegistry
} from '../lib/threatClassification.js';
import {
  applyThreatClassificationSortOrders,
  planThreatClassificationReorder,
  sortThreatClassificationsForDisplay,
  threatClassificationOrderSnapshot,
  THREAT_CLASSIFICATION_SORT_STEP
} from '../lib/threatClassificationReorder.js';

const ADMIN_LIST_ORDER_SQL = `
  CASE WHEN slug = '${UNKNOWN_THREAT_CLASSIFICATION}' THEN 0 ELSE 1 END,
  CASE WHEN active THEN 0 ELSE 1 END,
  sort_order ASC,
  name ASC
`;

function serializeThreatClassification(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    description: row.description || null,
    active: Boolean(row.active),
    sort_order: Number(row.sort_order) || 0,
    system_default: Boolean(row.system_default),
    created_at: row.created_at,
    updated_at: row.updated_at,
    created_by: row.created_by || null,
    updated_by: row.updated_by || null
  };
}

function classificationAuditSnapshot(row) {
  return serializeThreatClassification(row);
}

async function fetchClassificationById(pool, id) {
  const { rows } = await pool.query('SELECT * FROM threat_classifications WHERE id = $1::uuid', [id]);
  return rows[0] || null;
}

async function fetchAllClassifications(clientOrPool) {
  const { rows } = await clientOrPool.query(
    `SELECT * FROM threat_classifications ORDER BY ${ADMIN_LIST_ORDER_SQL}`
  );
  return rows;
}

async function findDuplicateSlug(pool, { slug, excludeId = null }) {
  const params = [slug];
  let sql = 'SELECT id FROM threat_classifications WHERE slug = $1';
  if (excludeId) {
    params.push(excludeId);
    sql += ' AND id <> $2::uuid';
  }
  sql += ' LIMIT 1';
  const { rows } = await pool.query(sql, params);
  return rows[0] || null;
}

async function countIocUsageBySlug(pool, slug) {
  const { rows } = await pool.query(
    `SELECT (
       (SELECT COUNT(*)::bigint FROM ioc_items WHERE threat_classification = $1)
       + (SELECT COUNT(*)::bigint FROM ioc_threat_classifications WHERE classification_slug = $1)
     ) AS cnt`,
    [slug]
  );
  return Number(rows[0]?.cnt || 0);
}

function userLabel(req) {
  return req.user?.email || req.user?.username || req.user?.publicId || null;
}

async function renumberClassificationsPreservingRelativeOrder(client, actor, { placeIdAtEndOfActive = null } = {}) {
  const rows = await fetchAllClassifications(client);
  const byId = new Map(rows.map((row) => [String(row.id), row]));
  let orderedIds = sortThreatClassificationsForDisplay(rows).map((row) => String(row.id));

  if (placeIdAtEndOfActive) {
    const targetId = String(placeIdAtEndOfActive);
    const target = byId.get(targetId);
    if (target) {
      orderedIds = orderedIds.filter((id) => id !== targetId);
      const unknownId = orderedIds.find((id) => byId.get(id)?.slug === UNKNOWN_THREAT_CLASSIFICATION);
      const rest = orderedIds.filter((id) => id !== unknownId);
      const activeIds = rest.filter((id) => byId.get(id)?.active !== false);
      const inactiveIds = rest.filter((id) => byId.get(id)?.active === false);
      if (target.active !== false) {
        orderedIds = [unknownId, ...activeIds, targetId, ...inactiveIds].filter(Boolean);
      } else {
        orderedIds = [unknownId, ...activeIds, ...inactiveIds, targetId].filter(Boolean);
      }
    }
  }

  const planned = planThreatClassificationReorder(rows, orderedIds);
  if (!planned.ok) throw new Error(planned.error);
  await applyThreatClassificationSortOrders(client, planned.assignments, actor);
  return planned.assignments;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 */
export function registerThreatClassificationRoutes(app, pool, audit) {
  app.get('/api/threat-classifications', async (_req, res) => {
    try {
      const list = await listActiveThreatClassifications(pool);
      return res.json(list);
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/admin/threat-classifications', requireRole(ROLES.ADMIN), async (req, res) => {
    const includeInactive = String(req.query?.include_inactive ?? 'true') !== 'false';
    try {
      const { rows } = await pool.query(
        `SELECT * FROM threat_classifications
         ${includeInactive ? '' : 'WHERE active = TRUE'}
         ORDER BY ${ADMIN_LIST_ORDER_SQL}`
      );
      return res.json({ threat_classifications: rows.map(serializeThreatClassification) });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/admin/threat-classifications/reorder', requireRole(ROLES.ADMIN), async (req, res) => {
    const orderedIds = req.body?.ordered_ids;
    const actor = userLabel(req);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const rows = await fetchAllClassifications(client);
      const before = threatClassificationOrderSnapshot(rows);
      const planned = planThreatClassificationReorder(rows, orderedIds);
      if (!planned.ok) {
        await client.query('ROLLBACK');
        return res.status(planned.status).json({ success: false, error: planned.error });
      }

      await applyThreatClassificationSortOrders(client, planned.assignments, actor);
      await client.query('COMMIT');

      invalidateThreatClassificationRegistry();
      await loadThreatClassificationRegistry(pool);

      const afterRows = await fetchAllClassifications(pool);
      const after = threatClassificationOrderSnapshot(afterRows);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.THREAT_CLASSIFICATION_REORDERED,
        entityType: AUDIT_ENTITY.THREAT_CLASSIFICATION,
        entityId: 'dictionary',
        entityDisplay: 'Threat Classifications',
        metadata: {
          before_order: before,
          after_order: after,
          count: planned.assignments.length
        }
      });

      return res.json({
        success: true,
        threat_classifications: afterRows.map(serializeThreatClassification)
      });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        /* ignore */
      }
      return res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  app.post('/api/admin/threat-classifications', requireRole(ROLES.ADMIN), async (req, res) => {
    const body = req.body || {};
    const name = String(body.name || '').trim();
    if (!name) return res.status(400).json({ success: false, error: 'name is required' });
    const slug = normalizeThreatClassificationSlugInput(body.slug || name);
    if (!slug) return res.status(400).json({ success: false, error: 'slug could not be generated' });
    if (slug === UNKNOWN_THREAT_CLASSIFICATION) {
      return res.status(400).json({ success: false, error: 'slug "unknown" is reserved' });
    }
    const description = body.description != null ? String(body.description).trim() || null : null;
    const active = body.active !== false;
    const actor = userLabel(req);

    const client = await pool.connect();
    try {
      const dup = await findDuplicateSlug(pool, { slug });
      if (dup) return res.status(409).json({ success: false, error: 'Threat classification slug already exists' });

      await client.query('BEGIN');
      // Temporary high order; renumber places active creates at end of active group.
      const tempOrder = 1_000_000 + THREAT_CLASSIFICATION_SORT_STEP;
      const { rows } = await client.query(
        `INSERT INTO threat_classifications
           (name, slug, description, active, sort_order, system_default, created_by, updated_by)
         VALUES ($1, $2, $3, $4, $5, FALSE, $6, $6)
         RETURNING *`,
        [name, slug, description, active, tempOrder, actor]
      );
      const row = rows[0];
      await renumberClassificationsPreservingRelativeOrder(client, actor, {
        placeIdAtEndOfActive: active ? row.id : null
      });
      await client.query('COMMIT');

      invalidateThreatClassificationRegistry();
      await loadThreatClassificationRegistry(pool);

      const fresh = await fetchClassificationById(pool, row.id);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.THREAT_CLASSIFICATION_CREATED,
        entityType: AUDIT_ENTITY.THREAT_CLASSIFICATION,
        entityId: String(fresh.id),
        entityDisplay: fresh.name,
        after: classificationAuditSnapshot(fresh),
        metadata: { slug: fresh.slug }
      });
      return res.status(201).json({ success: true, threat_classification: serializeThreatClassification(fresh) });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        /* ignore */
      }
      return res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  app.patch('/api/admin/threat-classifications/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = String(req.params.id || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, error: 'Invalid threat classification id' });
    }
    const prev = await fetchClassificationById(pool, id);
    if (!prev) return res.status(404).json({ success: false, error: 'Threat classification not found' });

    const body = req.body || {};
    const name = body.name !== undefined ? String(body.name || '').trim() : prev.name;
    if (!name) return res.status(400).json({ success: false, error: 'name cannot be empty' });

    let slug = prev.slug;
    if (body.slug !== undefined) {
      slug = normalizeThreatClassificationSlugInput(body.slug || name);
      if (!slug) return res.status(400).json({ success: false, error: 'slug cannot be empty' });
      if (prev.slug === UNKNOWN_THREAT_CLASSIFICATION && slug !== UNKNOWN_THREAT_CLASSIFICATION) {
        return res.status(400).json({ success: false, error: 'slug for Unknown classification cannot be changed' });
      }
      if (slug !== prev.slug) {
        const usage = await countIocUsageBySlug(pool, prev.slug);
        if (usage > 0) {
          return res.status(409).json({
            success: false,
            error: `Cannot change slug while ${usage} IOC(s) reference "${prev.slug}"`
          });
        }
      }
    }

    const description = body.description !== undefined
      ? (String(body.description || '').trim() || null)
      : prev.description;
    let active = body.active !== undefined ? Boolean(body.active) : prev.active;
    if (prev.slug === UNKNOWN_THREAT_CLASSIFICATION && active === false) {
      return res.status(400).json({ success: false, error: 'Unknown classification cannot be disabled' });
    }
    // sort_order remains a technical field; clients should use the reorder endpoint.
    // Keep PATCH acceptance for backward compatibility without encouraging UI edits.
    const sortOrder = body.sort_order !== undefined ? Number(body.sort_order) : prev.sort_order;
    const sort_order = Number.isFinite(sortOrder) ? Math.trunc(sortOrder) : prev.sort_order;
    const actor = userLabel(req);

    try {
      if (slug !== prev.slug) {
        const dup = await findDuplicateSlug(pool, { slug, excludeId: id });
        if (dup) return res.status(409).json({ success: false, error: 'Threat classification slug already exists' });
      }

      const { rows } = await pool.query(
        `UPDATE threat_classifications
         SET name = $2, slug = $3, description = $4, active = $5, sort_order = $6,
             updated_by = $7, updated_at = NOW()
         WHERE id = $1::uuid
         RETURNING *`,
        [id, name, slug, description, active, sort_order, actor]
      );
      const row = rows[0];
      invalidateThreatClassificationRegistry();
      await loadThreatClassificationRegistry(pool);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.THREAT_CLASSIFICATION_UPDATED,
        entityType: AUDIT_ENTITY.THREAT_CLASSIFICATION,
        entityId: String(row.id),
        entityDisplay: row.name,
        before: classificationAuditSnapshot(prev),
        after: classificationAuditSnapshot(row)
      });
      return res.json({ success: true, threat_classification: serializeThreatClassification(row) });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  async function setClassificationActive(req, res, active) {
    const id = String(req.params.id || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, error: 'Invalid threat classification id' });
    }
    const prev = await fetchClassificationById(pool, id);
    if (!prev) return res.status(404).json({ success: false, error: 'Threat classification not found' });
    if (prev.slug === UNKNOWN_THREAT_CLASSIFICATION && !active) {
      return res.status(400).json({ success: false, error: 'Unknown classification cannot be disabled' });
    }
    const actor = userLabel(req);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `UPDATE threat_classifications SET active = $2, updated_by = $3, updated_at = NOW()
         WHERE id = $1::uuid RETURNING *`,
        [id, active, actor]
      );
      const row = rows[0];
      // Keep dictionary order contiguous and enforce active-before-inactive after toggles.
      await renumberClassificationsPreservingRelativeOrder(client, actor, {
        placeIdAtEndOfActive: active ? row.id : null
      });
      await client.query('COMMIT');

      invalidateThreatClassificationRegistry();
      await loadThreatClassificationRegistry(pool);

      const fresh = await fetchClassificationById(pool, id);

      await audit.auditSuccess({
        req,
        action: active ? AUDIT_ACTION.THREAT_CLASSIFICATION_ENABLED : AUDIT_ACTION.THREAT_CLASSIFICATION_DISABLED,
        entityType: AUDIT_ENTITY.THREAT_CLASSIFICATION,
        entityId: String(fresh.id),
        entityDisplay: fresh.name,
        before: classificationAuditSnapshot(prev),
        after: classificationAuditSnapshot(fresh)
      });
      return res.json({ success: true, threat_classification: serializeThreatClassification(fresh) });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        /* ignore */
      }
      return res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  }

  app.patch('/api/admin/threat-classifications/:id/disable', requireRole(ROLES.ADMIN), (req, res) => setClassificationActive(req, res, false));
  app.patch('/api/admin/threat-classifications/:id/enable', requireRole(ROLES.ADMIN), (req, res) => setClassificationActive(req, res, true));
}

export async function resolveThreatClassificationBySlug(pool, slug) {
  if (!slug) return null;
  const { rows } = await pool.query(
    `SELECT slug, name, active, system_default, sort_order FROM threat_classifications WHERE slug = $1`,
    [slug]
  );
  return rows[0] || null;
}
