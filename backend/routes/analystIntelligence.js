import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { parsePositiveInt } from '../lib/tagHelpers.js';
import { isUuid } from '../lib/iocAuditMatch.js';
import {
  analystIntelligenceAuditSnapshot,
  buildAnalystIntelligenceSummary,
  diffAnalystIntelligenceFields,
  toPublicAnalystIntelligenceRow,
  validateAnalystIntelligencePayload
} from '../lib/analystIntelligence.js';

function resolveActor(req) {
  const userId = req.user?.publicId && /^[0-9a-f-]{36}$/i.test(req.user.publicId)
    ? req.user.publicId
    : null;
  const username = String(req.user?.username || req.user?.email || '').trim() || null;
  return { userId, username };
}

async function fetchIocContext(pool, iocId) {
  const { rows } = await pool.query(
    'SELECT id, public_id, observable, observable_type FROM ioc_items WHERE id = $1 LIMIT 1',
    [iocId]
  );
  return rows[0] || null;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 */
export function registerAnalystIntelligenceRoutes(app, pool, audit) {
  app.get('/api/ioc/:id/analyst-intelligence', async (req, res) => {
    const iocId = parsePositiveInt(req.params?.id);
    if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });

    try {
      const ioc = await fetchIocContext(pool, iocId);
      if (!ioc) return res.status(404).json({ message: 'IOC not found' });

      const { rows } = await pool.query(
        `SELECT *
         FROM ioc_analyst_intelligence
         WHERE ioc_id = $1
           AND ioc_observable_type = $2
           AND deleted_at IS NULL
         ORDER BY created_at DESC`,
        [iocId, ioc.observable_type]
      );

      const items = rows.map(toPublicAnalystIntelligenceRow);
      return res.json({
        items,
        summary: buildAnalystIntelligenceSummary(items)
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to fetch analyst intelligence', detail: err.message });
    }
  });

  app.post('/api/ioc/:id/analyst-intelligence', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    const iocId = parsePositiveInt(req.params?.id);
    if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });

    const validation = validateAnalystIntelligencePayload(req.body || {});
    if (!validation.ok) return res.status(400).json({ message: validation.errors.join('; ') });

    try {
      const ioc = await fetchIocContext(pool, iocId);
      if (!ioc) return res.status(404).json({ message: 'IOC not found' });

      const actor = resolveActor(req);
      const v = validation.value;
      const { rows } = await pool.query(
        `INSERT INTO ioc_analyst_intelligence (
           ioc_id, ioc_observable_type, title, url, source_name,
           reference_type, tlp, confidence, assessment_impact, note,
           created_by, created_by_username
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING *`,
        [
          iocId,
          ioc.observable_type,
          v.title,
          v.url,
          v.source_name,
          v.reference_type,
          v.tlp,
          v.confidence,
          v.assessment_impact,
          v.note,
          actor.userId,
          actor.username
        ]
      );

      const created = rows[0];
      await audit.auditSuccess({
        action: AUDIT_ACTION.IOC_ANALYST_INTELLIGENCE_CREATED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(ioc.public_id || iocId),
        entityDisplay: String(ioc.observable || iocId),
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          ioc_id: iocId,
          ...analystIntelligenceAuditSnapshot(created)
        }
      });

      return res.status(201).json(toPublicAnalystIntelligenceRow(created));
    } catch (err) {
      return res.status(500).json({ message: 'Failed to create analyst intelligence reference', detail: err.message });
    }
  });

  app.put('/api/ioc/:id/analyst-intelligence/:referenceId', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    const iocId = parsePositiveInt(req.params?.id);
    const referenceId = String(req.params?.referenceId || '').trim();
    if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
    if (!referenceId) return res.status(400).json({ message: 'Invalid reference id' });
    if (!isUuid(referenceId)) return res.status(400).json({ message: 'Invalid reference id' });

    const validation = validateAnalystIntelligencePayload(req.body || {}, { partial: false });
    if (!validation.ok) return res.status(400).json({ message: validation.errors.join('; ') });

    try {
      const ioc = await fetchIocContext(pool, iocId);
      if (!ioc) return res.status(404).json({ message: 'IOC not found' });

      const existingRes = await pool.query(
        `SELECT *
         FROM ioc_analyst_intelligence
         WHERE id = $1::uuid
           AND ioc_id = $2
           AND ioc_observable_type = $3
           AND deleted_at IS NULL
         LIMIT 1`,
        [referenceId, iocId, ioc.observable_type]
      );
      if (!existingRes.rowCount) return res.status(404).json({ message: 'Reference not found' });

      const before = existingRes.rows[0];
      const actor = resolveActor(req);
      const v = validation.value;
      const { rows } = await pool.query(
        `UPDATE ioc_analyst_intelligence
         SET title = $4,
             url = $5,
             source_name = $6,
             reference_type = $7,
             tlp = $8,
             confidence = $9,
             assessment_impact = $10,
             note = $11,
             updated_by = $12,
             updated_by_username = $13,
             updated_at = NOW()
         WHERE id = $1::uuid
           AND ioc_id = $2
           AND ioc_observable_type = $3
           AND deleted_at IS NULL
         RETURNING *`,
        [
          referenceId,
          iocId,
          ioc.observable_type,
          v.title,
          v.url,
          v.source_name,
          v.reference_type,
          v.tlp,
          v.confidence,
          v.assessment_impact,
          v.note,
          actor.userId,
          actor.username
        ]
      );

      const after = rows[0];
      await audit.auditSuccess({
        action: AUDIT_ACTION.IOC_ANALYST_INTELLIGENCE_UPDATED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(ioc.public_id || iocId),
        entityDisplay: String(ioc.observable || iocId),
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          ioc_id: iocId,
          reference_id: referenceId,
          changed_fields: diffAnalystIntelligenceFields(before, after),
          ...analystIntelligenceAuditSnapshot(after)
        }
      });

      return res.json(toPublicAnalystIntelligenceRow(after));
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update analyst intelligence reference', detail: err.message });
    }
  });

  app.delete('/api/ioc/:id/analyst-intelligence/:referenceId', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    const iocId = parsePositiveInt(req.params?.id);
    const referenceId = String(req.params?.referenceId || '').trim();
    if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
    if (!referenceId) return res.status(400).json({ message: 'Invalid reference id' });
    if (!isUuid(referenceId)) return res.status(400).json({ message: 'Invalid reference id' });

    try {
      const ioc = await fetchIocContext(pool, iocId);
      if (!ioc) return res.status(404).json({ message: 'IOC not found' });

      const existingRes = await pool.query(
        `SELECT *
         FROM ioc_analyst_intelligence
         WHERE id = $1::uuid
           AND ioc_id = $2
           AND ioc_observable_type = $3
           AND deleted_at IS NULL
         LIMIT 1`,
        [referenceId, iocId, ioc.observable_type]
      );
      if (!existingRes.rowCount) return res.status(404).json({ message: 'Reference not found' });

      const before = existingRes.rows[0];
      const actor = resolveActor(req);
      await pool.query(
        `UPDATE ioc_analyst_intelligence
         SET deleted_at = NOW(),
             deleted_by = $4,
             deleted_by_username = $5
         WHERE id = $1::uuid
           AND ioc_id = $2
           AND ioc_observable_type = $3
           AND deleted_at IS NULL`,
        [referenceId, iocId, ioc.observable_type, actor.userId, actor.username]
      );

      await audit.auditSuccess({
        action: AUDIT_ACTION.IOC_ANALYST_INTELLIGENCE_DELETED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(ioc.public_id || iocId),
        entityDisplay: String(ioc.observable || iocId),
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          ioc_id: iocId,
          ...analystIntelligenceAuditSnapshot(before)
        }
      });

      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ message: 'Failed to delete analyst intelligence reference', detail: err.message });
    }
  });
}

export async function enrichItemsWithAnalystIntelligenceCounts(pool, items) {
  const map = new Map();
  if (!items?.length) return map;

  const pairs = items
    .map((it) => ({
      id: Number(it?.id),
      observable_type: String(it?.observable_type || '').trim()
    }))
    .filter((p) => Number.isFinite(p.id) && p.id > 0 && p.observable_type);
  if (!pairs.length) return map;

  const values = pairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
  const params = pairs.flatMap((p) => [p.id, p.observable_type]);
  const { rows } = await pool.query(
    `SELECT ioc_id, ioc_observable_type,
            COUNT(*)::int AS analyst_intelligence_count,
            COUNT(*) FILTER (WHERE assessment_impact = 'supports_malicious')::int AS supports_malicious_count,
            COUNT(*) FILTER (WHERE assessment_impact = 'needs_review')::int AS needs_review_count
     FROM ioc_analyst_intelligence
     WHERE deleted_at IS NULL
       AND (ioc_id, ioc_observable_type) IN (VALUES ${values})
     GROUP BY ioc_id, ioc_observable_type`,
    params
  );

  for (const row of rows) {
    map.set(`${Number(row.ioc_id)}|${String(row.ioc_observable_type)}`, {
      analyst_intelligence_count: Number(row.analyst_intelligence_count || 0),
      supports_malicious_count: Number(row.supports_malicious_count || 0),
      needs_review_count: Number(row.needs_review_count || 0)
    });
  }
  return map;
}

export function mergeAnalystIntelligenceItem(item, countMap) {
  const key = `${Number(item?.id)}|${String(item?.observable_type || '')}`;
  const counts = countMap?.get(key) || {
    analyst_intelligence_count: 0,
    supports_malicious_count: 0,
    needs_review_count: 0
  };
  return { ...item, ...counts };
}
