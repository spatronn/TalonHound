import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';
import {
  TAG_CATEGORIES,
  categoryToLegacyType,
  isValidCategory,
  normalizeTagName,
  normalizeTagSlug,
  parsePositiveInt,
  tagAuditSnapshot,
  toPublicTag
} from '../lib/tagHelpers.js';

const TAG_SELECT = `
  SELECT id, name, slug, description, color, category, type, enabled, created_at, updated_at
  FROM tags
`;

function parseActiveQuery(value) {
  if (value === undefined || value === null || value === '') return true;
  const normalized = String(value).trim().toLowerCase();
  return normalized !== 'false' && normalized !== '0' && normalized !== 'no';
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 */
export function registerTagRoutes(app, pool, audit) {
  app.get('/api/tags', async (req, res) => {
    const activeOnly = parseActiveQuery(req.query.active);

    try {
      const params = [];
      let where = '';
      if (activeOnly) {
        where = 'WHERE enabled = TRUE';
      }

      const q = await pool.query(
        `${TAG_SELECT}
         ${where}
         ORDER BY category ASC NULLS LAST, name ASC`,
        params
      );
      return res.json(q.rows.map(toPublicTag));
    } catch (err) {
      return res.status(500).json({ message: 'Failed to fetch tags', detail: err.message });
    }
  });

  app.get('/api/admin/tags', requireRole(ROLES.ADMIN), async (req, res) => {
    const includeInactive = req.query.include_inactive !== 'false';

    try {
      const q = await pool.query(
        `${TAG_SELECT}
         ${includeInactive ? '' : 'WHERE enabled = TRUE'}
         ORDER BY enabled DESC, category ASC NULLS LAST, name ASC`
      );
      return res.json({ tags: q.rows.map(toPublicTag) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to fetch tags', detail: err.message });
    }
  });

  app.post('/api/admin/tags', requireRole(ROLES.ADMIN), async (req, res) => {
    const name = normalizeTagName(req.body?.name);
    const slug = normalizeTagSlug(req.body?.slug || name);
    const category = String(req.body?.category || 'custom').trim().toLowerCase();
    const description = req.body?.description != null ? String(req.body.description).trim() : null;
    const color = req.body?.color != null ? String(req.body.color).trim() : null;
    const enabled = req.body?.is_active !== false && req.body?.enabled !== false;

    if (!name) return res.status(400).json({ message: 'name is required' });
    if (!slug) return res.status(400).json({ message: 'slug is required' });
    if (!isValidCategory(category)) {
      return res.status(400).json({ message: 'Invalid category', allowed: TAG_CATEGORIES });
    }

    const legacyType = categoryToLegacyType(category);

    try {
      const q = await pool.query(
        `INSERT INTO tags (name, slug, type, category, description, color, enabled, updated_at)
         VALUES ($1, $2, $3::tag_type, $4, $5, $6, $7, NOW())
         RETURNING id, name, slug, description, color, category, type, enabled, created_at, updated_at`,
        [name, slug, legacyType, category, description || null, color || null, enabled]
      );

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.TAG_CREATED,
        entityType: AUDIT_ENTITY.TAG,
        entityId: String(q.rows[0].id),
        entityDisplay: q.rows[0].name,
        severity: AUDIT_SEVERITY.INFO,
        after: pickSafeFields(tagAuditSnapshot(q.rows[0]), ['id', 'name', 'slug', 'category', 'is_active'])
      });

      return res.status(201).json({ tag: toPublicTag(q.rows[0]) });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ message: 'Tag already exists' });
      }
      return res.status(500).json({ message: 'Failed to create tag', detail: err.message });
    }
  });

  app.put('/api/admin/tags/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const tagId = parsePositiveInt(req.params?.id);
    if (!tagId) return res.status(400).json({ message: 'Invalid id' });

    const hasName = req.body?.name != null;
    const hasSlug = req.body?.slug != null;
    const hasCategory = req.body?.category != null;
    const hasDescription = req.body?.description != null;
    const hasColor = req.body?.color != null;
    const hasEnabled = req.body?.is_active != null || req.body?.enabled != null;

    if (!hasName && !hasSlug && !hasCategory && !hasDescription && !hasColor && !hasEnabled) {
      return res.status(400).json({ message: 'No fields to update' });
    }

    try {
      const beforeQ = await pool.query(`${TAG_SELECT} WHERE id = $1`, [tagId]);
      if (!beforeQ.rowCount) return res.status(404).json({ message: 'Tag not found' });

      const fields = [];
      const params = [tagId];
      let idx = 2;

      if (hasName) {
        const name = normalizeTagName(req.body.name);
        if (!name) return res.status(400).json({ message: 'name cannot be empty' });
        fields.push(`name = $${idx++}`);
        params.push(name);
      }

      if (hasSlug) {
        const slug = normalizeTagSlug(req.body.slug);
        if (!slug) return res.status(400).json({ message: 'slug cannot be empty' });
        fields.push(`slug = $${idx++}`);
        params.push(slug);
      }

      if (hasCategory) {
        const category = String(req.body.category).trim().toLowerCase();
        if (!isValidCategory(category)) {
          return res.status(400).json({ message: 'Invalid category', allowed: TAG_CATEGORIES });
        }
        fields.push(`category = $${idx++}`);
        params.push(category);
        fields.push(`type = $${idx++}::tag_type`);
        params.push(categoryToLegacyType(category));
      }

      if (hasDescription) {
        fields.push(`description = $${idx++}`);
        params.push(String(req.body.description).trim() || null);
      }

      if (hasColor) {
        fields.push(`color = $${idx++}`);
        params.push(String(req.body.color).trim() || null);
      }

      if (hasEnabled) {
        const enabled = req.body?.is_active != null ? Boolean(req.body.is_active) : Boolean(req.body.enabled);
        fields.push(`enabled = $${idx++}`);
        params.push(enabled);
      }

      fields.push('updated_at = NOW()');

      const q = await pool.query(
        `UPDATE tags
         SET ${fields.join(', ')}
         WHERE id = $1
         RETURNING id, name, slug, description, color, category, type, enabled, created_at, updated_at`,
        params
      );

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.TAG_UPDATED,
        entityType: AUDIT_ENTITY.TAG,
        entityId: String(q.rows[0].id),
        entityDisplay: q.rows[0].name,
        severity: AUDIT_SEVERITY.INFO,
        before: pickSafeFields(tagAuditSnapshot(beforeQ.rows[0]), ['id', 'name', 'slug', 'category', 'is_active']),
        after: pickSafeFields(tagAuditSnapshot(q.rows[0]), ['id', 'name', 'slug', 'category', 'is_active'])
      });

      return res.json({ tag: toPublicTag(q.rows[0]) });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ message: 'Tag already exists' });
      }
      return res.status(500).json({ message: 'Failed to update tag', detail: err.message });
    }
  });

  app.delete('/api/admin/tags/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const tagId = parsePositiveInt(req.params?.id);
    if (!tagId) return res.status(400).json({ message: 'Invalid id' });

    try {
      const beforeQ = await pool.query(`${TAG_SELECT} WHERE id = $1`, [tagId]);
      if (!beforeQ.rowCount) return res.status(404).json({ message: 'Tag not found' });

      const usageQ = await pool.query(
        'SELECT COUNT(*)::int AS count FROM ioc_tags WHERE tag_id = $1',
        [tagId]
      );
      const inUse = Number(usageQ.rows[0]?.count || 0) > 0;

      const q = await pool.query(
        `UPDATE tags
         SET enabled = FALSE, updated_at = NOW()
         WHERE id = $1
         RETURNING id, name, slug, description, color, category, type, enabled, created_at, updated_at`,
        [tagId]
      );

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.TAG_UPDATED,
        entityType: AUDIT_ENTITY.TAG,
        entityId: String(q.rows[0].id),
        entityDisplay: q.rows[0].name,
        severity: AUDIT_SEVERITY.INFO,
        before: pickSafeFields(tagAuditSnapshot(beforeQ.rows[0]), ['id', 'name', 'is_active']),
        after: pickSafeFields(tagAuditSnapshot(q.rows[0]), ['id', 'name', 'is_active']),
        metadata: { disabled: true, in_use: inUse }
      });

      return res.json({ tag: toPublicTag(q.rows[0]), in_use: inUse });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to disable tag', detail: err.message });
    }
  });
}
