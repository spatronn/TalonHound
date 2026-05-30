import { requireRole, ROLES } from '../lib/rbac.js';
import {
  normalizeSourceNameInput,
  validateSourceName,
  validateSourceType,
  validateDefaultConfidence,
  validateDefaultExpirePolicy,
  validateExpireDays,
  serializeIocSourceRow
} from '../lib/iocSourceValidation.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';

const SOURCE_AUDIT_FIELDS = [
  'name', 'display_name', 'source_type', 'default_confidence',
  'default_expire_policy', 'default_expire_days', 'active'
];

function isAdmin(req) {
  return String(req.user?.role || 'admin').trim().toLowerCase() === ROLES.ADMIN;
}

function validateSourcePayload(body, partial = false) {
  const errors = [];

  if (!partial || body.name !== undefined) {
    const nameCheck = validateSourceName(body.name);
    if (!nameCheck.ok) errors.push(nameCheck.error);
  }

  if (body.source_type !== undefined) {
    const typeCheck = validateSourceType(body.source_type);
    if (!typeCheck.ok) errors.push(typeCheck.error);
  }

  if (body.default_confidence !== undefined) {
    const confCheck = validateDefaultConfidence(body.default_confidence);
    if (!confCheck.ok) errors.push(confCheck.error);
  }

  if (body.default_expire_policy !== undefined) {
    const polCheck = validateDefaultExpirePolicy(body.default_expire_policy);
    if (!polCheck.ok) errors.push(polCheck.error);
  }

  if (body.default_expire_days !== undefined) {
    const policy = body.default_expire_policy;
    const daysRequired = policy === 'expire_after_days';
    const daysCheck = validateExpireDays(body.default_expire_days, daysRequired);
    if (!daysCheck.ok) errors.push(daysCheck.error);
  }

  if (body.default_expire_policy === 'expire_after_days' && body.default_expire_days == null) {
    errors.push('default_expire_days is required when default_expire_policy is expire_after_days');
  }

  return errors;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 */
export function registerIocSourceRoutes(app, pool, audit) {
  app.get('/api/ioc-sources', async (req, res) => {
    try {
      const includeInactive = String(req.query?.include_inactive || '').toLowerCase() === 'true'
        || String(req.query?.include_inactive || '') === '1';
      if (includeInactive && !isAdmin(req)) {
        return res.status(403).json({ message: 'Forbidden' });
      }

      const { rows } = await pool.query(
        `SELECT *
         FROM ioc_sources
         ${includeInactive ? '' : 'WHERE active = TRUE'}
         ORDER BY active DESC, name ASC`
      );
      return res.json({ sources: rows.map(serializeIocSourceRow) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list IOC sources', detail: err.message });
    }
  });

  app.post('/api/ioc-sources', requireRole(ROLES.ADMIN), async (req, res) => {
    const body = req.body || {};
    const errors = validateSourcePayload(body, false);
    if (errors.length) return res.status(400).json({ message: errors.join('; ') });

    const nameCheck = validateSourceName(body.name);
    const typeCheck = validateSourceType(body.source_type || 'manual');
    const confCheck = validateDefaultConfidence(body.default_confidence);
    const polCheck = validateDefaultExpirePolicy(body.default_expire_policy);
    const daysCheck = validateExpireDays(
      body.default_expire_days,
      polCheck.value === 'expire_after_days'
    );
    if (!daysCheck.ok) return res.status(400).json({ message: daysCheck.error });

    const userId = req.user?.publicId && /^[0-9a-f-]{36}$/i.test(req.user.publicId)
      ? req.user.publicId
      : null;

    try {
      const { rows } = await pool.query(
        `INSERT INTO ioc_sources (
           name, display_name, description, source_type,
           default_confidence, default_expire_policy, default_expire_days,
           active, created_by
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, TRUE), $9::uuid)
         RETURNING *`,
        [
          nameCheck.value,
          body.display_name ? String(body.display_name).trim() : nameCheck.value,
          body.description ? String(body.description).trim() || null : null,
          typeCheck.value,
          confCheck.value,
          polCheck.value,
          daysCheck.value,
          body.active,
          userId
        ]
      );
      const source = serializeIocSourceRow(rows[0]);
      await audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_SOURCE_CREATED,
        entityType: AUDIT_ENTITY.IOC_SOURCE,
        entityId: String(source.id),
        entityDisplay: source.name,
        severity: AUDIT_SEVERITY.INFO,
        after: pickSafeFields(source, SOURCE_AUDIT_FIELDS)
      });
      return res.status(201).json({ source });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ message: 'IOC source name already exists' });
      return res.status(500).json({ message: 'Failed to create IOC source', detail: err.message });
    }
  });

  app.patch('/api/ioc-sources/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }

    const body = req.body || {};
    const errors = validateSourcePayload(body, true);
    if (errors.length) return res.status(400).json({ message: errors.join('; ') });

    const fields = [];
    const params = [id];

    const setField = (col, val) => {
      params.push(val);
      fields.push(`${col} = $${params.length}`);
    };

    if (body.display_name !== undefined) {
      setField('display_name', body.display_name ? String(body.display_name).trim() : null);
    }
    if (body.description !== undefined) {
      setField('description', body.description ? String(body.description).trim() || null : null);
    }
    if (body.source_type !== undefined) {
      const typeCheck = validateSourceType(body.source_type);
      if (!typeCheck.ok) return res.status(400).json({ message: typeCheck.error });
      setField('source_type', typeCheck.value);
    }
    if (body.default_confidence !== undefined) {
      const confCheck = validateDefaultConfidence(body.default_confidence);
      if (!confCheck.ok) return res.status(400).json({ message: confCheck.error });
      setField('default_confidence', confCheck.value);
    }
    if (body.default_expire_policy !== undefined) {
      const polCheck = validateDefaultExpirePolicy(body.default_expire_policy);
      if (!polCheck.ok) return res.status(400).json({ message: polCheck.error });
      setField('default_expire_policy', polCheck.value);
    }
    if (body.default_expire_days !== undefined) {
      const daysCheck = validateExpireDays(body.default_expire_days, false);
      if (!daysCheck.ok) return res.status(400).json({ message: daysCheck.error });
      setField('default_expire_days', daysCheck.value);
    }
    if (body.active !== undefined) setField('active', Boolean(body.active));

    if (!fields.length) return res.status(400).json({ message: 'No fields to update' });

    try {
      const beforeQ = await pool.query('SELECT * FROM ioc_sources WHERE id = $1', [id]);
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'IOC source not found' });
      const before = serializeIocSourceRow(beforeQ.rows[0]);

      fields.push('updated_at = NOW()');
      const { rows } = await pool.query(
        `UPDATE ioc_sources SET ${fields.join(', ')} WHERE id = $1 RETURNING *`,
        params
      );
      const source = serializeIocSourceRow(rows[0]);
      const action = body.active === false
        ? AUDIT_ACTION.IOC_SOURCE_DISABLED
        : AUDIT_ACTION.IOC_SOURCE_UPDATED;

      await audit?.auditSuccess({
        req,
        action,
        entityType: AUDIT_ENTITY.IOC_SOURCE,
        entityId: String(source.id),
        entityDisplay: source.name,
        severity: body.active === false ? AUDIT_SEVERITY.WARNING : AUDIT_SEVERITY.INFO,
        before: pickSafeFields(before, SOURCE_AUDIT_FIELDS),
        after: pickSafeFields(source, SOURCE_AUDIT_FIELDS)
      });

      return res.json({ source });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update IOC source', detail: err.message });
    }
  });
}

export { normalizeSourceNameInput };
