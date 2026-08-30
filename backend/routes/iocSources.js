import { requireRole, ROLES } from '../lib/rbac.js';
import {
  normalizeSourceNameInput,
  validateSourceName,
  validateDefaultConfidence,
  validateDefaultExpirePolicy,
  validatePrimaryThreatClassification,
  validateExpireDays,
  serializeIocSourceRow
} from '../lib/iocSourceValidation.js';
import {
  archiveIocSource,
  deleteIocSource,
  previewIocSourceDelete,
  serializeSourceWithUsage,
  setIocSourceActive
} from '../lib/iocSourceLifecycle.js';
import { executeIocSourceMove, previewIocSourceMove, resolveApplyTargetDefaults } from '../lib/iocSourceMove.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';
import { validateHexColor } from '../lib/sourceColor.js';

const SOURCE_AUDIT_FIELDS = [
  'name', 'description', 'default_confidence', 'default_threat_classification',
  'default_expire_policy', 'default_expire_days', 'color', 'active'
];

function isAdmin(req) {
  return String(req.user?.role || 'admin').trim().toLowerCase() === ROLES.ADMIN;
}

const VALID_OVERRIDE_IOC_TYPES = ['domain', 'ip', 'url', 'file_hash'];
const VALID_OVERRIDE_MODES = ['inherit', 'no_expire', 'fixed_ttl'];

function validateExpirationTypePolicies(entries) {
  if (!Array.isArray(entries)) return { ok: true, value: [] };
  const seen = new Set();
  const validated = [];
  for (const entry of entries) {
    const t = String(entry?.ioc_type || '').trim();
    const m = String(entry?.mode || 'inherit').trim();
    if (!VALID_OVERRIDE_IOC_TYPES.includes(t)) return { ok: false, error: `Invalid ioc_type: ${t}` };
    if (!VALID_OVERRIDE_MODES.includes(m)) return { ok: false, error: `Invalid mode: ${m}` };
    if (seen.has(t)) return { ok: false, error: `Duplicate ioc_type: ${t}` };
    seen.add(t);
    const ttl = entry.ttl_days != null ? Number(entry.ttl_days) : null;
    if (m === 'fixed_ttl') {
      if (!Number.isInteger(ttl) || ttl <= 0) {
        return { ok: false, error: `ttl_days must be a positive integer for fixed_ttl mode (ioc_type: ${t})` };
      }
    }
    validated.push({ ioc_type: t, mode: m, ttl_days: m === 'fixed_ttl' ? ttl : null });
  }
  return { ok: true, value: validated };
}

function resolveExpireDays(body, policyValue) {
  if (policyValue === 'expire_after_days') {
    return validateExpireDays(body.default_expire_days, true);
  }
  return validateExpireDays(body.default_expire_days, false);
}

function validateSourcePayload(body, partial = false) {
  const errors = [];

  if (!partial) {
    const nameCheck = validateSourceName(body.name);
    if (!nameCheck.ok) errors.push(nameCheck.error);
  } else if (body.name !== undefined) {
    errors.push('Source name cannot be changed after creation');
  }

  if (body.default_confidence !== undefined) {
    const confCheck = validateDefaultConfidence(body.default_confidence);
    if (!confCheck.ok) errors.push(confCheck.error);
  }

  if (body.default_expire_policy !== undefined) {
    const polCheck = validateDefaultExpirePolicy(body.default_expire_policy);
    if (!polCheck.ok) errors.push(polCheck.error);
  }

  const policy = body.default_expire_policy;
  if (body.default_expire_days !== undefined || policy === 'expire_after_days') {
    const daysCheck = resolveExpireDays(body, policy);
    if (!daysCheck.ok) errors.push(daysCheck.error);
  }

  if (policy === 'expire_after_days' && body.default_expire_days == null) {
    errors.push('default_expire_days is required when default_expire_policy is expire_after_days');
  }

  if (body.color !== undefined) {
    const colorCheck = validateHexColor(body.color);
    if (!colorCheck.ok) errors.push(colorCheck.error);
  }

  return errors;
}

function resolveSourceAuditAction(before, after) {
  if (before.active !== false && after.active === false) {
    return AUDIT_ACTION.IOC_SOURCE_DISABLED;
  }
  if (before.active === false && after.active !== false) {
    return AUDIT_ACTION.IOC_SOURCE_ENABLED;
  }
  return AUDIT_ACTION.IOC_SOURCE_UPDATED;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 */
export function registerIocSourceRoutes(app, pool, audit) {
  async function listSources(includeInactive) {
    const { rows } = await pool.query(
      `SELECT s.*,
              (SELECT COUNT(*)::int FROM ioc_items i WHERE i.ioc_source_id = s.id) AS ioc_count
       FROM ioc_sources s
       ${includeInactive ? '' : 'WHERE s.active = TRUE AND s.archived_at IS NULL'}
       ORDER BY s.archived_at NULLS FIRST, s.active DESC, s.name ASC`
    );
    const sources = rows.map(serializeIocSourceRow);
    if (sources.length) {
      const ids = sources.map((s) => s.id);
      const { rows: tpRows } = await pool.query(
        'SELECT source_id, ioc_type, mode, ttl_days FROM ioc_source_expiration_type_policies WHERE source_id = ANY($1::bigint[]) ORDER BY source_id, ioc_type',
        [ids]
      );
      const tpMap = {};
      for (const r of tpRows) {
        if (!tpMap[r.source_id]) tpMap[r.source_id] = [];
        tpMap[r.source_id].push({ ioc_type: r.ioc_type, mode: r.mode, ttl_days: r.ttl_days });
      }
      for (const s of sources) s.expiration_type_policies = tpMap[s.id] || [];
    }
    return sources;
  }

  app.get('/api/admin/ioc-sources', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const includeInactive = String(req.query?.include_inactive || '').toLowerCase() === 'true'
        || String(req.query?.include_inactive || '') === '1';
      return res.json({ sources: await listSources(includeInactive) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list IOC sources', detail: err.message });
    }
  });

  app.get('/api/ioc-sources', async (req, res) => {
    try {
      const includeInactive = String(req.query?.include_inactive || '').toLowerCase() === 'true'
        || String(req.query?.include_inactive || '') === '1';
      if (includeInactive && !isAdmin(req)) {
        return res.status(403).json({ message: 'Forbidden' });
      }

      return res.json({ sources: await listSources(includeInactive) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list IOC sources', detail: err.message });
    }
  });

  app.post('/api/ioc-sources', requireRole(ROLES.ADMIN), async (req, res) => {
    const body = req.body || {};
    const errors = validateSourcePayload(body, false);
    if (errors.length) return res.status(400).json({ message: errors.join('; ') });

    const nameCheck = validateSourceName(body.name);
    const confCheck = validateDefaultConfidence(body.default_confidence);
    const threatClassCheck = await validatePrimaryThreatClassification(pool, body.default_threat_classification);
    if (!threatClassCheck.ok) return res.status(400).json({ message: threatClassCheck.error });
    const polCheck = validateDefaultExpirePolicy(body.default_expire_policy);
    const daysCheck = resolveExpireDays(body, polCheck.value);
    if (!daysCheck.ok) return res.status(400).json({ message: daysCheck.error });
    const colorCheck = validateHexColor(body.color);
    if (!colorCheck.ok) return res.status(400).json({ message: colorCheck.error });

    let createTypePoliciesCheck = { ok: true, value: [] };
    if (Array.isArray(body.expiration_type_policies)) {
      createTypePoliciesCheck = validateExpirationTypePolicies(body.expiration_type_policies);
      if (!createTypePoliciesCheck.ok) return res.status(400).json({ message: createTypePoliciesCheck.error });
    }

    const userId = req.user?.publicId && /^[0-9a-f-]{36}$/i.test(req.user.publicId)
      ? req.user.publicId
      : null;

    try {
      const { rows } = await pool.query(
        `INSERT INTO ioc_sources (
           name, display_name, description, source_type,
           default_confidence, default_threat_classification, default_expire_policy, default_expire_days,
           color, active, created_by
         ) VALUES ($1, $1, $2, 'manual', $3, $4, $5, $6, $7, COALESCE($8, TRUE), $9::uuid)
         RETURNING *`,
        [
          nameCheck.value,
          body.description ? String(body.description).trim() || null : null,
          confCheck.value,
          threatClassCheck.value,
          polCheck.value,
          daysCheck.value,
          colorCheck.value,
          body.active,
          userId
        ]
      );
      const source = serializeIocSourceRow(rows[0]);
      for (const p of createTypePoliciesCheck.value.filter((x) => x.mode !== 'inherit')) {
        await pool.query(
          'INSERT INTO ioc_source_expiration_type_policies (source_id, ioc_type, mode, ttl_days) VALUES ($1, $2, $3, $4)',
          [source.id, p.ioc_type, p.mode, p.ttl_days]
        );
      }
      const { rows: tpRows } = await pool.query(
        'SELECT ioc_type, mode, ttl_days FROM ioc_source_expiration_type_policies WHERE source_id = $1 ORDER BY ioc_type',
        [source.id]
      );
      source.expiration_type_policies = tpRows;
      await audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_SOURCE_CREATED,
        entityType: AUDIT_ENTITY.IOC_SOURCE,
        entityId: String(source.id),
        entityDisplay: source.name,
        severity: AUDIT_SEVERITY.INFO,
        after: pickSafeFields(source, SOURCE_AUDIT_FIELDS),
        metadata: { source_id: source.id, source_name: source.name }
      });
      return res.status(201).json({ source });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ message: 'An IOC source with this name already exists' });
      }
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
    const changedFields = [];

    const setField = (col, val) => {
      params.push(val);
      fields.push(`${col} = $${params.length}`);
      changedFields.push(col);
    };

    if (body.description !== undefined) {
      setField('description', body.description ? String(body.description).trim() || null : null);
    }
    if (body.default_confidence !== undefined) {
      const confCheck = validateDefaultConfidence(body.default_confidence);
      if (!confCheck.ok) return res.status(400).json({ message: confCheck.error });
      setField('default_confidence', confCheck.value);
    }
    if (body.default_threat_classification !== undefined) {
      const classCheck = await validatePrimaryThreatClassification(pool, body.default_threat_classification);
      if (!classCheck.ok) return res.status(400).json({ message: classCheck.error });
      setField('default_threat_classification', classCheck.value);
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
    if (body.color !== undefined) {
      const colorCheck = validateHexColor(body.color);
      if (!colorCheck.ok) return res.status(400).json({ message: colorCheck.error });
      setField('color', colorCheck.value);
    }
    if (body.active !== undefined) setField('active', Boolean(body.active));

    const hasTypePolicies = Array.isArray(body.expiration_type_policies);
    if (!fields.length && !hasTypePolicies) return res.status(400).json({ message: 'No fields to update' });

    let patchTypePoliciesCheck = { ok: true, value: [] };
    if (hasTypePolicies) {
      patchTypePoliciesCheck = validateExpirationTypePolicies(body.expiration_type_policies);
      if (!patchTypePoliciesCheck.ok) return res.status(400).json({ message: patchTypePoliciesCheck.error });
    }

    const client = await pool.connect();
    try {
      const beforeQ = await client.query('SELECT * FROM ioc_sources WHERE id = $1', [id]);
      if (!beforeQ.rows.length) {
        // Do not release here — `finally` owns the single release path.
        // Early release + finally release crashed the process (pg-pool throwOnDoubleRelease).
        return res.status(404).json({ message: 'IOC source not found' });
      }
      const before = serializeIocSourceRow(beforeQ.rows[0]);
      let updatedRow = beforeQ.rows[0];

      await client.query('BEGIN');

      if (fields.length) {
        fields.push('updated_at = NOW()');
        const { rows } = await client.query(
          `UPDATE ioc_sources SET ${fields.join(', ')} WHERE id = $1 RETURNING *`,
          params
        );
        updatedRow = rows[0];
      }

      if (hasTypePolicies) {
        await client.query('DELETE FROM ioc_source_expiration_type_policies WHERE source_id = $1', [id]);
        for (const p of patchTypePoliciesCheck.value.filter((x) => x.mode !== 'inherit')) {
          await client.query(
            'INSERT INTO ioc_source_expiration_type_policies (source_id, ioc_type, mode, ttl_days) VALUES ($1, $2, $3, $4)',
            [id, p.ioc_type, p.mode, p.ttl_days]
          );
        }
      }

      await client.query('COMMIT');

      const { rows: tpRows } = await client.query(
        'SELECT ioc_type, mode, ttl_days FROM ioc_source_expiration_type_policies WHERE source_id = $1 ORDER BY ioc_type',
        [id]
      );

      const source = { ...serializeIocSourceRow(updatedRow), expiration_type_policies: tpRows };
      const action = resolveSourceAuditAction(before, source);
      const severity = action === AUDIT_ACTION.IOC_SOURCE_DISABLED
        ? AUDIT_SEVERITY.WARNING
        : AUDIT_SEVERITY.INFO;

      await audit?.auditSuccess({
        req,
        action,
        entityType: AUDIT_ENTITY.IOC_SOURCE,
        entityId: String(source.id),
        entityDisplay: source.name,
        severity,
        before: pickSafeFields(before, SOURCE_AUDIT_FIELDS),
        after: pickSafeFields(source, SOURCE_AUDIT_FIELDS),
        metadata: {
          source_id: source.id,
          source_name: source.name,
          changed_fields: changedFields
        }
      });

      return res.json({ source });
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch (_) {}
      return res.status(500).json({ message: 'Failed to update IOC source', detail: err.message });
    } finally {
      client.release();
    }
  });

  async function handleDisable(req, res) {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }
    const result = await setIocSourceActive(pool, id, false, { req, audit, user: req.user });
    return res.status(result.status).json(result.body);
  }

  async function handleEnable(req, res) {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }
    const result = await setIocSourceActive(pool, id, true, { req, audit, user: req.user });
    return res.status(result.status).json(result.body);
  }

  async function handleArchive(req, res) {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }
    const result = await archiveIocSource(pool, id, { req, audit, user: req.user });
    return res.status(result.status).json(result.body);
  }

  async function handleDeletePreview(req, res) {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }
    const result = await previewIocSourceDelete(pool, id);
    return res.status(result.status).json(result.body);
  }

  async function handleDelete(req, res) {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }
    try {
      const result = await deleteIocSource(pool, id, { req, audit, user: req.user });
      return res.status(result.status).json(result.body);
    } catch (err) {
      console.error('[ioc-source] delete handler error', { id, message: err.message });
      return res.status(500).json({
        message: 'Failed to delete IOC source',
        detail: err.message
      });
    }
  }

  async function handleMovePreview(req, res) {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }
    const result = await previewIocSourceMove(pool, id, req.body || {});
    if (result.status === 200 && audit?.auditSuccess) {
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_SOURCE_MOVE_PREVIEW,
        entityType: AUDIT_ENTITY.IOC_SOURCE,
        entityId: String(id),
        entityDisplay: result.body.source_name,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          source_from_id: result.body.source_id,
          source_from_name: result.body.source_name,
          source_to_id: result.body.target_source_id,
          source_to_name: result.body.target_source_name,
          ioc_count: result.body.ioc_count,
          apply_target_defaults: resolveApplyTargetDefaults(req.body || {}),
          archive_source_after_move: Boolean(req.body?.archive_source_after_move),
          moved: result.body.will_move,
          merged: result.body.will_merge,
          skipped: result.body.will_skip
        }
      });
    }
    return res.status(result.status).json(result.body);
  }

  async function handleMove(req, res) {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }
    const result = await executeIocSourceMove(pool, id, req.body || {}, { req, audit, user: req.user });
    return res.status(result.status).json(result.body);
  }

  app.get('/api/admin/ioc-sources/:id/delete-preview', requireRole(ROLES.ADMIN), handleDeletePreview);
  app.post('/api/admin/ioc-sources/:id/disable', requireRole(ROLES.ADMIN), handleDisable);
  app.post('/api/admin/ioc-sources/:id/enable', requireRole(ROLES.ADMIN), handleEnable);
  app.post('/api/admin/ioc-sources/:id/archive', requireRole(ROLES.ADMIN), handleArchive);
  app.delete('/api/admin/ioc-sources/:id', requireRole(ROLES.ADMIN), handleDelete);
  app.post('/api/admin/ioc-sources/:id/move-preview', requireRole(ROLES.ADMIN), handleMovePreview);
  app.post('/api/admin/ioc-sources/:id/move', requireRole(ROLES.ADMIN), handleMove);
}

export { normalizeSourceNameInput };
