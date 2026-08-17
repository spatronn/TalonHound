/**
 * Safe bulk IOC triage (v1): explicit selected IDs only, backend-enforced batch cap.
 * Reuses single-IOC tag / classification / suppression / expiration services.
 */

import { BULK_TRIAGE_MAX_ITEMS } from './rbac.js';
import { ensureIocTagAssignment } from './tagCatalogService.js';
import { createManualSuppression } from './manualSuppressionCreate.js';
import { parseRequiredReason } from './reasonValidation.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';
import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { evaluateIocStatusOverrideRequest } from './iocStatusOverrideGuards.js';
import { validateIocThreatClassificationSlugs } from './iocThreatClassifications.js';
import {
  listActiveThreatClassificationOverrides,
  syncThreatClassificationOverrides
} from './iocThreatClassificationOverrides.js';

export { BULK_TRIAGE_MAX_ITEMS };

function bulkMeta(base, extraMetadata) {
  return { bulk: true, ...(base || {}), ...(extraMetadata || {}) };
}

export function parseIocIdList(raw, { max = BULK_TRIAGE_MAX_ITEMS } = {}) {
  if (!Array.isArray(raw)) {
    return { ok: false, status: 400, message: 'ioc_ids must be an array of positive integers' };
  }
  if (!raw.length) {
    return { ok: false, status: 400, message: 'ioc_ids must not be empty' };
  }
  if (raw.length > max) {
    return { ok: false, status: 400, message: `ioc_ids cannot exceed ${max} items` };
  }
  const ids = [];
  const seen = new Set();
  for (const item of raw) {
    const n = Number(item);
    if (!Number.isInteger(n) || n <= 0) {
      return { ok: false, status: 400, message: 'ioc_ids must contain only positive integers' };
    }
    if (seen.has(n)) continue;
    seen.add(n);
    ids.push(n);
  }
  return { ok: true, ids };
}

function resultRow(id, status, message = null) {
  return { id, status, ...(message ? { message } : {}) };
}

export function summarizeBulkResults(results) {
  let succeeded = 0;
  let failed = 0;
  let skipped = 0;
  for (const r of results) {
    if (r.status === 'ok') succeeded += 1;
    else if (r.status === 'skipped') skipped += 1;
    else failed += 1;
  }
  return {
    requested: results.length,
    succeeded,
    skipped,
    failed,
    results
  };
}

async function loadIocsByIds(pool, ids) {
  const { rows } = await pool.query(
    `SELECT id, public_id, observable, observable_type, status,
            manual_status_override, manual_status, manual_expires_at
     FROM ioc_items
     WHERE id = ANY($1::bigint[])`,
    [ids]
  );
  const byId = new Map(rows.map((r) => [Number(r.id), r]));
  return { rows, byId };
}

export async function bulkAddTag(pool, { iocIds, tagId, user, req, audit, extraMetadata }) {
  const idNum = Number(tagId);
  if (!Number.isInteger(idNum) || idNum <= 0) {
    return { ok: false, status: 400, message: 'tag_id must be a positive integer' };
  }
  const tagQ = await pool.query(
    `SELECT id, name, type, category FROM tags WHERE id = $1 AND enabled = TRUE LIMIT 1`,
    [idNum]
  );
  if (!tagQ.rowCount) {
    return { ok: false, status: 404, message: 'Tag not found or disabled' };
  }
  const tag = tagQ.rows[0];
  const { byId } = await loadIocsByIds(pool, iocIds);
  const results = [];
  for (const id of iocIds) {
    const ioc = byId.get(id);
    if (!ioc) {
      results.push(resultRow(id, 'error', 'IOC not found'));
      continue;
    }
    try {
      const insertResult = await ensureIocTagAssignment(pool, {
        iocId: id,
        observableType: ioc.observable_type,
        tagId: tag.id,
        origin: 'manual',
        createdBy: user?.id ?? null
      });
      if (insertResult.inserted) {
        await audit?.auditSuccess?.({
          req,
          action: AUDIT_ACTION.IOC_TAG_ADDED,
          entityType: AUDIT_ENTITY.IOC,
          entityId: ioc.public_id ? String(ioc.public_id) : String(id),
          entityDisplay: ioc.observable || String(id),
          subjectIocId: id,
          subjectIocType: ioc.observable_type || null,
          subjectIocValue: ioc.observable || null,
          severity: AUDIT_SEVERITY.INFO,
          metadata: bulkMeta({
            ioc_id: String(id),
            tag_id: tag.id,
            tag_name: tag.name
          }, extraMetadata)
        }).catch(() => {});
        results.push(resultRow(id, 'ok'));
      } else {
        results.push(resultRow(id, 'skipped', 'Tag already assigned'));
      }
    } catch (err) {
      results.push(resultRow(id, 'error', String(err?.message || err)));
    }
  }
  return { ok: true, ...summarizeBulkResults(results) };
}

export async function bulkAddClassification(pool, { iocIds, slug, user, req, audit, extraMetadata }) {
  if (!String(slug || '').trim()) {
    return { ok: false, status: 400, message: 'classification_slug is required' };
  }
  const check = await validateIocThreatClassificationSlugs(pool, [slug], { requireActive: true });
  if (!check.ok) {
    return { ok: false, status: 400, message: check.error || 'Invalid classification' };
  }
  const addSlug = check.value[0];
  if (!addSlug) {
    return { ok: false, status: 400, message: 'classification_slug is required' };
  }
  const actor = String(user?.email || user?.username || '').trim() || null;
  const { byId } = await loadIocsByIds(pool, iocIds);
  const results = [];
  for (const id of iocIds) {
    const ioc = byId.get(id);
    if (!ioc) {
      results.push(resultRow(id, 'error', 'IOC not found'));
      continue;
    }
    try {
      const existing = await listActiveThreatClassificationOverrides(pool, id, ioc.observable_type);
      const activeAdds = existing.filter((r) => r.action === 'add').map((r) => r.classification_slug);
      const activeSuppress = existing.filter((r) => r.action === 'suppress' && !r.source_name)
        .map((r) => r.classification_slug);
      if (activeAdds.some((s) => String(s).toLowerCase() === addSlug.toLowerCase())) {
        results.push(resultRow(id, 'skipped', 'Classification already added'));
        continue;
      }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await syncThreatClassificationOverrides(client, {
          iocId: id,
          observableType: ioc.observable_type,
          additions: [...activeAdds, addSlug],
          suppressions: activeSuppress,
          actor
        });
        await client.query('COMMIT');
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        throw err;
      } finally {
        client.release();
      }
      await audit?.auditSuccess?.({
        req,
        action: AUDIT_ACTION.IOC_THREAT_CLASSIFICATIONS_UPDATED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(id),
        entityDisplay: `${ioc.observable_type} · ${ioc.observable}`,
        metadata: bulkMeta({ added: addSlug, observable_type: ioc.observable_type }, extraMetadata)
      }).catch(() => {});
      results.push(resultRow(id, 'ok'));
    } catch (err) {
      results.push(resultRow(id, 'error', String(err?.message || err)));
    }
  }
  return { ok: true, ...summarizeBulkResults(results) };
}

export async function bulkSuppress(pool, { iocIds, reason, expiresAt, user, req, audit, extraMetadata }) {
  const reasonCheck = parseRequiredReason(reason, { field: 'reason', minLength: 3, maxLength: 500 });
  if (!reasonCheck.ok) return { ok: false, status: 400, message: reasonCheck.message };
  const bulkAudit = audit?.auditSuccess
    ? {
      ...audit,
      auditSuccess: (evt) => audit.auditSuccess({
        ...evt,
        metadata: bulkMeta(evt?.metadata, extraMetadata)
      })
    }
    : audit;
  const { byId } = await loadIocsByIds(pool, iocIds);
  const results = [];
  for (const id of iocIds) {
    const ioc = byId.get(id);
    if (!ioc) {
      results.push(resultRow(id, 'error', 'IOC not found'));
      continue;
    }
    const created = await createManualSuppression(pool, {
      ioc_value: ioc.observable,
      ioc_type: ioc.observable_type,
      reason: reasonCheck.reason,
      expires_at: expiresAt
    }, { req, user, audit: bulkAudit });
    if (created.status === 409) {
      results.push(resultRow(id, 'skipped', 'Already suppressed'));
      continue;
    }
    if (created.status >= 400) {
      results.push(resultRow(id, 'error', created.body?.message || 'Failed to suppress'));
      continue;
    }
    results.push(resultRow(id, 'ok'));
  }
  return { ok: true, ...summarizeBulkResults(results) };
}

export async function bulkExpire(pool, { iocIds, reason, user, req, audit, extraMetadata }, deps = {}) {
  const recompute = deps.recomputeIocGlobalStatus || recomputeIocGlobalStatus;
  const reasonCheck = parseRequiredReason(reason, { field: 'reason', minLength: 3 });
  if (!reasonCheck.ok) return { ok: false, status: 400, message: reasonCheck.message };
  const { byId } = await loadIocsByIds(pool, iocIds);
  const userId = user?.publicId && /^[0-9a-f-]{36}$/i.test(user.publicId) ? user.publicId : null;
  const results = [];
  for (const id of iocIds) {
    const ioc = byId.get(id);
    if (!ioc) {
      results.push(resultRow(id, 'error', 'IOC not found'));
      continue;
    }
    const body = { manual_status: 'expired', reason: reasonCheck.reason };
    const noopCheck = evaluateIocStatusOverrideRequest(ioc, body);
    if (noopCheck.noop) {
      results.push(resultRow(id, 'skipped', noopCheck.message || 'Already expired'));
      continue;
    }
    try {
      await pool.query(
        `UPDATE ioc_items
         SET manual_status_override = TRUE,
             manual_status = 'expired',
             manual_expires_at = NULL,
             manual_override_reason = $3,
             manual_override_by_user_id = $4::uuid,
             manual_override_at = NOW()
         WHERE id = $1 AND observable_type = $2`,
        [id, ioc.observable_type, reasonCheck.reason, userId]
      );
      await recompute(pool, id, ioc.observable_type, {
        audit,
        actor: { actor_type: 'user', source: 'web' }
      });
      await audit?.auditSuccess?.({
        req,
        action: AUDIT_ACTION.IOC_EXPIRED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(id),
        entityDisplay: `${ioc.observable_type} · ${ioc.observable}`,
        metadata: bulkMeta({
          reason: reasonCheck.reason,
          manual_status: 'expired',
          observable_type: ioc.observable_type
        }, extraMetadata)
      }).catch(() => {});
      results.push(resultRow(id, 'ok'));
    } catch (err) {
      results.push(resultRow(id, 'error', String(err?.message || err)));
    }
  }
  return { ok: true, ...summarizeBulkResults(results) };
}
