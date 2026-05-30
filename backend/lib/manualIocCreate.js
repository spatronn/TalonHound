import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { parseManualExpirationInput } from './iocSourceValidation.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';
import { pickSafeFields } from './auditRedaction.js';
import { formatIocEntityDisplay } from './auditIocContext.js';

export function inferObservableType(value) {
  const v = String(value || '').trim();
  if (!v) return null;
  const isUrl = /^https?:\/\//i.test(v);
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v);
  if (isUrl || v.includes('/')) return 'url';
  if (isIpv4) return 'ip';
  if (/^[a-f0-9]{32,128}$/i.test(v)) return 'hash';
  return 'domain';
}

export function resolveManualIocConfidenceProvenance(body, sourceRow, confidence) {
  const sourceDefault = sourceRow?.default_confidence
    ? String(sourceRow.default_confidence).trim().toLowerCase()
    : null;
  const userSentConfidence = body?.confidence != null && String(body.confidence).trim() !== '';
  const usedSourceDefault = sourceDefault
    ? confidence === sourceDefault
    : !userSentConfidence;

  if (usedSourceDefault) {
    return {
      confidence_source: 'ioc_source_default',
      confidence_source_name: String(sourceRow.name)
    };
  }
  return {
    confidence_source: 'manual_entry',
    confidence_source_name: null
  };
}

function normalizeConfidence(value) {
  const c = String(value || 'medium').trim().toLowerCase();
  if (['low', 'medium', 'high'].includes(c)) return c;
  return 'medium';
}

export function serializeManualIocResponse(row, source, expiration) {
  if (!row) return null;
  return {
    id: Number(row.id),
    public_id: row.public_id,
    observable: row.observable,
    observable_type: row.observable_type,
    source_name: row.source_name,
    source_url: row.source_url,
    ioc_source_id: row.ioc_source_id != null ? Number(row.ioc_source_id) : null,
    source: source ? {
      id: source.id,
      name: source.name
    } : null,
    confidence: row.confidence,
    category: row.category,
    note: row.note,
    status: row.status || 'active',
    expires_at: row.expires_at,
    expired_at: row.expired_at,
    expiration_reason: row.expiration_reason || null,
    manual_status_override: Boolean(row.manual_status_override),
    manual_status: row.manual_status || null,
    manual_expires_at: row.manual_expires_at || null,
    expiration_policy: expiration?.policy || null,
    expire_days: expiration?.expire_days ?? null,
    created_at: row.created_at
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} body
 * @param {{ req?: import('express').Request, user?: object, audit?: object, onAfterInsert?: Function }} opts
 */
export async function createManualIoc(pool, body, opts = {}) {
  const value = String(body?.ip || body?.observable || '').trim();
  if (!value) {
    return { status: 400, body: { message: 'ip (IOC value) is required' } };
  }

  const sourceId = Number(body?.source_id ?? body?.ioc_source_id);
  if (!Number.isFinite(sourceId) || sourceId <= 0) {
    return { status: 400, body: { message: 'source_id is required' } };
  }

  const { rows: sourceRows } = await pool.query(
    `SELECT id, name, default_confidence, default_expire_policy, default_expire_days, active
     FROM ioc_sources WHERE id = $1`,
    [sourceId]
  );
  const sourceRow = sourceRows[0];
  if (!sourceRow) {
    return { status: 400, body: { message: 'Invalid IOC source' } };
  }
  if (sourceRow.active === false) {
    return { status: 400, body: { message: 'Selected IOC source is inactive.' } };
  }

  const observableType = inferObservableType(value);
  if (!observableType) {
    return { status: 400, body: { message: 'Could not infer IOC type from value' } };
  }

  const expirationInput = {
    expiration_policy: body?.expiration_policy ?? sourceRow.default_expire_policy ?? 'never',
    expire_days: body?.expire_days ?? sourceRow.default_expire_days,
    expires_at: body?.expires_at ?? body?.custom_expires_at
  };
  const expiration = parseManualExpirationInput(expirationInput);
  if (!expiration.ok) {
    return { status: 400, body: { message: expiration.error } };
  }

  const confidence = normalizeConfidence(body?.confidence ?? sourceRow.default_confidence);
  const confidenceProvenance = resolveManualIocConfidenceProvenance(body, sourceRow, confidence);
  const sourceName = String(sourceRow.name);
  const sourceUrl = body?.source_url ? String(body.source_url).trim() || null : null;
  const category = body?.category ? String(body.category).trim() || null : null;
  const note = body?.note ? String(body.note).trim() || null : null;
  const userId = opts.user?.publicId && /^[0-9a-f-]{36}$/i.test(opts.user.publicId)
    ? opts.user.publicId
    : null;

  const insertQ = `
    INSERT INTO ioc_items (
      observable, observable_type, source_name, source_url, confidence, category, note,
      ioc_source_id, confidence_source, confidence_source_name,
      manual_status_override, manual_status, manual_expires_at,
      manual_override_reason, manual_override_by_user_id, manual_override_at
    )
    SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, 'active', $11, $12, $13::uuid, NOW()
    WHERE NOT EXISTS (
      SELECT 1 FROM ioc_items
      WHERE observable = $1
        AND observable_type = $2
        AND source_name = $3
        AND confidence = $5
        AND COALESCE(category, '') = COALESCE($6, '')
        AND COALESCE(source_url, '') = COALESCE($4, '')
    )
    RETURNING *
  `;

  const insertParams = [
    value,
    observableType,
    sourceName,
    sourceUrl,
    confidence,
    category,
    note,
    sourceId,
    confidenceProvenance.confidence_source,
    confidenceProvenance.confidence_source_name,
    expiration.manual_expires_at,
    expiration.manual_override_reason,
    userId
  ];

  const { rows } = await pool.query(insertQ, insertParams);
  if (!rows.length) {
    return { status: 200, body: { skipped: true, reason: 'duplicate_tuple' } };
  }

  const row = rows[0];
  await pool.query(
    `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
     VALUES ($1, $2, $3)
     ON CONFLICT (ioc_public_id, observable_type, observable_value) DO NOTHING`,
    [row.public_id, row.observable_type, String(row.observable || '').toLowerCase()]
  ).catch(() => {});

  await recomputeIocGlobalStatus(pool, row.id, row.observable_type, {
    audit: opts.audit,
    actor: { actor_type: 'user', source: 'web' }
  });

  const { rows: freshRows } = await pool.query(
    `SELECT * FROM ioc_items WHERE id = $1 AND observable_type = $2`,
    [row.id, row.observable_type]
  );
  const fresh = freshRows[0] || row;

  if (typeof opts.onAfterInsert === 'function') {
    await opts.onAfterInsert(fresh);
  }

  const source = {
    id: Number(sourceRow.id),
    name: sourceRow.name
  };
  const response = serializeManualIocResponse(fresh, source, expiration);

  if (opts.audit?.auditSuccess && opts.req) {
    await opts.audit.auditSuccess({
      req: opts.req,
      action: AUDIT_ACTION.IOC_CREATED,
      entityType: AUDIT_ENTITY.IOC,
      entityId: String(fresh.id),
      entityDisplay: formatIocEntityDisplay(fresh.observable_type, fresh.observable),
      severity: AUDIT_SEVERITY.INFO,
      after: pickSafeFields(response, [
        'id', 'observable', 'observable_type', 'source_name', 'ioc_source_id',
        'status', 'expires_at', 'manual_expires_at', 'expiration_policy'
      ]),
      metadata: {
        manual_add: true,
        source_id: source.id,
        source_name: source.name,
        expiration_policy: expiration.policy,
        expire_days: expiration.expire_days ?? null
      }
    });
  }

  return { status: 201, body: response };
}
