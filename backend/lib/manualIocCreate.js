import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { parseManualExpirationInput, validateThreatClassifications } from './iocSourceValidation.js';
import {
  buildMultiThreatClassificationResponseFields,
  legacyThreatClassificationColumnValue,
  replaceIocThreatClassifications
} from './iocThreatClassifications.js';
import {
  buildMultiThreatActorResponseFields,
  emptyThreatActorResponseFields,
  legacyThreatActorColumnValue,
  replaceIocThreatActors,
  validateIocThreatActorIds
} from './iocThreatActors.js';
import { isExplicitIocLifecycleOverride } from './iocStatusOverrideGuards.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';
import { pickSafeFields } from './auditRedaction.js';
import { formatIocEntityDisplay } from './auditIocContext.js';
import { ensureIocTagAssignment } from './tagCatalogService.js';
import { parseExcludeTagIds } from './tagHelpers.js';
import { inferExactHashType, normalizeHashValue } from './fileArtifacts/hashNormalize.js';

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

/**
 * Map API/UI abstract "hash" to the concrete ioc_items observable_type
 * (md5/sha1/sha256) used by feeds and the ioc_file_hash partition.
 */
export function resolveStorageObservableType(value, inferredType = null) {
  const inferred = inferredType || inferObservableType(value);
  if (inferred !== 'hash') return { ok: true, type: inferred, value: String(value || '').trim() };
  const normalized = normalizeHashValue(value);
  const exact = inferExactHashType(normalized);
  if (!exact) {
    return {
      ok: false,
      error: 'Unsupported or invalid hash (expected md5/sha1/sha256 hex)'
    };
  }
  return { ok: true, type: exact, value: normalized };
}

export function resolveManualExpirationFromSource(sourceRow, opts = {}) {
  return parseManualExpirationInput(
    {
      expiration_policy: sourceRow?.default_expire_policy ?? 'never',
      expire_days: sourceRow?.default_expire_days
    },
    opts
  );
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

/**
 * Canonical identity for the WHERE NOT EXISTS duplicate predicate.
 * Used as pg_advisory_xact_lock(hashtext(...)) key so concurrent creates serialize.
 */
export function manualIocDuplicateLockKey({
  observable,
  observableType,
  sourceName,
  confidence,
  category,
  sourceUrl,
  threatClassification,
  threatActorId
}) {
  return [
    'manual_ioc',
    String(observable || ''),
    String(observableType || ''),
    String(sourceName || ''),
    String(confidence || ''),
    String(category ?? ''),
    String(sourceUrl ?? ''),
    String(threatClassification ?? 'unknown'),
    threatActorId == null || threatActorId === '' ? '' : String(threatActorId)
  ].join('\u001f');
}

export function serializeManualIocResponse(row, source, expiration, classificationFields = null, tags = null, actorFields = null) {
  if (!row) return null;
  const classFields = classificationFields || buildMultiThreatClassificationResponseFields([]);
  const threatActors = actorFields || (row.threat_actor_id
    ? buildMultiThreatActorResponseFields([{ id: row.threat_actor_id, name: null, active: true }])
    : emptyThreatActorResponseFields());
  const response = {
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
    ...classFields,
    ...threatActors,
    note: row.note,
    status: row.status || 'active',
    expires_at: row.expires_at,
    expired_at: row.expired_at,
    expiration_reason: row.expiration_reason || null,
    // A manual source is not a lifecycle override, even though its row carries
    // manual_status_override for its own expiry bookkeeping. Report the analyst-facing value.
    manual_status_override: isExplicitIocLifecycleOverride(row),
    manual_status: row.manual_status || null,
    manual_expires_at: row.manual_expires_at || null,
    expiration_policy: expiration?.policy || null,
    expire_days: expiration?.expire_days ?? null,
    created_at: row.created_at
  };
  if (Array.isArray(tags)) {
    response.tags = tags;
  }
  return response;
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
    `SELECT id, name, default_confidence, default_threat_classification, default_expire_policy, default_expire_days, active, archived_at
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
  if (sourceRow.archived_at) {
    return { status: 400, body: { message: 'Selected IOC source is archived.' } };
  }

  const inferredType = inferObservableType(value);
  if (!inferredType) {
    return { status: 400, body: { message: 'Could not infer IOC type from value' } };
  }
  const storage = resolveStorageObservableType(value, inferredType);
  if (!storage.ok) {
    return { status: 400, body: { message: storage.error } };
  }
  const observableType = storage.type;
  const observable = storage.value;

  const expiration = resolveManualExpirationFromSource(sourceRow);
  if (!expiration.ok) {
    return { status: 400, body: { message: expiration.error } };
  }

  const confidence = normalizeConfidence(body?.confidence ?? sourceRow.default_confidence);
  const rawClassifications = body?.threat_classifications
    ?? (body?.threat_classification != null || body?.primary_threat_classification != null
      ? [body?.threat_classification ?? body?.primary_threat_classification]
      : sourceRow.default_threat_classification);
  const threatClassCheck = await validateThreatClassifications(pool, rawClassifications);
  if (!threatClassCheck.ok) return { status: 400, body: { message: threatClassCheck.error } };
  const threatClassSlugs = threatClassCheck.value;
  const legacyThreatClass = legacyThreatClassificationColumnValue(threatClassSlugs);

  let threatActorIds = [];
  let threatActorRows = [];
  if (Array.isArray(body?.threat_actor_ids) || Array.isArray(body?.threat_actors)) {
    const raw = Array.isArray(body?.threat_actor_ids)
      ? body.threat_actor_ids
      : body.threat_actors.map((x) => x?.id ?? x?.threat_actor_id ?? x);
    const check = await validateIocThreatActorIds(pool, raw, { requireActive: true });
    if (!check.ok) return { status: 400, body: { message: check.error } };
    threatActorIds = check.value;
    threatActorRows = check.rows || [];
  } else if (body?.threat_actor_id != null && body?.threat_actor_id !== '') {
    const check = await validateIocThreatActorIds(pool, [body.threat_actor_id], { requireActive: true });
    if (!check.ok) return { status: 400, body: { message: check.error } };
    threatActorIds = check.value;
    threatActorRows = check.rows || [];
  }
  const threatActorId = legacyThreatActorColumnValue(threatActorIds);
  const confidenceProvenance = resolveManualIocConfidenceProvenance(body, sourceRow, confidence);
  const sourceName = String(sourceRow.name);
  const sourceUrl = body?.source_url ? String(body.source_url).trim() || null : null;
  const category = body?.category ? String(body.category).trim() || null : null;
  const note = body?.note ? String(body.note).trim() || null : null;
  const userId = opts.user?.publicId && /^[0-9a-f-]{36}$/i.test(opts.user.publicId)
    ? opts.user.publicId
    : null;

  const requestedTagIds = parseExcludeTagIds(body?.tag_ids ?? body?.tags);
  let resolvedTags = [];
  if (requestedTagIds.length) {
    const tagQ = await pool.query(
      `SELECT id, name, type, category
       FROM tags
       WHERE id = ANY($1::int[]) AND enabled = TRUE`,
      [requestedTagIds]
    );
    if (tagQ.rows.length !== requestedTagIds.length) {
      return { status: 400, body: { message: 'One or more tags are invalid or disabled' } };
    }
    // Preserve request orde
    const byId = new Map(tagQ.rows.map((row) => [Number(row.id), row]));
    resolvedTags = requestedTagIds.map((id) => byId.get(id)).filter(Boolean);
  }

  const createdOrigin = opts.createdOrigin === 'api' ? 'api' : 'manual_add';
  // API-created rows have no user UUID; web manual-add stamps the session user.
  const createdByUserId = createdOrigin === 'api' ? null : userId;

  const insertQ = `
    INSERT INTO ioc_items (
      observable, observable_type, source_name, source_url, confidence, category, threat_classification, threat_actor_id, note,
      ioc_source_id, confidence_source, confidence_source_name,
      manual_status_override, manual_status, manual_expires_at,
      manual_override_reason, manual_override_by_user_id, manual_override_at,
      created_origin, created_by_user_id
    )
    SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, TRUE, 'active', $13, $14, $15::uuid, NOW(),
           $16, $17::uuid
    WHERE NOT EXISTS (
      SELECT 1 FROM ioc_items
      WHERE observable = $1
        AND observable_type = $2
        AND source_name = $3
        AND confidence = $5
        AND COALESCE(category, '') = COALESCE($6, '')
        AND COALESCE(source_url, '') = COALESCE($4, '')
        AND COALESCE(threat_classification, 'unknown') = COALESCE($7, 'unknown')
        AND threat_actor_id IS NOT DISTINCT FROM $8::uuid
    )
    RETURNING *
  `;

  const insertParams = [
    observable,
    observableType,
    sourceName,
    sourceUrl,
    confidence,
    category,
    legacyThreatClass,
    threatActorId,
    note,
    sourceId,
    confidenceProvenance.confidence_source,
    confidenceProvenance.confidence_source_name,
    expiration.manual_expires_at,
    expiration.manual_override_reason,
    userId,
    createdOrigin,
    createdByUserId
  ];

  const lockKey = manualIocDuplicateLockKey({
    observable,
    observableType,
    sourceName,
    confidence,
    category,
    sourceUrl,
    threatClassification: legacyThreatClass,
    threatActorId
  });

  const client = await pool.connect();
  let rows;
  try {
    await client.query('BEGIN');
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtext($1)::bigint)',
      [lockKey]
    );
    const insertResult = await client.query(insertQ, insertParams);
    rows = insertResult.rows;
    await client.query('COMMIT');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  } finally {
    client.release();
  }

  if (!rows.length) {
    return { status: 200, body: { skipped: true, reason: 'duplicate_tuple' } };
  }

  const row = rows[0];
  await replaceIocThreatClassifications(pool, {
    iocId: row.id,
    observableType: row.observable_type,
    slugs: threatClassSlugs,
    sourceType: 'manual',
    sourceName,
    actor: userId
  }).catch(() => {});

  if (threatActorIds.length) {
    await replaceIocThreatActors(pool, {
      iocId: row.id,
      observableType: row.observable_type,
      threatActorIds,
      sourceType: 'manual',
      sourceName,
      actor: userId
    }).catch(() => {});
  }

  const assignedTags = [];
  for (const tag of resolvedTags) {
    try {
      await ensureIocTagAssignment(pool, {
        iocId: row.id,
        observableType: row.observable_type,
        tagId: tag.id,
        origin: 'manual',
        createdBy: opts.user?.id ?? null
      });
      assignedTags.push({
        id: Number(tag.id),
        name: tag.name,
        type: tag.type || null
      });
    } catch {
      // Tag assignment must not fail manual IOC create after insert
    }
  }

  await pool.query(
    `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
     VALUES ($1, $2, $3)
     ON CONFLICT (ioc_public_id, observable_type, observable_value) DO NOTHING`,
    [row.public_id, row.observable_type, String(row.observable || '').toLowerCase()]
  ).catch(() => {});

  try {
    const { dualWriteFileArtifactForObservable } = await import('./fileArtifacts/dualWrite.js');
    await dualWriteFileArtifactForObservable(pool, {
      observable: row.observable,
      observableType: row.observable_type,
      sourceName,
      note: row.note,
      confidence: row.confidence,
      firstSeenAt: row.created_at,
      lastSeenAt: row.created_at,
      attachNoteSiblings: false,
      providerMapping: false
    });
  } catch {
    // dual-write must never fail manual IOC create
  }

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
  const classFields = buildMultiThreatClassificationResponseFields(threatClassSlugs);
  const actorFields = threatActorRows.length
    ? buildMultiThreatActorResponseFields(threatActorRows)
    : emptyThreatActorResponseFields();
  const response = serializeManualIocResponse(fresh, source, expiration, classFields, assignedTags, actorFields);

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
        'threat_classification', 'threat_classifications', 'threat_actor_id', 'threat_actor_ids',
        'status', 'expires_at', 'manual_expires_at', 'expiration_policy'
      ]),
      metadata: {
        manual_add: createdOrigin === 'manual_add',
        api_create: createdOrigin === 'api',
        created_origin: createdOrigin,
        source_id: source.id,
        source_name: source.name,
        expiration_policy: expiration.policy,
        expire_days: expiration.expire_days ?? null,
        tag_ids: assignedTags.map((t) => t.id)
      }
    });

    for (const tag of assignedTags) {
      await opts.audit.auditSuccess({
        req: opts.req,
        action: AUDIT_ACTION.IOC_TAG_ADDED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: fresh.public_id ? String(fresh.public_id) : String(fresh.id),
        entityDisplay: fresh.observable || String(fresh.id),
        subjectIocId: fresh.id,
        subjectIocType: fresh.observable_type || null,
        subjectIocValue: fresh.observable || null,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          ioc_id: String(fresh.id),
          subject_ioc_id: String(fresh.id),
          subject_ioc_type: fresh.observable_type || null,
          subject_ioc_value: fresh.observable || null,
          tag_id: tag.id,
          tag_name: tag.name,
          tag_type: tag.type,
          via: 'manual_create'
        }
      }).catch(() => {});
    }
  }

  return { status: 201, body: response };
}
