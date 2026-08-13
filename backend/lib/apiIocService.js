/**
 * Shared IOC create/update application service for REST (and future MCP).
 * Reuses createManualIoc + existing classification/tag helpers — no parallel domain logic.
 */

import { createManualIoc, inferObservableType, serializeManualIocResponse } from './manualIocCreate.js';
import { resolveApiSystemSource } from './apiSystemSource.js';
import { normalizeConfidence, CONFIDENCE_LEVELS } from './iocConfidence.js';
import { validateThreatClassifications } from './iocSourceValidation.js';
import {
  buildMultiThreatClassificationResponseFields,
  legacyThreatClassificationColumnValue,
  replaceIocThreatClassifications,
  fetchIocThreatClassificationSlugs
} from './iocThreatClassifications.js';
import { ensureIocTagAssignment } from './tagCatalogService.js';
import { normalizeTagName } from './tagHelpers.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';
import { pickSafeFields } from './auditRedaction.js';
import { formatIocEntityDisplay } from './auditIocContext.js';
import { API_ERROR_CODE } from './apiV1Errors.js';

export const API_IOC_TYPES = Object.freeze(['ip', 'domain', 'url', 'hash']);

function apiActorAuditFields(apiKey) {
  return {
    actorUsername: apiKey?.name ? `api_key:${apiKey.name}` : 'api_key',
    actorEmail: null,
    actorRole: 'api_key',
    actorPublicId: null,
    source: 'api',
    metadataExtras: {
      actor_type: 'api_key',
      actor_id: apiKey?.id != null ? Number(apiKey.id) : null,
      actor_name: apiKey?.name || null,
      access_profile: apiKey?.key_type || null
    }
  };
}

/**
 * Normalize IOC value for storage/lookup. Aligns with manual create + observables.
 * @param {string} type
 * @param {string} value
 */
export function normalizeApiIocValue(type, value) {
  const t = String(type || '').trim().toLowerCase();
  let v = String(value || '').trim();
  if (!v) return { ok: false, code: API_ERROR_CODE.INVALID_IOC_VALUE, message: 'value is required' };

  if (t === 'hash') {
    v = v.toLowerCase();
    if (!/^[a-f0-9]{32}$/.test(v) && !/^[a-f0-9]{40}$/.test(v) && !/^[a-f0-9]{64}$/.test(v) && !/^[a-f0-9]{128}$/.test(v)) {
      return {
        ok: false,
        code: API_ERROR_CODE.INVALID_IOC_VALUE,
        message: 'The supplied value is not a valid hash (md5/sha1/sha256/sha512 hex).'
      };
    }
  } else if (t === 'ip') {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v);
    // Minimal IPv6 acceptance (contains colon, no spaces)
    const ipv6 = v.includes(':') && !/\s/.test(v);
    if (!ipv4 && !ipv6) {
      return {
        ok: false,
        code: API_ERROR_CODE.INVALID_IOC_VALUE,
        message: 'The supplied value is not a valid IP address.'
      };
    }
  } else if (t === 'domain') {
    v = v.toLowerCase().replace(/\.$/, '');
    if (v.includes('/') || /\s/.test(v) || !/^[a-z0-9._-]+$/i.test(v) || !v.includes('.')) {
      return {
        ok: false,
        code: API_ERROR_CODE.INVALID_IOC_VALUE,
        message: 'The supplied value is not a valid domain.'
      };
    }
  } else if (t === 'url') {
    if (!/^https?:\/\//i.test(v)) {
      return {
        ok: false,
        code: API_ERROR_CODE.INVALID_IOC_VALUE,
        message: 'The supplied value is not a valid URL (must start with http:// or https://).'
      };
    }
  } else {
    return {
      ok: false,
      code: API_ERROR_CODE.INVALID_IOC_TYPE,
      message: `type must be one of: ${API_IOC_TYPES.join(', ')}`
    };
  }

  return { ok: true, type: t, value: v };
}

export function parseApiIocType(raw) {
  const t = String(raw || '').trim().toLowerCase();
  if (!t) {
    return { ok: false, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'type is required' };
  }
  if (!API_IOC_TYPES.includes(t)) {
    return {
      ok: false,
      code: API_ERROR_CODE.INVALID_IOC_TYPE,
      message: `type must be one of: ${API_IOC_TYPES.join(', ')}`
    };
  }
  return { ok: true, value: t };
}

function parseOptionalConfidence(raw, { required = false } = {}) {
  if (raw == null || String(raw).trim() === '') {
    if (required) {
      return { ok: false, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'confidence is required' };
    }
    return { ok: true, value: undefined };
  }
  const c = normalizeConfidence(raw);
  if (!c) {
    return {
      ok: false,
      code: API_ERROR_CODE.VALIDATION_ERROR,
      message: `confidence must be one of: ${CONFIDENCE_LEVELS.join(', ')}`
    };
  }
  return { ok: true, value: c };
}

function parseClassificationsField(body) {
  if (body?.classifications != null) return body.classifications;
  if (body?.threat_classifications != null) return body.threat_classifications;
  if (body?.threat_classification != null) return [body.threat_classification];
  return undefined;
}

function parseTagsField(body) {
  if (body?.tags != null) return body.tags;
  return undefined;
}

/**
 * Resolve tag names to enabled catalog rows. Unknown names are rejected.
 * @param {import('pg').Pool} pool
 * @param {unknown} tagsRaw
 */
export async function resolveTagNames(pool, tagsRaw) {
  if (tagsRaw === undefined) return { ok: true, value: undefined };
  if (!Array.isArray(tagsRaw)) {
    return { ok: false, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'tags must be an array of tag names' };
  }
  const names = [];
  const seen = new Set();
  for (const raw of tagsRaw) {
    if (typeof raw !== 'string' && typeof raw !== 'number') {
      return { ok: false, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'tags must be an array of tag names' };
    }
    const name = normalizeTagName(raw);
    if (!name) {
      return { ok: false, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'tags must not contain empty names' };
    }
    if (!seen.has(name)) {
      seen.add(name);
      names.push(name);
    }
  }
  if (!names.length) return { ok: true, value: [] };

  const { rows } = await pool.query(
    `SELECT id, name, type, category, enabled
     FROM tags
     WHERE lower(name) = ANY($1::text[])`,
    [names]
  );
  const byLower = new Map(rows.map((r) => [normalizeTagName(r.name), r]));
  const missing = names.filter((n) => !byLower.has(n));
  if (missing.length) {
    return {
      ok: false,
      code: API_ERROR_CODE.VALIDATION_ERROR,
      message: `Unknown or disabled tags: ${missing.join(', ')}`
    };
  }
  const disabled = names.filter((n) => byLower.get(n)?.enabled === false);
  if (disabled.length) {
    return {
      ok: false,
      code: API_ERROR_CODE.VALIDATION_ERROR,
      message: `Unknown or disabled tags: ${disabled.join(', ')}`
    };
  }
  return {
    ok: true,
    value: names.map((n) => {
      const row = byLower.get(n);
      return { id: Number(row.id), name: row.name, type: row.type || null };
    })
  };
}

export function toApiIocResponse(row, extras = {}) {
  return {
    id: Number(row.id),
    public_id: row.public_id || null,
    type: row.observable_type || row.type,
    value: row.observable || row.value,
    confidence: row.confidence ?? null,
    classifications: row.classifications
      || row.threat_classifications
      || (row.threat_classification ? [row.threat_classification] : []),
    tags: Array.isArray(row.tags)
      ? row.tags.map((t) => (typeof t === 'string' ? t : t?.name)).filter(Boolean)
      : [],
    note: row.note ?? null,
    status: row.status || null,
    created_at: row.created_at || null,
    ...extras
  };
}

async function findExistingIoc(pool, type, value) {
  const { rows } = await pool.query(
    `SELECT *
     FROM ioc_items
     WHERE observable_type = $1 AND observable = $2
     ORDER BY created_at ASC, id ASC
     LIMIT 1`,
    [type, value]
  );
  return rows[0] || null;
}

export async function loadManualTags(pool, iocId, observableType) {
  const { rows } = await pool.query(
    `SELECT t.id, t.name, t.type
     FROM ioc_tags it
     JOIN tags t ON t.id = it.tag_id
     WHERE it.ioc_id = $1
       AND it.ioc_observable_type = $2
       AND it.origin = 'manual'
       AND t.enabled = TRUE
     ORDER BY t.name ASC`,
    [iocId, observableType]
  );
  return rows.map((r) => ({ id: Number(r.id), name: r.name, type: r.type || null }));
}

/**
 * Create (or return existing) IOC via shared domain logic.
 * @returns {Promise<{ status: number, body?: object, error?: { code: string, message: string, details?: unknown } }>}
 */
export async function createApiIoc(pool, body, opts = {}) {
  const apiKey = opts.apiKey;
  const typeParsed = parseApiIocType(body?.type);
  if (!typeParsed.ok) return { status: 400, error: typeParsed };

  const norm = normalizeApiIocValue(typeParsed.value, body?.value ?? body?.observable ?? body?.ip);
  if (!norm.ok) return { status: 400, error: norm };

  // Reject / ignore provenance spoof fields — never accept client source.
  const confidenceParsed = parseOptionalConfidence(body?.confidence);
  if (!confidenceParsed.ok) return { status: 400, error: confidenceParsed };

  const tagsResolved = await resolveTagNames(pool, parseTagsField(body));
  if (!tagsResolved.ok) return { status: 400, error: tagsResolved };

  const rawClassifications = parseClassificationsField(body);
  let threatClassSlugs;
  if (rawClassifications !== undefined) {
    const check = await validateThreatClassifications(pool, rawClassifications);
    if (!check.ok) {
      return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: check.error } };
    }
    threatClassSlugs = check.value;
  }

  const note = body?.note != null ? String(body.note).trim() || null : null;

  const existing = await findExistingIoc(pool, norm.type, norm.value);
  if (existing) {
    const tags = await loadManualTags(pool, existing.id, existing.observable_type);
    const classSlugs = await fetchIocThreatClassificationSlugs(pool, existing.id, existing.observable_type);
    return {
      status: 200,
      body: toApiIocResponse(
        {
          ...existing,
          classifications: classSlugs.length
            ? classSlugs
            : (existing.threat_classification ? [existing.threat_classification] : []),
          tags
        },
        { created: false, existing: true }
      )
    };
  }

  let sourceRow;
  try {
    sourceRow = await resolveApiSystemSource(pool);
  } catch (err) {
    return {
      status: 500,
      error: {
        code: API_ERROR_CODE.INTERNAL_ERROR,
        message: err?.code === 'API_SYSTEM_SOURCE_MISSING'
          ? 'System API IOC source is not configured'
          : 'Internal error'
      }
    };
  }

  const manualBody = {
    observable: norm.value,
    ip: norm.value,
    source_id: Number(sourceRow.id),
    confidence: confidenceParsed.value,
    threat_classifications: threatClassSlugs,
    tag_ids: tagsResolved.value?.map((t) => t.id),
    note
    // intentionally omit source_name / source_url / any client provenance
  };

  const actor = apiActorAuditFields(apiKey);
  const result = await createManualIoc(pool, manualBody, {
    req: opts.req,
    user: null,
    audit: opts.audit
      ? {
        auditSuccess: (event) => opts.audit.auditSuccess({
          ...event,
          actorUsername: actor.actorUsername,
          actorEmail: actor.actorEmail,
          actorRole: actor.actorRole,
          actorPublicId: actor.actorPublicId,
          source: actor.source,
          metadata: {
            ...(event.metadata || {}),
            ...actor.metadataExtras,
            via: 'api_v1'
          }
        })
      }
      : null,
    createdOrigin: 'api',
    onAfterInsert: opts.onAfterInsert
  });

  if (result.status === 200 && result.body?.skipped) {
    // Race: another insert won the tuple race; re-lookup by type+value.
    const raced = await findExistingIoc(pool, norm.type, norm.value);
    if (raced) {
      const tags = await loadManualTags(pool, raced.id, raced.observable_type);
      const classSlugs = await fetchIocThreatClassificationSlugs(pool, raced.id, raced.observable_type);
      return {
        status: 200,
        body: toApiIocResponse(
          {
            ...raced,
            classifications: classSlugs.length
              ? classSlugs
              : (raced.threat_classification ? [raced.threat_classification] : []),
            tags
          },
          { created: false, existing: true }
        )
      };
    }
    return {
      status: 200,
      body: { created: false, existing: true, skipped: true, reason: result.body.reason }
    };
  }

  if (result.status >= 400) {
    const msg = result.body?.message || 'Validation failed';
    let code = API_ERROR_CODE.VALIDATION_ERROR;
    if (/type/i.test(msg)) code = API_ERROR_CODE.INVALID_IOC_TYPE;
    if (/value|observable|ip /i.test(msg)) code = API_ERROR_CODE.INVALID_IOC_VALUE;
    return { status: result.status, error: { code, message: msg } };
  }

  const created = result.body;
  return {
    status: 201,
    body: toApiIocResponse(
      {
        id: created.id,
        public_id: created.public_id,
        observable_type: created.observable_type || norm.type,
        observable: created.observable || norm.value,
        confidence: created.confidence,
        classifications: created.threat_classifications || [],
        tags: created.tags || tagsResolved.value || [],
        note: created.note,
        status: created.status,
        created_at: created.created_at
      },
      { created: true }
    )
  };
}

/**
 * Update mutable IOC metadata. type/value are immutable.
 */
export async function updateApiIoc(pool, iocId, body, opts = {}) {
  const id = Number(iocId);
  if (!Number.isFinite(id) || id <= 0) {
    return {
      status: 400,
      error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'Invalid IOC id' }
    };
  }

  if (body && Object.prototype.hasOwnProperty.call(body, 'type')) {
    return {
      status: 400,
      error: {
        code: API_ERROR_CODE.VALIDATION_ERROR,
        message: 'type is immutable; create a new IOC instead of changing identity'
      }
    };
  }
  if (body && (
    Object.prototype.hasOwnProperty.call(body, 'value')
    || Object.prototype.hasOwnProperty.call(body, 'observable')
    || Object.prototype.hasOwnProperty.call(body, 'ip')
  )) {
    return {
      status: 400,
      error: {
        code: API_ERROR_CODE.VALIDATION_ERROR,
        message: 'value is immutable; create a new IOC instead of changing identity'
      }
    };
  }

  // Strip / reject provenance spoof attempts silently (ignored) except documented rejects above.
  const hasConfidence = body && Object.prototype.hasOwnProperty.call(body, 'confidence');
  const hasClassifications = body && (
    Object.prototype.hasOwnProperty.call(body, 'classifications')
    || Object.prototype.hasOwnProperty.call(body, 'threat_classifications')
    || Object.prototype.hasOwnProperty.call(body, 'threat_classification')
  );
  const hasTags = body && Object.prototype.hasOwnProperty.call(body, 'tags');
  const hasNote = body && Object.prototype.hasOwnProperty.call(body, 'note');

  if (!hasConfidence && !hasClassifications && !hasTags && !hasNote) {
    return {
      status: 400,
      error: {
        code: API_ERROR_CODE.VALIDATION_ERROR,
        message: 'No mutable fields provided (confidence, classifications, tags, note)'
      }
    };
  }

  const { rows } = await pool.query(`SELECT * FROM ioc_items WHERE id = $1 LIMIT 1`, [id]);
  const row = rows[0];
  if (!row) {
    return { status: 404, error: { code: API_ERROR_CODE.IOC_NOT_FOUND, message: 'IOC not found' } };
  }

  const before = {
    confidence: row.confidence,
    note: row.note,
    classifications: await fetchIocThreatClassificationSlugs(pool, row.id, row.observable_type),
    tags: await loadManualTags(pool, row.id, row.observable_type)
  };

  if (hasConfidence) {
    const confidenceParsed = parseOptionalConfidence(body.confidence, { required: true });
    if (!confidenceParsed.ok) return { status: 400, error: confidenceParsed };
    await pool.query(
      `UPDATE ioc_items
       SET confidence = $3,
           analyst_confidence_override = $3,
           analyst_confidence_override_reason = $4,
           analyst_confidence_overridden_at = NOW()
       WHERE id = $1 AND observable_type = $2`,
      [row.id, row.observable_type, confidenceParsed.value, 'Updated via API']
    );
  }

  if (hasClassifications) {
    const check = await validateThreatClassifications(pool, parseClassificationsField(body));
    if (!check.ok) {
      return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: check.error } };
    }
    await replaceIocThreatClassifications(pool, {
      iocId: row.id,
      observableType: row.observable_type,
      slugs: check.value,
      sourceType: 'manual',
      sourceName: opts.apiKey?.name || 'API',
      actor: opts.apiKey ? `api_key:${opts.apiKey.id}` : 'api'
    });
  }

  if (hasTags) {
    const tagsResolved = await resolveTagNames(pool, body.tags);
    if (!tagsResolved.ok) return { status: 400, error: tagsResolved };
    const nextIds = new Set(tagsResolved.value.map((t) => t.id));
    await pool.query(
      `DELETE FROM ioc_tags
       WHERE ioc_id = $1
         AND ioc_observable_type = $2
         AND origin = 'manual'
         AND NOT (tag_id = ANY($3::int[]))`,
      [row.id, row.observable_type, [...nextIds]]
    );
    for (const tag of tagsResolved.value) {
      await ensureIocTagAssignment(pool, {
        iocId: row.id,
        observableType: row.observable_type,
        tagId: tag.id,
        origin: 'manual',
        createdBy: null
      });
    }
  }

  if (hasNote) {
    const note = body.note == null ? null : (String(body.note).trim() || null);
    await pool.query(
      `UPDATE ioc_items SET note = $3 WHERE id = $1 AND observable_type = $2`,
      [row.id, row.observable_type, note]
    );
  }

  const { rows: freshRows } = await pool.query(
    `SELECT * FROM ioc_items WHERE id = $1 AND observable_type = $2`,
    [row.id, row.observable_type]
  );
  const fresh = freshRows[0] || row;
  const classifications = await fetchIocThreatClassificationSlugs(pool, fresh.id, fresh.observable_type);
  const tags = await loadManualTags(pool, fresh.id, fresh.observable_type);
  const response = toApiIocResponse({
    ...fresh,
    classifications,
    tags
  });

  if (opts.audit?.auditSuccess && opts.req) {
    const actor = apiActorAuditFields(opts.apiKey);
    await opts.audit.auditSuccess({
      req: opts.req,
      action: AUDIT_ACTION.IOC_UPDATED,
      entityType: AUDIT_ENTITY.IOC,
      entityId: String(fresh.id),
      entityDisplay: formatIocEntityDisplay(fresh.observable_type, fresh.observable),
      severity: AUDIT_SEVERITY.INFO,
      actorUsername: actor.actorUsername,
      actorEmail: actor.actorEmail,
      actorRole: actor.actorRole,
      actorPublicId: actor.actorPublicId,
      source: actor.source,
      before: pickSafeFields(before, ['confidence', 'note', 'classifications', 'tags']),
      after: pickSafeFields(response, ['confidence', 'note', 'classifications', 'tags']),
      metadata: {
        ...actor.metadataExtras,
        via: 'api_v1',
        changed: {
          confidence: hasConfidence,
          classifications: hasClassifications,
          tags: hasTags,
          note: hasNote
        }
      }
    });
  }

  return { status: 200, body: response };
}

export { serializeManualIocResponse, inferObservableType, legacyThreatClassificationColumnValue, buildMultiThreatClassificationResponseFields };
