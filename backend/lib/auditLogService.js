import { AUDIT_SEVERITY, AUDIT_STATUS } from './auditConstants.js';
import { redactSensitive } from './auditRedaction.js';
import { normalizeAppRole, ROLES } from './rbac.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(value) {
  return UUID_RE.test(String(value || '').trim());
}

function resolveSource(req, explicit) {
  if (explicit) return String(explicit);
  const via = String(req?.authVia || '').toLowerCase();
  if (via === 'ingest') return 'ingest';
  if (via === 'mcp') return 'mcp';
  if (via === 'bearer') return 'api';
  if (via === 'api_key') return 'api';
  return 'web';
}

function resolveIp(req) {
  const fwd = String(req?.headers?.['x-forwarded-for'] || '')
    .split(',')[0]
    .trim();
  if (fwd) return fwd;
  return req?.ip || req?.socket?.remoteAddress || null;
}

function resolveRequestId(req, explicit) {
  if (explicit) return String(explicit).trim().slice(0, 128) || null;
  const hdr = req?.headers?.['x-request-id'] || req?.headers?.['x-correlation-id'];
  if (hdr) return String(hdr).trim().slice(0, 128);
  // Server-assigned per-request id (ensureRequestId in server.js) so every
  // audit row written during one HTTP request shares a correlation key.
  return req?.requestId ? String(req.requestId).slice(0, 128) : null;
}

function normalizeSeverity(value) {
  const s = String(value || AUDIT_SEVERITY.INFO).toLowerCase();
  if (s === AUDIT_SEVERITY.WARNING || s === AUDIT_SEVERITY.CRITICAL) return s;
  return AUDIT_SEVERITY.INFO;
}

function normalizeStatus(value) {
  const s = String(value || AUDIT_STATUS.SUCCESS).toLowerCase();
  if (s === AUDIT_STATUS.FAILED || s === AUDIT_STATUS.PARTIAL) return s;
  return AUDIT_STATUS.SUCCESS;
}

function jsonOrNull(value) {
  if (value == null) return null;
  const redacted = redactSensitive(value);
  if (redacted == null) return null;
  return redacted;
}

/**
 * @param {import('pg').Pool} pool
 */
export function createAuditLogService(pool) {
  const publicIdCache = new Map();

  /**
   * Resolve the persisted users.public_id for a session user. Interactive
   * (cookie/JWT) sessions only carry the numeric id, so this is the single
   * place that turns a request principal into an attributable actor id.
   * @param {object|null|undefined} user - req.user-shaped principal
   */
  async function resolveUserPublicId(user) {
    if (user?.publicId && isUuid(user.publicId)) {
      return String(user.publicId);
    }
    const internalId = user?.id;
    if (internalId == null || !Number.isFinite(Number(internalId))) return null;
    const key = Number(internalId);
    if (publicIdCache.has(key)) return publicIdCache.get(key);
    try {
      const { rows } = await pool.query('SELECT public_id FROM users WHERE id = $1 LIMIT 1', [key]);
      const pid = rows[0]?.public_id ? String(rows[0].public_id) : null;
      publicIdCache.set(key, pid);
      return pid;
    } catch {
      return null;
    }
  }

  /**
   * Actor principal for a request: `req.user` enriched with its public id.
   * Use it when a user-initiated operation must stamp `created_by` /
   * `requested_by` columns or hand the actor to a service layer.
   * @param {import('express').Request|undefined} req
   */
  async function resolveActor(req) {
    const user = req?.user;
    if (!user) return null;
    const publicId = await resolveUserPublicId(user);
    return { ...user, publicId: publicId || user.publicId || null };
  }

  /**
   * @param {{
   *   req?: import('express').Request,
   *   actor?: object|null,
   *   requestId?: string|null,
   *   action: string,
   *   entityType: string,
   *   entityId?: string|number|null,
   *   entityDisplay?: string|null,
   *   subjectIocId?: number|string|null,
   *   subjectIocType?: string|null,
   *   subjectIocValue?: string|null,
   *   targetType?: string|null,
   *   targetValue?: string|null,
   *   severity?: string,
   *   status?: string,
   *   before?: unknown,
   *   after?: unknown,
   *   metadata?: unknown,
   *   source?: string,
   *   actorPublicId?: string|null,
   *   actorUsername?: string|null,
   *   actorEmail?: string|null,
   *   actorRole?: string|null,
   * }} event
   */
  async function auditLog(event) {
    try {
      const req = event.req;
      // Actor precedence: explicit actor* fields → request principal → `actor`
      // (a req.user-shaped object for callers that run outside the request).
      const principal = req?.user || (event.actor && typeof event.actor === 'object' ? event.actor : null);
      const actorPublicId = event.actorPublicId ?? (principal ? await resolveUserPublicId(principal) : null);
      const actorUsername = event.actorUsername ?? (principal?.username || principal?.email || null);
      const actorEmail = event.actorEmail ?? (principal?.email || principal?.username || null);
      const actorRole = event.actorRole ?? (normalizeAppRole(principal?.role) || ROLES.ADMIN);

      const meta = event.metadata && typeof event.metadata === 'object' ? event.metadata : {};
      const subjectIocIdRaw = event.subjectIocId ?? meta.subject_ioc_id ?? meta.ioc_id;
      const subjectIocId = subjectIocIdRaw != null && Number.isFinite(Number(subjectIocIdRaw))
        ? Number(subjectIocIdRaw)
        : null;
      const subjectIocType = event.subjectIocType ?? meta.subject_ioc_type ?? meta.observable_type ?? null;
      const subjectIocValue = event.subjectIocValue ?? meta.subject_ioc_value ?? meta.observable_value ?? meta.original_value ?? null;
      const targetType = event.targetType ?? meta.target_type ?? null;
      const targetValue = event.targetValue ?? meta.target_value ?? null;

      await pool.query(
        `INSERT INTO audit_logs (
           actor_user_id, actor_username, actor_email, actor_role,
           action, entity_type, entity_id, entity_display,
           subject_ioc_id, subject_ioc_type, subject_ioc_value, target_type, target_value,
           severity, status, ip_address, user_agent, request_id, source,
           before_data, after_data, metadata
         ) VALUES (
           $1::uuid, $2, $3, $4,
           $5, $6, $7, $8,
           $9, $10, $11, $12, $13,
           $14, $15, $16::inet, $17, $18, $19,
           $20::jsonb, $21::jsonb, $22::jsonb
         )`,
        [
          actorPublicId && isUuid(actorPublicId) ? actorPublicId : null,
          actorUsername ? String(actorUsername).slice(0, 255) : null,
          actorEmail ? String(actorEmail).slice(0, 255) : null,
          actorRole ? String(actorRole).slice(0, 64) : null,
          String(event.action || '').slice(0, 128),
          String(event.entityType || '').slice(0, 128),
          event.entityId != null ? String(event.entityId).slice(0, 255) : null,
          event.entityDisplay != null ? String(event.entityDisplay).slice(0, 512) : null,
          subjectIocId,
          subjectIocType ? String(subjectIocType).slice(0, 64) : null,
          subjectIocValue ? String(subjectIocValue).slice(0, 2048) : null,
          targetType ? String(targetType).slice(0, 64) : null,
          targetValue ? String(targetValue).slice(0, 512) : null,
          normalizeSeverity(event.severity),
          normalizeStatus(event.status),
          resolveIp(req),
          req?.headers?.['user-agent'] ? String(req.headers['user-agent']).slice(0, 512) : null,
          resolveRequestId(req, event.requestId),
          resolveSource(req, event.source),
          jsonOrNull(event.before),
          jsonOrNull(event.after),
          jsonOrNull(event.metadata)
        ]
      );
    } catch (err) {
      console.warn('[audit-log] insert failed:', err?.message || err);
    }
  }

  function auditSuccess(event) {
    return auditLog({ ...event, status: AUDIT_STATUS.SUCCESS });
  }

  function auditFailure(event) {
    return auditLog({ ...event, status: AUDIT_STATUS.FAILED });
  }

  return { auditLog, auditSuccess, auditFailure, resolveActor, resolveUserPublicId };
}
