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
  if (via === 'bearer') return 'api';
  return 'web';
}

function resolveIp(req) {
  const fwd = String(req?.headers?.['x-forwarded-for'] || '')
    .split(',')[0]
    .trim();
  if (fwd) return fwd;
  return req?.ip || req?.socket?.remoteAddress || null;
}

function resolveRequestId(req) {
  const hdr = req?.headers?.['x-request-id'] || req?.headers?.['x-correlation-id'];
  return hdr ? String(hdr).trim().slice(0, 128) : null;
}

function normalizeSeverity(value) {
  const s = String(value || AUDIT_SEVERITY.INFO).toLowerCase();
  if (s === AUDIT_SEVERITY.WARNING || s === AUDIT_SEVERITY.CRITICAL) return s;
  return AUDIT_SEVERITY.INFO;
}

function normalizeStatus(value) {
  const s = String(value || AUDIT_STATUS.SUCCESS).toLowerCase();
  return s === AUDIT_STATUS.FAILED ? AUDIT_STATUS.FAILED : AUDIT_STATUS.SUCCESS;
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

  async function resolveActorPublicId(req) {
    if (req?.user?.publicId && isUuid(req.user.publicId)) {
      return String(req.user.publicId);
    }
    const internalId = req?.user?.id;
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
   * @param {{
   *   req?: import('express').Request,
   *   action: string,
   *   entityType: string,
   *   entityId?: string|number|null,
   *   entityDisplay?: string|null,
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
      const actorPublicId = event.actorPublicId ?? (req ? await resolveActorPublicId(req) : null);
      const actorUsername = event.actorUsername ?? (req?.user?.username || req?.user?.email || null);
      const actorEmail = event.actorEmail ?? (req?.user?.email || req?.user?.username || null);
      const actorRole = event.actorRole ?? (normalizeAppRole(req?.user?.role) || ROLES.ADMIN);

      await pool.query(
        `INSERT INTO audit_logs (
           actor_user_id, actor_username, actor_email, actor_role,
           action, entity_type, entity_id, entity_display,
           severity, status, ip_address, user_agent, request_id, source,
           before_data, after_data, metadata
         ) VALUES (
           $1::uuid, $2, $3, $4,
           $5, $6, $7, $8,
           $9, $10, $11::inet, $12, $13, $14,
           $15::jsonb, $16::jsonb, $17::jsonb
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
          normalizeSeverity(event.severity),
          normalizeStatus(event.status),
          resolveIp(req),
          req?.headers?.['user-agent'] ? String(req.headers['user-agent']).slice(0, 512) : null,
          resolveRequestId(req),
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

  return { auditLog, auditSuccess, auditFailure };
}
