/**
 * Ownership helpers for Action Center artifacts (exports / deep searches).
 * Prefer immutable requested_by_id; never authorize solely by recyclable email (IDOR-01).
 */
import { isAdminRole, normalizeAppRole } from './rbac.js';

export function actorEmail(req) {
  return String(req?.user?.email || req?.user?.username || '').trim();
}

export function actorUserId(req) {
  const id = Number(req?.user?.id);
  return Number.isFinite(id) && id > 0 ? id : null;
}

/**
 * Admin: all. Otherwise require a positive requested_by_id matching the caller.
 * Historical email-only rows (requested_by_id NULL) are not granted to any non-admin —
 * including a new account that reused the same email.
 */
export function canAccessOwnedArtifact(req, row) {
  if (isAdminRole(normalizeAppRole(req?.user?.role))) return true;
  const ownerId = row?.requested_by_id != null ? Number(row.requested_by_id) : null;
  if (!Number.isFinite(ownerId) || ownerId <= 0) return false;
  const uid = actorUserId(req);
  return uid != null && uid === ownerId;
}
