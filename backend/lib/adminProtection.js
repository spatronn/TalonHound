/**
 * Pure, framework-agnostic guards for protected user mutations. Kept out of the route so the
 * decision rules are unit-testable; the route supplies the locked row + a race-safe count of
 * the OTHER active admins (see routes/users.js) and just applies the returned decision.
 *
 * Two protections:
 *   1. The system administrator account (is_system_admin = TRUE) can never be deleted,
 *      deactivated, renamed, or demoted below admin.
 *   2. A general invariant: an operation must never drop the active-admin count to zero.
 */

/** Fixed, human-readable messages (stable strings, safe to surface to clients). */
export const SYSTEM_ADMIN_PROTECTED_MESSAGE = 'Protected system administrator account';
export const LAST_ACTIVE_ADMIN_MESSAGE = 'The system must always have at least one active administrator';

/** Operations that strip a user's active-admin standing. */
const STRIPS_ACTIVE_ADMIN = new Set(['delete', 'deactivate', 'demote']);

/**
 * Evaluate whether a mutation on a target user is allowed.
 *
 * @param {object} args
 * @param {'delete'|'deactivate'|'demote'|'rename'} args.operation
 * @param {boolean} [args.isSystemAdmin] target's is_system_admin flag
 * @param {string} [args.currentRole] target's current role
 * @param {string} [args.currentStatus] target's current status ('active'|'passive')
 * @param {number} [args.otherActiveAdminCount] active admins EXCLUDING the target
 * @returns {{ ok: true } | { ok: false, status: number, message: string }}
 */
export function evaluateProtectedMutation({
  operation,
  isSystemAdmin = false,
  currentRole,
  currentStatus,
  otherActiveAdminCount = 0
} = {}) {
  const stripsActiveAdmin = STRIPS_ACTIVE_ADMIN.has(operation);

  // (1) The protected system administrator identity is off-limits for destructive/identity ops.
  if (isSystemAdmin === true && (stripsActiveAdmin || operation === 'rename')) {
    return { ok: false, status: 403, message: SYSTEM_ADMIN_PROTECTED_MESSAGE };
  }

  // (2) Never let the last active administrator be removed.
  if (stripsActiveAdmin) {
    const isActiveAdmin = currentRole === 'admin' && currentStatus === 'active';
    if (isActiveAdmin && Number(otherActiveAdminCount) < 1) {
      return { ok: false, status: 409, message: LAST_ACTIVE_ADMIN_MESSAGE };
    }
  }

  return { ok: true };
}
