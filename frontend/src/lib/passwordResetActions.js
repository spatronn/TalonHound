/**
 * Pure helpers for the admin "Reset Password" user action. Kept out of the React
 * component so the visibility rules and secret-state handling are unit-testable and
 * so the temporary password is never persisted anywhere beyond in-memory state.
 */

/**
 * Whether the Reset Password action should be offered for a given user row.
 * Admin-only, never on the admin's own row, and not for deactivated accounts.
 * @param {{ isAdmin?: boolean, isOwnRow?: boolean, status?: string }} ctx
 * @returns {boolean}
 */
export function canResetUserPassword({ isAdmin, isOwnRow, status } = {}) {
  if (!isAdmin) return false;
  if (isOwnRow) return false;
  if (String(status || 'active') === 'passive') return false;
  return true;
}

/** Empty result-modal state — closing the dialog must scrub the one-time secret. */
export function clearTemporaryPasswordState() {
  return { open: false, username: '', password: '' };
}
