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

/**
 * Whether the self-service "Change Password" action should be offered for a row.
 * Only ever on the signed-in user's own row, and only while the account is active.
 * This is a UI affordance only — the backend change-password endpoint always
 * derives the target from the authenticated session, never from this flag.
 * @param {{ isOwnRow?: boolean, status?: string }} ctx
 * @returns {boolean}
 */
export function canChangeOwnPassword({ isOwnRow, status } = {}) {
  if (!isOwnRow) return false;
  if (String(status || 'active') === 'passive') return false;
  return true;
}

/**
 * Resolve which single password action a Users-table row should offer.
 * The signed-in user's own row gets self-service `'change'`; any other row an
 * admin may act on gets `'reset'`. The two are mutually exclusive by construction,
 * so a row never shows both buttons.
 * @param {{ isAdmin?: boolean, isOwnRow?: boolean, status?: string }} ctx
 * @returns {'change' | 'reset' | null}
 */
export function resolveRowPasswordAction({ isAdmin, isOwnRow, status } = {}) {
  if (canChangeOwnPassword({ isOwnRow, status })) return 'change';
  if (canResetUserPassword({ isAdmin, isOwnRow, status })) return 'reset';
  return null;
}

/** Empty result-modal state — closing the dialog must scrub the one-time secret. */
export function clearTemporaryPasswordState() {
  return { open: false, username: '', password: '' };
}
