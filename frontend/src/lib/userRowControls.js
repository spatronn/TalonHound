/**
 * Pure helper deciding the action-button state for a Users-table row. Kept out of the React
 * component so the protection rules are unit-testable. The backend is the real enforcement
 * point; these flags only shape the UI (disable + explain protected actions).
 */

export const SYSTEM_ADMIN_PROTECTED_TITLE = 'Protected system administrator account';

/**
 * @param {{ isSystemAdmin?: boolean, isOwnRow?: boolean, statusBusy?: boolean }} ctx
 * @returns {{
 *   showProtectedBadge: boolean,
 *   deactivateDisabled: boolean,
 *   deleteDisabled: boolean,
 *   deactivateTitle: string,
 *   deleteTitle: string
 * }}
 */
export function resolveUserRowControls({ isSystemAdmin = false, isOwnRow = false, statusBusy = false } = {}) {
  const protectedAccount = Boolean(isSystemAdmin);
  const deactivateTitle = protectedAccount
    ? SYSTEM_ADMIN_PROTECTED_TITLE
    : (isOwnRow ? 'You cannot deactivate your own account' : 'Deactivate user');
  return {
    showProtectedBadge: protectedAccount,
    // System admin can never be deactivated or deleted; own-row/busy rules still apply otherwise.
    deactivateDisabled: protectedAccount || isOwnRow || statusBusy,
    deleteDisabled: protectedAccount,
    deactivateTitle,
    deleteTitle: protectedAccount ? SYSTEM_ADMIN_PROTECTED_TITLE : 'Delete user'
  };
}
