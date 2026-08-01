/**
 * Shared, framework-agnostic logic for the self-service change-password form.
 *
 * Both the standalone Change Password page and the Users-page modal render the
 * same `ChangePasswordForm` React component, and that component delegates all
 * validation, the API call, and error-message derivation to these helpers so the
 * behaviour lives in exactly one place (and is unit-testable without a DOM).
 *
 * Security note: the request body only ever carries { currentPassword, newPassword }.
 * The target account is derived server-side from the authenticated session; the
 * client never sends a user id/email to select whose password changes.
 */

export const CHANGE_PASSWORD_ENDPOINT = '/auth/change-password';

/**
 * Client-side validation mirroring the backend contract. Returns an empty string
 * when the input is acceptable, otherwise a human-readable error message.
 * @param {{ currentPassword?: string, newPassword?: string, confirmPassword?: string }} input
 * @returns {string}
 */
export function validateChangePasswordInput({ currentPassword, newPassword, confirmPassword } = {}) {
  if (!currentPassword || !newPassword || !confirmPassword) {
    return 'Fill in all password fields.';
  }
  if (newPassword !== confirmPassword) {
    return 'New password and confirmation do not match.';
  }
  if (newPassword === currentPassword) {
    return 'New password must be different from the current password.';
  }
  return '';
}

/**
 * Derive a safe, user-facing error message from a failed request. Only the
 * backend `message` field is surfaced — never a raw `detail`/stack — so internal
 * error text can't leak into the UI.
 * @param {any} err
 * @returns {string}
 */
export function changePasswordErrorMessage(err) {
  return err?.response?.data?.message || 'Failed to change password';
}

/**
 * Validate then submit a password change. Never throws: the outcome is always a
 * result object so callers only need to branch on `ok`.
 * @param {{ post: Function }} api axios-like client
 * @param {{ currentPassword: string, newPassword: string, confirmPassword: string }} values
 * @returns {Promise<{ ok: boolean, error: string }>}
 */
export async function submitChangePassword(api, values) {
  const error = validateChangePasswordInput(values);
  if (error) return { ok: false, error };
  try {
    await api.post(CHANGE_PASSWORD_ENDPOINT, {
      currentPassword: values.currentPassword,
      newPassword: values.newPassword
    });
    return { ok: true, error: '' };
  } catch (err) {
    return { ok: false, error: changePasswordErrorMessage(err) };
  }
}
