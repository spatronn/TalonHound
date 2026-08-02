/**
 * Delete-user confirmation helpers (replaces window.confirm for Users delete).
 */

export function deleteUserConfirmCopy(username) {
  const name = String(username || 'this user').trim() || 'this user';
  return {
    title: 'Delete user',
    description: `Are you sure you want to delete ${name}? This cannot be undone.`
  };
}

/** Initial focus target for destructive confirm — Cancel, never Delete. */
export const DELETE_USER_CONFIRM_PREFER_CANCEL = true;
