/**
 * Client-side helpers for forced password-change flow.
 */

export const CHANGE_PASSWORD_PATH = '/change-password';

/**
 * @param {boolean} mustChangePassword
 * @param {string} pathname
 * @returns {boolean}
 */
export function shouldForceChangePassword(mustChangePassword, pathname) {
  if (!mustChangePassword) return false;
  const path = String(pathname || '');
  if (path === CHANGE_PASSWORD_PATH) return false;
  if (path === '/login' || path === '/setup') return false;
  return true;
}

/**
 * Destination after successful login given user payload.
 * @param {{ mustChangePassword?: boolean } | null | undefined} user
 * @returns {string}
 */
export function postLoginDestination(user) {
  if (user?.mustChangePassword) return CHANGE_PASSWORD_PATH;
  return '/ioc';
}
