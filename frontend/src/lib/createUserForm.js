/**
 * Pure helpers for Create User modal validation / payload / error focus.
 * Mirrors existing backend contract: username + password required; role defaults to readonly.
 * No password strength/policy invented here.
 */

export const CREATE_USER_ROLES = Object.freeze([
  { value: 'admin', label: 'Admin (Full Access)' },
  { value: 'analyst', label: 'Analyst (Triage)' },
  { value: 'readonly', label: 'Read Only (View Only)' }
]);

export const EMPTY_CREATE_USER_FORM = Object.freeze({
  first_name: '',
  last_name: '',
  username: '',
  password: '',
  role: 'readonly'
});

/**
 * @param {{ username?: string, password?: string }} form
 * @returns {boolean}
 */
export function isCreateUserFormValid(form = {}) {
  const username = String(form.username || '').trim();
  const password = form.password;
  return Boolean(username && typeof password === 'string' && password.length > 0);
}

/**
 * @param {{ first_name?: string, last_name?: string, username?: string, password?: string, role?: string }} form
 */
export function buildCreateUserPayload(form = {}) {
  return {
    username: String(form.username || '').trim(),
    password: form.password,
    first_name: String(form.first_name || '').trim(),
    last_name: String(form.last_name || '').trim(),
    role: String(form.role || 'readonly').trim() || 'readonly'
  };
}

/**
 * Map a known API/client error message to a field id for focus.
 * @param {string} message
 * @returns {'username'|'password'|null}
 */
export function createUserErrorFocusField(message) {
  const msg = String(message || '');
  if (/already in use|already exists/i.test(msg)) return 'username';
  if (/username and password are required/i.test(msg)) return 'username';
  if (/password/i.test(msg) && !/username/i.test(msg)) return 'password';
  return null;
}

/**
 * Friendly duplicate-username message (kept identical to prior UI copy).
 * @param {{ status?: number, message?: string }} err
 * @returns {string}
 */
export function createUserErrorMessage(err = {}) {
  const status = Number(err.status || 0);
  const backendMsg = String(err.message || '').trim();
  if (status === 409 || /already exists/i.test(backendMsg)) {
    return 'This username is already in use. Please choose another one.';
  }
  return backendMsg || 'Failed to create user';
}
