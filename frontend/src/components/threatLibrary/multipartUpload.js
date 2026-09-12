/**
 * Shared helpers for Threat Library multipart uploads.
 * Never set Content-Type manually for FormData — the browser must supply the boundary.
 */

/**
 * Build axios config for a FormData body.
 * Deletes any Content-Type so axios/browser can set multipart boundary.
 * @param {Record<string, unknown>} [extra]
 */
export function multipartFormConfig(extra = {}) {
  const headers = { ...(extra.headers || {}) };
  // Axios may inherit defaults; force deletion so the runtime sets multipart boundary.
  delete headers['Content-Type'];
  delete headers['content-type'];
  return {
    ...extra,
    headers: {
      ...headers,
      // Explicit undefined also clears axios instance defaults for this request.
      'Content-Type': undefined
    }
  };
}

/**
 * Human-readable max PDF size for UI copy.
 * @param {number} bytes
 */
export function formatUploadBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n >= 1_048_576) return `${Math.round(n / 1_048_576)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KB`;
  return `${n} bytes`;
}

/**
 * Prefer structured backend error payload for import failures.
 * @param {unknown} err
 * @param {string} fallback
 */
export function importErrorMessage(err, fallback) {
  const data = err?.response?.data;
  if (data && typeof data === 'object') {
    if (typeof data.message === 'string' && data.message.trim()) return data.message.trim();
  }
  const status = err?.response?.status;
  if (status === 413) {
    return 'The uploaded file exceeds the server size limit. Try a smaller PDF or reduce embedded images.';
  }
  if (status === 401 || status === 403) {
    return 'You are not allowed to import intelligence with this account.';
  }
  return fallback;
}
