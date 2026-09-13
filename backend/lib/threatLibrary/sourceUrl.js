/**
 * Provenance-only Source URL validation for Threat Library reports.
 * Does not fetch, resolve DNS, or enqueue analysis.
 */

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);
const BLOCKED_SCHEMES = new Set(['javascript:', 'file:', 'data:', 'vbscript:', 'about:']);

/**
 * @param {unknown} raw
 * @returns {{ ok: true, value: string|null } | { ok: false, error: string, message: string }}
 */
export function validateReportSourceUrl(raw) {
  if (raw == null) return { ok: true, value: null };
  const trimmed = String(raw).trim();
  if (!trimmed) return { ok: true, value: null };

  let url;
  try {
    url = new URL(trimmed);
  } catch {
    return {
      ok: false,
      error: 'malformed_url',
      message: 'Source URL is not a valid http(s) URL.'
    };
  }

  const scheme = String(url.protocol || '').toLowerCase();
  if (BLOCKED_SCHEMES.has(scheme) || !ALLOWED_SCHEMES.has(scheme)) {
    return {
      ok: false,
      error: 'invalid_scheme',
      message: 'Source URL must use http or https.'
    };
  }
  if (!url.hostname) {
    return {
      ok: false,
      error: 'malformed_url',
      message: 'Source URL is not a valid http(s) URL.'
    };
  }

  url.hash = '';
  url.username = '';
  url.password = '';
  return { ok: true, value: url.toString() };
}
