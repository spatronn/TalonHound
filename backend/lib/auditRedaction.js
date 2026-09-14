const SENSITIVE_KEY_RE = /^(password|passwd|pwd|token|api_key|apikey|api-key|secret|authorization|cookie|access_key|accesskey|refresh_token|refresh-token|private_key|private-key|password_hash|token_hash)$/i;

const REDACTED = '[REDACTED]';

const MAX_STRING_LEN = 4000;
const MAX_ARRAY_LEN = 100;
const MAX_OBJECT_KEYS = 80;
const MAX_DEPTH = 8;

function isPlainObject(v) {
  return v != null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Date);
}

/**
 * Recursively redact sensitive fields from audit payloads.
 * @param {unknown} value
 * @param {{ depth?: number }} [opts]
 * @returns {unknown}
 */
export function redactSensitive(value, opts = {}) {
  const depth = opts.depth ?? 0;
  if (value == null) return value;

  if (typeof value === 'string') {
    if (value.length > MAX_STRING_LEN) {
      return `${value.slice(0, MAX_STRING_LEN)}…[truncated]`;
    }
    return value;
  }

  if (typeof value === 'number' || typeof value === 'boolean') return value;

  if (value instanceof Date) return value.toISOString();

  if (Array.isArray(value)) {
    if (depth >= MAX_DEPTH) return '[truncated]';
    return value.slice(0, MAX_ARRAY_LEN).map((item) => redactSensitive(item, { depth: depth + 1 }));
  }

  if (isPlainObject(value)) {
    if (depth >= MAX_DEPTH) return '[truncated]';
    const out = {};
    const entries = Object.entries(value).slice(0, MAX_OBJECT_KEYS);
    for (const [key, val] of entries) {
      if (SENSITIVE_KEY_RE.test(String(key))) {
        out[key] = REDACTED;
      } else {
        out[key] = redactSensitive(val, { depth: depth + 1 });
      }
    }
    return out;
  }

  return String(value);
}

/**
 * Pick safe subset of fields for audit snapshots.
 * @param {Record<string, unknown>|null|undefined} obj
 * @param {string[]} fields
 */
export function pickSafeFields(obj, fields) {
  if (!obj || typeof obj !== 'object') return null;
  const out = {};
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(obj, f)) {
      out[f] = obj[f];
    }
  }
  return redactSensitive(out);
}

// Query parameter names that commonly carry credentials in intel/report URLs.
const SENSITIVE_QUERY_PARAM_RE = /^(api[_-]?key|apikey|key|token|access[_-]?token|auth[_-]?token|auth|authorization|secret|client[_-]?secret|password|passwd|pwd|sig|signature|x-amz-signature|x-amz-credential|x-amz-security-token|sas|st|se|sp|sv|sr|skoid|sktid|skt|ske|sks|skv)$/i;

/**
 * Redact a URL for audit storage: drop userinfo, mask credential-like query
 * parameter values, keep host/path so the row stays meaningful. Non-URL input
 * is returned as a bounded string (never throws).
 * @param {unknown} value
 * @returns {string|null}
 */
export function redactUrlSecrets(value) {
  if (value == null) return null;
  const raw = String(value).trim();
  if (!raw) return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return raw.length > 512 ? `${raw.slice(0, 512)}…[truncated]` : raw;
  }
  u.username = '';
  u.password = '';
  for (const key of Array.from(u.searchParams.keys())) {
    if (SENSITIVE_QUERY_PARAM_RE.test(key)) u.searchParams.set(key, REDACTED);
  }
  const out = u.toString();
  return out.length > 2048 ? `${out.slice(0, 2048)}…[truncated]` : out;
}

export { REDACTED };
