/**
 * Custom Threat Feed authentication helpers.
 *
 * Supported auth types: none | bearer_token | api_key_header | basic_auth
 *
 * Secrets are never logged or returned raw to API callers — only masked summaries.
 */

export const ALLOWED_AUTH_TYPES = ['none', 'bearer_token', 'api_key_header', 'basic_auth'];

const BLOCKED_HEADER_NAMES = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'proxy-authorization',
  'proxy-authenticate',
  'te',
  'trailer'
]);

export function maskSecret(value) {
  const s = String(value || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  const show = Math.min(2, Math.floor(s.length / 4));
  return `${s.slice(0, show)}****${s.slice(-show)}`;
}

function validateHeaderName(name) {
  if (!name || typeof name !== 'string') return { ok: false, error: 'header_name is required' };
  const n = String(name).trim();
  if (!n) return { ok: false, error: 'header_name is required' };
  if (n.length > 100) return { ok: false, error: 'header_name must be 100 characters or fewer' };
  if (/[\r\n:]/.test(n)) return { ok: false, error: 'header_name must not contain newlines or colons' };
  if (!/^[\x21-\x7e]+$/.test(n)) return { ok: false, error: 'header_name must contain only printable ASCII characters' };
  if (BLOCKED_HEADER_NAMES.has(n.toLowerCase())) {
    return { ok: false, error: `header_name '${n}' is not allowed` };
  }
  return { ok: true, value: n };
}

/**
 * Validate the `auth` field from an API request body.
 * Returns { ok, value } where value is the normalized validated input (not yet merged with existing).
 * Returns { ok: true, value: null } when auth is omitted (no change semantics).
 */
export function validateCustomFeedAuth(auth) {
  if (auth === undefined || auth === null) return { ok: true, value: null };
  if (typeof auth !== 'object' || Array.isArray(auth)) {
    return { ok: false, error: 'auth must be an object' };
  }
  const t = String(auth.auth_type ?? 'none').trim();
  if (!ALLOWED_AUTH_TYPES.includes(t)) {
    return { ok: false, error: `auth_type must be one of: ${ALLOWED_AUTH_TYPES.join(', ')}` };
  }

  if (t === 'none') return { ok: true, value: { auth_type: 'none' } };

  if (t === 'bearer_token') {
    const token = auth.token !== undefined ? String(auth.token || '').trim() : undefined;
    const clearToken = auth.clear_token === true;
    if (!clearToken && token !== undefined && !token) {
      return { ok: false, error: 'token must not be empty; use clear_token: true to remove' };
    }
    return { ok: true, value: { auth_type: 'bearer_token', token, clear_token: clearToken } };
  }

  if (t === 'api_key_header') {
    const nameCheck = validateHeaderName(auth.header_name);
    if (!nameCheck.ok) return { ok: false, error: nameCheck.error };
    const headerValue = auth.header_value !== undefined ? String(auth.header_value || '').trim() : undefined;
    const clearHeaderValue = auth.clear_header_value === true;
    if (!clearHeaderValue && headerValue !== undefined && !headerValue) {
      return { ok: false, error: 'header_value must not be empty; use clear_header_value: true to remove' };
    }
    return {
      ok: true,
      value: {
        auth_type: 'api_key_header',
        header_name: nameCheck.value,
        header_value: headerValue,
        clear_header_value: clearHeaderValue
      }
    };
  }

  if (t === 'basic_auth') {
    const username = String(auth.username || '').trim();
    if (!username) return { ok: false, error: 'username is required for basic_auth' };
    const password = auth.password !== undefined ? String(auth.password || '').trim() : undefined;
    const clearPassword = auth.clear_password === true;
    if (!clearPassword && password !== undefined && !password) {
      return { ok: false, error: 'password must not be empty; use clear_password: true to remove' };
    }
    return { ok: true, value: { auth_type: 'basic_auth', username, password, clear_password: clearPassword } };
  }

  return { ok: false, error: 'invalid auth configuration' };
}

/**
 * Merge validated auth input with existing DB credentials.
 * Preserves existing secrets when the new payload omits them.
 * Drops old secrets when auth_type changes.
 */
export function normalizeCustomFeedAuth(validatedAuth, existingCredentials) {
  if (!validatedAuth) return existingCredentials || {};

  const existing = existingCredentials && typeof existingCredentials === 'object' ? existingCredentials : {};
  const t = validatedAuth.auth_type;

  if (t === 'none') return { auth_type: 'none' };

  if (t === 'bearer_token') {
    let token;
    if (validatedAuth.clear_token) {
      token = null;
    } else if (validatedAuth.token !== undefined) {
      token = validatedAuth.token || null;
    } else {
      token = existing.auth_type === 'bearer_token' ? (existing.token || null) : null;
    }
    return { auth_type: 'bearer_token', token };
  }

  if (t === 'api_key_header') {
    let headerValue;
    if (validatedAuth.clear_header_value) {
      headerValue = null;
    } else if (validatedAuth.header_value !== undefined) {
      headerValue = validatedAuth.header_value || null;
    } else {
      const sameHeader =
        existing.auth_type === 'api_key_header' &&
        existing.header_name === validatedAuth.header_name;
      headerValue = sameHeader ? (existing.header_value || null) : null;
    }
    return { auth_type: 'api_key_header', header_name: validatedAuth.header_name, header_value: headerValue };
  }

  if (t === 'basic_auth') {
    const username = validatedAuth.username;
    let password;
    if (validatedAuth.clear_password) {
      password = null;
    } else if (validatedAuth.password !== undefined) {
      password = validatedAuth.password || null;
    } else {
      password = existing.auth_type === 'basic_auth' ? (existing.password || null) : null;
    }
    return { auth_type: 'basic_auth', username, password };
  }

  return {};
}

/**
 * Build HTTP request headers from stored credentials.
 * Never throws — returns empty object if credentials are missing or incomplete.
 */
export function buildCustomFeedAuthHeaders(credentials) {
  const headers = {};
  if (!credentials || !credentials.auth_type || credentials.auth_type === 'none') return headers;
  const t = credentials.auth_type;
  if (t === 'bearer_token' && credentials.token) {
    headers['Authorization'] = `Bearer ${credentials.token}`;
  } else if (t === 'api_key_header' && credentials.header_name && credentials.header_value) {
    headers[credentials.header_name] = credentials.header_value;
  } else if (t === 'basic_auth' && credentials.username && credentials.password) {
    const encoded = Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64');
    headers['Authorization'] = `Basic ${encoded}`;
  }
  return headers;
}

/**
 * Build a safe masked summary of credentials for API responses.
 * Never includes raw secrets.
 */
export function buildCustomFeedAuthSummary(credentials) {
  if (!credentials || !credentials.auth_type || credentials.auth_type === 'none') {
    return { auth_type: 'none', configured: false };
  }
  const t = credentials.auth_type;
  if (t === 'bearer_token') {
    return {
      auth_type: 'bearer_token',
      configured: Boolean(credentials.token),
      masked_token: credentials.token ? maskSecret(credentials.token) : null
    };
  }
  if (t === 'api_key_header') {
    return {
      auth_type: 'api_key_header',
      configured: Boolean(credentials.header_value),
      header_name: credentials.header_name || null,
      masked_header_value: credentials.header_value ? maskSecret(credentials.header_value) : null
    };
  }
  if (t === 'basic_auth') {
    return {
      auth_type: 'basic_auth',
      configured: Boolean(credentials.password),
      username: credentials.username || null,
      password_configured: Boolean(credentials.password)
    };
  }
  return { auth_type: t, configured: false };
}

/**
 * Scrub secret values from an error message string before logging or storing.
 */
export function redactCustomFeedSecrets(message, credentials) {
  if (!message || !credentials) return message;
  let result = String(message);
  const replace = (str, secret) => (secret ? str.split(secret).join('[REDACTED]') : str);
  const t = credentials.auth_type;
  if (t === 'bearer_token') {
    result = replace(result, credentials.token);
  } else if (t === 'api_key_header') {
    result = replace(result, credentials.header_value);
  } else if (t === 'basic_auth') {
    result = replace(result, credentials.password);
    if (credentials.username && credentials.password) {
      const encoded = Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64');
      result = replace(result, encoded);
    }
  }
  return result;
}
