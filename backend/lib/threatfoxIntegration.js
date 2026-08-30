export const THREATFOX_FEED_KEY = 'threatfox-abusech';
export const THREATFOX_API_URL_DEFAULT = 'https://threatfox-api.abuse.ch/api/v1/';
export const THREATFOX_RECENT_DAYS_DEFAULT = 3;
export const THREATFOX_RECENT_DAYS_MIN = 1;
export const THREATFOX_RECENT_DAYS_MAX = 7;

export function validateThreatFoxRecentDays(value, fallback = THREATFOX_RECENT_DAYS_DEFAULT) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const rounded = Math.floor(n);
  if (rounded < THREATFOX_RECENT_DAYS_MIN || rounded > THREATFOX_RECENT_DAYS_MAX) {
    return fallback;
  }
  return rounded;
}

export function maskThreatFoxAuthKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `************${s.slice(-4)}`;
}

export function sanitizeThreatFoxErrorMessage(message) {
  let out = String(message || '');
  out = out.replace(/\bAuth-Key\s*[:=]\s*\S+/gi, 'Auth-Key: ***');
  out = out.replace(/\bBearer\s+\S+/gi, 'Bearer ***');
  out = out.replace(/("auth_key"\s*:\s*)"[^"]*"/gi, '$1"***"');
  return out;
}

export function formatThreatFoxCredentialsSummary(credentials) {
  const authKey = credentials && typeof credentials === 'object' ? credentials.auth_key : null;
  const configured = Boolean(String(authKey || '').trim());
  return {
    auth_key_configured: configured,
    masked_auth_key: maskThreatFoxAuthKey(authKey),
    recent_days: validateThreatFoxRecentDays(credentials?.recent_days)
  };
}

export async function testThreatFoxConnection({
  authKey,
  apiUrl = process.env.THREATFOX_API_URL || THREATFOX_API_URL_DEFAULT,
  days = 1,
  timeoutMs = Number(process.env.THREATFOX_TEST_TIMEOUT_MS || 15000),
  signal
}) {
  const key = String(authKey || process.env.THREATFOX_AUTH_KEY || '').trim();
  if (!key) {
    return { ok: false, message: 'ThreatFox Auth-Key is missing' };
  }

  const url = String(apiUrl || THREATFOX_API_URL_DEFAULT).trim().replace(/\/?$/, '/');
  const ms = Math.max(Number(timeoutMs) || 15000, 1000);
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), ms);

  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        'Auth-Key': key,
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: JSON.stringify({ query: 'get_iocs', days: validateThreatFoxRecentDays(days, 1) }),
      signal: controller.signal
    });
  } catch (err) {
    if (err?.name === 'AbortError') {
      return { ok: false, message: `ThreatFox API request timed out after ${ms}ms` };
    }
    return { ok: false, message: sanitizeThreatFoxErrorMessage(err?.message || 'ThreatFox API request failed') };
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }

  const text = await res.text();
  let json = {};
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    return { ok: false, message: `ThreatFox API returned invalid JSON (HTTP ${res.status})` };
  }

  if (res.status === 401 || res.status === 403) {
    return { ok: false, message: `ThreatFox API authentication failed (HTTP ${res.status})` };
  }

  if (!res.ok) {
    return { ok: false, message: `ThreatFox API request failed (HTTP ${res.status})` };
  }

  const status = String(json.query_status || '').toLowerCase();
  if (status === 'ok' || status === 'no_result') {
    return { ok: true, message: 'ThreatFox API connection successful', query_status: status };
  }

  return {
    ok: false,
    message: sanitizeThreatFoxErrorMessage(String(json.query_status_desc || json.query_status || 'ThreatFox API query failed'))
  };
}
