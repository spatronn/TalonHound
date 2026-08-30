/**
 * Backend-side AlienVault OTX helpers: credential masking, summary, error
 * sanitization, and a lightweight "test connection" call for server.js.
 *
 * NOTE: The integration worker service has its own copy of the OTX client
 * (integration/lib/alienvaultOtx.js). The two services do not share node_modules,
 * so this backend module intentionally re-implements the small subset the API
 * server needs (mirrors the threatfoxIntegration.js / urlhausIntegration.js split).
 */

export const ALIENVAULT_OTX_FEED_KEY = 'alienvault-otx';
export const ALIENVAULT_OTX_API_BASE_DEFAULT = 'https://otx.alienvault.com';
export const ALIENVAULT_OTX_SUBSCRIBED_PATH = '/api/v1/pulses/subscribed';

export function maskOtxApiKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `************${s.slice(-4)}`;
}

export function sanitizeOtxErrorMessage(message) {
  let out = String(message || '');
  out = out.replace(/\bX-OTX-API-KEY\s*[:=]\s*\S+/gi, 'X-OTX-API-KEY: ***');
  out = out.replace(/([?&]apikey=)[^&\s]+/gi, '$1***');
  out = out.replace(/("api_key"\s*:\s*)"[^"]*"/gi, '$1"***"');
  return out;
}

export function formatOtxCredentialsSummary(credentials) {
  const authKey = credentials && typeof credentials === 'object' ? credentials.auth_key : null;
  const configured = Boolean(String(authKey || '').trim());
  return {
    auth_key_configured: configured,
    masked_auth_key: maskOtxApiKey(authKey)
  };
}

/**
 * Minimal authenticated request against the subscribed-pulses endpoint to
 * verify the API key. Uses limit=1 to keep the response small.
 */
export async function testOtxConnection({
  authKey,
  apiBase = process.env.ALIENVAULT_OTX_API_BASE || ALIENVAULT_OTX_API_BASE_DEFAULT
} = {}) {
  const key = String(authKey || process.env.ALIENVAULT_OTX_API_KEY || '').trim();
  if (!key) {
    return { ok: false, message: 'AlienVault OTX API key is missing' };
  }

  const base = String(apiBase || ALIENVAULT_OTX_API_BASE_DEFAULT).trim().replace(/\/+$/, '');
  const url = `${base}${ALIENVAULT_OTX_SUBSCRIBED_PATH}?limit=1`;

  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'X-OTX-API-KEY': key,
        Accept: 'application/json'
      }
    });

    if (res.status === 401 || res.status === 403) {
      return { ok: false, message: 'OTX API key is invalid or unauthorized.' };
    }
    if (res.status === 429) {
      return { ok: false, message: 'OTX API rate limit reached. Please retry later or reduce schedule frequency.' };
    }
    if (!res.ok) {
      return { ok: false, message: `AlienVault OTX API request failed (HTTP ${res.status})` };
    }

    const text = await res.text();
    try {
      const json = text ? JSON.parse(text) : {};
      if (Array.isArray(json?.results)) {
        return { ok: true, message: 'AlienVault OTX API connection successful' };
      }
      return { ok: true, message: 'AlienVault OTX API connection successful' };
    } catch {
      return { ok: false, message: `AlienVault OTX API returned invalid JSON (HTTP ${res.status})` };
    }
  } catch (err) {
    return {
      ok: false,
      message: sanitizeOtxErrorMessage(err?.message || 'AlienVault OTX connection failed')
    };
  }
}
