import {
  MALWAREBAZAAR_FEED_KEY,
  formatMalwareBazaarCredentialsSummary,
  sanitizeMalwareBazaarErrorMessage
} from './malwarebazaarIntegration.js';
import {
  THREATFOX_FEED_KEY,
  formatThreatFoxCredentialsSummary,
  sanitizeThreatFoxErrorMessage
} from './threatfoxIntegration.js';
import {
  ALIENVAULT_OTX_FEED_KEY,
  formatOtxCredentialsSummary,
  sanitizeOtxErrorMessage
} from './alienvaultOtxIntegration.js';

export const URLHAUS_FEED_KEY = 'urlhaus-abusech';
export const URLHAUS_EXPORT_URL_MASKED = 'https://urlhaus-api.abuse.ch/v2/files/exports/***/recent.csv';

export {
  MALWAREBAZAAR_FEED_KEY,
  formatMalwareBazaarCredentialsSummary,
  sanitizeMalwareBazaarErrorMessage,
  THREATFOX_FEED_KEY,
  formatThreatFoxCredentialsSummary,
  sanitizeThreatFoxErrorMessage,
  ALIENVAULT_OTX_FEED_KEY,
  formatOtxCredentialsSummary,
  sanitizeOtxErrorMessage
};

export function maskUrlhausAuthKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `************${s.slice(-4)}`;
}

export function sanitizeUrlhausErrorMessage(message) {
  let out = String(message || '');
  out = out.replace(
    /https?:\/\/urlhaus-api\.abuse\.ch\/v2\/files\/exports\/[^/\s]+\/recent\.csv/gi,
    URLHAUS_EXPORT_URL_MASKED
  );
  out = out.replace(/\/exports\/[^/\s]+\/recent\.csv/gi, '/exports/***/recent.csv');
  return out;
}

export function formatUrlhausCredentialsSummary(credentials) {
  const authKey = credentials && typeof credentials === 'object' ? credentials.auth_key : null;
  const configured = Boolean(String(authKey || '').trim());
  return {
    auth_key_configured: configured,
    masked_auth_key: maskUrlhausAuthKey(authKey)
  };
}

export async function testUrlhausConnection({ authKey } = {}) {
  const key = String(authKey || process.env.URLHAUS_AUTH_KEY || '').trim();
  if (!key) {
    return { ok: false, message: 'URLHaus Auth-Key is missing' };
  }

  const url = `https://urlhaus-api.abuse.ch/v2/files/exports/${encodeURIComponent(key)}/recent.csv`;
  try {
    const res = await fetch(url, { method: 'HEAD' });
    if (res.status === 401 || res.status === 403) {
      return { ok: false, message: `URLHaus API authentication failed (HTTP ${res.status})` };
    }
    if (res.ok) {
      return { ok: true, message: 'URLHaus API connection successful' };
    }
    return { ok: false, message: `URLHaus API request failed (HTTP ${res.status})` };
  } catch (err) {
    return {
      ok: false,
      message: sanitizeUrlhausErrorMessage(err?.message || 'URLHaus connection failed')
    };
  }
}

export function formatFeedCredentialsSummary(feedKey, credentials) {
  if (feedKey === URLHAUS_FEED_KEY) return formatUrlhausCredentialsSummary(credentials);
  if (feedKey === MALWAREBAZAAR_FEED_KEY) return formatMalwareBazaarCredentialsSummary(credentials);
  if (feedKey === THREATFOX_FEED_KEY) return formatThreatFoxCredentialsSummary(credentials);
  if (feedKey === ALIENVAULT_OTX_FEED_KEY) return formatOtxCredentialsSummary(credentials);
  return null;
}

export function sanitizeFeedErrorMessage(feedKey, message) {
  if (feedKey === URLHAUS_FEED_KEY) {
    return sanitizeUrlhausErrorMessage(message);
  }
  if (feedKey === MALWAREBAZAAR_FEED_KEY) {
    return sanitizeMalwareBazaarErrorMessage(message);
  }
  if (feedKey === THREATFOX_FEED_KEY) {
    return sanitizeThreatFoxErrorMessage(message);
  }
  if (feedKey === ALIENVAULT_OTX_FEED_KEY) {
    return sanitizeOtxErrorMessage(message);
  }
  return String(message || '');
}

export const AUTH_KEY_FEED_KEYS = new Set([
  URLHAUS_FEED_KEY,
  MALWAREBAZAAR_FEED_KEY,
  THREATFOX_FEED_KEY,
  ALIENVAULT_OTX_FEED_KEY
]);
