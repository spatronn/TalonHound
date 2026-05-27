import {
  MALWAREBAZAAR_FEED_KEY,
  formatMalwareBazaarCredentialsSummary,
  sanitizeMalwareBazaarErrorMessage
} from './malwarebazaarIntegration.js';

export const URLHAUS_FEED_KEY = 'urlhaus-abusech';
export const URLHAUS_EXPORT_URL_MASKED = 'https://urlhaus-api.abuse.ch/v2/files/exports/***/recent.csv';

export {
  MALWAREBAZAAR_FEED_KEY,
  formatMalwareBazaarCredentialsSummary,
  sanitizeMalwareBazaarErrorMessage
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

export function formatFeedCredentialsSummary(feedKey, credentials) {
  if (feedKey === URLHAUS_FEED_KEY) return formatUrlhausCredentialsSummary(credentials);
  if (feedKey === MALWAREBAZAAR_FEED_KEY) return formatMalwareBazaarCredentialsSummary(credentials);
  return null;
}

export function sanitizeFeedErrorMessage(feedKey, message) {
  if (feedKey === URLHAUS_FEED_KEY) {
    return sanitizeUrlhausErrorMessage(message);
  }
  if (feedKey === MALWAREBAZAAR_FEED_KEY) {
    return sanitizeMalwareBazaarErrorMessage(message);
  }
  return String(message || '');
}
