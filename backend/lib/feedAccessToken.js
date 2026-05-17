import crypto from 'crypto';

const TOKEN_BYTES = 32;

export function generateFeedAccessToken() {
  return crypto.randomBytes(TOKEN_BYTES).toString('base64url');
}

export function hashFeedAccessToken(rawToken) {
  return crypto.createHash('sha256').update(String(rawToken), 'utf8').digest('hex');
}

export function buildPublicFeedUrl(req, rawToken) {
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(',')[0].trim();
  const base = `${proto}://${host}`;
  return `${base}/public/feeds/${encodeURIComponent(rawToken)}/feed.txt`;
}
