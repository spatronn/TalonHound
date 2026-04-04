import './ensure-jwt-secret.js';
import jwt from 'jsonwebtoken';

const secret = process.env.JWT_SECRET;
const expiresIn = process.env.JWT_EXPIRES_IN || '24h';

export const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'demo_session';

function cookieMaxAgeMs(inStr) {
  const s = String(inStr || '24h').trim();
  const m = s.match(/^(\d+)([smhd])$/i);
  if (m) {
    const n = Number(m[1]);
    const u = m[2].toLowerCase();
    const mult = { s: 1000, m: 60 * 1000, h: 60 * 60 * 1000, d: 24 * 60 * 60 * 1000 };
    return n * (mult[u] ?? 60 * 60 * 1000);
  }
  const sec = Number(s);
  if (Number.isFinite(sec) && sec > 0) return Math.floor(sec * 1000);
  return 24 * 60 * 60 * 1000;
}

function cookieSecureFlag(req) {
  if (process.env.AUTH_COOKIE_SECURE === '0') return false;
  if (process.env.AUTH_COOKIE_SECURE === '1') return true;
  const fwd = String(req.headers['x-forwarded-proto'] || '')
    .split(',')[0]
    .trim();
  if (fwd === 'https') return true;
  return Boolean(req.secure);
}

export function appendAuthCookie(req, res, token) {
  res.cookie(AUTH_COOKIE_NAME, token, {
    httpOnly: true,
    secure: cookieSecureFlag(req),
    sameSite: 'lax',
    maxAge: cookieMaxAgeMs(expiresIn),
    path: '/'
  });
}

export function clearAuthCookie(req, res) {
  res.clearCookie(AUTH_COOKIE_NAME, {
    path: '/',
    secure: cookieSecureFlag(req),
    sameSite: 'lax',
    httpOnly: true
  });
}

export function signUserToken(email) {
  const e = String(email || '').trim();
  return jwt.sign({ email: e }, secret, { subject: e, expiresIn });
}

function extractBearer(req) {
  const h = req.headers.authorization;
  if (!h || typeof h !== 'string') return null;
  const m = h.match(/^Bearer\s+(\S+)/i);
  return m ? m[1].trim() : null;
}

function extractSessionToken(req) {
  const fromHeader = extractBearer(req);
  if (fromHeader) return fromHeader;
  const c = req.cookies && req.cookies[AUTH_COOKIE_NAME];
  if (c && typeof c === 'string' && c.trim()) return c.trim();
  return null;
}

export function requireAuth(req, res, next) {
  const token = extractSessionToken(req);
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  try {
    const payload = jwt.verify(token, secret);
    const email = payload.email || payload.sub;
    if (!email || typeof email !== 'string') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.user = { email: email.trim() };
    return next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

export function apiAuthGate(req, res, next) {
  if (req.method === 'OPTIONS') return next();
  if (req.path === '/api/auth/login' && req.method === 'POST') return next();
  if (req.path === '/api/auth/logout' && req.method === 'POST') return next();
  if (req.path.startsWith('/api')) {
    return requireAuth(req, res, next);
  }
  return next();
}
