import './ensure-jwt-secret.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const secret = process.env.JWT_SECRET;
const expiresIn = process.env.JWT_EXPIRES_IN || '24h';

export const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'demo_session';
export const CSRF_COOKIE_NAME = process.env.CSRF_COOKIE_NAME || 'demo_csrf';

/** Opaque machine credential (not a JWT). Prefer API_INGEST_TOKEN; API_BEARER_TOKEN kept as alias. */
const API_INGEST_TOKEN = String(process.env.API_INGEST_TOKEN || process.env.API_BEARER_TOKEN || '').trim();

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

export function appendCsrfCookie(req, res) {
  const tok = crypto.randomBytes(32).toString('hex');
  res.cookie(CSRF_COOKIE_NAME, tok, {
    httpOnly: false,
    secure: cookieSecureFlag(req),
    sameSite: 'lax',
    maxAge: cookieMaxAgeMs(expiresIn),
    path: '/'
  });
}

export function clearCsrfCookie(req, res) {
  res.clearCookie(CSRF_COOKIE_NAME, {
    path: '/',
    secure: cookieSecureFlag(req),
    sameSite: 'lax',
    httpOnly: false
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

function extractIngestHeader(req) {
  const x = req.headers['x-api-ingest-token'];
  if (x && typeof x === 'string') return x.trim();
  return '';
}

function ingestTokenOk(provided) {
  if (!API_INGEST_TOKEN) return false;
  try {
    const a = Buffer.from(provided, 'utf8');
    const b = Buffer.from(API_INGEST_TOKEN, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function safeEqualUtf8(a, b) {
  try {
    const ba = Buffer.from(String(a), 'utf8');
    const bb = Buffer.from(String(b), 'utf8');
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

export function requireAuth(req, res, next) {
  const ingestHdr = extractIngestHeader(req);
  if (ingestHdr) {
    if (!API_INGEST_TOKEN || !ingestTokenOk(ingestHdr)) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    req.user = { email: 'api-ingest@internal' };
    req.authVia = 'ingest';
    return next();
  }

  const bearer = extractBearer(req);
  if (bearer) {
    if (process.env.ALLOW_JWT_BEARER !== '1') {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    try {
      const payload = jwt.verify(bearer, secret);
      const email = payload.email || payload.sub;
      if (!email || typeof email !== 'string') {
        return res.status(401).json({ message: 'Invalid token' });
      }
      req.user = { email: email.trim() };
      req.authVia = 'bearer';
      return next();
    } catch {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  }

  const c = req.cookies && req.cookies[AUTH_COOKIE_NAME];
  const fromCookie = c && typeof c === 'string' ? c.trim() : '';
  if (!fromCookie) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  try {
    const payload = jwt.verify(fromCookie, secret);
    const email = payload.email || payload.sub;
    if (!email || typeof email !== 'string') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.user = { email: email.trim() };
    req.authVia = 'cookie';
    return next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

export function csrfProtection(req, res, next) {
  const m = req.method;
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return next();
  const p = req.path || '';
  if (p === '/api/auth/login' || p === '/api/auth/logout') return next();
  if (!p.startsWith('/api')) return next();
  if (req.authVia === 'ingest' || req.authVia === 'bearer') return next();

  const hdr = req.headers['x-csrf-token'];
  const ck = req.cookies?.[CSRF_COOKIE_NAME];
  if (!hdr || !ck || !safeEqualUtf8(hdr, ck)) {
    return res.status(403).json({ message: 'CSRF token missing or invalid' });
  }
  return next();
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
