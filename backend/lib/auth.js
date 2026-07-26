import './ensure-jwt-secret.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { effectiveRoleFromPayload, normalizeAppRole, ROLES } from './rbac.js';

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

/**
 * @param {string | { email?: string, username?: string, userId?: number|null, role?: string }} payload
 * Backward compatible: signUserToken('user@x') issues admin role for legacy demo sessions.
 */
export function signUserToken(payload) {
  if (typeof payload === 'string') {
    const email = String(payload || '').trim();
    return jwt.sign({ email, role: ROLES.ADMIN }, secret, { subject: email, expiresIn });
  }
  const username = String(payload.username || payload.email || '').trim();
  const email = String(payload.email || username).trim();
  const sub = email || username;
  const roleNorm = normalizeAppRole(payload.role) || ROLES.READONLY;
  const body = { email: sub, username: username || sub, role: roleNorm };
  if (payload.userId != null && Number.isFinite(Number(payload.userId))) {
    body.userId = Number(payload.userId);
  }
  return jwt.sign(body, secret, { subject: sub, expiresIn });
}

function userFromJwtPayload(payload) {
  const email = String(payload.email || payload.sub || '').trim();
  if (!email) return null;
  const username = String(payload.username || email).trim();
  const role = effectiveRoleFromPayload(payload.role);
  const id =
    payload.userId != null && Number.isFinite(Number(payload.userId)) ? Number(payload.userId) : null;
  return { email, username, id, role: role || ROLES.ADMIN };
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
    req.user = {
      email: 'api-ingest@internal',
      username: 'api-ingest@internal',
      id: null,
      role: ROLES.ADMIN
    };
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
      const u = userFromJwtPayload(payload);
      if (!u) {
        return res.status(401).json({ message: 'Invalid token' });
      }
      req.user = u;
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
    const u = userFromJwtPayload(payload);
    if (!u) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.user = u;
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
  if (p === '/api/setup/complete') return next();
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
  // Initial setup must be reachable before any user session exists.
  if (
    req.path === '/api/setup/status'
    || req.path === '/api/setup/preview'
    || (req.path === '/api/setup/complete' && req.method === 'POST')
  ) {
    return next();
  }
  if (req.path.startsWith('/api')) {
    return requireAuth(req, res, next);
  }
  return next();
}
