import './ensure-jwt-secret.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { effectiveRoleFromPayload, normalizeAppRole, ROLES } from './rbac.js';
import { getSessionConfig } from './sessionConfig.js';

const secret = process.env.JWT_SECRET;

export const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'demo_session';
export const CSRF_COOKIE_NAME = process.env.CSRF_COOKIE_NAME || 'demo_csrf';
export const AUTH_REFRESH_COOKIE_NAME = process.env.AUTH_REFRESH_COOKIE_NAME || 'demo_refresh';
// Refresh cookie is only ever sent to the auth endpoints, never on every API call.
export const REFRESH_COOKIE_PATH = '/api/auth';

/** Opaque machine credential (not a JWT). Prefer API_INGEST_TOKEN; API_BEARER_TOKEN kept as alias. */
const API_INGEST_TOKEN = String(process.env.API_INGEST_TOKEN || process.env.API_BEARER_TOKEN || '').trim();

// Browser cookies live for the whole absolute session window. The access JWT inside
// demo_session expires far sooner (ACCESS_TOKEN_TTL); its expiry — not the cookie's —
// is what drives silent refresh. Bounding the cookie to the absolute lifetime means a
// closed-then-reopened browser cannot present stale credentials past the hard cap.
function sessionCookieMaxAgeMs() {
  return getSessionConfig().absoluteMs;
}

/**
 * Cookie Secure flag (JWT-05).
 * - AUTH_COOKIE_SECURE=1 → Secure
 * - NODE_ENV=production → Secure unconditionally (AUTH_COOKIE_SECURE=0 / spoofed
 *   x-forwarded-proto cannot downgrade production)
 * - AUTH_COOKIE_SECURE=0 → non-Secure (local HTTP only; ignored in production)
 * - otherwise: https forwarded proto or req.secure
 */
export function cookieSecureFlag(req, env = process.env) {
  if (env.AUTH_COOKIE_SECURE === '1') return true;
  if (env.NODE_ENV === 'production') return true;
  if (env.AUTH_COOKIE_SECURE === '0') return false;
  const fwd = String(req?.headers?.['x-forwarded-proto'] || '')
    .split(',')[0]
    .trim();
  if (fwd === 'https') return true;
  return Boolean(req?.secure);
}

export function appendAuthCookie(req, res, token) {
  res.cookie(AUTH_COOKIE_NAME, token, {
    httpOnly: true,
    secure: cookieSecureFlag(req),
    sameSite: 'lax',
    maxAge: sessionCookieMaxAgeMs(),
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

/** HttpOnly refresh-token cookie, scoped to /api/auth so it never rides ordinary API calls. */
export function appendRefreshCookie(req, res, refreshToken) {
  res.cookie(AUTH_REFRESH_COOKIE_NAME, refreshToken, {
    httpOnly: true,
    secure: cookieSecureFlag(req),
    sameSite: 'lax',
    maxAge: sessionCookieMaxAgeMs(),
    path: REFRESH_COOKIE_PATH
  });
}

export function clearRefreshCookie(req, res) {
  res.clearCookie(AUTH_REFRESH_COOKIE_NAME, {
    path: REFRESH_COOKIE_PATH,
    secure: cookieSecureFlag(req),
    sameSite: 'lax',
    httpOnly: true
  });
}

export function readRefreshCookie(req) {
  const v = req.cookies?.[AUTH_REFRESH_COOKIE_NAME];
  return v && typeof v === 'string' ? v.trim() : '';
}

export function appendCsrfCookie(req, res) {
  const tok = crypto.randomBytes(32).toString('hex');
  res.cookie(CSRF_COOKIE_NAME, tok, {
    httpOnly: false,
    secure: cookieSecureFlag(req),
    sameSite: 'lax',
    maxAge: sessionCookieMaxAgeMs(),
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
 * @param {{ email?: string, username?: string, userId?: number|null, role: string, authVersion?: number|null }} payload
 * Role must be an explicit canonical app role. Omitted/invalid role does not default to admin.
 * When userId is present, authVersion (users.auth_version) is required in the JWT (JWT-03).
 */
export function signUserToken(payload) {
  if (payload == null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new TypeError('signUserToken requires an object payload with an explicit role');
  }
  const username = String(payload.username || payload.email || '').trim();
  const email = String(payload.email || username).trim();
  const sub = email || username;
  if (!sub) {
    throw new TypeError('signUserToken requires email or username');
  }
  const roleNorm = normalizeAppRole(payload.role);
  if (!roleNorm) {
    throw new TypeError('signUserToken requires an explicit valid role (admin|analyst|readonly)');
  }
  const body = { email: sub, username: username || sub, role: roleNorm };
  if (payload.userId != null && Number.isFinite(Number(payload.userId))) {
    body.userId = Number(payload.userId);
    const av = Number(payload.authVersion);
    if (!Number.isFinite(av) || av < 1) {
      throw new TypeError('signUserToken requires a positive authVersion when userId is set');
    }
    body.av = Math.floor(av);
    // Bind the access token to a server-side session when one is supplied. Interactive
    // logins always pass a sessionId; the per-request gate enforces the session's
    // idle/absolute/revocation state (JWT-06 bounded sessions).
    if (payload.sessionId != null && String(payload.sessionId).trim() !== '') {
      body.sid = String(payload.sessionId).trim();
    }
  }
  const expiresInSeconds = getSessionConfig().accessTtlSeconds;
  return jwt.sign(body, secret, { subject: sub, expiresIn: expiresInSeconds });
}

/** Last verified JWT payload attached by tryAttachSession (for auth_version gate). */
const JWT_PAYLOAD_SYM = Symbol.for('talonhound.jwtPayload');

function userFromJwtPayload(payload) {
  const email = String(payload.email || payload.sub || '').trim();
  if (!email) return null;
  const username = String(payload.username || email).trim();
  const role = effectiveRoleFromPayload(payload.role);
  if (!role) return null;
  const id =
    payload.userId != null && Number.isFinite(Number(payload.userId)) ? Number(payload.userId) : null;
  return { email, username, id, role };
}

export function getRequestTokenAuthVersion(req) {
  const p = req?.[JWT_PAYLOAD_SYM];
  if (!p || p.av == null) return null;
  const n = Number(p.av);
  return Number.isFinite(n) ? n : null;
}

/** Session id (`sid`) claim from the last verified interactive JWT, or null. */
export function getRequestTokenSessionId(req) {
  const p = req?.[JWT_PAYLOAD_SYM];
  const sid = p?.sid;
  return sid != null && String(sid).trim() !== '' ? String(sid).trim() : null;
}

/** Absolute expiry (`exp`, seconds since epoch) from the last verified JWT, or null. */
export function getRequestTokenExp(req) {
  const p = req?.[JWT_PAYLOAD_SYM];
  if (!p || p.exp == null) return null;
  const n = Number(p.exp);
  return Number.isFinite(n) ? n : null;
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

function tryAttachSession(req) {
  const ingestHdr = extractIngestHeader(req);
  if (ingestHdr) {
    if (!API_INGEST_TOKEN || !ingestTokenOk(ingestHdr)) return false;
    req.user = {
      email: 'api-ingest@internal',
      username: 'api-ingest@internal',
      id: null,
      role: ROLES.ADMIN,
      principalType: 'machine_ingest'
    };
    req.authVia = 'ingest';
    return true;
  }

  const bearer = extractBearer(req);
  if (bearer) {
    if (process.env.ALLOW_JWT_BEARER !== '1') return false;
    try {
      const payload = jwt.verify(bearer, secret);
      const u = userFromJwtPayload(payload);
      if (!u) return false;
      req[JWT_PAYLOAD_SYM] = payload;
      req.user = u;
      req.authVia = 'bearer';
      return true;
    } catch {
      return false;
    }
  }

  const fromCookie = req.cookies?.[AUTH_COOKIE_NAME];
  const token = fromCookie && typeof fromCookie === 'string' ? fromCookie.trim() : '';
  if (!token) return false;
  try {
    const payload = jwt.verify(token, secret);
    const u = userFromJwtPayload(payload);
    if (!u) return false;
    req[JWT_PAYLOAD_SYM] = payload;
    req.user = u;
    req.authVia = 'cookie';
    return true;
  } catch {
    return false;
  }
}

export function requireAuth(req, res, next) {
  if (tryAttachSession(req)) return next();
  return res.status(401).json({ message: 'Unauthorized' });
}

/**
 * Attach user when credentials are present and valid; otherwise continue unauthenticated.
 * Used by POST /api/setup/complete so greenfield stays anonymous while existing-install
 * admin sessions are visible to the handler (AUTH-05).
 */
export function optionalAuth(req, _res, next) {
  tryAttachSession(req);
  return next();
}

export function csrfProtection(req, res, next) {
  const m = req.method;
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return next();
  const p = req.path || '';
  if (p === '/api/auth/login' || p === '/api/auth/logout') return next();
  if (p === '/api/setup/complete' || p === '/api/setup/verify-code') return next();
  if (!p.startsWith('/api')) return next();
  // Machine API key clients and public docs have no CSRF cookie.
  if (p === '/api/v1' || p.startsWith('/api/v1/')) return next();
  if (p === '/mcp' || p.startsWith('/mcp/')) return next();
  if (req.authVia === 'ingest' || req.authVia === 'bearer' || req.authVia === 'api_key' || req.authVia === 'mcp') return next();

  const hdr = req.headers['x-csrf-token'];
  const ck = req.cookies?.[CSRF_COOKIE_NAME];
  if (!hdr || !ck || !safeEqualUtf8(hdr, ck)) {
    return res.status(403).json({ message: 'CSRF token missing or invalid' });
  }
  return next();
}

function isPublicApiDocsPath(path) {
  return path === '/api/docs'
    || path === '/api/openapi.json'
    || path === '/api/docs/static'
    || path.startsWith('/api/docs/static/');
}

function isApiV1Path(path) {
  return path === '/api/v1' || path.startsWith('/api/v1/');
}

function isMcpPath(path) {
  return path === '/mcp' || path.startsWith('/mcp/');
}

export function apiAuthGate(req, res, next) {
  if (req.method === 'OPTIONS') return next();
  if (req.path === '/api/auth/login' && req.method === 'POST') return next();
  if (req.path === '/api/auth/logout' && req.method === 'POST') {
    // Optional session so we can bump auth_version (logout-all) when a cookie is present.
    return optionalAuth(req, res, next);
  }
  // Refresh is authorized by the HttpOnly refresh cookie (validated in the handler),
  // not by an access token — the access token is expected to be expired here. CSRF
  // double-submit still applies downstream.
  if (req.path === '/api/auth/refresh' && req.method === 'POST') return next();
  // Setup status/preview stay public (greenfield + read-only discovery).
  // POST /api/setup/complete: optionally authenticated — handler enforces admin
  // when timezone_configuration_required (existing install). Keep unauthenticated
  // path open for true first-run (AUTH-05).
  if (req.path === '/api/setup/status' || req.path === '/api/setup/preview') {
    return next();
  }
  if (req.path === '/api/system/timezones' && req.method === 'GET') {
    return next();
  }
  if (req.path === '/api/setup/complete' && req.method === 'POST') {
    return optionalAuth(req, res, next);
  }
  // First-run setup-code pre-check: unauthenticated (greenfield). Handler rate-limits and
  // refuses once setup is complete.
  if (req.path === '/api/setup/verify-code' && req.method === 'POST') {
    return next();
  }

  // OpenAPI docs are public (contract discovery); management calls still need API keys.
  if (isPublicApiDocsPath(req.path)) {
    return next();
  }
  // /api/v1 is authenticated by Bearer API key middleware on those routes —
  // not by session cookies. Do not inherit browser-session roles.
  if (isApiV1Path(req.path)) {
    return next();
  }
  // MCP Streamable HTTP is authenticated by Bearer MCP API key middleware.
  if (isMcpPath(req.path)) {
    return next();
  }
  // Public Published Feed pull: authorized by ?api_key=, not by a user session.
  // Scoped to GET /api/published-feeds/{slug} with an api_key query parameter so
  // the admin feed-config routes still require authentication.
  if (
    req.method === 'GET'
    && typeof req.query?.api_key === 'string'
    && req.query.api_key !== ''
    && /^\/api\/published-feeds\/[^/]+$/.test(req.path)
    && req.path !== '/api/published-feeds/source-options'
  ) {
    return next();
  }
  if (req.path.startsWith('/api')) {
    return requireAuth(req, res, next);
  }
  return next();
}
