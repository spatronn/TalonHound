import './ensure-jwt-secret.js';
import jwt from 'jsonwebtoken';

const secret = process.env.JWT_SECRET;
const expiresIn = process.env.JWT_EXPIRES_IN || '24h';

if (process.env.NODE_ENV === 'production' && !process.env.INGEST_API_KEY) {
  console.warn('[auth] INGEST_API_KEY is not set; POST /api/sysmon/events accepts unauthenticated requests');
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

export function requireAuth(req, res, next) {
  const token = extractBearer(req);
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

export function requireAuthOrIngestKey(req, res, next) {
  const ingestKey = process.env.INGEST_API_KEY;
  if (ingestKey) {
    const provided = String(req.get('x-ingest-key') || '');
    if (provided && provided === ingestKey) return next();
    return requireAuth(req, res, next);
  }
  return next();
}

export function apiAuthGate(req, res, next) {
  if (req.method === 'OPTIONS') return next();
  if (req.path === '/api/auth/login' && req.method === 'POST') return next();
  if (req.path === '/api/sysmon/events' && req.method === 'POST') {
    return requireAuthOrIngestKey(req, res, next);
  }
  if (req.path.startsWith('/api')) {
    return requireAuth(req, res, next);
  }
  return next();
}
