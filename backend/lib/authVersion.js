/**
 * JWT-03 — server-side session invalidation via users.auth_version.
 *
 * Security-sensitive account events bump auth_version. Authenticated cookie/bearer
 * requests must present a matching JWT `av` claim. Missing/mismatched av → 401.
 * Logout increments version (logout-all sessions for that user).
 */

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {number} userId
 * @returns {Promise<number|null>} new auth_version or null if user missing
 */
export async function bumpAuthVersion(db, userId) {
  const id = Number(userId);
  if (!Number.isFinite(id)) return null;
  const { rows } = await db.query(
    `UPDATE users
        SET auth_version = auth_version + 1
      WHERE id = $1
      RETURNING auth_version`,
    [id]
  );
  return rows[0]?.auth_version != null ? Number(rows[0].auth_version) : null;
}

/**
 * Express middleware: after requireAuth attaches req.user, verify JWT auth version and
 * (when session enforcement is wired) the bounded server-side session.
 *
 * Ingest / API-key principals skip — they are a separate security domain. Humans without
 * userId fail closed. When `getTokenSessionId` is provided, interactive cookie sessions
 * MUST carry a valid, non-revoked, non-idle-expired, non-absolute-expired `sid` session;
 * this READS the session but never advances its idle clock, so ordinary API traffic and
 * background polling cannot keep an idle session alive. All of it is one DB round trip.
 *
 * @param {import('pg').Pool} pool
 * @param {{
 *   getTokenAuthVersion: (req) => number|null|undefined,
 *   getTokenSessionId?: (req) => string|null|undefined,
 *   getTokenExp?: (req) => number|null|undefined,
 *   now?: () => Date
 * }} deps
 *
 * Bearer JWTs (ALLOW_JWT_BEARER=1): idle/session revoke via `sid` does not apply when
 * the token has no sid. Absolute expiry (`exp`), auth_version, and user status MUST
 * still hold — this gate enforces those three for bearer the same as for cookies
 * (session row checks remain cookie-only).
 */
export function createAuthVersionGate(pool, deps = {}) {
  const getTokenAuthVersion = deps.getTokenAuthVersion || (() => null);
  const sessionEnforced = typeof deps.getTokenSessionId === 'function';
  const getTokenSessionId = deps.getTokenSessionId || (() => null);
  const getTokenExp = deps.getTokenExp || (() => null);
  const nowFn = deps.now || (() => new Date());

  return async function authVersionGate(req, res, next) {
    if (!req.path?.startsWith('/api')) return next();
    // Always allow logout to clear cookies even when the JWT is already revoked/stale.
    if (req.path === '/api/auth/logout' && req.method === 'POST') return next();
    if (req.authVia === 'ingest' || req.authVia === 'api_key') return next();
    if (!req.user) return next();

    const userId = req.user.id;
    if (userId == null || !Number.isFinite(Number(userId))) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const claimAv = getTokenAuthVersion(req);
    if (claimAv == null || !Number.isFinite(Number(claimAv))) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // Session enforcement applies to interactive cookie logins. Legacy cookie tokens
    // issued before this feature carry no sid → fail closed (one-time forced re-login).
    const enforceSession = sessionEnforced && req.authVia === 'cookie';
    const sid = enforceSession ? getTokenSessionId(req) : null;
    if (enforceSession && !sid) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // Bearer (and any non-cookie human principal): still require absolute JWT expiry.
    // Without sid, idle timeout / server-side session revoke do not apply.
    if (req.authVia === 'bearer') {
      const exp = getTokenExp(req);
      if (exp == null || !Number.isFinite(Number(exp))) {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      if (Number(exp) * 1000 <= nowFn().getTime()) {
        return res.status(401).json({ message: 'Session expired', code: 'TOKEN_EXPIRED' });
      }
    }

    try {
      const { rows } = await pool.query(
        `SELECT u.auth_version, u.status,
                s.session_id, s.revoked_at, s.idle_expires_at, s.absolute_expires_at
           FROM users u
           LEFT JOIN auth_sessions s ON s.session_id = $2 AND s.user_id = u.id
          WHERE u.id = $1`,
        [Number(userId), sid]
      );
      if (!rows.length) {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      const row = rows[0];
      if (String(row.status || 'active') === 'passive') {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      const current = Number(row.auth_version);
      if (!Number.isFinite(current) || current !== Number(claimAv)) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      if (enforceSession) {
        const now = nowFn();
        if (!row.session_id || row.revoked_at) {
          return res.status(401).json({ message: 'Unauthorized' });
        }
        if (new Date(row.absolute_expires_at).getTime() <= now.getTime()) {
          return res.status(401).json({ message: 'Session expired', code: 'SESSION_EXPIRED_ABSOLUTE' });
        }
        if (new Date(row.idle_expires_at).getTime() <= now.getTime()) {
          return res.status(401).json({ message: 'Session expired', code: 'SESSION_EXPIRED_IDLE' });
        }
      }

      return next();
    } catch (err) {
      return res.status(500).json({ message: 'Session validation failed' });
    }
  };
}
