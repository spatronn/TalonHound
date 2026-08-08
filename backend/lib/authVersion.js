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
 * Express middleware: after requireAuth attaches req.user, verify JWT auth version.
 * Ingest / API-key principals skip. Humans without userId fail closed.
 *
 * @param {import('pg').Pool} pool
 * @param {{ getTokenAuthVersion: (req) => number|null|undefined }} deps
 */
export function createAuthVersionGate(pool, deps = {}) {
  const getTokenAuthVersion = deps.getTokenAuthVersion || (() => null);

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

    try {
      const { rows } = await pool.query(
        `SELECT auth_version, status FROM users WHERE id = $1`,
        [Number(userId)]
      );
      if (!rows.length) {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      if (String(rows[0].status || 'active') === 'passive') {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      const current = Number(rows[0].auth_version);
      if (!Number.isFinite(current) || current !== Number(claimAv)) {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      return next();
    } catch (err) {
      return res.status(500).json({ message: 'Session validation failed' });
    }
  };
}
