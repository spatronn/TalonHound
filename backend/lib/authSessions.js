/**
 * Server-side interactive session store (security: enforce bounded browser sessions).
 *
 * Backs the short-access-token + rotating-refresh model. The DB stores only a SHA-256
 * hash of the refresh secret — never the raw token. Three limits are enforced here and
 * (for immediacy) in the per-request auth gate:
 *   - absolute lifetime from original login (never extended by refresh),
 *   - idle timeout driven ONLY by the explicit activity heartbeat,
 *   - explicit revocation (logout / password / admin reset / disable / delete / reuse).
 *
 * Refresh rotation is single-flight per session via SELECT ... FOR UPDATE so a burst of
 * concurrent 401s (refresh storm) cannot double-rotate or corrupt the session; a
 * previously-rotated (replayed) refresh secret is treated as compromise and revokes the
 * whole session.
 */
import crypto from 'crypto';
import { getSessionConfig } from './sessionConfig.js';

/** SHA-256 hex of a refresh secret. */
export function hashSecret(secret) {
  return crypto.createHash('sha256').update(String(secret), 'utf8').digest('hex');
}

/** Timing-safe hex-string comparison. */
function safeEqualHex(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  try {
    return crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

/** Refresh token wire format: `<sessionId>.<secret>`. */
export function parseRefreshToken(raw) {
  const s = String(raw || '').trim();
  const idx = s.indexOf('.');
  if (idx <= 0 || idx >= s.length - 1) return null;
  const sessionId = s.slice(0, idx);
  const secret = s.slice(idx + 1);
  if (!sessionId || !secret) return null;
  return { sessionId, secret };
}

function newSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function truncateUa(ua) {
  const s = ua == null ? null : String(ua);
  if (!s) return null;
  return s.length > 255 ? s.slice(0, 255) : s;
}

/**
 * Create a new session for a freshly-authenticated user.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {{ userId:number, authVersion:number, userAgent?:string|null }} params
 * @param {{ now?:Date, config?:object }} [opts]
 * @returns {Promise<{ sessionId:string, refreshToken:string, absoluteExpiresAt:Date, idleExpiresAt:Date }>}
 */
export async function createSession(db, params, opts = {}) {
  const config = opts.config || getSessionConfig();
  const now = opts.now || new Date();
  const userId = Number(params.userId);
  const authVersion = Number(params.authVersion);
  if (!Number.isFinite(userId) || !Number.isFinite(authVersion)) {
    throw new TypeError('createSession requires numeric userId and authVersion');
  }
  const sessionId = crypto.randomUUID();
  const secret = newSecret();
  const tokenHash = hashSecret(secret);
  const idleExpiresAt = new Date(now.getTime() + config.idleMs);
  const absoluteExpiresAt = new Date(now.getTime() + config.absoluteMs);

  await db.query(
    `INSERT INTO auth_sessions
       (session_id, user_id, refresh_token_hash, auth_version_at_issue,
        created_at, last_activity_at, rotated_at, idle_expires_at, absolute_expires_at, user_agent)
     VALUES ($1, $2, $3, $4, $5, $5, $5, $6, $7, $8)`,
    [
      sessionId,
      userId,
      tokenHash,
      authVersion,
      now.toISOString(),
      idleExpiresAt.toISOString(),
      absoluteExpiresAt.toISOString(),
      truncateUa(params.userAgent)
    ]
  );

  return {
    sessionId,
    refreshToken: `${sessionId}.${secret}`,
    absoluteExpiresAt,
    idleExpiresAt
  };
}

/**
 * Read-only validation used by the per-request auth gate. Does NOT mutate the row
 * (so ordinary API traffic and background polling never extend the idle clock).
 * @returns {Promise<{ ok:boolean, reason?:string, userId?:number }>}
 */
export async function validateAccessSession(db, sessionId, opts = {}) {
  const now = opts.now || new Date();
  if (!sessionId) return { ok: false, reason: 'missing' };
  const { rows } = await db.query(
    `SELECT user_id, revoked_at, idle_expires_at, absolute_expires_at
       FROM auth_sessions WHERE session_id = $1`,
    [sessionId]
  );
  if (!rows.length) return { ok: false, reason: 'not_found' };
  const row = rows[0];
  if (row.revoked_at) return { ok: false, reason: 'revoked', userId: Number(row.user_id) };
  if (new Date(row.absolute_expires_at).getTime() <= now.getTime()) {
    return { ok: false, reason: 'absolute', userId: Number(row.user_id) };
  }
  if (new Date(row.idle_expires_at).getTime() <= now.getTime()) {
    return { ok: false, reason: 'idle', userId: Number(row.user_id) };
  }
  return { ok: true, userId: Number(row.user_id) };
}

/**
 * Advance the genuine-activity clock. Called ONLY by the explicit heartbeat endpoint.
 * Server-side throttled: skips the write if the last activity was very recent, bounding
 * write amplification regardless of client behaviour. Never resurrects a dead session.
 * @returns {Promise<{ updated:boolean }>}
 */
export async function touchActivity(db, sessionId, opts = {}) {
  const config = opts.config || getSessionConfig();
  const now = opts.now || new Date();
  if (!sessionId) return { updated: false };
  const nowIso = now.toISOString();
  const idleExpiresAt = new Date(now.getTime() + config.idleMs).toISOString();
  const minUpdateCutoff = new Date(now.getTime() - config.activityMinUpdateMs).toISOString();
  const { rowCount } = await db.query(
    `UPDATE auth_sessions
        SET last_activity_at = $2::timestamptz,
            idle_expires_at  = $3::timestamptz
      WHERE session_id = $1
        AND revoked_at IS NULL
        AND absolute_expires_at > $2::timestamptz
        AND idle_expires_at     > $2::timestamptz
        AND last_activity_at   <= $4::timestamptz`,
    [sessionId, nowIso, idleExpiresAt, minUpdateCutoff]
  );
  return { updated: rowCount > 0 };
}

/**
 * Rotate the refresh token for a session and mint the next access token window.
 * Enforces revocation, absolute expiry, idle expiry, auth_version currency and
 * replay detection. Does NOT extend the idle clock (refresh is not user activity).
 *
 * @param {import('pg').Pool} pool
 * @param {{ rawRefresh:string, userAgent?:string|null }} params
 * @param {{ now?:Date, config?:object }} [opts]
 * @returns {Promise<
 *   { ok:true, sessionId:string, userId:number, refreshToken:string, authVersion:number }
 *   | { ok:false, reason:string }
 * >}
 */
export async function rotateRefresh(pool, params, opts = {}) {
  const config = opts.config || getSessionConfig();
  const now = opts.now || new Date();
  const parsed = parseRefreshToken(params.rawRefresh);
  if (!parsed) return { ok: false, reason: 'invalid' };

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT s.id, s.session_id, s.user_id, s.refresh_token_hash, s.prev_refresh_token_hash,
              s.rotated_at, s.auth_version_at_issue,
              s.revoked_at, s.idle_expires_at, s.absolute_expires_at,
              u.auth_version AS user_auth_version, u.status AS user_status
         FROM auth_sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.session_id = $1
        FOR UPDATE OF s`,
      [parsed.sessionId]
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return { ok: false, reason: 'not_found' };
    }
    const row = rows[0];

    if (row.revoked_at) {
      await client.query('ROLLBACK');
      return { ok: false, reason: 'revoked' };
    }
    if (new Date(row.absolute_expires_at).getTime() <= now.getTime()) {
      await revokeWithin(client, parsed.sessionId, 'absolute_timeout', now);
      await client.query('COMMIT');
      return { ok: false, reason: 'absolute' };
    }
    if (new Date(row.idle_expires_at).getTime() <= now.getTime()) {
      await revokeWithin(client, parsed.sessionId, 'idle_timeout', now);
      await client.query('COMMIT');
      return { ok: false, reason: 'idle' };
    }

    const presentedHash = hashSecret(parsed.secret);
    const matchesCurrent = safeEqualHex(presentedHash, row.refresh_token_hash);
    // Grace window: two tabs sharing the cookie may race to refresh. The loser presents
    // the immediately-previous secret moments after the winner rotated — accept it as the
    // same rotation instead of flagging reuse.
    const withinGrace =
      row.prev_refresh_token_hash != null
      && row.rotated_at != null
      && (now.getTime() - new Date(row.rotated_at).getTime()) <= config.refreshGraceMs
      && safeEqualHex(presentedHash, row.prev_refresh_token_hash);

    if (!matchesCurrent && !withinGrace) {
      // Replay/reuse: a rotated (or forged) refresh token outside the grace window.
      await revokeWithin(client, parsed.sessionId, 'refresh_reuse', now);
      await client.query('COMMIT');
      return { ok: false, reason: 'reuse' };
    }

    if (String(row.user_status || 'active') === 'passive') {
      await revokeWithin(client, parsed.sessionId, 'user_disabled', now);
      await client.query('COMMIT');
      return { ok: false, reason: 'user_disabled' };
    }
    const currentAv = Number(row.user_auth_version);
    if (!Number.isFinite(currentAv) || currentAv !== Number(row.auth_version_at_issue)) {
      await revokeWithin(client, parsed.sessionId, 'auth_version', now);
      await client.query('COMMIT');
      return { ok: false, reason: 'auth_version' };
    }

    if (withinGrace && !matchesCurrent) {
      // A concurrent tab already rotated; the shared cookie now holds the current secret.
      // Mint a fresh access token but leave the refresh token as-is (no re-rotation).
      await client.query('COMMIT');
      return {
        ok: true,
        sessionId: parsed.sessionId,
        userId: Number(row.user_id),
        refreshToken: null,
        rotated: false,
        authVersion: currentAv
      };
    }

    // Rotate: new secret, remember the prior one for the grace window, idle/absolute unchanged.
    const nextSecret = newSecret();
    await client.query(
      `UPDATE auth_sessions
          SET prev_refresh_token_hash = refresh_token_hash,
              refresh_token_hash = $2,
              rotated_at = $4::timestamptz,
              user_agent = COALESCE($3, user_agent)
        WHERE session_id = $1`,
      [parsed.sessionId, hashSecret(nextSecret), truncateUa(params.userAgent), now.toISOString()]
    );
    await client.query('COMMIT');
    return {
      ok: true,
      sessionId: parsed.sessionId,
      userId: Number(row.user_id),
      refreshToken: `${parsed.sessionId}.${nextSecret}`,
      rotated: true,
      authVersion: currentAv
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function revokeWithin(db, sessionId, reason, now) {
  await db.query(
    `UPDATE auth_sessions
        SET revoked_at = COALESCE(revoked_at, $2::timestamptz), revoked_reason = COALESCE(revoked_reason, $3)
      WHERE session_id = $1`,
    [sessionId, (now || new Date()).toISOString(), reason]
  );
}

/** Revoke a single session (e.g. logout). Idempotent. */
export async function revokeSession(db, sessionId, reason, opts = {}) {
  if (!sessionId) return { revoked: false };
  const { rowCount } = await db.query(
    `UPDATE auth_sessions
        SET revoked_at = COALESCE(revoked_at, $2::timestamptz), revoked_reason = COALESCE(revoked_reason, $3)
      WHERE session_id = $1 AND revoked_at IS NULL`,
    [sessionId, (opts.now || new Date()).toISOString(), reason || 'logout']
  );
  return { revoked: rowCount > 0 };
}

/**
 * Revoke every active session for a user (logout-all, password change, admin reset,
 * disable, delete). Complements the users.auth_version bump those events already do.
 */
export async function revokeAllForUser(db, userId, reason, opts = {}) {
  const id = Number(userId);
  if (!Number.isFinite(id)) return { revoked: 0 };
  const { rowCount } = await db.query(
    `UPDATE auth_sessions
        SET revoked_at = COALESCE(revoked_at, $2::timestamptz), revoked_reason = COALESCE(revoked_reason, $3)
      WHERE user_id = $1 AND revoked_at IS NULL`,
    [id, (opts.now || new Date()).toISOString(), reason || 'revoke_all']
  );
  return { revoked: rowCount };
}

/**
 * Bounded deletion of terminal (revoked or absolutely-expired) session rows older than
 * the retention window. Mirrors the audit-log retention pattern: one bounded DELETE per
 * call, driven by the maintenance worker.
 * @returns {Promise<{ deleted:number }>}
 */
export async function cleanupSessions(db, opts = {}) {
  const config = opts.config || getSessionConfig();
  const now = opts.now || new Date();
  const batchSize = Math.max(Number(opts.batchSize) || 1000, 1);
  const cutoff = new Date(now.getTime() - config.cleanupRetentionDays * 24 * 60 * 60 * 1000).toISOString();
  const { rowCount } = await db.query(
    `DELETE FROM auth_sessions
      WHERE id IN (
        SELECT id FROM auth_sessions
         WHERE (
                 (revoked_at IS NOT NULL AND revoked_at < $1::timestamptz)
              OR (absolute_expires_at < $1::timestamptz)
               )
         ORDER BY id
         LIMIT $2
      )`,
    [cutoff, batchSize]
  );
  return { deleted: rowCount };
}
