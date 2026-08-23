import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { bumpAuthVersion } from '../lib/authVersion.js';

/**
 * Self-service password change endpoint.
 *
 * Security: the account being changed is derived ONLY from the authenticated
 * session (`req.user.id`). No target user id/email is read from the request body
 * or params, so a caller can never change another user's password through this
 * route. Extracted from server.js verbatim so the ownership guarantee is testable
 * against the real handler (see routes/authPassword.test.js).
 *
 * @param {import('express').Express} app
 * @param {{ query: Function }} pool
 * @param {{
 *   bcrypt: { compare: Function, hash: Function },
 *   signUserToken: Function,
 *   appendAuthCookie: Function,
 *   appendCsrfCookie: Function,
 *   audit: { auditSuccess: Function }
 * }} deps
 */
export function registerAuthPasswordRoutes(app, pool, deps) {
  const {
    bcrypt,
    signUserToken,
    appendAuthCookie,
    appendCsrfCookie,
    appendRefreshCookie,
    createSession,
    revokeAllForUser,
    audit
  } = deps;

  app.post('/api/auth/change-password', async (req, res) => {
    const userId = req.user?.id;
    if (userId == null || !Number.isFinite(Number(userId))) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const currentPassword = req.body?.currentPassword ?? req.body?.current_password;
    const newPassword = req.body?.newPassword ?? req.body?.new_password;

    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string' || !currentPassword || !newPassword) {
      return res.status(400).json({ message: 'currentPassword and newPassword are required' });
    }
    if (newPassword === currentPassword) {
      return res.status(400).json({ message: 'New password must be different from the current password' });
    }

    try {
      const { rows } = await pool.query(
        'SELECT id, public_id, username, password_hash, role, must_change_password, auth_version FROM users WHERE id = $1',
        [Number(userId)]
      );
      if (!rows.length) {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      const u = rows[0];
      const ok = await bcrypt.compare(currentPassword, u.password_hash);
      if (!ok) {
        return res.status(401).json({ message: 'Current password is incorrect' });
      }

      const hash = await bcrypt.hash(newPassword, 12);
      const updated = await pool.query(
        `UPDATE users
         SET password_hash = $2,
             must_change_password = FALSE,
             auth_version = auth_version + 1
         WHERE id = $1
         RETURNING public_id, username, role, must_change_password, auth_version`,
        [u.id, hash]
      );
      const next = updated.rows[0];
      const nextAuthVersion = Number(next.auth_version) || 1;
      // JWT-06: the auth_version bump above already invalidates every outstanding
      // session for this user. Revoke their session rows too (belt-and-suspenders +
      // reuse-detection cleanup), then mint a fresh bounded session for this request.
      if (typeof revokeAllForUser === 'function') {
        await revokeAllForUser(pool, u.id, 'password_change').catch(() => {});
      }
      let sessionId;
      if (typeof createSession === 'function' && typeof appendRefreshCookie === 'function') {
        const session = await createSession(pool, {
          userId: u.id,
          authVersion: nextAuthVersion,
          userAgent: req.headers['user-agent'] || null
        });
        sessionId = session.sessionId;
        appendRefreshCookie(req, res, session.refreshToken);
      }
      const token = signUserToken({
        userId: u.id,
        username: next.username,
        email: next.username,
        role: next.role,
        authVersion: nextAuthVersion,
        sessionId
      });
      appendAuthCookie(req, res, token);
      appendCsrfCookie(req, res);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.USER_PASSWORD_CHANGED,
        entityType: AUDIT_ENTITY.USER,
        entityId: String(next.public_id || u.id),
        entityDisplay: next.username,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { source: 'self_change_password', auth_version: next.auth_version }
      }).catch(() => {});

      return res.json({
        user: {
          email: next.username,
          username: next.username,
          id: next.public_id,
          role: next.role,
          mustChangePassword: Boolean(next.must_change_password)
        }
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to change password', detail: err.message });
    }
  });
}

// bumpAuthVersion re-export for callers that need an explicit bump without password change
export { bumpAuthVersion };
