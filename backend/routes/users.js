import bcrypt from 'bcrypt';
import { normalizeAppRole, requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';
import { parseActionReason } from '../lib/reasonValidation.js';

const USER_STATUSES = new Set(['active', 'passive']);

function normalizeUserStatus(value) {
  const s = String(value || '').trim().toLowerCase();
  if (USER_STATUSES.has(s)) return s;
  return null;
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

function toPublicUser(row) {
  if (!row) return null;
  return {
    id: String(row.public_id || ''),
    username: row.username,
    first_name: row.first_name,
    last_name: row.last_name,
    role: row.role,
    status: row.status || 'active',
    created_at: row.created_at
  };
}

function userAuditSnapshot(row) {
  return pickSafeFields(toPublicUser(row), ['id', 'username', 'first_name', 'last_name', 'role', 'status']);
}

async function resolveInternalUserId(pool, publicId) {
  const val = String(publicId || '').trim();
  if (!isUuid(val)) return null;
  const { rows } = await pool.query('SELECT id FROM users WHERE public_id = $1::uuid', [val]);
  if (!rows.length) return null;
  return Number(rows[0].id);
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function, auditFailure?: Function }} audit
 */
export function registerUserManagementRoutes(app, pool, audit) {
  app.post('/api/users', requireRole(ROLES.ADMIN), async (req, res) => {
    const username = String(req.body?.username || '').trim();
    const password = req.body?.password;
    const first_name = String(req.body?.first_name ?? '').trim();
    const last_name = String(req.body?.last_name ?? '').trim();
    const roleRaw = req.body?.role;
    const role = normalizeAppRole(roleRaw) || ROLES.READONLY;

    if (!username || !password || typeof password !== 'string') {
      return res.status(400).json({ message: 'username and password are required' });
    }
    if (normalizeAppRole(roleRaw) === null && roleRaw != null && String(roleRaw).trim() !== '') {
      return res.status(400).json({ message: 'role must be admin, analyst, or readonly' });
    }

    try {
      const hash = await bcrypt.hash(password, 12);
      const { rows } = await pool.query(
        `INSERT INTO users (username, password_hash, first_name, last_name, role)
         VALUES ($1, $2, $3, $4, $5::app_user_role)
         RETURNING public_id, username, first_name, last_name, role, status, created_at`,
        [username, hash, first_name, last_name, role]
      );
      const user = toPublicUser(rows[0]);
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.USER_CREATED,
        entityType: AUDIT_ENTITY.USER,
        entityId: user.id,
        entityDisplay: user.username,
        severity: AUDIT_SEVERITY.WARNING,
        after: userAuditSnapshot(rows[0]),
        metadata: { role: user.role }
      });
      return res.status(201).json({ user });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ message: 'Username already exists' });
      }
      return res.status(500).json({ message: 'Failed to create user', detail: err.message });
    }
  });

  app.get('/api/users', async (req, res) => {
    const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;

    try {
      if (role === ROLES.ADMIN) {
        const { rows } = await pool.query(
          `SELECT public_id, username, first_name, last_name, role, status, created_at
           FROM users ORDER BY created_at ASC`
        );
        return res.json({ users: rows.map(toPublicUser) });
      }

      if (!req.user?.id) {
        return res.status(403).json({ message: 'Forbidden' });
      }
      const { rows } = await pool.query(
        `SELECT public_id, username, first_name, last_name, role, status, created_at
         FROM users WHERE id = $1`,
        [req.user.id]
      );
      if (!rows.length) {
        return res.json({ users: [] });
      }
      return res.json({ users: [toPublicUser(rows[0])] });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list users', detail: err.message });
    }
  });

  app.put('/api/users/:id', async (req, res) => {
    const id = await resolveInternalUserId(pool, req.params.id);
    if (!id) {
      return res.status(400).json({ message: 'Invalid user id' });
    }

    const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;

    if (role === ROLES.READONLY) {
      if (req.user?.id !== id) {
        return res.status(403).json({ message: 'Forbidden' });
      }
      const body = req.body || {};
      if (
        Object.prototype.hasOwnProperty.call(body, 'role') ||
        Object.prototype.hasOwnProperty.call(body, 'password') ||
        Object.prototype.hasOwnProperty.call(body, 'username')
      ) {
        return res.status(403).json({ message: 'Cannot modify restricted fields' });
      }
      const first_name = body.first_name !== undefined ? String(body.first_name).trim() : undefined;
      const last_name = body.last_name !== undefined ? String(body.last_name).trim() : undefined;
      if (first_name === undefined && last_name === undefined) {
        return res.status(400).json({ message: 'No updatable fields' });
      }
      try {
        const { rows } = await pool.query(
          `UPDATE users SET
             first_name = COALESCE($2, first_name),
             last_name = COALESCE($3, last_name)
           WHERE id = $1
           RETURNING public_id, username, first_name, last_name, role, status, created_at`,
          [id, first_name ?? null, last_name ?? null]
        );
        if (!rows.length) {
          return res.status(404).json({ message: 'User not found' });
        }
        return res.json({ user: toPublicUser(rows[0]) });
      } catch (err) {
        return res.status(500).json({ message: 'Failed to update user', detail: err.message });
      }
    }

    if (role !== ROLES.ADMIN) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const body = req.body || {};
    const first_name = body.first_name !== undefined ? String(body.first_name).trim() : undefined;
    const last_name = body.last_name !== undefined ? String(body.last_name).trim() : undefined;
    const username = body.username !== undefined ? String(body.username).trim() : undefined;
    if (username !== undefined && !username) {
      return res.status(400).json({ message: 'username cannot be empty' });
    }
    const password = body.password;
    let nextRole = undefined;
    if (Object.prototype.hasOwnProperty.call(body, 'role')) {
      const nr = normalizeAppRole(body.role);
      if (nr === null && String(body.role || '').trim() !== '') {
        return res.status(400).json({ message: 'role must be admin, analyst, or readonly' });
      }
      nextRole = nr;
    }

    let roleChangeReason = null;
    if (nextRole != null) {
      const reasonCheck = parseActionReason(body);
      if (!reasonCheck.ok) {
        return res.status(400).json({ message: reasonCheck.message });
      }
      roleChangeReason = reasonCheck.reason;
    }

    try {
      const cur = await pool.query(
        'SELECT id, public_id, username, first_name, last_name, role, status, password_hash FROM users WHERE id = $1',
        [id]
      );
      if (!cur.rowCount) {
        return res.status(404).json({ message: 'User not found' });
      }
      const before = userAuditSnapshot(cur.rows[0]);

      let password_hash = cur.rows[0].password_hash;
      const passwordChanged = password != null && String(password).length > 0;
      if (passwordChanged) {
        if (typeof password !== 'string') {
          return res.status(400).json({ message: 'Invalid password' });
        }
        password_hash = await bcrypt.hash(password, 12);
      }

      const { rows } = await pool.query(
        `UPDATE users SET
           username = COALESCE($2, username),
           password_hash = $3,
           first_name = COALESCE($4, first_name),
           last_name = COALESCE($5, last_name),
           role = COALESCE($6::app_user_role, role),
           must_change_password = CASE WHEN $7 THEN FALSE ELSE must_change_password END
         WHERE id = $1
         RETURNING public_id, username, first_name, last_name, role, status, created_at`,
        [
          id,
          username ?? null,
          password_hash,
          first_name ?? null,
          last_name ?? null,
          nextRole ?? null,
          passwordChanged
        ]
      );

      const user = toPublicUser(rows[0]);
      const after = userAuditSnapshot(rows[0]);

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.USER_UPDATED,
        entityType: AUDIT_ENTITY.USER,
        entityId: user.id,
        entityDisplay: user.username,
        severity: AUDIT_SEVERITY.INFO,
        before,
        after,
        metadata: { endpoint: 'PUT /api/users/:id' }
      });

      if (nextRole != null && nextRole !== before?.role) {
        audit?.auditSuccess({
          req,
          action: AUDIT_ACTION.USER_ROLE_CHANGED,
          entityType: AUDIT_ENTITY.USER,
          entityId: user.id,
          entityDisplay: user.username,
          severity: AUDIT_SEVERITY.CRITICAL,
          before: { role: before?.role },
          after: { role: after?.role },
          metadata: {
            previous_role: before?.role,
            new_role: after?.role,
            reason: roleChangeReason
          }
        });
      }

      if (passwordChanged) {
        audit?.auditSuccess({
          req,
          action: AUDIT_ACTION.USER_PASSWORD_CHANGED,
          entityType: AUDIT_ENTITY.USER,
          entityId: user.id,
          entityDisplay: user.username,
          severity: AUDIT_SEVERITY.CRITICAL,
          metadata: { changed_by_admin: true }
        });
      }

      return res.json({ user });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ message: 'Username already exists' });
      }
      return res.status(500).json({ message: 'Failed to update user', detail: err.message });
    }
  });

  app.patch('/api/users/:id/status', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = await resolveInternalUserId(pool, req.params.id);
    if (!id) {
      return res.status(400).json({ message: 'Invalid user id' });
    }

    const next = normalizeUserStatus(req.body?.status);
    if (next === null) {
      return res.status(400).json({ message: 'status must be active or passive' });
    }

    const reasonCheck = parseActionReason(req.body);
    if (!reasonCheck.ok) {
      return res.status(400).json({ message: reasonCheck.message });
    }

    if (next === 'passive' && req.user?.id != null && Number(req.user.id) === id) {
      return res.status(403).json({ message: 'Cannot deactivate your own account' });
    }

    try {
      const cur = await pool.query(
        'SELECT public_id, username, first_name, last_name, role, status FROM users WHERE id = $1',
        [id]
      );
      if (!cur.rowCount) return res.status(404).json({ message: 'User not found' });
      const before = userAuditSnapshot(cur.rows[0]);

      const { rows } = await pool.query(
        `UPDATE users SET status = $2::app_user_status WHERE id = $1
         RETURNING public_id, username, first_name, last_name, role, status, created_at`,
        [id, next]
      );
      if (!rows.length) {
        return res.status(404).json({ message: 'User not found' });
      }

      const user = toPublicUser(rows[0]);
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.USER_STATUS_CHANGED,
        entityType: AUDIT_ENTITY.USER,
        entityId: user.id,
        entityDisplay: user.username,
        severity: next === 'passive' ? AUDIT_SEVERITY.CRITICAL : AUDIT_SEVERITY.WARNING,
        before,
        after: userAuditSnapshot(rows[0]),
        metadata: {
          previous_status: before?.status,
          new_status: user.status,
          reason: reasonCheck.reason
        }
      });

      return res.json({ user });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update status', detail: err.message });
    }
  });

  app.delete('/api/users/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = await resolveInternalUserId(pool, req.params.id);
    if (!id) {
      return res.status(400).json({ message: 'Invalid user id' });
    }
    try {
      const cur = await pool.query(
        'SELECT public_id, username, first_name, last_name, role, status FROM users WHERE id = $1',
        [id]
      );
      if (!cur.rowCount) return res.status(404).json({ message: 'User not found' });
      const before = userAuditSnapshot(cur.rows[0]);

      const { rowCount } = await pool.query('DELETE FROM users WHERE id = $1', [id]);
      if (!rowCount) {
        return res.status(404).json({ message: 'User not found' });
      }

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.USER_DELETED,
        entityType: AUDIT_ENTITY.USER,
        entityId: before?.id,
        entityDisplay: before?.username,
        severity: AUDIT_SEVERITY.CRITICAL,
        before,
        metadata: { deleted_username: before?.username, deleted_email: before?.username }
      });

      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ message: 'Failed to delete user', detail: err.message });
    }
  });
}
