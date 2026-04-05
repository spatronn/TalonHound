import bcrypt from 'bcrypt';
import { normalizeAppRole, requireRole, ROLES } from '../lib/rbac.js';

const USER_STATUSES = new Set(['active', 'passive']);

function normalizeUserStatus(value) {
  const s = String(value || '').trim().toLowerCase();
  if (USER_STATUSES.has(s)) return s;
  return null;
}

function toPublicUser(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    username: row.username,
    first_name: row.first_name,
    last_name: row.last_name,
    role: row.role,
    status: row.status || 'active',
    created_at: row.created_at
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 */
export function registerUserManagementRoutes(app, pool) {
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
      return res.status(400).json({ message: 'role must be admin or readonly' });
    }

    try {
      const hash = await bcrypt.hash(password, 12);
      const { rows } = await pool.query(
        `INSERT INTO users (username, password_hash, first_name, last_name, role)
         VALUES ($1, $2, $3, $4, $5::app_user_role)
         RETURNING id, username, first_name, last_name, role, status, created_at`,
        [username, hash, first_name, last_name, role]
      );
      return res.status(201).json({ user: toPublicUser(rows[0]) });
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
          `SELECT id, username, first_name, last_name, role, status, created_at
           FROM users ORDER BY id ASC`
        );
        return res.json({ users: rows.map(toPublicUser) });
      }

      if (!req.user?.id) {
        return res.status(403).json({ message: 'Forbidden' });
      }
      const { rows } = await pool.query(
        `SELECT id, username, first_name, last_name, role, status, created_at
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
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
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
           RETURNING id, username, first_name, last_name, role, status, created_at`,
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
        return res.status(400).json({ message: 'role must be admin or readonly' });
      }
      nextRole = nr;
    }

    try {
      const cur = await pool.query(
        'SELECT id, username, password_hash FROM users WHERE id = $1',
        [id]
      );
      if (!cur.rowCount) {
        return res.status(404).json({ message: 'User not found' });
      }

      let password_hash = cur.rows[0].password_hash;
      if (password != null && String(password).length > 0) {
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
           role = COALESCE($6::app_user_role, role)
         WHERE id = $1
         RETURNING id, username, first_name, last_name, role, status, created_at`,
        [
          id,
          username ?? null,
          password_hash,
          first_name ?? null,
          last_name ?? null,
          nextRole ?? null
        ]
      );

      return res.json({ user: toPublicUser(rows[0]) });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ message: 'Username already exists' });
      }
      return res.status(500).json({ message: 'Failed to update user', detail: err.message });
    }
  });

  app.patch('/api/users/:id/status', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: 'Invalid user id' });
    }

    const next = normalizeUserStatus(req.body?.status);
    if (next === null) {
      return res.status(400).json({ message: 'status must be active or passive' });
    }

    if (next === 'passive' && req.user?.id != null && Number(req.user.id) === id) {
      return res.status(403).json({ message: 'Cannot deactivate your own account' });
    }

    try {
      const { rows } = await pool.query(
        `UPDATE users SET status = $2::app_user_status WHERE id = $1
         RETURNING id, username, first_name, last_name, role, status, created_at`,
        [id, next]
      );
      if (!rows.length) {
        return res.status(404).json({ message: 'User not found' });
      }
      return res.json({ user: toPublicUser(rows[0]) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update status', detail: err.message });
    }
  });

  app.delete('/api/users/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: 'Invalid user id' });
    }
    try {
      const { rowCount } = await pool.query('DELETE FROM users WHERE id = $1', [id]);
      if (!rowCount) {
        return res.status(404).json({ message: 'User not found' });
      }
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ message: 'Failed to delete user', detail: err.message });
    }
  });
}
