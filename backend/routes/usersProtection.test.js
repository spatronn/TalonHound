import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { rbacHttpPolicy } from '../lib/rbac.js';
import { registerUserManagementRoutes } from './users.js';
import {
  SYSTEM_ADMIN_PROTECTED_MESSAGE,
  LAST_ACTIVE_ADMIN_MESSAGE
} from '../lib/adminProtection.js';

const ACTING = { id: 1, role: 'admin', publicId: '11111111-1111-4111-8111-111111111111', username: 'acting@admin' };

let uuidSeq = 0;
const uuid = () => {
  uuidSeq += 1;
  const h = String(uuidSeq).padStart(12, '0');
  return `22222222-2222-4222-8222-${h}`;
};

/**
 * In-memory users store that supports the transactional guard queries. `opLog` records the
 * transaction/locking steps so a test can assert the lock-then-mutate ordering.
 */
function createMockDb(initialUsers) {
  const users = initialUsers.map((u) => ({ ...u }));
  const opLog = [];
  const byId = (id) => users.find((u) => u.id === id);

  async function run(sql, params = []) {
    const s = String(sql);
    if (/^\s*BEGIN/i.test(s)) { opLog.push('BEGIN'); return { rows: [], rowCount: 0 }; }
    if (/^\s*COMMIT/i.test(s)) { opLog.push('COMMIT'); return { rows: [], rowCount: 0 }; }
    if (/^\s*ROLLBACK/i.test(s)) { opLog.push('ROLLBACK'); return { rows: [], rowCount: 0 }; }

    if (s.includes('WHERE public_id = $1::uuid')) {
      const found = users.find((u) => u.public_id === params[0]);
      return { rows: found ? [{ id: found.id }] : [], rowCount: found ? 1 : 0 };
    }
    if (s.includes("WHERE role = 'admin' ORDER BY id FOR UPDATE")) {
      opLog.push('LOCK_ADMINS');
      return { rows: users.filter((u) => u.role === 'admin').map((u) => ({ id: u.id })), rowCount: 0 };
    }
    if (s.includes('FROM users WHERE id = $1 FOR UPDATE')) {
      opLog.push('LOCK_TARGET');
      const found = byId(params[0]);
      // reset-password uses a narrower FOR UPDATE select; both are satisfied by returning the row.
      return { rows: found ? [{ ...found }] : [], rowCount: found ? 1 : 0 };
    }
    if (s.includes('COUNT(*)::int AS n') && s.includes('id <> $1')) {
      const n = users.filter((u) => u.role === 'admin' && u.status === 'active' && u.id !== params[0]).length;
      return { rows: [{ n }], rowCount: 1 };
    }
    if (/^\s*SELECT/i.test(s) && s.includes('FROM users WHERE id = $1')) {
      // plain (non-locking) select used by reset-password preflight
      const found = byId(params[0]);
      return { rows: found ? [{ ...found }] : [], rowCount: found ? 1 : 0 };
    }
    if (s.includes('DELETE FROM users WHERE id = $1')) {
      opLog.push('DELETE');
      const idx = users.findIndex((u) => u.id === params[0]);
      if (idx === -1) return { rows: [], rowCount: 0 };
      users.splice(idx, 1);
      return { rows: [], rowCount: 1 };
    }
    if (s.includes('UPDATE auth_sessions')) {
      // JWT-06: disable/reset revokes the target user's bounded sessions.
      opLog.push('REVOKE_SESSIONS');
      return { rows: [], rowCount: 0 };
    }
    if (s.includes('UPDATE users SET status')) {
      opLog.push('UPDATE_STATUS');
      const found = byId(params[0]);
      if (!found) return { rows: [], rowCount: 0 };
      found.status = params[1];
      return { rows: [{ ...found }], rowCount: 1 };
    }
    if (s.includes('UPDATE users SET') && s.includes('password_hash = $2') && s.includes('must_change_password = TRUE')) {
      opLog.push('RESET_PW');
      const found = byId(params[0]);
      if (!found) return { rows: [], rowCount: 0 };
      found.password_hash = params[1];
      found.must_change_password = true;
      return { rows: [{ ...found }], rowCount: 1 };
    }
    if (s.includes('UPDATE users SET') && s.includes('role = COALESCE')) {
      opLog.push('UPDATE_USER');
      const found = byId(params[0]);
      if (!found) return { rows: [], rowCount: 0 };
      const [, username, newHash, first_name, last_name, nextRole, passwordChanged] = params;
      if (username != null) found.username = username;
      if (newHash != null) found.password_hash = newHash;
      if (first_name != null) found.first_name = first_name;
      if (last_name != null) found.last_name = last_name;
      if (nextRole != null) found.role = nextRole;
      if (passwordChanged) found.must_change_password = false;
      return { rows: [{ ...found }], rowCount: 1 };
    }
    throw new Error(`unexpected sql: ${s.slice(0, 120)}`);
  }

  const pool = {
    async query(sql, params) { return run(sql, params); },
    async connect() { return { async query(sql, params) { return run(sql, params); }, release() {} }; }
  };
  return { pool, users, opLog };
}

function createApp(pool, auditCalls) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user'] ? JSON.parse(String(req.headers['x-test-user'])) : ACTING;
    next();
  });
  app.use(rbacHttpPolicy);
  registerUserManagementRoutes(app, pool, {
    auditSuccess: async (p) => { auditCalls.push({ status: 'success', ...p }); },
    auditFailure: async (p) => { auditCalls.push({ status: 'failure', ...p }); }
  });
  return app;
}

async function request(app, method, path, { body, user } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (user) headers['x-test-user'] = JSON.stringify(user);
  const res = await fetch(`http://127.0.0.1:${app.__port}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function withServer(users, testFn) {
  const auditCalls = [];
  const db = createMockDb(users);
  const app = createApp(db.pool, auditCalls);
  const server = app.listen(0);
  app.__port = server.address().port;
  try {
    await testFn({ app, db, auditCalls });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const mk = (over) => ({
  id: 2, public_id: uuid(), username: 'user@x', first_name: 'U', last_name: 'X',
  role: 'readonly', status: 'active', is_system_admin: false, password_hash: 'h', must_change_password: false, ...over
});

// Baseline: acting admin (id 1, non-system) + a protected system admin (id 2) + others.
function baseUsers() {
  return [
    mk({ id: 1, public_id: ACTING.publicId, username: 'acting@admin', role: 'admin' }),
    mk({ id: 2, username: 'admin@talonhound.local', role: 'admin', is_system_admin: true, first_name: 'System', last_name: 'Administrator' }),
    mk({ id: 3, username: 'reader@x', role: 'readonly' })
  ];
}
const SYS = (db) => db.users.find((u) => u.id === 2);
const pub = (db, id) => db.users.find((u) => u.id === id).public_id;

test('system admin delete is rejected (403) and nothing is deleted', async () => {
  await withServer(baseUsers(), async ({ app, db, auditCalls }) => {
    const res = await request(app, 'DELETE', `/api/users/${SYS(db).public_id}`);
    assert.equal(res.status, 403);
    assert.equal(res.data.message, SYSTEM_ADMIN_PROTECTED_MESSAGE);
    assert.ok(db.users.some((u) => u.id === 2), 'system admin still present');
    assert.deepEqual(db.opLog, ['BEGIN', 'LOCK_ADMINS', 'LOCK_TARGET', 'ROLLBACK']);
    assert.ok(auditCalls.some((c) => c.status === 'failure' && c.metadata?.reason === 'system_admin_protected'));
  });
});

test('system admin deactivate is rejected (403)', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    const res = await request(app, 'PATCH', `/api/users/${SYS(db).public_id}/status`, { body: { status: 'passive', reason: 'attempt to disable' } });
    assert.equal(res.status, 403);
    assert.equal(res.data.message, SYSTEM_ADMIN_PROTECTED_MESSAGE);
    assert.equal(SYS(db).status, 'active');
  });
});

test('system admin demotion is rejected (403)', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    const res = await request(app, 'PUT', `/api/users/${SYS(db).public_id}`, { body: { role: 'readonly', reason: 'attempt to demote' } });
    assert.equal(res.status, 403);
    assert.equal(res.data.message, SYSTEM_ADMIN_PROTECTED_MESSAGE);
    assert.equal(SYS(db).role, 'admin');
  });
});

test('system admin rename (username change) is rejected (403)', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    const res = await request(app, 'PUT', `/api/users/${SYS(db).public_id}`, { body: { username: 'hijack@evil.com' } });
    assert.equal(res.status, 403);
    assert.equal(SYS(db).username, 'admin@talonhound.local');
  });
});

test('system admin name (first/last) change is still allowed', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    const res = await request(app, 'PUT', `/api/users/${SYS(db).public_id}`, { body: { first_name: 'Sys', last_name: 'Admin' } });
    assert.equal(res.status, 200);
    assert.equal(SYS(db).first_name, 'Sys');
    assert.equal(SYS(db).role, 'admin');
    assert.equal(SYS(db).is_system_admin, true);
  });
});

test('another admin can Reset Password for the system admin', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    const res = await request(app, 'POST', `/api/admin/users/${SYS(db).public_id}/reset-password`);
    assert.equal(res.status, 200);
    assert.equal(res.data.ok, true);
    assert.equal(typeof res.data.temporary_password, 'string');
    assert.equal(SYS(db).must_change_password, true);
  });
});

test('last active admin cannot be deleted (409)', async () => {
  // Single admin in the system (the acting admin, non-system), acting on themselves.
  const users = [mk({ id: 1, public_id: ACTING.publicId, username: 'only@admin', role: 'admin' }), mk({ id: 3, role: 'readonly' })];
  await withServer(users, async ({ app, db }) => {
    const res = await request(app, 'DELETE', `/api/users/${ACTING.publicId}`);
    assert.equal(res.status, 409);
    assert.equal(res.data.message, LAST_ACTIVE_ADMIN_MESSAGE);
    assert.ok(db.users.some((u) => u.id === 1));
  });
});

test('last active admin cannot be deactivated (409)', async () => {
  const other = { id: 5, role: 'admin', publicId: uuid(), username: 'other@admin' };
  const users = [
    mk({ id: 1, public_id: ACTING.publicId, username: 'acting@admin', role: 'admin' }),
    mk({ id: 5, public_id: other.publicId, username: 'other@admin', role: 'admin' })
  ];
  // Acting admin (id 1) deactivates the only OTHER admin (id 5) — but there are 2 admins, so allowed.
  // Then, to hit the invariant, deactivate id 1 leaving zero: acting as id 5.
  await withServer(users, async ({ app, db }) => {
    // First deactivate id 5 while acting as id 1 → still one active admin (id 1) → allowed.
    const ok = await request(app, 'PATCH', `/api/users/${other.publicId}/status`, { body: { status: 'passive', reason: 'rotate out' } });
    assert.equal(ok.status, 200);
    // Now only id 1 is an active admin. Acting as id 5, try to deactivate id 1 → last admin → 409.
    const res = await request(app, 'PATCH', `/api/users/${ACTING.publicId}/status`, {
      body: { status: 'passive', reason: 'disable last admin' },
      user: { id: 5, role: 'admin', publicId: other.publicId, username: 'other@admin' }
    });
    assert.equal(res.status, 409);
    assert.equal(db.users.find((u) => u.id === 1).status, 'active');
  });
});

test('last active admin cannot be demoted (409)', async () => {
  const users = [mk({ id: 1, public_id: ACTING.publicId, username: 'only@admin', role: 'admin' })];
  await withServer(users, async ({ app, db }) => {
    const res = await request(app, 'PUT', `/api/users/${ACTING.publicId}`, { body: { role: 'analyst', reason: 'demote self' } });
    assert.equal(res.status, 409);
    assert.equal(db.users.find((u) => u.id === 1).role, 'admin');
  });
});

test('with multiple active admins, deleting a non-last normal admin succeeds', async () => {
  const extra = uuid();
  const users = [
    mk({ id: 1, public_id: ACTING.publicId, username: 'acting@admin', role: 'admin' }),
    mk({ id: 6, public_id: extra, username: 'extra@admin', role: 'admin' }),
    mk({ id: 3, role: 'readonly' })
  ];
  await withServer(users, async ({ app, db }) => {
    const res = await request(app, 'DELETE', `/api/users/${extra}`);
    assert.equal(res.status, 204);
    assert.ok(!db.users.some((u) => u.id === 6));
    assert.deepEqual(db.opLog, ['BEGIN', 'LOCK_ADMINS', 'LOCK_TARGET', 'DELETE', 'COMMIT']);
  });
});

test('deactivating a normal (non-admin) user is unaffected', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    const res = await request(app, 'PATCH', `/api/users/${pub(db, 3)}/status`, { body: { status: 'passive', reason: 'routine deactivate' } });
    assert.equal(res.status, 200);
    assert.equal(db.users.find((u) => u.id === 3).status, 'passive');
  });
});
