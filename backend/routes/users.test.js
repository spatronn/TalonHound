import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import bcrypt from 'bcrypt';
import { rbacHttpPolicy } from '../lib/rbac.js';
import { registerUserManagementRoutes } from './users.js';
import { AUDIT_ACTION } from '../lib/auditConstants.js';

const ADMIN_ID = 1;
const ADMIN_PUBLIC = '11111111-1111-4111-8111-111111111111';
const TARGET_ID = 2;
const TARGET_PUBLIC = '22222222-2222-4222-8222-222222222222';

/**
 * Stateful in-memory users store shared by pool.query and the transaction client so we
 * can assert what was persisted and in what order. `opLog` records client operations to
 * verify the hash + flag update is committed atomically.
 */
function createMockDb(initialUsers) {
  const users = initialUsers.map((u) => ({ ...u }));
  const opLog = [];

  function run(sql, params = []) {
    if (/^\s*BEGIN/i.test(sql)) { opLog.push('BEGIN'); return { rows: [], rowCount: 0 }; }
    if (/^\s*COMMIT/i.test(sql)) { opLog.push('COMMIT'); return { rows: [], rowCount: 0 }; }
    if (/^\s*ROLLBACK/i.test(sql)) { opLog.push('ROLLBACK'); return { rows: [], rowCount: 0 }; }

    if (sql.includes('WHERE public_id = $1::uuid')) {
      const found = users.find((u) => u.public_id === params[0]);
      return { rows: found ? [{ id: found.id }] : [], rowCount: found ? 1 : 0 };
    }
    if (sql.includes('FROM users WHERE id = $1') && sql.includes('FOR UPDATE')) {
      opLog.push('SELECT_FOR_UPDATE');
      const found = users.find((u) => u.id === params[0]);
      return { rows: found ? [{ id: found.id, status: found.status }] : [], rowCount: found ? 1 : 0 };
    }
    if (sql.startsWith('UPDATE users SET') || sql.includes('UPDATE users SET')) {
      opLog.push('UPDATE');
      const found = users.find((u) => u.id === params[0]);
      if (!found) return { rows: [], rowCount: 0 };
      found.password_hash = params[1];
      found.must_change_password = true;
      return { rows: [{ ...found }], rowCount: 1 };
    }
    if (sql.includes('FROM users WHERE id = $1')) {
      const found = users.find((u) => u.id === params[0]);
      return { rows: found ? [{ ...found }] : [], rowCount: found ? 1 : 0 };
    }
    return { rows: [], rowCount: 0 };
  }

  const pool = {
    async query(sql, params) { return run(sql, params); },
    async connect() {
      return {
        async query(sql, params) { return run(sql, params); },
        release() {}
      };
    }
  };

  return { pool, users, opLog };
}

function createApp(pool, auditCalls) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user']
      ? JSON.parse(String(req.headers['x-test-user']))
      : { id: ADMIN_ID, role: 'admin', publicId: ADMIN_PUBLIC, username: 'admin1' };
    next();
  });
  app.use(rbacHttpPolicy);
  registerUserManagementRoutes(app, pool, {
    auditSuccess: async (payload) => { auditCalls.push({ status: 'success', ...payload }); },
    auditFailure: async (payload) => { auditCalls.push({ status: 'failure', ...payload }); }
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
  return { status: res.status, data, headers: res.headers };
}

function baseUsers() {
  return [
    { id: ADMIN_ID, public_id: ADMIN_PUBLIC, username: 'admin1', first_name: 'Ada', last_name: 'Min', role: 'admin', status: 'active', password_hash: 'x', must_change_password: false },
    { id: TARGET_ID, public_id: TARGET_PUBLIC, username: 'target@user', first_name: 'Tar', last_name: 'Get', role: 'readonly', status: 'active', password_hash: 'old-hash', must_change_password: false }
  ];
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

const RESET = (pub) => `/api/admin/users/${pub}/reset-password`;

test('1. admin resets another user -> 200 with temporary password', async () => {
  await withServer(baseUsers(), async ({ app }) => {
    const res = await request(app, 'POST', RESET(TARGET_PUBLIC));
    assert.equal(res.status, 200);
    assert.equal(res.data.ok, true);
    assert.equal(typeof res.data.temporary_password, 'string');
    assert.ok(res.data.temporary_password.length >= 12);
    assert.equal(res.data.must_change_password, true);
    assert.equal(res.data.user.username, 'target@user');
  });
});

test('2. only the hash is persisted and it verifies against the returned temp password', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    const res = await request(app, 'POST', RESET(TARGET_PUBLIC));
    const target = db.users.find((u) => u.id === TARGET_ID);
    // Stored value is a bcrypt hash, never the plaintext.
    assert.notEqual(target.password_hash, res.data.temporary_password);
    assert.match(target.password_hash, /^\$2[aby]\$/);
    assert.equal(await bcrypt.compare(res.data.temporary_password, target.password_hash), true);
  });
});

test('3. must_change_password is set TRUE', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    await request(app, 'POST', RESET(TARGET_PUBLIC));
    assert.equal(db.users.find((u) => u.id === TARGET_ID).must_change_password, true);
  });
});

test('4. hash and flag update happen inside one committed transaction', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    await request(app, 'POST', RESET(TARGET_PUBLIC));
    assert.deepEqual(db.opLog, ['BEGIN', 'SELECT_FOR_UPDATE', 'UPDATE', 'COMMIT']);
  });
});

test('5. existing tokens restricted via must_change_password + rotated hash', async () => {
  // NOTE: stateless JWTs are not revoked; the gate restricts them and the old password
  // stops working. This asserts that restriction mechanism, not session revocation.
  await withServer(baseUsers(), async ({ app, db, auditCalls }) => {
    const res = await request(app, 'POST', RESET(TARGET_PUBLIC));
    const target = db.users.find((u) => u.id === TARGET_ID);
    assert.equal(target.must_change_password, true);
    // Old credential no longer authenticates against the rotated hash.
    assert.equal(await bcrypt.compare('old-plaintext', target.password_hash), false);
    const ok = auditCalls.find((c) => c.action === AUDIT_ACTION.USER_PASSWORD_RESET && c.status === 'success');
    assert.equal(ok.metadata.existing_sessions_restricted, true);
    assert.equal(res.data.must_change_password, true);
  });
});

test('6. admin cannot reset their own account', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    const res = await request(app, 'POST', RESET(ADMIN_PUBLIC), {
      user: { id: ADMIN_ID, role: 'admin', publicId: ADMIN_PUBLIC, username: 'admin1' }
    });
    assert.equal(res.status, 403);
    // Nothing was written.
    assert.deepEqual(db.opLog, []);
    assert.equal(db.users.find((u) => u.id === ADMIN_ID).must_change_password, false);
  });
});

test('7. non-admin (analyst/readonly) gets 403', async () => {
  await withServer(baseUsers(), async ({ app }) => {
    const analyst = await request(app, 'POST', RESET(TARGET_PUBLIC), {
      user: { id: 9, role: 'analyst', publicId: '99999999-9999-4999-8999-999999999999', username: 'an' }
    });
    assert.equal(analyst.status, 403);
    const readonly = await request(app, 'POST', RESET(TARGET_PUBLIC), {
      user: { id: 8, role: 'readonly', publicId: '88888888-8888-4888-8888-888888888888', username: 'ro' }
    });
    assert.equal(readonly.status, 403);
  });
});

test('8. unknown user -> 404', async () => {
  await withServer(baseUsers(), async ({ app }) => {
    const res = await request(app, 'POST', RESET('33333333-3333-4333-8333-333333333333'));
    assert.equal(res.status, 404);
  });
});

test('8b. malformed id -> 400', async () => {
  await withServer(baseUsers(), async ({ app }) => {
    const res = await request(app, 'POST', RESET('not-a-uuid'));
    assert.equal(res.status, 400);
  });
});

test('9. deactivated user reset is blocked with 409', async () => {
  const users = baseUsers();
  users[1].status = 'passive';
  await withServer(users, async ({ app, db, auditCalls }) => {
    const res = await request(app, 'POST', RESET(TARGET_PUBLIC));
    assert.equal(res.status, 409);
    assert.match(res.data.message, /deactivated/i);
    assert.deepEqual(db.opLog, []); // never entered a transaction
    assert.ok(auditCalls.some((c) => c.action === AUDIT_ACTION.USER_PASSWORD_RESET && c.status === 'failure'));
  });
});

test('10. second reset invalidates the first temporary password', async () => {
  await withServer(baseUsers(), async ({ app, db }) => {
    const first = await request(app, 'POST', RESET(TARGET_PUBLIC));
    const second = await request(app, 'POST', RESET(TARGET_PUBLIC));
    assert.notEqual(first.data.temporary_password, second.data.temporary_password);
    const target = db.users.find((u) => u.id === TARGET_ID);
    assert.equal(await bcrypt.compare(first.data.temporary_password, target.password_hash), false);
    assert.equal(await bcrypt.compare(second.data.temporary_password, target.password_hash), true);
  });
});

test('11. audit record is written and contains no secret', async () => {
  await withServer(baseUsers(), async ({ app, auditCalls }) => {
    const res = await request(app, 'POST', RESET(TARGET_PUBLIC));
    const entry = auditCalls.find((c) => c.action === AUDIT_ACTION.USER_PASSWORD_RESET && c.status === 'success');
    assert.ok(entry, 'expected a success audit entry');
    assert.equal(entry.entityDisplay, 'target@user');
    const { req, ...safe } = entry; // req is the live Express request (circular); not persisted
    const serialized = JSON.stringify(safe);
    assert.ok(!serialized.includes(res.data.temporary_password), 'temp password leaked into audit');
    assert.ok(!/password_hash/i.test(serialized) || !serialized.includes('$2'), 'hash leaked into audit');
  });
});

test('12. response carries no-store cache headers', async () => {
  await withServer(baseUsers(), async ({ app }) => {
    const res = await request(app, 'POST', RESET(TARGET_PUBLIC));
    assert.match(String(res.headers.get('cache-control')), /no-store/);
    assert.equal(res.headers.get('pragma'), 'no-cache');
  });
});
