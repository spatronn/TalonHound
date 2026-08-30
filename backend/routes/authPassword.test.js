import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerAuthPasswordRoutes } from './authPassword.js';

const SELF_ID = 7;
const SELF_PUBLIC = '77777777-7777-4777-8777-777777777777';
const OTHER_ID = 8;
const OTHER_PUBLIC = '88888888-8888-4888-8888-888888888888';

/**
 * In-memory users store. Records every id passed to a SELECT/UPDATE so a test can
 * assert exactly which account the handler touched, regardless of request body.
 */
function createMockDb(initialUsers) {
  const users = initialUsers.map((u) => ({ ...u }));
  const selectedIds = [];
  const updatedIds = [];

  async function query(sql, params = []) {
    if (/^\s*SELECT/i.test(sql) && sql.includes('FROM users WHERE id = $1')) {
      selectedIds.push(params[0]);
      const found = users.find((u) => u.id === params[0]);
      return { rows: found ? [{ ...found }] : [], rowCount: found ? 1 : 0 };
    }
    if (/UPDATE users/i.test(sql)) {
      updatedIds.push(params[0]);
      const found = users.find((u) => u.id === params[0]);
      if (!found) return { rows: [], rowCount: 0 };
      found.password_hash = params[1];
      found.must_change_password = false;
      return { rows: [{ ...found }], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  return { pool: { query }, users, selectedIds, updatedIds };
}

// Deterministic fakes so tests never depend on real bcrypt/JWT/cookies.
function fakeDeps(auditCalls) {
  return {
    bcrypt: {
      // "correct" current password is literally the stored hash prefixed with 'hash:'
      async compare(plain, hash) { return `hash:${plain}` === hash; },
      async hash(plain) { return `hash:${plain}`; }
    },
    signUserToken: () => 'signed.jwt.token',
    appendAuthCookie: () => {},
    appendCsrfCookie: () => {},
    audit: { auditSuccess: async (payload) => { auditCalls.push(payload); return; } }
  };
}

function baseUsers() {
  return [
    { id: SELF_ID, public_id: SELF_PUBLIC, username: 'self@user', role: 'analyst', password_hash: 'hash:oldpass', must_change_password: false },
    { id: OTHER_ID, public_id: OTHER_PUBLIC, username: 'victim@user', role: 'admin', password_hash: 'hash:victimpass', must_change_password: false }
  ];
}

function createApp(pool, deps, sessionUser) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    if (sessionUser !== null) req.user = sessionUser;
    next();
  });
  registerAuthPasswordRoutes(app, pool, deps);
  return app;
}

async function request(app, body) {
  const res = await fetch(`http://127.0.0.1:${app.__port}/api/auth/change-password`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function withServer({ users = baseUsers(), sessionUser = { id: SELF_ID, role: 'analyst' } } = {}, testFn) {
  const auditCalls = [];
  const db = createMockDb(users);
  const deps = fakeDeps(auditCalls);
  const app = createApp(db.pool, deps, sessionUser);
  const server = app.listen(0);
  app.__port = server.address().port;
  try {
    await testFn({ app, db, auditCalls });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('changes only the authenticated req.user.id account on success', async () => {
  await withServer({}, async ({ app, db, auditCalls }) => {
    const res = await request(app, { currentPassword: 'oldpass', newPassword: 'brand-new-pass' });
    assert.equal(res.status, 200);
    assert.equal(res.data.user.username, 'self@user');
    // Only the caller's own row was read and written.
    assert.deepEqual(db.selectedIds, [SELF_ID]);
    assert.deepEqual(db.updatedIds, [SELF_ID]);
    // The victim's password_hash is untouched.
    assert.equal(db.users.find((u) => u.id === OTHER_ID).password_hash, 'hash:victimpass');
    // Audit records the self-change against the caller.
    assert.equal(auditCalls[0].entityDisplay, 'self@user');
    assert.equal(auditCalls[0].metadata.source, 'self_change_password');
  });
});

test('ignores a target user id/public_id/email in the body — still changes only the caller', async () => {
  await withServer({}, async ({ app, db }) => {
    const res = await request(app, {
      currentPassword: 'oldpass',
      newPassword: 'brand-new-pass',
      // Attacker attempts to redirect the change at another account.
      id: OTHER_ID,
      userId: OTHER_ID,
      user_id: OTHER_ID,
      public_id: OTHER_PUBLIC,
      username: 'victim@user',
      email: 'victim@user',
      targetId: OTHER_ID
    });
    assert.equal(res.status, 200);
    // The victim account was never selected or updated.
    assert.ok(!db.selectedIds.includes(OTHER_ID), 'victim row must not be selected');
    assert.ok(!db.updatedIds.includes(OTHER_ID), 'victim row must not be updated');
    assert.equal(db.users.find((u) => u.id === OTHER_ID).password_hash, 'hash:victimpass');
    // The caller's own account was updated with the new password.
    assert.deepEqual(db.updatedIds, [SELF_ID]);
    assert.equal(db.users.find((u) => u.id === SELF_ID).password_hash, 'hash:brand-new-pass');
  });
});

test('wrong current password -> 401 and nothing is written', async () => {
  await withServer({}, async ({ app, db }) => {
    const res = await request(app, { currentPassword: 'wrong', newPassword: 'brand-new-pass' });
    assert.equal(res.status, 401);
    assert.match(res.data.message, /current password is incorrect/i);
    assert.deepEqual(db.updatedIds, []);
  });
});

test('unauthenticated request -> 401 and no db access', async () => {
  await withServer({ sessionUser: null }, async ({ app, db }) => {
    const res = await request(app, { currentPassword: 'oldpass', newPassword: 'brand-new-pass' });
    assert.equal(res.status, 401);
    assert.deepEqual(db.selectedIds, []);
    assert.deepEqual(db.updatedIds, []);
  });
});

test('missing fields -> 400', async () => {
  await withServer({}, async ({ app }) => {
    const res = await request(app, { currentPassword: 'oldpass' });
    assert.equal(res.status, 400);
    assert.match(res.data.message, /required/i);
  });
});

test('new password equal to current -> 400', async () => {
  await withServer({}, async ({ app, db }) => {
    const res = await request(app, { currentPassword: 'oldpass', newPassword: 'oldpass' });
    assert.equal(res.status, 400);
    assert.match(res.data.message, /different/i);
    assert.deepEqual(db.updatedIds, []);
  });
});
