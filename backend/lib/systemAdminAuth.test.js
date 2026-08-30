import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isCallerSystemAdmin,
  requireSystemAdmin,
  SYSTEM_ADMIN_FORBIDDEN
} from './systemAdminAuth.js';

function makePool({ systemAdmins = new Set(), throwOnQuery = false } = {}) {
  return {
    async query(sql, params = []) {
      if (throwOnQuery) throw new Error('db down');
      const s = String(sql);
      if (s.includes('FROM users') && s.includes('is_system_admin')) {
        const id = Number(params[0]);
        return { rows: [{ is_system_admin: systemAdmins.has(id) }] };
      }
      throw new Error(`unexpected sql: ${s}`);
    }
  };
}

async function runRequire(pool, req) {
  const handler = requireSystemAdmin(pool);
  let statusCode = null;
  let body = null;
  let nextCalled = false;
  const res = {
    status(code) { statusCode = code; return this; },
    json(payload) { body = payload; return this; }
  };
  await handler(req, res, () => { nextCalled = true; });
  return { statusCode, body, nextCalled };
}

test('isCallerSystemAdmin is true only for users.is_system_admin', async () => {
  const pool = makePool({ systemAdmins: new Set([1]) });
  assert.equal(await isCallerSystemAdmin(pool, { user: { id: 1, role: 'admin' } }), true);
  assert.equal(await isCallerSystemAdmin(pool, { user: { id: 2, role: 'admin' } }), false);
});

test('isCallerSystemAdmin ignores role, username, and email', async () => {
  const pool = makePool({ systemAdmins: new Set() });
  assert.equal(
    await isCallerSystemAdmin(pool, {
      user: { id: 9, role: 'admin', email: 'admin@talonhound.local', username: 'admin@talonhound.local' }
    }),
    false
  );
});

test('isCallerSystemAdmin fails closed for ingest, missing id, missing pool, and db errors', async () => {
  const pool = makePool({ systemAdmins: new Set([1]) });
  assert.equal(await isCallerSystemAdmin(pool, { authVia: 'ingest', user: { id: 1, role: 'admin' } }), false);
  assert.equal(await isCallerSystemAdmin(pool, { user: { role: 'admin' } }), false);
  assert.equal(await isCallerSystemAdmin(pool, { user: { id: 'x', role: 'admin' } }), false);
  assert.equal(await isCallerSystemAdmin(null, { user: { id: 1, role: 'admin' } }), false);
  assert.equal(await isCallerSystemAdmin(makePool({ throwOnQuery: true }), { user: { id: 1 } }), false);
});

test('requireSystemAdmin allows the System Administrator and 403s everyone else', async () => {
  const pool = makePool({ systemAdmins: new Set([1]) });
  const allowed = await runRequire(pool, { user: { id: 1, role: 'admin' } });
  assert.equal(allowed.nextCalled, true);
  assert.equal(allowed.statusCode, null);

  const denied = await runRequire(pool, { user: { id: 2, role: 'admin' } });
  assert.equal(denied.nextCalled, false);
  assert.equal(denied.statusCode, 403);
  assert.equal(denied.body.code, SYSTEM_ADMIN_FORBIDDEN.code);
  assert.equal(denied.body.message, SYSTEM_ADMIN_FORBIDDEN.message);
});
