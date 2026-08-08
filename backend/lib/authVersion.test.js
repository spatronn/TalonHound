import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { bumpAuthVersion, createAuthVersionGate } from './authVersion.js';
import { signUserToken } from './auth.js';
import { ROLES } from './rbac.js';

if (!process.env.JWT_SECRET || String(process.env.JWT_SECRET).trim().length < 32) {
  process.env.JWT_SECRET = 'test-jwt-secret-for-unit-tests-only!!';
}

test('JWT-03: bumpAuthVersion increments', async () => {
  let version = 1;
  const db = {
    async query(sql) {
      assert.match(String(sql), /auth_version = auth_version \+ 1/);
      version += 1;
      return { rows: [{ auth_version: version }] };
    }
  };
  const next = await bumpAuthVersion(db, 7);
  assert.equal(next, 2);
});

test('JWT-03: gate denies missing av claim and version mismatch', async () => {
  const pool = {
    async query() {
      return { rows: [{ auth_version: 2, status: 'active' }] };
    }
  };
  const gate = createAuthVersionGate(pool, {
    getTokenAuthVersion: (req) => req._av
  });

  async function run(req) {
    return new Promise((resolve) => {
      let status = null;
      gate(req, {
        status(c) {
          status = c;
          return { json() { resolve({ status, next: false }); } };
        }
      }, () => resolve({ status, next: true }));
    });
  }

  const missing = await run({
    path: '/api/ioc/list',
    method: 'GET',
    authVia: 'cookie',
    user: { id: 1, role: ROLES.ADMIN },
    _av: null
  });
  assert.equal(missing.status, 401);

  const mismatch = await run({
    path: '/api/ioc/list',
    method: 'GET',
    authVia: 'cookie',
    user: { id: 1, role: ROLES.ADMIN },
    _av: 1
  });
  assert.equal(mismatch.status, 401);

  const ok = await run({
    path: '/api/ioc/list',
    method: 'GET',
    authVia: 'cookie',
    user: { id: 1, role: ROLES.ADMIN },
    _av: 2
  });
  assert.equal(ok.next, true);
});

test('JWT-03: signed token contains av claim', () => {
  const token = signUserToken({
    userId: 9,
    email: 'b@x',
    role: ROLES.READONLY,
    authVersion: 4
  });
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  assert.equal(payload.av, 4);
  assert.equal(payload.userId, 9);
});

test('JWT-03: signUserToken refuses userId without authVersion', () => {
  assert.throws(
    () => signUserToken({ userId: 1, email: 'x@y', role: ROLES.ADMIN }),
    /authVersion/i
  );
});

test('JWT-03: gate skips logout and ingest', async () => {
  const gate = createAuthVersionGate({
    async query() {
      throw new Error('should not query');
    }
  });
  for (const req of [
    { path: '/api/auth/logout', method: 'POST', user: { id: 1 }, authVia: 'cookie' },
    { path: '/api/ioc/ip', method: 'POST', user: { id: null }, authVia: 'ingest' }
  ]) {
    const out = await new Promise((resolve) => {
      gate(req, { status() { return { json() { resolve({ next: false }); } }; } }, () => resolve({ next: true }));
    });
    assert.equal(out.next, true);
  }
});
