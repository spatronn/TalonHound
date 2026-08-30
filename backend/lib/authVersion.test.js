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

// --- JWT-06: bounded-session enforcement in the gate --------------------------------

function runGate(gate, req) {
  return new Promise((resolve) => {
    let status = null;
    let body = null;
    gate(
      req,
      {
        status(c) {
          status = c;
          return { json(b) { body = b; resolve({ status, body, next: false }); } };
        }
      },
      () => resolve({ status, body, next: true })
    );
  });
}

const now = () => new Date('2026-08-23T12:00:00Z');
const future = new Date('2026-08-23T13:00:00Z').toISOString();
const past = new Date('2026-08-23T11:00:00Z').toISOString();

function sessionPool(sessionFields) {
  let calls = 0;
  const pool = {
    async query(sql) {
      calls += 1;
      // Gate must READ only — never UPDATE — so polling can't extend the idle clock.
      assert.doesNotMatch(String(sql), /UPDATE|INSERT|DELETE/i);
      return { rows: [{ auth_version: 2, status: 'active', ...sessionFields }] };
    }
  };
  return { pool, getCalls: () => calls };
}

const baseReq = { path: '/api/ioc/list', method: 'GET', authVia: 'cookie', user: { id: 1, role: ROLES.ADMIN } };

test('JWT-06: valid session passes the gate', async () => {
  const { pool } = sessionPool({ session_id: 's1', revoked_at: null, idle_expires_at: future, absolute_expires_at: future });
  const gate = createAuthVersionGate(pool, { getTokenAuthVersion: () => 2, getTokenSessionId: () => 's1', now });
  const out = await runGate(gate, { ...baseReq });
  assert.equal(out.next, true);
});

test('JWT-06: idle-expired session is rejected — and repeated polling never revives it', async () => {
  const { pool } = sessionPool({ session_id: 's1', revoked_at: null, idle_expires_at: past, absolute_expires_at: future });
  const gate = createAuthVersionGate(pool, { getTokenAuthVersion: () => 2, getTokenSessionId: () => 's1', now });
  // Simulate a burst of background polling requests against an idle session.
  for (let i = 0; i < 5; i += 1) {
    const out = await runGate(gate, { ...baseReq });
    assert.equal(out.status, 401);
    assert.equal(out.body.code, 'SESSION_EXPIRED_IDLE');
  }
});

test('JWT-06: absolute-expired session is rejected even if idle window is open', async () => {
  const { pool } = sessionPool({ session_id: 's1', revoked_at: null, idle_expires_at: future, absolute_expires_at: past });
  const gate = createAuthVersionGate(pool, { getTokenAuthVersion: () => 2, getTokenSessionId: () => 's1', now });
  const out = await runGate(gate, { ...baseReq });
  assert.equal(out.status, 401);
  assert.equal(out.body.code, 'SESSION_EXPIRED_ABSOLUTE');
});

test('JWT-06: revoked session (logout/password/disable) is rejected', async () => {
  const { pool } = sessionPool({ session_id: 's1', revoked_at: past, idle_expires_at: future, absolute_expires_at: future });
  const gate = createAuthVersionGate(pool, { getTokenAuthVersion: () => 2, getTokenSessionId: () => 's1', now });
  const out = await runGate(gate, { ...baseReq });
  assert.equal(out.status, 401);
});

test('JWT-06: cookie session without sid claim fails closed (legacy token → re-login)', async () => {
  const { pool } = sessionPool({ session_id: 's1', revoked_at: null, idle_expires_at: future, absolute_expires_at: future });
  const gate = createAuthVersionGate(pool, { getTokenAuthVersion: () => 2, getTokenSessionId: () => null, now });
  const out = await runGate(gate, { ...baseReq });
  assert.equal(out.status, 401);
});

test('JWT-06: unknown/missing session row is rejected', async () => {
  const { pool } = sessionPool({ session_id: null, revoked_at: null, idle_expires_at: null, absolute_expires_at: null });
  const gate = createAuthVersionGate(pool, { getTokenAuthVersion: () => 2, getTokenSessionId: () => 's-missing', now });
  const out = await runGate(gate, { ...baseReq });
  assert.equal(out.status, 401);
});

test('JWT-06: bearer principal (no sid) keeps av/status checks, skips session enforcement', async () => {
  const { pool } = sessionPool({ session_id: null, revoked_at: null, idle_expires_at: null, absolute_expires_at: null });
  const gate = createAuthVersionGate(pool, {
    getTokenAuthVersion: () => 2,
    getTokenSessionId: () => null,
    getTokenExp: () => Math.floor(now().getTime() / 1000) + 3600,
    now
  });
  const out = await runGate(gate, { ...baseReq, authVia: 'bearer' });
  assert.equal(out.next, true);
});

test('JWT-06: bearer rejects expired JWT exp claim', async () => {
  const { pool } = sessionPool({ session_id: null, revoked_at: null, idle_expires_at: null, absolute_expires_at: null });
  const gate = createAuthVersionGate(pool, {
    getTokenAuthVersion: () => 2,
    getTokenSessionId: () => null,
    getTokenExp: () => Math.floor(now().getTime() / 1000) - 10,
    now
  });
  const out = await runGate(gate, { ...baseReq, authVia: 'bearer' });
  assert.equal(out.status, 401);
  assert.equal(out.body.code, 'TOKEN_EXPIRED');
});

test('JWT-06: bearer rejects missing exp claim', async () => {
  const { pool } = sessionPool({ session_id: null, revoked_at: null, idle_expires_at: null, absolute_expires_at: null });
  const gate = createAuthVersionGate(pool, {
    getTokenAuthVersion: () => 2,
    getTokenSessionId: () => null,
    getTokenExp: () => null,
    now
  });
  const out = await runGate(gate, { ...baseReq, authVia: 'bearer' });
  assert.equal(out.status, 401);
});

test('JWT-06: bearer rejects passive/disabled user even with valid exp', async () => {
  const pool = {
    async query() {
      return { rows: [{ auth_version: 2, status: 'passive', session_id: null, revoked_at: null, idle_expires_at: null, absolute_expires_at: null }] };
    }
  };
  const gate = createAuthVersionGate(pool, {
    getTokenAuthVersion: () => 2,
    getTokenSessionId: () => null,
    getTokenExp: () => Math.floor(now().getTime() / 1000) + 3600,
    now
  });
  const out = await runGate(gate, { ...baseReq, authVia: 'bearer' });
  assert.equal(out.status, 401);
});

test('JWT-06: bearer without sid documents idle/session revoke does not apply (av+status+exp hold)', async () => {
  // No sid → session row checks skipped; revoked session fields are ignored.
  const { pool } = sessionPool({
    session_id: 'ignored',
    revoked_at: past,
    idle_expires_at: past,
    absolute_expires_at: past
  });
  const gate = createAuthVersionGate(pool, {
    getTokenAuthVersion: () => 2,
    getTokenSessionId: () => null,
    getTokenExp: () => Math.floor(now().getTime() / 1000) + 60,
    now
  });
  const out = await runGate(gate, { ...baseReq, authVia: 'bearer' });
  assert.equal(out.next, true);
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
