import test from 'node:test';
import assert from 'node:assert/strict';
import { rbacHttpPolicy, ROLES } from './rbac.js';
import {
  ingestCapabilityPolicy,
  isHumanAdmin,
  isIngestAuth,
  INGEST_ALLOWED_ROUTES
} from './ingestPrincipal.js';

function runPolicy(mw, req) {
  return new Promise((resolve) => {
    let status = null;
    let body = null;
    let next = false;
    const res = {
      status(c) {
        status = c;
        return {
          json(b) {
            body = b;
            resolve({ status, body, next });
          }
        };
      }
    };
    mw(req, res, () => {
      next = true;
      resolve({ status, body, next });
    });
  });
}

test('AUTH-03: readonly Bearer write is denied (parity with cookie)', async () => {
  const req = {
    path: '/api/ioc/ip',
    method: 'POST',
    authVia: 'bearer',
    user: { role: ROLES.READONLY, email: 'ro@x' }
  };
  const out = await runPolicy(rbacHttpPolicy, req);
  assert.equal(out.next, false);
  assert.equal(out.status, 403);
});

test('AUTH-03: readonly Bearer GET is allowed', async () => {
  const req = {
    path: '/api/ioc/list',
    method: 'GET',
    authVia: 'bearer',
    user: { role: ROLES.READONLY, email: 'ro@x' }
  };
  const out = await runPolicy(rbacHttpPolicy, req);
  assert.equal(out.next, true);
});

test('AUTH-03: readonly cookie write remains denied', async () => {
  const req = {
    path: '/api/ioc/ip',
    method: 'POST',
    authVia: 'cookie',
    user: { role: ROLES.READONLY, email: 'ro@x' }
  };
  const out = await runPolicy(rbacHttpPolicy, req);
  assert.equal(out.status, 403);
});

test('AUTH-03: analyst Bearer write allowed like cookie', async () => {
  for (const authVia of ['cookie', 'bearer']) {
    const out = await runPolicy(rbacHttpPolicy, {
      path: '/api/ioc/ip',
      method: 'POST',
      authVia,
      user: { role: ROLES.ANALYST, email: 'a@x' }
    });
    assert.equal(out.next, true, authVia);
  }
});

test('AUTH-04: isHumanAdmin rejects ingest even with synthetic admin role', () => {
  const req = {
    authVia: 'ingest',
    user: { role: ROLES.ADMIN, email: 'api-ingest@internal', principalType: 'machine_ingest' }
  };
  assert.equal(isIngestAuth(req), true);
  assert.equal(isHumanAdmin(req), false);
});

test('AUTH-04: isHumanAdmin allows cookie admin', () => {
  assert.equal(
    isHumanAdmin({ authVia: 'cookie', user: { role: ROLES.ADMIN, email: 'admin@talonhound.local' } }),
    true
  );
});

test('AUTH-04: ingest allowed only for POST /api/ioc/ip', async () => {
  assert.deepEqual(INGEST_ALLOWED_ROUTES, [{ method: 'POST', path: '/api/ioc/ip' }]);

  const ok = await runPolicy(ingestCapabilityPolicy, {
    path: '/api/ioc/ip',
    method: 'POST',
    authVia: 'ingest',
    user: { role: ROLES.ADMIN, principalType: 'machine_ingest' }
  });
  assert.equal(ok.next, true);

  for (const path of [
    '/api/admin/users',
    '/api/ioc/abc',
    '/api/admin/enrichment-providers/virustotal',
    '/api/setup/complete'
  ]) {
    const denied = await runPolicy(ingestCapabilityPolicy, {
      path,
      method: 'DELETE',
      authVia: 'ingest',
      user: { role: ROLES.ADMIN, principalType: 'machine_ingest' }
    });
    assert.equal(denied.status, 403, path);
  }
});

test('AUTH-04: non-ingest requests pass ingestCapabilityPolicy', async () => {
  const out = await runPolicy(ingestCapabilityPolicy, {
    path: '/api/admin/users',
    method: 'GET',
    authVia: 'cookie',
    user: { role: ROLES.ADMIN }
  });
  assert.equal(out.next, true);
});
