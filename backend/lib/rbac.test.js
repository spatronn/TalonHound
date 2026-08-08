import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ROLES,
  BULK_TRIAGE_MAX_ITEMS,
  canTriage,
  effectiveRoleFromPayload,
  isAdminRole,
  isReadOnlyRole,
  normalizeAppRole,
  rbacHttpPolicy,
  requireRole
} from './rbac.js';

function runPolicy({ method = 'GET', path = '/api/ioc/recent-manual', role, authVia } = {}) {
  const req = { method, path, user: role ? { role } : undefined, authVia };
  let statusCode = null;
  let nextCalled = false;
  const res = {
    status(code) { statusCode = code; return this; },
    json() { return this; }
  };
  rbacHttpPolicy(req, res, () => { nextCalled = true; });
  return { statusCode, nextCalled };
}

function runRequireRole(allowed, { role, authVia } = {}) {
  const handler = requireRole(...allowed);
  const req = { user: role != null ? { role } : {}, authVia };
  let statusCode = null;
  let nextCalled = false;
  const res = {
    status(code) { statusCode = code; return this; },
    json() { return this; }
  };
  handler(req, res, () => { nextCalled = true; });
  return { statusCode, nextCalled };
}

test('normalizeAppRole accepts analyst', () => {
  assert.equal(normalizeAppRole('analyst'), ROLES.ANALYST);
  assert.equal(normalizeAppRole('Analyst'), ROLES.ANALYST);
});

test('canTriage allows admin and analyst only', () => {
  assert.equal(canTriage(ROLES.ADMIN), true);
  assert.equal(canTriage(ROLES.ANALYST), true);
  assert.equal(canTriage(ROLES.READONLY), false);
  assert.equal(canTriage(null), false);
});

test('isAdminRole and isReadOnlyRole', () => {
  assert.equal(isAdminRole(ROLES.ADMIN), true);
  assert.equal(isAdminRole(ROLES.ANALYST), false);
  assert.equal(isReadOnlyRole(ROLES.READONLY), true);
  assert.equal(isReadOnlyRole(ROLES.ANALYST), false);
});

test('bulk triage max limit is defined', () => {
  assert.equal(BULK_TRIAGE_MAX_ITEMS, 100);
});

// GET /api/ioc/recent-manual authorization: consistent with who can view the
// Add IOC page (all authenticated roles; read-only sees it read-only) and with
// the documented rbacHttpPolicy that intentionally grants read-only users GET
// access. Same posture as the /api/ioc/recent endpoint it replaces.
test('rbacHttpPolicy allows every signed-in role to GET recent-manual', () => {
  for (const role of [ROLES.ADMIN, ROLES.ANALYST, ROLES.READONLY]) {
    const { nextCalled, statusCode } = runPolicy({ role });
    assert.equal(nextCalled, true, `${role} should be allowed to GET`);
    assert.equal(statusCode, null, `${role} should not be blocked`);
  }
});

test('rbacHttpPolicy still blocks read-only writes on the recent-manual path', () => {
  const { nextCalled, statusCode } = runPolicy({ method: 'POST', role: ROLES.READONLY });
  assert.equal(nextCalled, false);
  assert.equal(statusCode, 403);
});

test('JWT-01: effectiveRoleFromPayload never maps missing/invalid role to admin', () => {
  assert.equal(effectiveRoleFromPayload(undefined), null);
  assert.equal(effectiveRoleFromPayload(null), null);
  assert.equal(effectiveRoleFromPayload(''), null);
  assert.equal(effectiveRoleFromPayload('   '), null);
  assert.equal(effectiveRoleFromPayload('superuser'), null);
  assert.equal(effectiveRoleFromPayload(42), null);
  assert.equal(effectiveRoleFromPayload({ role: 'admin' }), null);
  assert.equal(effectiveRoleFromPayload(ROLES.ADMIN), ROLES.ADMIN);
  assert.equal(effectiveRoleFromPayload(ROLES.READONLY), ROLES.READONLY);
  assert.equal(effectiveRoleFromPayload(ROLES.ANALYST), ROLES.ANALYST);
});

test('JWT-01: rbacHttpPolicy denies requests without a valid role (no admin default)', () => {
  const missing = runPolicy({ role: undefined });
  assert.equal(missing.nextCalled, false);
  assert.equal(missing.statusCode, 403);

  const req = { method: 'GET', path: '/api/ioc/list', user: { role: '' } };
  let statusCode = null;
  let nextCalled = false;
  rbacHttpPolicy(req, { status(c) { statusCode = c; return this; }, json() { return this; } }, () => { nextCalled = true; });
  assert.equal(nextCalled, false);
  assert.equal(statusCode, 403);
});

test('JWT-01: requireRole denies missing/unknown role instead of elevating to admin', () => {
  const missing = runRequireRole([ROLES.ADMIN], { role: undefined });
  assert.equal(missing.nextCalled, false);
  assert.equal(missing.statusCode, 403);

  const unknown = runRequireRole([ROLES.ADMIN], { role: 'root' });
  assert.equal(unknown.nextCalled, false);
  assert.equal(unknown.statusCode, 403);

  const adminOk = runRequireRole([ROLES.ADMIN], { role: ROLES.ADMIN });
  assert.equal(adminOk.nextCalled, true);
  assert.equal(adminOk.statusCode, null);
});
