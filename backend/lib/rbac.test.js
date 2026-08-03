import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ROLES,
  BULK_TRIAGE_MAX_ITEMS,
  canTriage,
  isAdminRole,
  isReadOnlyRole,
  normalizeAppRole,
  rbacHttpPolicy
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
