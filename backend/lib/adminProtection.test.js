import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateProtectedMutation,
  SYSTEM_ADMIN_PROTECTED_MESSAGE,
  LAST_ACTIVE_ADMIN_MESSAGE
} from './adminProtection.js';

const sysAdmin = { isSystemAdmin: true, currentRole: 'admin', currentStatus: 'active' };

test('system admin cannot be deleted', () => {
  const r = evaluateProtectedMutation({ ...sysAdmin, operation: 'delete', otherActiveAdminCount: 5 });
  assert.equal(r.ok, false);
  assert.equal(r.status, 403);
  assert.equal(r.message, SYSTEM_ADMIN_PROTECTED_MESSAGE);
});

test('system admin cannot be deactivated', () => {
  const r = evaluateProtectedMutation({ ...sysAdmin, operation: 'deactivate', otherActiveAdminCount: 5 });
  assert.equal(r.ok, false);
  assert.equal(r.status, 403);
});

test('system admin cannot be demoted', () => {
  const r = evaluateProtectedMutation({ ...sysAdmin, operation: 'demote', otherActiveAdminCount: 5 });
  assert.equal(r.ok, false);
  assert.equal(r.status, 403);
});

test('system admin cannot be renamed', () => {
  const r = evaluateProtectedMutation({ ...sysAdmin, operation: 'rename' });
  assert.equal(r.ok, false);
  assert.equal(r.status, 403);
  assert.equal(r.message, SYSTEM_ADMIN_PROTECTED_MESSAGE);
});

test('last active admin cannot be deleted', () => {
  const r = evaluateProtectedMutation({ operation: 'delete', currentRole: 'admin', currentStatus: 'active', otherActiveAdminCount: 0 });
  assert.equal(r.ok, false);
  assert.equal(r.status, 409);
  assert.equal(r.message, LAST_ACTIVE_ADMIN_MESSAGE);
});

test('last active admin cannot be deactivated', () => {
  const r = evaluateProtectedMutation({ operation: 'deactivate', currentRole: 'admin', currentStatus: 'active', otherActiveAdminCount: 0 });
  assert.equal(r.ok, false);
  assert.equal(r.status, 409);
});

test('last active admin cannot be demoted', () => {
  const r = evaluateProtectedMutation({ operation: 'demote', currentRole: 'admin', currentStatus: 'active', otherActiveAdminCount: 0 });
  assert.equal(r.ok, false);
  assert.equal(r.status, 409);
});

test('a non-last admin can be deleted/deactivated/demoted', () => {
  for (const operation of ['delete', 'deactivate', 'demote']) {
    const r = evaluateProtectedMutation({ operation, currentRole: 'admin', currentStatus: 'active', otherActiveAdminCount: 1 });
    assert.equal(r.ok, true, `${operation} should be allowed with another active admin`);
  }
});

test('a non-admin user is unaffected by the admin invariant', () => {
  const r = evaluateProtectedMutation({ operation: 'delete', currentRole: 'readonly', currentStatus: 'active', otherActiveAdminCount: 0 });
  assert.equal(r.ok, true);
});

test('a passive admin (already inactive) does not count against the invariant', () => {
  // Deleting an already-passive admin cannot reduce the active-admin count.
  const r = evaluateProtectedMutation({ operation: 'delete', currentRole: 'admin', currentStatus: 'passive', otherActiveAdminCount: 0 });
  assert.equal(r.ok, true);
});

test('renaming a normal user is always allowed', () => {
  const r = evaluateProtectedMutation({ operation: 'rename', isSystemAdmin: false });
  assert.equal(r.ok, true);
});
