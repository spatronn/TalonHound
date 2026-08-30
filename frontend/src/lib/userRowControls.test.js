import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveUserRowControls, SYSTEM_ADMIN_PROTECTED_TITLE } from './userRowControls.js';

test('system admin row shows the protected badge', () => {
  assert.equal(resolveUserRowControls({ isSystemAdmin: true }).showProtectedBadge, true);
});

test('non-system row shows no protected badge', () => {
  assert.equal(resolveUserRowControls({ isSystemAdmin: false }).showProtectedBadge, false);
});

test('system admin Deactivate and Delete are disabled with a protected title', () => {
  const c = resolveUserRowControls({ isSystemAdmin: true });
  assert.equal(c.deactivateDisabled, true);
  assert.equal(c.deleteDisabled, true);
  assert.equal(c.deactivateTitle, SYSTEM_ADMIN_PROTECTED_TITLE);
  assert.equal(c.deleteTitle, SYSTEM_ADMIN_PROTECTED_TITLE);
});

test('a normal active user (not own row) has enabled Deactivate and Delete', () => {
  const c = resolveUserRowControls({ isSystemAdmin: false, isOwnRow: false, statusBusy: false });
  assert.equal(c.deactivateDisabled, false);
  assert.equal(c.deleteDisabled, false);
  assert.equal(c.deactivateTitle, 'Deactivate user');
  assert.equal(c.deleteTitle, 'Delete user');
});

test('own row keeps the existing self-deactivate disable (but Delete stays enabled)', () => {
  const c = resolveUserRowControls({ isSystemAdmin: false, isOwnRow: true });
  assert.equal(c.deactivateDisabled, true);
  assert.equal(c.deactivateTitle, 'You cannot deactivate your own account');
  assert.equal(c.deleteDisabled, false);
});

test('busy state disables Deactivate for a normal user', () => {
  assert.equal(resolveUserRowControls({ isSystemAdmin: false, statusBusy: true }).deactivateDisabled, true);
});

test('system admin protection overrides own-row title', () => {
  const c = resolveUserRowControls({ isSystemAdmin: true, isOwnRow: true });
  assert.equal(c.deactivateTitle, SYSTEM_ADMIN_PROTECTED_TITLE);
  assert.equal(c.deactivateDisabled, true);
});
