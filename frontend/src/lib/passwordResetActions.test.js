import test from 'node:test';
import assert from 'node:assert/strict';
import { canResetUserPassword, canChangeOwnPassword, resolveRowPasswordAction, clearTemporaryPasswordState } from './passwordResetActions.js';

test('admin can reset another active user', () => {
  assert.equal(canResetUserPassword({ isAdmin: true, isOwnRow: false, status: 'active' }), true);
});

test('non-admin never sees the action', () => {
  assert.equal(canResetUserPassword({ isAdmin: false, isOwnRow: false, status: 'active' }), false);
});

test('own row is excluded', () => {
  assert.equal(canResetUserPassword({ isAdmin: true, isOwnRow: true, status: 'active' }), false);
});

test('deactivated (passive) user is excluded', () => {
  assert.equal(canResetUserPassword({ isAdmin: true, isOwnRow: false, status: 'passive' }), false);
});

test('missing status defaults to active/allowed for an admin on another row', () => {
  assert.equal(canResetUserPassword({ isAdmin: true, isOwnRow: false }), true);
});

test('change-password is offered on the signed-in user own active row', () => {
  assert.equal(canChangeOwnPassword({ isOwnRow: true, status: 'active' }), true);
});

test('change-password is not offered on another user row', () => {
  assert.equal(canChangeOwnPassword({ isOwnRow: false, status: 'active' }), false);
});

test('change-password defaults to allowed on own row when status is missing', () => {
  assert.equal(canChangeOwnPassword({ isOwnRow: true }), true);
});

test('change-password is hidden on a deactivated own row', () => {
  assert.equal(canChangeOwnPassword({ isOwnRow: true, status: 'passive' }), false);
});

test('reset and change-password are mutually exclusive on the own row', () => {
  const ctx = { isAdmin: true, isOwnRow: true, status: 'active' };
  assert.equal(canResetUserPassword(ctx), false);
  assert.equal(canChangeOwnPassword(ctx), true);
});

test('reset and change-password are mutually exclusive on another row', () => {
  const ctx = { isAdmin: true, isOwnRow: false, status: 'active' };
  assert.equal(canResetUserPassword(ctx), true);
  assert.equal(canChangeOwnPassword(ctx), false);
});

// resolveRowPasswordAction drives which single button a Users-table row renders.
test('own active row resolves to the Change Password action', () => {
  assert.equal(resolveRowPasswordAction({ isAdmin: true, isOwnRow: true, status: 'active' }), 'change');
});

test('another active row resolves to the Reset Password action for an admin', () => {
  assert.equal(resolveRowPasswordAction({ isAdmin: true, isOwnRow: false, status: 'active' }), 'reset');
});

test('another row resolves to no action for a non-admin', () => {
  assert.equal(resolveRowPasswordAction({ isAdmin: false, isOwnRow: false, status: 'active' }), null);
});

test('deactivated own row resolves to no action', () => {
  assert.equal(resolveRowPasswordAction({ isAdmin: true, isOwnRow: true, status: 'passive' }), null);
});

test('resolver never returns both actions for the same row', () => {
  for (const isOwnRow of [true, false]) {
    for (const status of ['active', 'passive']) {
      const action = resolveRowPasswordAction({ isAdmin: true, isOwnRow, status });
      assert.ok(action === 'change' || action === 'reset' || action === null);
    }
  }
});

test('clearing yields empty, closed secret state', () => {
  assert.deepEqual(clearTemporaryPasswordState(), { open: false, username: '', password: '' });
});
