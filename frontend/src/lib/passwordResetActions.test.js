import test from 'node:test';
import assert from 'node:assert/strict';
import { canResetUserPassword, clearTemporaryPasswordState } from './passwordResetActions.js';

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

test('clearing yields empty, closed secret state', () => {
  assert.deepEqual(clearTemporaryPasswordState(), { open: false, username: '', password: '' });
});
