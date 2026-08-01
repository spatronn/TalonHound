import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CHANGE_PASSWORD_PATH,
  postLoginDestination,
  shouldForceChangePassword
} from './passwordChangeGate.js';

test('postLoginDestination sends mustChangePassword users to change-password', () => {
  assert.equal(postLoginDestination({ mustChangePassword: true }), CHANGE_PASSWORD_PATH);
  assert.equal(postLoginDestination({ mustChangePassword: false }), '/ioc');
  assert.equal(postLoginDestination(null), '/ioc');
});

test('shouldForceChangePassword blocks app routes until password changed', () => {
  assert.equal(shouldForceChangePassword(true, '/ioc'), true);
  assert.equal(shouldForceChangePassword(true, '/administration/users'), true);
  assert.equal(shouldForceChangePassword(true, CHANGE_PASSWORD_PATH), false);
  assert.equal(shouldForceChangePassword(true, '/login'), false);
  assert.equal(shouldForceChangePassword(false, '/ioc'), false);
});
