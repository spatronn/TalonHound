import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CHANGE_PASSWORD_ENDPOINT,
  validateChangePasswordInput,
  changePasswordErrorMessage,
  submitChangePassword
} from './changePasswordForm.js';

function fakeApi(impl) {
  const calls = [];
  return {
    calls,
    async post(url, body) {
      calls.push({ url, body });
      return impl ? impl(url, body) : { data: {} };
    }
  };
}

const VALID = { currentPassword: 'old-secret', newPassword: 'new-secret-1', confirmPassword: 'new-secret-1' };

test('validation flags missing fields', () => {
  assert.match(validateChangePasswordInput({ currentPassword: '', newPassword: 'x', confirmPassword: 'x' }), /Fill in all/);
});

test('validation flags a confirmation mismatch', () => {
  assert.match(validateChangePasswordInput({ currentPassword: 'a', newPassword: 'b', confirmPassword: 'c' }), /do not match/);
});

test('validation flags reusing the current password', () => {
  assert.match(validateChangePasswordInput({ currentPassword: 'same', newPassword: 'same', confirmPassword: 'same' }), /different/);
});

test('validation passes for a well-formed input', () => {
  assert.equal(validateChangePasswordInput(VALID), '');
});

test('successful submit calls the change-password endpoint with only current/new password', async () => {
  const api = fakeApi(() => ({ data: { user: {} } }));
  const result = await submitChangePassword(api, VALID);
  assert.deepEqual(result, { ok: true, error: '' });
  assert.equal(api.calls.length, 1);
  assert.equal(api.calls[0].url, CHANGE_PASSWORD_ENDPOINT);
  // Body must not carry the confirmation, nor any target user id/email.
  assert.deepEqual(api.calls[0].body, { currentPassword: 'old-secret', newPassword: 'new-secret-1' });
});

test('submit never sends a target user id/email even if extra fields are present', async () => {
  const api = fakeApi(() => ({ data: {} }));
  await submitChangePassword(api, { ...VALID, id: 99, userId: 99, email: 'victim@user', username: 'victim' });
  assert.deepEqual(Object.keys(api.calls[0].body).sort(), ['currentPassword', 'newPassword']);
});

test('failed validation short-circuits before any API call', async () => {
  const api = fakeApi();
  const result = await submitChangePassword(api, { currentPassword: 'a', newPassword: 'b', confirmPassword: 'c' });
  assert.equal(result.ok, false);
  assert.match(result.error, /do not match/);
  assert.equal(api.calls.length, 0);
});

test('wrong current password surfaces the safe backend message and reports not-ok', async () => {
  const api = fakeApi(() => {
    const err = new Error('Request failed');
    err.response = { status: 401, data: { message: 'Current password is incorrect' } };
    throw err;
  });
  const result = await submitChangePassword(api, VALID);
  assert.equal(result.ok, false);
  assert.equal(result.error, 'Current password is incorrect');
});

test('a 500 with a raw detail never leaks the detail into the error message', async () => {
  const api = fakeApi(() => {
    const err = new Error('Request failed');
    err.response = { status: 500, data: { message: 'Failed to change password', detail: 'pg: relation "users" ... stack' } };
    throw err;
  });
  const result = await submitChangePassword(api, VALID);
  assert.equal(result.ok, false);
  assert.equal(result.error, 'Failed to change password');
  assert.ok(!/pg:|stack|relation/.test(result.error), 'raw detail must not appear');
});

test('an error without a message falls back to a generic safe message', () => {
  assert.equal(changePasswordErrorMessage(new Error('boom')), 'Failed to change password');
  assert.equal(changePasswordErrorMessage({}), 'Failed to change password');
});
