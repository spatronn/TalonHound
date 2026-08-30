import test from 'node:test';
import assert from 'node:assert/strict';
import {
  EMPTY_CREATE_USER_FORM,
  buildCreateUserPayload,
  createUserErrorFocusField,
  createUserErrorMessage,
  isCreateUserFormValid
} from './createUserForm.js';

test('empty form is invalid; default role is readonly', () => {
  assert.equal(isCreateUserFormValid(EMPTY_CREATE_USER_FORM), false);
  assert.equal(EMPTY_CREATE_USER_FORM.role, 'readonly');
});

test('whitespace-only username is invalid', () => {
  assert.equal(isCreateUserFormValid({ username: '  ', password: 'x' }), false);
});

test('username + password valid even without names', () => {
  assert.equal(isCreateUserFormValid({ username: 'alice', password: 'x' }), true);
});

test('buildCreateUserPayload trims fields and keeps default role', () => {
  assert.deepEqual(
    buildCreateUserPayload({
      first_name: '  Ada ',
      last_name: ' Lovelace ',
      username: ' ada ',
      password: 'secret',
      role: ''
    }),
    {
      first_name: 'Ada',
      last_name: 'Lovelace',
      username: 'ada',
      password: 'secret',
      role: 'readonly'
    }
  );
});

test('createUserErrorFocusField maps duplicate username to username field', () => {
  assert.equal(createUserErrorFocusField('This username is already in use. Please choose another one.'), 'username');
  assert.equal(createUserErrorFocusField('Username already exists'), 'username');
  assert.equal(createUserErrorFocusField('Username and password are required.'), 'username');
});

test('createUserErrorMessage special-cases 409', () => {
  assert.equal(
    createUserErrorMessage({ status: 409, message: 'Username already exists' }),
    'This username is already in use. Please choose another one.'
  );
  assert.equal(createUserErrorMessage({ message: 'boom' }), 'boom');
  assert.equal(createUserErrorMessage({}), 'Failed to create user');
});

test('submit stays disabled while invalid — mirrors Create User CTA gate', () => {
  const saving = false;
  const canSubmit = isCreateUserFormValid({ username: '', password: '' }) && !saving;
  assert.equal(canSubmit, false);
  assert.equal(isCreateUserFormValid({ username: 'u', password: 'p' }) && !saving, true);
  assert.equal(isCreateUserFormValid({ username: 'u', password: 'p' }) && !true, false);
});
