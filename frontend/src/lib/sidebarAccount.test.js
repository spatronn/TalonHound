import test from 'node:test';
import assert from 'node:assert/strict';
import { formatSidebarRoleLabel, userInitialsFromEmail } from './sidebarAccount.js';

test('user initials from email', () => {
  assert.equal(userInitialsFromEmail('safa@safa.com'), 'SA');
  assert.equal(userInitialsFromEmail('jane.doe@example.com'), 'JD');
  assert.equal(userInitialsFromEmail(''), '?');
});

test('sidebar role labels', () => {
  assert.equal(formatSidebarRoleLabel('admin'), 'Administrator');
  assert.equal(formatSidebarRoleLabel('readonly'), 'Read-only');
  assert.equal(formatSidebarRoleLabel('analyst'), 'Analyst');
});
