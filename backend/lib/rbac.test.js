import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ROLES,
  BULK_TRIAGE_MAX_ITEMS,
  canTriage,
  isAdminRole,
  isReadOnlyRole,
  normalizeAppRole
} from './rbac.js';

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
