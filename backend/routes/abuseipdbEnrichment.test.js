import test from 'node:test';
import assert from 'node:assert/strict';
import { requireRole, ROLES, rbacHttpPolicy } from '../lib/rbac.js';

test('requireRole rejects analyst for admin-only handler', () => {
  const handler = requireRole(ROLES.ADMIN);
  const req = { user: { role: 'analyst' }, authVia: 'session' };
  let blocked = false;
  handler(req, { status: () => ({ json: () => { blocked = true; } }) }, () => {});
  assert.equal(blocked, true);
});

test('readonly role policy blocks POST refresh at HTTP layer', () => {
  const req = {
    path: '/api/enrichment/abuseipdb/ip/8.8.8.8/refresh',
    method: 'POST',
    authVia: 'session',
    user: { role: 'readonly' }
  };
  let statusCode = null;
  const res = {
    status(code) { statusCode = code; return this; },
    json() { return this; }
  };
  let nextCalled = false;
  rbacHttpPolicy(req, res, () => { nextCalled = true; });
  assert.equal(statusCode, 403);
  assert.equal(nextCalled, false);
});
