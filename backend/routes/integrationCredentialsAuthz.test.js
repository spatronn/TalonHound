import test from 'node:test';
import assert from 'node:assert/strict';
import { requireRole, ROLES } from '../lib/rbac.js';

/**
 * AUTH-06: vendor integration credential mutations must be admin-only.
 * Mirrors requireRole(ROLES.ADMIN) wired on PUT/POST credentials routes in server.js.
 */
test('AUTH-06: requireRole(ADMIN) rejects analyst on credential mutation', () => {
  const handler = requireRole(ROLES.ADMIN);
  for (const role of ['analyst', 'readonly']) {
    const req = { user: { role }, authVia: 'cookie' };
    let status = null;
    handler(req, { status(c) { status = c; return { json() {} }; } }, () => {});
    assert.equal(status, 403, `${role} must be forbidden for credential writes`);
  }
});

test('AUTH-06: requireRole(ADMIN) allows admin credential mutation', () => {
  const handler = requireRole(ROLES.ADMIN);
  const req = { user: { role: 'admin' }, authVia: 'cookie' };
  let next = false;
  handler(req, { status() { return { json() {} }; } }, () => { next = true; });
  assert.equal(next, true);
});
