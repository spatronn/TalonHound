import test from 'node:test';
import assert from 'node:assert/strict';
import { canAccessOwnedArtifact, actorUserId } from './artifactOwnership.js';

const ADMIN = { role: 'admin', id: 1, email: 'admin@example.com' };
const OWNER = { role: 'analyst', id: 11, email: 'same@example.com' };
const RECYCLED = { role: 'analyst', id: 99, email: 'same@example.com' };

test('IDOR-01: owner with matching requested_by_id can access', () => {
  assert.equal(
    canAccessOwnedArtifact({ user: OWNER }, { requested_by_id: 11, requested_by_email: 'same@example.com' }),
    true
  );
});

test('IDOR-01: recycled email with different id cannot access id-backed row', () => {
  assert.equal(
    canAccessOwnedArtifact({ user: RECYCLED }, { requested_by_id: 11, requested_by_email: 'same@example.com' }),
    false
  );
});

test('IDOR-01: historical email-only row is not auto-assigned to same email', () => {
  assert.equal(
    canAccessOwnedArtifact({ user: OWNER }, { requested_by_id: null, requested_by_email: 'same@example.com' }),
    false
  );
  assert.equal(
    canAccessOwnedArtifact({ user: RECYCLED }, { requested_by_id: null, requested_by_email: 'same@example.com' }),
    false
  );
});

test('IDOR-01: admin can access any row including email-only historical', () => {
  assert.equal(
    canAccessOwnedArtifact({ user: ADMIN }, { requested_by_id: null, requested_by_email: 'same@example.com' }),
    true
  );
  assert.equal(
    canAccessOwnedArtifact({ user: ADMIN }, { requested_by_id: 11, requested_by_email: 'same@example.com' }),
    true
  );
});

test('actorUserId ignores non-positive ids', () => {
  assert.equal(actorUserId({ user: { id: 0 } }), null);
  assert.equal(actorUserId({ user: { id: 'x' } }), null);
  assert.equal(actorUserId({ user: { id: 7 } }), 7);
});
