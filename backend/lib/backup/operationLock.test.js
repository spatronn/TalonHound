import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  canStartBackup,
  assertCanStartBackup,
  canTransition,
  assertTransition,
  advisoryLockKey
} from './operationLock.js';

describe('backup operationLock', () => {
  it('enforces concurrent lock', () => {
    assert.equal(canStartBackup(0, 1), true);
    assert.equal(canStartBackup(1, 1), false);
    assert.throws(() => assertCanStartBackup(1, 1), (err) => err.code === 'CONCURRENT');
  });

  it('validates status transitions', () => {
    assert.equal(canTransition('queued', 'running'), true);
    assert.equal(canTransition('running', 'verifying'), true);
    assert.equal(canTransition('verifying', 'completed'), true);
    assert.equal(canTransition('completed', 'running'), false);
    assert.throws(() => assertTransition('completed', 'running'));
  });

  it('produces stable advisory key', () => {
    assert.equal(advisoryLockKey('x'), advisoryLockKey('x'));
    assert.notEqual(advisoryLockKey('x'), advisoryLockKey('y'));
  });
});
