import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateIocStatusOverrideRequest } from './iocStatusOverrideGuards.js';

const activeRow = { status: 'active', manual_status_override: false };
const expiredRow = { status: 'expired', manual_status_override: false };
const activeWithOverride = { status: 'active', manual_status_override: true, manual_status: 'active' };

describe('evaluateIocStatusOverrideRequest', () => {
  it('noops reactivate when IOC is already active', () => {
    const r = evaluateIocStatusOverrideRequest(activeRow, {
      manual_status_override: true,
      manual_status: 'active',
      manual_expires_at: null,
      reason: 'test'
    });
    assert.equal(r.noop, true);
    assert.match(r.message, /already active/i);
  });

  it('allows reactivate when IOC is expired', () => {
    const r = evaluateIocStatusOverrideRequest(expiredRow, {
      manual_status_override: true,
      manual_status: 'active',
      manual_expires_at: null,
      reason: 'test'
    });
    assert.equal(r.noop, false);
  });

  it('noops expire when IOC is already expired', () => {
    const r = evaluateIocStatusOverrideRequest(expiredRow, {
      manual_status_override: true,
      manual_status: 'expired',
      reason: 'test'
    });
    assert.equal(r.noop, true);
    assert.match(r.message, /already expired/i);
  });

  it('allows expire when IOC is active', () => {
    const r = evaluateIocStatusOverrideRequest(activeRow, {
      manual_status_override: true,
      manual_status: 'expired',
      reason: 'test'
    });
    assert.equal(r.noop, false);
  });

  it('allows custom expire date on active IOC', () => {
    const r = evaluateIocStatusOverrideRequest(activeRow, {
      manual_status_override: true,
      manual_status: 'active',
      manual_expires_at: '2027-01-01T00:00:00.000Z',
      reason: 'test'
    });
    assert.equal(r.noop, false);
  });

  it('noops clear override when none set', () => {
    const r = evaluateIocStatusOverrideRequest(activeRow, { manual_status_override: false });
    assert.equal(r.noop, true);
  });

  it('allows clear override when override exists', () => {
    const r = evaluateIocStatusOverrideRequest(activeWithOverride, { manual_status_override: false });
    assert.equal(r.noop, false);
  });
});
