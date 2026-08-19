import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateIocStatusOverrideRequest,
  isExplicitIocLifecycleOverride,
  isManualSourceLifecycleBookkeeping
} from './iocStatusOverrideGuards.js';

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

describe('isExplicitIocLifecycleOverride — manual source != manual override', () => {
  // Case A/B: a manually-added source (createManualIoc) carries manual_status_override for its
  // own expiry bookkeeping but is NOT an explicit lifecycle override.
  it('treats a never-expire manual source as bookkeeping, not an override', () => {
    const row = { manual_status_override: true, manual_status: 'active', manual_override_reason: 'manual_never_expire' };
    assert.equal(isManualSourceLifecycleBookkeeping(row), true);
    assert.equal(isExplicitIocLifecycleOverride(row), false);
  });

  it('treats a fixed-expiry manual source as bookkeeping, not an override', () => {
    const row = { manual_status_override: true, manual_status: 'active', manual_override_reason: 'manual_custom_expire' };
    assert.equal(isExplicitIocLifecycleOverride(row), false);
  });

  // Case C: genuine explicit overrides.
  it('treats an explicit expire (Expire IOC now) as an override', () => {
    const row = { manual_status_override: true, manual_status: 'expired', manual_override_reason: 'confirmed false positive' };
    assert.equal(isManualSourceLifecycleBookkeeping(row), false);
    assert.equal(isExplicitIocLifecycleOverride(row), true);
  });

  it('treats an explicit reactivate/custom-expiry with a free-text reason as an override', () => {
    const row = { manual_status_override: true, manual_status: 'active', manual_override_reason: 'reactivated per IR-4821' };
    assert.equal(isExplicitIocLifecycleOverride(row), true);
  });

  // Case D: no override flag at all.
  it('reports no override when the flag is not set', () => {
    assert.equal(isExplicitIocLifecycleOverride({ manual_status_override: false, manual_status: 'active' }), false);
    assert.equal(isExplicitIocLifecycleOverride(null), false);
  });

  it('does not misclassify a feed sentinel reason without the override flag', () => {
    const row = { manual_status_override: false, manual_status: 'active', manual_override_reason: 'manual_never_expire' };
    assert.equal(isExplicitIocLifecycleOverride(row), false);
  });
});
