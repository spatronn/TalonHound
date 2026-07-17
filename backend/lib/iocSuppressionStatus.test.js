import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeSuppressionEffectiveStatus,
  isSuppressionEffectivelyActive,
  normalizeSuppressionStatusFilter,
  SUPPRESSION_STATUS
} from './iocSuppressionStatus.js';

const NOW = new Date('2026-07-17T12:00:00.000Z');

test('effective status: active when enabled and never expires', () => {
  assert.equal(
    computeSuppressionEffectiveStatus({ active: true, expires_at: null, deleted_at: null }, NOW),
    SUPPRESSION_STATUS.ACTIVE
  );
  assert.equal(isSuppressionEffectivelyActive({ active: true, expires_at: null }, NOW), true);
});

test('effective status: disabled wins over expiration', () => {
  assert.equal(
    computeSuppressionEffectiveStatus({
      active: false,
      expires_at: '2026-07-01T00:00:00.000Z',
      deleted_at: null
    }, NOW),
    SUPPRESSION_STATUS.DISABLED
  );
  assert.equal(isSuppressionEffectivelyActive({ active: false, expires_at: null }, NOW), false);
});

test('effective status: expired when enabled and past expires_at', () => {
  assert.equal(
    computeSuppressionEffectiveStatus({
      active: true,
      expires_at: '2026-07-01T00:00:00.000Z',
      deleted_at: null
    }, NOW),
    SUPPRESSION_STATUS.EXPIRED
  );
  assert.equal(
    isSuppressionEffectivelyActive({ active: true, expires_at: '2026-07-01T00:00:00.000Z' }, NOW),
    false
  );
});

test('effective status: deleted overrides everything', () => {
  assert.equal(
    computeSuppressionEffectiveStatus({
      active: true,
      expires_at: null,
      deleted_at: '2026-07-17T11:00:00.000Z'
    }, NOW),
    SUPPRESSION_STATUS.DELETED
  );
});

test('effective status: future expiration stays active', () => {
  assert.equal(
    computeSuppressionEffectiveStatus({
      active: true,
      expires_at: '2026-08-01T00:00:00.000Z',
      deleted_at: null
    }, NOW),
    SUPPRESSION_STATUS.ACTIVE
  );
});

test('normalizeSuppressionStatusFilter maps inactive to disabled', () => {
  assert.equal(normalizeSuppressionStatusFilter('inactive'), 'disabled');
  assert.equal(normalizeSuppressionStatusFilter('Disabled'), 'disabled');
  assert.equal(normalizeSuppressionStatusFilter('active'), 'active');
  assert.equal(normalizeSuppressionStatusFilter(''), 'all');
});

test('enabled + past expiration is expired not active', () => {
  assert.equal(
    computeSuppressionEffectiveStatus({
      active: true,
      expires_at: '2020-01-01T00:00:00.000Z',
      deleted_at: null
    }, NOW),
    SUPPRESSION_STATUS.EXPIRED
  );
});

test('never expiration + enabled is active', () => {
  assert.equal(
    isSuppressionEffectivelyActive({ active: true, expires_at: null, deleted_at: null }, NOW),
    true
  );
});
