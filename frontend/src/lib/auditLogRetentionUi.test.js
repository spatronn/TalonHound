import test from 'node:test';
import assert from 'node:assert/strict';
import {
  retentionSelectionFromDays,
  describeRetention,
  isRetentionReduction,
  validateCustomDays,
  resolveTargetDays,
  AUDIT_RETENTION_KEEP_FOREVER,
  AUDIT_RETENTION_CUSTOM,
  AUDIT_RETENTION_MAX_DAYS
} from './auditLogRetentionUi.js';

test('retentionSelectionFromDays maps presets, custom and keep forever', () => {
  assert.equal(retentionSelectionFromDays(null), AUDIT_RETENTION_KEEP_FOREVER);
  assert.equal(retentionSelectionFromDays(365), '365');
  assert.equal(retentionSelectionFromDays(90), '90');
  assert.equal(retentionSelectionFromDays(45), AUDIT_RETENTION_CUSTOM);
});

test('describeRetention renders readable labels', () => {
  assert.equal(describeRetention(null), 'Keep forever');
  assert.equal(describeRetention(1), '1 day');
  assert.equal(describeRetention(365), '365 days');
});

test('isRetentionReduction flags destructive changes only', () => {
  // 365 -> 90 destructive
  assert.equal(isRetentionReduction(365, 90), true);
  // 730 -> 365 destructive
  assert.equal(isRetentionReduction(730, 365), true);
  // Keep forever -> 365 destructive
  assert.equal(isRetentionReduction(null, 365), true);
  // 365 -> 730 increase
  assert.equal(isRetentionReduction(365, 730), false);
  // 90 -> 365 increase
  assert.equal(isRetentionReduction(90, 365), false);
  // finite -> Keep forever increase
  assert.equal(isRetentionReduction(365, null), false);
  // equal is not a reduction
  assert.equal(isRetentionReduction(365, 365), false);
});

test('validateCustomDays enforces positive integers within the cap', () => {
  assert.deepEqual(validateCustomDays('45'), { ok: true, days: 45 });
  assert.deepEqual(validateCustomDays(45), { ok: true, days: 45 });
  assert.equal(validateCustomDays('0').ok, false);
  assert.equal(validateCustomDays('-3').ok, false);
  assert.equal(validateCustomDays('30.5').ok, false);
  assert.equal(validateCustomDays(30.5).ok, false);
  assert.equal(validateCustomDays('abc').ok, false);
  assert.equal(validateCustomDays('').ok, false);
  assert.equal(validateCustomDays(String(AUDIT_RETENTION_MAX_DAYS + 1)).ok, false);
});

test('resolveTargetDays resolves selection tokens', () => {
  assert.deepEqual(resolveTargetDays(AUDIT_RETENTION_KEEP_FOREVER, ''), { ok: true, days: null });
  assert.deepEqual(resolveTargetDays('365', ''), { ok: true, days: 365 });
  assert.deepEqual(resolveTargetDays(AUDIT_RETENTION_CUSTOM, '45'), { ok: true, days: 45 });
  assert.equal(resolveTargetDays(AUDIT_RETENTION_CUSTOM, 'x').ok, false);
});
