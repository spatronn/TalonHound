import test from 'node:test';
import assert from 'node:assert/strict';
import {
  filterTimezones,
  ensureTimezoneInOptions,
  clearSupportedTimezonesCache
} from './timezones.js';

test('filterTimezones matches case-insensitive substrings', () => {
  const zones = ['UTC', 'Europe/Istanbul', 'America/New_York', 'Pacific/Auckland'];
  assert.deepEqual(filterTimezones(zones, 'istanbul'), ['Europe/Istanbul']);
  assert.deepEqual(filterTimezones(zones, 'Pacific'), ['Pacific/Auckland']);
  assert.deepEqual(filterTimezones(zones, ''), zones);
});

test('ensureTimezoneInOptions keeps configured timezone visible during load', () => {
  assert.deepEqual(
    ensureTimezoneInOptions(['UTC', 'Europe/London'], 'Europe/Istanbul'),
    ['Europe/Istanbul', 'UTC', 'Europe/London']
  );
  assert.deepEqual(
    ensureTimezoneInOptions(['UTC', 'Europe/Istanbul'], 'Europe/Istanbul'),
    ['UTC', 'Europe/Istanbul']
  );
});

test('clearSupportedTimezonesCache resets module cache', () => {
  clearSupportedTimezonesCache();
  assert.doesNotThrow(() => clearSupportedTimezonesCache());
});
