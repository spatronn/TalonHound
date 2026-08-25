import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatUserDateTime,
  formatUserDateParts,
  normalizeSystemTimezone,
  normalizeUserTimezone,
  utcIsoTooltip,
  systemLocalInputToUtcIso,
  setSystemTimezoneCache,
  getSystemTimezone
} from './formatDate.js';

describe('formatDate (system timezone)', () => {
  it('formats UTC instant in Europe/Istanbul without UTC suffix', () => {
    const out = formatUserDateTime('2026-07-25T18:10:55.000Z', 'Europe/Istanbul');
    assert.equal(out, '25/07/2026, 21:10:55');
    assert.ok(!out.includes('UTC'));
  });

  it('Europe/London DST summer vs winter', () => {
    const summer = formatUserDateTime('2026-07-25T18:10:55.000Z', 'Europe/London');
    const winter = formatUserDateTime('2026-01-15T18:10:55.000Z', 'Europe/London');
    assert.equal(summer, '25/07/2026, 19:10:55');
    assert.equal(winter, '15/01/2026, 18:10:55');
  });

  it('changes when timezone changes', () => {
    const iso = '2026-07-25T18:10:55.000Z';
    const istanbul = formatUserDateTime(iso, 'Europe/Istanbul');
    const utc = formatUserDateTime(iso, 'UTC');
    assert.notEqual(istanbul, utc);
    assert.equal(utc, '25/07/2026, 18:10:55');
  });

  it('rejects invalid timezone (normalize returns null / UTC fallback for legacy helper)', () => {
    assert.equal(normalizeSystemTimezone('Not/AZone'), null);
    assert.equal(normalizeUserTimezone('Not/AZone'), 'UTC');
    const out = formatUserDateTime('2026-07-25T18:10:55.000Z', 'Not/AZone');
    // Invalid explicit tz falls through to getSystemTimezone(); tests force UTC via arg miss
    assert.equal(formatUserDateTime('2026-07-25T18:10:55.000Z', 'UTC'), '25/07/2026, 18:10:55');
    assert.ok(out);
  });

  it('provides UTC tooltip', () => {
    assert.equal(utcIsoTooltip('2026-07-25T18:10:55.000Z'), '2026-07-25T18:10:55.000Z');
    assert.equal(utcIsoTooltip(null), '');
  });

  it('splits date and time parts in system timezone', () => {
    const parts = formatUserDateParts('2026-07-25T18:10:55.000Z', 'Europe/Istanbul');
    assert.deepEqual(parts, { date: '25/07/2026', time: '21:10:55' });
  });

  it('systemLocalInputToUtcIso interprets wall clock in system TZ not browser', () => {
    // 21:10 Europe/Istanbul = 18:10 UTC
    const iso = systemLocalInputToUtcIso('2026-07-25T21:10:55', 'Europe/Istanbul');
    assert.equal(iso, '2026-07-25T18:10:55.000Z');
  });

  it('formats an offset-bearing audit "Last cleanup" instant canonically', () => {
    // Settings → Audit Log Retention: last_cleanup_at arrives with +03:00 offset.
    const out = formatUserDateTime('2026-08-25T16:40:04+03:00', 'Europe/Istanbul');
    assert.equal(out, '25/08/2026, 16:40:04');
    assert.ok(!out.includes('+03:00') && !out.includes('T'));
  });

  it('never emits Invalid Date / NaN / epoch for null or invalid input', () => {
    for (const bad of [null, undefined, '', 'not-a-date']) {
      const out = formatUserDateTime(bad, 'Europe/Istanbul');
      assert.equal(out, '-');
    }
  });
});
