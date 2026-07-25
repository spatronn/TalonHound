import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatUserDateTime,
  normalizeUserTimezone,
  utcIsoTooltip
} from './formatDate.js';

describe('formatDate', () => {
  it('formats UTC instant in Europe/Istanbul without UTC suffix', () => {
    const out = formatUserDateTime('2026-07-25T18:10:55.000Z', 'Europe/Istanbul');
    assert.equal(out, '25/07/2026, 21:10:55');
    assert.ok(!out.includes('UTC'));
  });

  it('changes when timezone changes', () => {
    const iso = '2026-07-25T18:10:55.000Z';
    const istanbul = formatUserDateTime(iso, 'Europe/Istanbul');
    const utc = formatUserDateTime(iso, 'UTC');
    assert.notEqual(istanbul, utc);
    assert.equal(utc, '25/07/2026, 18:10:55');
  });

  it('falls back invalid timezone to UTC', () => {
    assert.equal(normalizeUserTimezone('Not/AZone'), 'UTC');
    const out = formatUserDateTime('2026-07-25T18:10:55.000Z', 'Not/AZone');
    assert.equal(out, '25/07/2026, 18:10:55');
  });

  it('provides UTC tooltip', () => {
    assert.equal(utcIsoTooltip('2026-07-25T18:10:55.000Z'), '2026-07-25T18:10:55.000Z');
    assert.equal(utcIsoTooltip(null), '');
  });
});
