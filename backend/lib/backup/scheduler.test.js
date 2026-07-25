import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { matchCronField, cronMatchesUtc, nextCronFireUtc, minuteKeyUtc } from './scheduler.js';

describe('backup scheduler', () => {
  it('matches cron fields', () => {
    assert.equal(matchCronField('*', 5), true);
    assert.equal(matchCronField('2', 2), true);
    assert.equal(matchCronField('1-3', 2), true);
    assert.equal(matchCronField('*/15', 30), true);
    assert.equal(matchCronField('*/15', 31), false);
  });

  it('matches full expression in UTC', () => {
    // 2026-07-25 02:00:00 UTC = Sat
    const d = new Date('2026-07-25T02:00:00Z');
    assert.equal(cronMatchesUtc('0 2 * * *', d), true);
    assert.equal(cronMatchesUtc('0 3 * * *', d), false);
  });

  it('finds next fire', () => {
    const from = new Date('2026-07-25T01:30:00Z');
    const next = nextCronFireUtc('0 2 * * *', from, 24);
    assert.equal(next, '2026-07-25T02:00:00.000Z');
  });

  it('minute key suppresses duplicates', () => {
    assert.equal(minuteKeyUtc(new Date('2026-07-25T02:00:10Z')), '2026-07-25T02:00');
  });
});
