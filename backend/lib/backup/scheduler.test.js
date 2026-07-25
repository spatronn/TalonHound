import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  matchCronField,
  cronMatchesUtc,
  cronMatchesInTimezone,
  nextBackupFireAt,
  nextCronFireUtc,
  describeBackupSchedule,
  minuteKeyUtc
} from './scheduler.js';
import { getBackupConfig } from './config.js';

describe('backup scheduler', () => {
  it('matches cron fields', () => {
    assert.equal(matchCronField('*', 5), true);
    assert.equal(matchCronField('2', 2), true);
    assert.equal(matchCronField('1-3', 2), true);
    assert.equal(matchCronField('*/15', 30), true);
    assert.equal(matchCronField('*/15', 31), false);
  });

  it('default config cron is weekly Sunday midnight', () => {
    const prev = process.env.BACKUP_CRON;
    delete process.env.BACKUP_CRON;
    try {
      assert.equal(getBackupConfig().cron, '0 0 * * 0');
    } finally {
      if (prev == null) delete process.env.BACKUP_CRON;
      else process.env.BACKUP_CRON = prev;
    }
  });

  it('env cron override is preserved', () => {
    const prev = process.env.BACKUP_CRON;
    process.env.BACKUP_CRON = '15 3 * * 1';
    try {
      assert.equal(getBackupConfig().cron, '15 3 * * 1');
    } finally {
      if (prev == null) delete process.env.BACKUP_CRON;
      else process.env.BACKUP_CRON = prev;
    }
  });

  it('matches full expression in UTC', () => {
    const d = new Date('2026-07-25T02:00:00Z');
    assert.equal(cronMatchesUtc('0 2 * * *', d), true);
    assert.equal(cronMatchesUtc('0 3 * * *', d), false);
  });

  it('matches weekly Sunday 00:00 in Europe/Istanbul', () => {
    // 2026-07-26 is Sunday. 00:00 Istanbul = 2026-07-25T21:00:00Z (EEST UTC+3)
    const wall = new Date('2026-07-25T21:00:00.000Z');
    assert.equal(cronMatchesInTimezone('0 0 * * 0', wall, 'Europe/Istanbul'), true);
    assert.equal(cronMatchesInTimezone('0 0 * * 0', wall, 'UTC'), false);
  });

  it('nextBackupFireAt finds next Sunday in schedule timezone beyond 48h', () => {
    // Monday 2026-07-20 10:00 Istanbul
    const from = new Date('2026-07-20T07:00:00.000Z');
    const next = nextBackupFireAt('0 0 * * 0', from, 'Europe/Istanbul');
    assert.ok(next);
    // Should be Sunday 2026-07-26 00:00 Istanbul = 2026-07-25T21:00:00.000Z
    assert.equal(next, '2026-07-25T21:00:00.000Z');
  });

  it('nextCronFireUtc horizon covers weekly', () => {
    const from = new Date('2026-07-20T12:00:00Z');
    const next = nextCronFireUtc('0 0 * * 0', from);
    assert.ok(next);
  });

  it('describeBackupSchedule for weekly', () => {
    const d = describeBackupSchedule('0 0 * * 0', 'Europe/Istanbul');
    assert.equal(d.summary, 'Every Sunday at 00:00');
    assert.equal(d.timezone, 'Europe/Istanbul');
  });

  it('invalid timezone normalizes via describe', () => {
    const d = describeBackupSchedule('0 0 * * 0', 'Not/Real');
    assert.equal(d.timezone, 'UTC');
  });

  it('minute key suppresses duplicates', () => {
    assert.equal(minuteKeyUtc(new Date('2026-07-25T02:00:10Z')), '2026-07-25T02:00');
  });
});
