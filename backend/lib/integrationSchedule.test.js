import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildHourlySlotMap,
  computeNextRunAt,
  effectiveCronForFeed,
  buildRepeatableNextRunMap,
  buildRepeatJobConfig,
  getSystemScheduleTimezone
} from './integrationSchedule.js';

test('hourly slots are computed from active feeds only', () => {
  const active = [
    { key: 'threatfox-abusech', schedule: '0 * * * *' },
    { key: 'et-blockrules', schedule: '0 * * * *' },
    { key: 'urlhaus-abusech', schedule: '0 * * * *' }
  ];
  const slots = buildHourlySlotMap(active);
  assert.equal(slots.size, 3);
  assert.equal(slots.get('et-blockrules'), 0);
  assert.equal(slots.get('threatfox-abusech'), 20);
  assert.equal(slots.get('urlhaus-abusech'), 40);
  assert.equal(effectiveCronForFeed('threatfox-abusech', '0 * * * *', slots), '20 * * * *');
});

test('disabled feeds are excluded from slot map', () => {
  const slots = buildHourlySlotMap([
    { key: 'et-blockrules', schedule: '0 * * * *' },
    { key: 'usom-trcert', schedule: '0 * * * *' }
  ]);
  assert.equal(slots.get('usom-trcert'), 30);
  const withoutUsom = buildHourlySlotMap([{ key: 'et-blockrules', schedule: '0 * * * *' }]);
  assert.equal(withoutUsom.get('et-blockrules'), 0);
  assert.equal(withoutUsom.size, 1);
});

test('many active hourly feeds get evenly spaced slots', () => {
  const feeds = Array.from({ length: 15 }, (_, i) => ({
    key: `feed-${String(i).padStart(2, '0')}`,
    schedule: '0 * * * *'
  }));
  const slots = buildHourlySlotMap(feeds);
  assert.equal(slots.size, 15);
  assert.equal(slots.get('feed-00'), 0);
  assert.equal(slots.get('feed-14'), 56);
});

test('computeNextRunAt uses dynamic slot map', () => {
  const now = new Date('2026-05-29T19:42:00+03:00');
  const slots = buildHourlySlotMap([
    { key: 'et-blockrules', schedule: '0 * * * *' },
    { key: 'urlhaus-abusech', schedule: '0 * * * *' }
  ]);
  const etNext = computeNextRunAt('0 * * * *', 'et-blockrules', now, slots);
  const urlhausNext = computeNextRunAt('0 * * * *', 'urlhaus-abusech', now, slots);

  assert.equal(etNext.getHours(), 20);
  assert.equal(etNext.getMinutes(), 0);
  assert.equal(urlhausNext.getHours(), 20);
  assert.equal(urlhausNext.getMinutes(), 30);
});

test('daily schedule runs at system midnight UTC and is excluded from hourly slots', () => {
  assert.equal(getSystemScheduleTimezone(), 'UTC');
  assert.equal(effectiveCronForFeed('phishtank-opendnsrr', '0 0 * * *', new Map()), '0 0 * * *');
  const slots = buildHourlySlotMap([
    { key: 'et-blockrules', schedule: '0 * * * *' },
    { key: 'phishtank-opendnsrr', schedule: '0 0 * * *' }
  ]);
  assert.equal(slots.size, 1);
  assert.equal(slots.has('phishtank-opendnsrr'), false);
  assert.equal(slots.has('et-blockrules'), true);

  const now = new Date('2026-05-29T20:49:43.000Z');
  const next = computeNextRunAt('0 0 * * *', 'et-blockrules', now);
  assert.equal(next.toISOString(), '2026-05-30T00:00:00.000Z');
});

test('daily repeat config uses system schedule timezone', () => {
  const repeat = buildRepeatJobConfig('et-blockrules', '0 0 * * *', new Map());
  assert.equal(repeat.pattern, '0 0 * * *');
  assert.equal(repeat.tz, 'UTC');
});

test('buildRepeatableNextRunMap maps scheduler ids to feed keys', () => {
  const map = buildRepeatableNextRunMap([
    { id: 'threatfox-abusech-scheduled', next: 1780070400000 }
  ]);
  assert.equal(map.get('threatfox-abusech')?.toISOString(), new Date(1780070400000).toISOString());
});
