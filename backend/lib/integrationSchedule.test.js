import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildHourlySlotMap,
  computeNextRunAt,
  effectiveCronForFeed,
  buildRepeatableNextRunMap
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

test('daily schedule runs at midnight and is excluded from hourly slots', () => {
  assert.equal(effectiveCronForFeed('phishtank-opendnsrr', '0 0 * * *', new Map()), '0 0 * * *');
  const slots = buildHourlySlotMap([
    { key: 'et-blockrules', schedule: '0 * * * *' },
    { key: 'phishtank-opendnsrr', schedule: '0 0 * * *' }
  ]);
  assert.equal(slots.size, 1);
  assert.equal(slots.has('phishtank-opendnsrr'), false);

  const now = new Date('2026-05-29T15:30:00+03:00');
  const next = computeNextRunAt('0 0 * * *', 'phishtank-opendnsrr', now);
  assert.equal(next.getDate(), 30);
  assert.equal(next.getHours(), 0);
  assert.equal(next.getMinutes(), 0);
});

test('buildRepeatableNextRunMap maps scheduler ids to feed keys', () => {
  const map = buildRepeatableNextRunMap([
    { id: 'threatfox-abusech-scheduled', next: 1780070400000 }
  ]);
  assert.equal(map.get('threatfox-abusech')?.toISOString(), new Date(1780070400000).toISOString());
});
