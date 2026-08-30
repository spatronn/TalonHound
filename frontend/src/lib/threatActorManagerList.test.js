import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildThreatActorManagerQueryParams,
  clampThreatActorManagerPage,
  formatThreatActorAliases,
  formatThreatActorManagerShowingLabel,
  parseThreatActorManagerUrlState
} from './threatActorManagerList.js';

test('buildThreatActorManagerQueryParams includes search and pagination', () => {
  assert.deepEqual(
    buildThreatActorManagerQueryParams({ page: 2, search: 'APT28', showInactive: false }),
    { page: 2, page_size: 25, include_inactive: 'false', search: 'APT28' }
  );
});

test('parseThreatActorManagerUrlState reads search and inactive flag', () => {
  const params = new URLSearchParams('search=Midnight%20Blizzard&page=3&show_inactive=false');
  assert.deepEqual(parseThreatActorManagerUrlState(params), {
    page: 3,
    search: 'Midnight Blizzard',
    showInactive: false
  });
});

test('clampThreatActorManagerPage clamps to available pages', () => {
  assert.equal(clampThreatActorManagerPage(99, 40, 25), 2);
});

test('formatThreatActorManagerShowingLabel renders range', () => {
  assert.equal(
    formatThreatActorManagerShowingLabel({ page: 1, pageSize: 25, totalItems: 1043 }),
    'Showing 1–25 of 1043'
  );
});

test('formatThreatActorAliases renders list and empty states', () => {
  assert.equal(formatThreatActorAliases(['Fancy Bear', 'Sofacy']), 'Fancy Bear, Sofacy');
  assert.equal(formatThreatActorAliases([]), '—');
});
