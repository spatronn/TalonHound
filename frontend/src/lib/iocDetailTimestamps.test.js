import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIocDetailTimestampCards,
  formatIocDetailDateTime,
  getManualSourceActionStates,
  getSourceMembershipActionStates,
  listSourceMembershipActions,
  resolveIocDetailImportedAt,
  resolveTimestampSourceContext
} from './iocDetailTimestamps.js';

test('resolveIocDetailImportedAt prefers imported_at', () => {
  assert.equal(
    resolveIocDetailImportedAt({ imported_at: '2026-07-26T14:32:41.000Z', created_at: '2026-07-26T10:00:00.000Z' }),
    '2026-07-26T14:32:41.000Z'
  );
});

test('resolveIocDetailImportedAt falls back to created_at only via shared list helper', () => {
  assert.equal(
    resolveIocDetailImportedAt({ created_at: '2026-07-26T14:32:41.000Z' }),
    '2026-07-26T14:32:41.000Z'
  );
});

test('null imported_at renders em dash without inventing fallbacks', () => {
  assert.equal(formatIocDetailDateTime(null), '—');
  assert.equal(formatIocDetailDateTime(''), '—');
  const cards = buildIocDetailTimestampCards({ imported_at: null, created_at: null }, [], []);
  assert.equal(cards[0].display, '—');
  assert.equal(cards[0].context, 'Source: System');
});

test('timestamp cards use Inserted / First seen / Last seen only', () => {
  const cards = buildIocDetailTimestampCards(
    {
      imported_at: '2026-07-26T14:32:41.000Z',
      first_seen_at: '2026-07-26T14:30:05.000Z',
      last_seen_at: '2026-07-26T14:30:05.000Z',
      last_seen_in_source: '2026-07-26T14:30:05.000Z',
      last_changed_in_source: '2026-07-26T14:30:05.000Z',
      last_confirmed_at: '2026-07-26T14:30:05.000Z'
    },
    [{
      name: 'MalwareBazaar abuse.ch',
      first_seen_at: '2026-07-26T14:30:05.000Z',
      last_changed_at: '2026-07-26T14:30:05.000Z',
      last_seen_at: '2026-07-26T14:30:05.000Z',
      last_seen_in_source: '2026-07-26T14:30:05.000Z'
    }],
    []
  );
  assert.equal(cards.length, 3);
  assert.equal(cards[0].label, 'Inserted into Platform');
  assert.equal(cards[1].label, 'First seen in source');
  assert.equal(cards[2].label, 'Last seen in source');
  assert.equal(cards.some((card) => card.label === 'Last changed in source'), false);
  assert.equal(cards[1].context, 'Source: MalwareBazaar abuse.ch');
  assert.equal(cards[0].value, '2026-07-26T14:32:41.000Z');
  assert.equal(
    cards.some((card) => card.label === 'Last confirmed / Last seen'),
    false
  );
});

test('multi-source context avoids a single misleading source name', () => {
  const ctx = resolveTimestampSourceContext({
    value: '2026-07-26T14:30:05.000Z',
    sources: [
      { name: 'A', first_seen_at: '2026-07-26T14:30:05.000Z' },
      { name: 'B', first_seen_at: '2026-07-26T14:30:05.000Z' }
    ],
    pick: (s) => s.first_seen_at
  });
  assert.equal(ctx, 'Across 2 sources');
});

test('source action states keep invalid actions disabled', () => {
  const active = getSourceMembershipActionStates({
    source_type: 'feed',
    status: 'active',
    actions_enabled: true,
    override_enabled: false
  });
  assert.equal(active.reactivate_membership.enabled, false);
  assert.equal(active.custom_expire_membership.enabled, true);
  assert.equal(active.expire_membership.enabled, true);
  assert.equal(active.clear_membership_override.enabled, false);

  const withOverride = getSourceMembershipActionStates({
    source_type: 'feed',
    status: 'active',
    actions_enabled: true,
    override_enabled: true
  });
  assert.equal(withOverride.clear_membership_override.enabled, true);

  const actions = listSourceMembershipActions({
    source_type: 'feed',
    status: 'active',
    actions_enabled: true,
    override_enabled: true
  });
  assert.equal(actions.length, 4);
  assert.deepEqual(
    actions.map((a) => a.label),
    ['Reactivate source', 'Custom expire', 'Expire source', 'Clear override']
  );
});

test('removable manual/custom source exposes a single Remove from source action', () => {
  const states = getManualSourceActionStates({ source_type: 'manual', removable: true });
  assert.equal(states.remove_manual_source.enabled, true);
  assert.equal(states.remove_manual_source.danger, true);

  const actions = listSourceMembershipActions({ source_type: 'manual', removable: true });
  assert.equal(actions.length, 1);
  assert.equal(actions[0].type, 'remove_manual_source');
  assert.equal(actions[0].label, 'Remove from source');
  assert.equal(actions[0].enabled, true);
});

test('non-removable / historical manual source does not enable removal', () => {
  // Manual source without the removable flag (e.g. historical) is not removable.
  assert.equal(getManualSourceActionStates({ source_type: 'manual' }).remove_manual_source.enabled, false);
  // Feed sources never get the manual remove action.
  const feedActions = listSourceMembershipActions({ source_type: 'feed', status: 'active', actions_enabled: true });
  assert.ok(!feedActions.some((a) => a.type === 'remove_manual_source'));
});

test('Threat Library report-side dates render as calendar days with publisher provenance (never import time)', () => {
  const cards = buildIocDetailTimestampCards(
    {
      imported_at: '2026-10-09T16:51:33.814Z',
      first_seen_at: '2023-05-25T03:00:00+03:00',
      last_seen_in_source: '2023-05-25T03:00:00+03:00',
      first_seen_provenance: { date: '2023-05-25', basis: 'publisher_observation', precision: 'date', report_id: 'r1', report_title: 'Advisory' },
      last_seen_provenance: { date: '2023-05-25', basis: 'publisher_observation', precision: 'date', report_id: 'r1', report_title: 'Advisory' }
    },
    [{ name: 'Threat_Library', first_seen_at: '2026-10-09T16:51:33.814Z' }],
    []
  );
  assert.equal(cards[1].display, '25/05/2023');
  assert.equal(cards[1].context, 'Source: Threat Library report (publisher observation)');
  assert.equal(cards[2].display, '25/05/2023');
  assert.equal(cards[2].context, 'Source: Threat Library report (publisher observation)');
  assert.notEqual(cards[0].display, cards[1].display, 'import time stays on Inserted into Platform only');
});

test('report publication fallback is labelled as such', () => {
  const cards = buildIocDetailTimestampCards(
    {
      imported_at: '2026-10-09T16:51:33.814Z',
      first_seen_at: '2026-10-08T00:00:00.000Z',
      last_seen_in_source: '2026-10-08T00:00:00.000Z',
      first_seen_provenance: { date: '2026-10-08', basis: 'report_publication', precision: 'date' },
      last_seen_provenance: { date: '2026-10-08', basis: 'report_publication', precision: 'date' }
    },
    [],
    []
  );
  assert.equal(cards[1].display, '08/10/2026');
  assert.equal(cards[1].context, 'Source: Threat Library report (report publication date)');
});
