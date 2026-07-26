import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIocDetailTimestampCards,
  formatIocDetailDateTime,
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

test('timestamp cards use correct labels and values', () => {
  const cards = buildIocDetailTimestampCards(
    {
      imported_at: '2026-07-26T14:32:41.000Z',
      first_seen_at: '2026-07-26T14:30:05.000Z',
      last_seen_at: '2026-07-26T14:30:05.000Z',
      last_confirmed_at: '2026-07-26T14:30:05.000Z'
    },
    [{
      name: 'MalwareBazaar abuse.ch',
      first_seen_at: '2026-07-26T14:30:05.000Z',
      last_changed_at: '2026-07-26T14:30:05.000Z',
      last_seen_at: '2026-07-26T14:30:05.000Z'
    }],
    []
  );
  assert.equal(cards[0].label, 'Inserted into Platform');
  assert.equal(cards[1].label, 'First seen in source');
  assert.equal(cards[2].label, 'Last changed in source');
  assert.equal(cards[3].label, 'Last confirmed / Last seen');
  assert.equal(cards[1].context, 'Source: MalwareBazaar abuse.ch');
  assert.equal(cards[0].value, '2026-07-26T14:32:41.000Z');
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
});
