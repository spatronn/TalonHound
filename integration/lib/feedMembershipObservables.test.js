import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  loadFeedMembershipObservableSet,
  selectEntriesMissingMembership
} from './feedMembershipObservables.js';

describe('selectEntriesMissingMembership', () => {
  it('returns only identities absent from the membership set', () => {
    const existing = new Set(['a.example', 'b.example']);
    const entries = [
      { observable: 'a.example' },
      { observable: 'c.example' },
      { observable: 'b.example' },
      { observable: 'd.example' }
    ];
    const added = selectEntriesMissingMembership(entries, existing);
    assert.deepEqual(added.map((e) => e.observable), ['c.example', 'd.example']);
  });

  it('treats empty membership set as initial import (all entries)', () => {
    const entries = [{ observable: 'a.example' }, { observable: 'b.example' }];
    const added = selectEntriesMissingMembership(entries, new Set());
    assert.equal(added.length, 2);
  });

  it('identical refresh yields zero additions', () => {
    const existing = new Set(['a.example', 'b.example']);
    const entries = [{ observable: 'a.example' }, { observable: 'b.example' }];
    assert.equal(selectEntriesMissingMembership(entries, existing).length, 0);
  });

  it('supports custom observable getter (PhishTank url entries)', () => {
    const existing = new Set(['https://a.example/x']);
    const entries = [
      { observable: 'https://a.example/x', observableType: 'url' },
      { observable: 'https://b.example/y', observableType: 'url' }
    ];
    const added = selectEntriesMissingMembership(entries, existing, (e) => e.observable);
    assert.deepEqual(added.map((e) => e.observable), ['https://b.example/y']);
  });
});

describe('loadFeedMembershipObservableSet', () => {
  it('queries the domain partition for domain memberships', async () => {
    const calls = [];
    const db = {
      async query(sql, params) {
        calls.push({ sql: String(sql), params });
        return { rows: [{ observable: 'a.example' }, { observable: 'b.example' }] };
      }
    };
    const set = await loadFeedMembershipObservableSet(db, 'feed-uuid', 'domain');
    assert.equal(set.size, 2);
    assert.equal(set.has('a.example'), true);
    assert.match(calls[0].sql, /JOIN ioc_domain i/i);
    assert.equal(calls[0].params[0], 'feed-uuid');
    assert.equal(calls[0].params[1], 'domain');
  });

  it('queries the url partition for url memberships', async () => {
    const calls = [];
    const db = {
      async query(sql, params) {
        calls.push({ sql: String(sql), params });
        return { rows: [] };
      }
    };
    await loadFeedMembershipObservableSet(db, 'feed-uuid', 'url');
    assert.match(calls[0].sql, /JOIN ioc_url i/i);
  });

  it('returns empty set when feed id missing', async () => {
    const set = await loadFeedMembershipObservableSet({ query: async () => ({ rows: [] }) }, null, 'domain');
    assert.equal(set.size, 0);
  });
});
