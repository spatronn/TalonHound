import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  projectionIdentityKey,
  projectionContentFingerprint,
  canUseIncrementalRefresh,
  isProjectionReady,
  PROJECTION_STATUS,
  upsertProjectionBatch,
  confidenceRank
} from './publishedFeedProjection.js';
import {
  decideRefreshMode,
  applyIncrementalProjectionUpdate,
  collectDirtyIocIds
} from './publishedFeedIncremental.js';

describe('publishedFeedProjection helpers', () => {
  it('builds stable identity keys', () => {
    assert.equal(projectionIdentityKey('Evil.COM', 'domain'), 'o:domain:evil.com');
    assert.equal(projectionIdentityKey('aa', 'sha256', { artifactId: 'uuid-1' }), 'a:uuid-1');
  });

  it('fingerprints TXT/JSON content stably', () => {
    const a = projectionContentFingerprint({ txtValue: 'evil.com', itemJson: { value: 'evil.com', type: 'domain' } });
    const b = projectionContentFingerprint({ txtValue: 'evil.com', itemJson: { value: 'evil.com', type: 'domain' } });
    const c = projectionContentFingerprint({ txtValue: 'evil.com', itemJson: { value: 'evil.com', type: 'domain', tags: ['c2'] } });
    assert.equal(a, b);
    assert.notEqual(a, c);
  });

  it('confidenceRank maps labels', () => {
    assert.equal(confidenceRank('high'), 100);
    assert.equal(confidenceRank('medium'), 50);
  });

  it('canUseIncrementalRefresh is conservative for max_items and windows', () => {
    const ready = { projection_status: PROJECTION_STATUS.READY, time_window: 'all', max_items: null };
    assert.equal(canUseIncrementalRefresh(ready), true);
    assert.equal(canUseIncrementalRefresh({ ...ready, max_items: 1000 }), false);
    assert.equal(canUseIncrementalRefresh({ ...ready, time_window: '7d' }), false);
    assert.equal(canUseIncrementalRefresh(ready, { force: true }), false);
    assert.equal(isProjectionReady({ projection_status: 'absent' }), false);
  });
});

describe('decideRefreshMode', () => {
  it('defaults to full when streaming off', () => {
    assert.equal(decideRefreshMode({ projection_status: 'ready' }, { streamingEnabled: false }), 'full');
  });

  it('bootstraps when projection absent and incremental+streaming on', () => {
    assert.equal(decideRefreshMode(
      { projection_status: 'absent', time_window: 'all' },
      { streamingEnabled: true, incrementalEnabled: true }
    ), 'bootstrap');
  });

  it('uses incremental when ready', () => {
    assert.equal(decideRefreshMode(
      { projection_status: 'ready', time_window: 'all', max_items: null },
      { streamingEnabled: true, incrementalEnabled: true }
    ), 'incremental');
  });

  it('falls back to full on force/config change', () => {
    assert.equal(decideRefreshMode(
      { projection_status: 'ready', time_window: 'all' },
      { streamingEnabled: true, incrementalEnabled: true, force: true }
    ), 'full');
  });

  it('stays full (no bootstrap) when incremental disabled and projection absent', () => {
    assert.equal(decideRefreshMode(
      { id: 1, projection_status: 'absent', time_window: 'all' },
      { streamingEnabled: true, incrementalEnabled: false }
    ), 'full');
  });
});

describe('upsertProjectionBatch', () => {
  it('issues idempotent upsert SQL', async () => {
    const calls = [];
    const db = {
      async query(sql, params) {
        calls.push({ sql: String(sql).replace(/\s+/g, ' '), params });
        return { rowCount: 1 };
      }
    };
    const n = await upsertProjectionBatch(db, [{
      feed_id: 1,
      window: 'all',
      identity_key: 'o:domain:evil.com',
      ioc_item_id: 9,
      observable: 'evil.com',
      observable_type: 'domain',
      recency_ts: '2026-08-09T00:00:00Z',
      confidence: 'high',
      category: 'malware',
      confidence_rank: 100,
      txt_value: 'evil.com',
      item_json: { value: 'evil.com', type: 'domain' },
      content_fingerprint: 'abc'
    }]);
    assert.equal(n, 1);
    assert.match(calls[0].sql, /ON CONFLICT \(feed_id, snapshot_window, identity_key\) DO UPDATE/);
    assert.match(calls[0].sql, /INSERT INTO published_feed_items \(\s*feed_id, snapshot_window,/);
    assert.equal(calls[0].params[0], 1);
    assert.equal(calls[0].params[2], 'o:domain:evil.com');
  });
});

describe('collectDirtyIocIds / applyIncrementalProjectionUpdate', () => {
  it('returns forceFull when tags catalog watermark is newer than cutoff', async () => {
    const cutoff = new Date('2026-08-01T00:00:00Z');
    const db = {
      async query(sql) {
        if (String(sql).includes('published_feed_global_watermarks')) {
          return { rows: [{ watermark: new Date('2026-08-09T00:00:00Z') }] };
        }
        return { rows: [] };
      }
    };
    const dirty = await collectDirtyIocIds(db, { include_enrichment: false }, cutoff);
    assert.equal(dirty.forceFull, true);
    assert.equal(dirty.reason, 'tags_catalog');
  });

  it('applies enter/update/remove semantics with mocked evaluate path', async () => {
    // Minimal mock: existing projection has identity A; matched returns A' with new fingerprint → update.
    // Also leave identity B.
    const existing = [
      { identity_key: 'o:domain:a.com', ioc_item_id: 1, content_fingerprint: 'old' },
      { identity_key: 'o:domain:b.com', ioc_item_id: 2, content_fingerprint: 'keep' }
    ];
    const calls = [];
    const db = {
      async query(sql, params) {
        const s = String(sql).replace(/\s+/g, ' ');
        calls.push(s.slice(0, 60));
        if (s.includes('FROM ioc_items WHERE id = ANY') && s.includes('DISTINCT lower')) {
          return { rows: [{ obs: 'a.com', otype: 'domain' }, { obs: 'b.com', otype: 'domain' }] };
        }
        if (s.includes('SELECT DISTINCT lower(observable)')) {
          return { rows: [{ obs: 'a.com', otype: 'domain' }, { obs: 'b.com', otype: 'domain' }] };
        }
        if (s.includes('JOIN ioc_items i2')) {
          return { rows: [{ id: 1 }, { id: 2 }] };
        }
        if (s.includes('FROM published_feed_items') && s.includes('ioc_item_id = ANY')) {
          if (s.includes('content_fingerprint')) return { rows: existing };
          return { rows: existing.map((e) => ({ identity_key: e.identity_key, ioc_item_id: e.ioc_item_id })) };
        }
        if (s.includes('DISTINCT ON') || s.includes('FROM (')) {
          // evaluateCandidatesAgainstFeed — only a.com still matches
          return {
            rows: [{
              id: 1,
              observable: 'a.com',
              observable_type: 'domain',
              confidence: 'high',
              category: 'malware',
              created_at: '2026-08-01T00:00:00Z',
              ioc_source_id: null,
              source_name: 'x',
              recency_ts: '2026-08-09T00:00:00Z'
            }]
          };
        }
        if (s.includes('FROM ioc_feed_memberships') || s.includes('FROM ioc_tags') || s.includes('lower(i.observable) = ANY')) {
          return { rows: [] };
        }
        if (s.startsWith('DELETE FROM published_feed_items')) {
          return { rowCount: (params?.[2] || []).length };
        }
        if (s.includes('INSERT INTO published_feed_items')) {
          return { rowCount: 1 };
        }
        return { rows: [] };
      }
    };

    const feed = {
      id: 7,
      format: 'txt',
      filter_mode: 'basic',
      ioc_types: ['domain'],
      time_window: 'all',
      include_source_metadata: false,
      include_classification: false,
      include_enrichment: false,
      exclude_expired: true,
      exclude_false_positive: true
    };

    const result = await applyIncrementalProjectionUpdate(
      db,
      feed,
      'all',
      ['domain'],
      { ids: [1, 2], forceFull: false, truncated: false, sources: {} }
    );
    assert.equal(result.forceFull, false);
    assert.ok(result.removed >= 1); // b.com left
    assert.ok(result.entered + result.updated >= 1); // a.com upserted
    assert.equal(result.artifactDirty, true);
  });
});
