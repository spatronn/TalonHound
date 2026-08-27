import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  projectionIdentityKey,
  projectionContentFingerprint,
  canUseIncrementalRefresh,
  isProjectionReady,
  PROJECTION_STATUS,
  PROJECTION_UPSERT_MAX_ROWS,
  upsertProjectionBatch,
  confidenceRank,
  clearFeedProjection
} from './publishedFeedProjection.js';
import {
  decideRefreshMode,
  applyIncrementalProjectionUpdate,
  collectDirtyIocIds
} from './publishedFeedIncremental.js';
import { buildStreamingBaseSql, buildStreamingHashBaseSql } from './feedPublisherService.js';

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

  it('splits oversized batches below the Postgres bind protocol limit', async () => {
    const calls = [];
    const db = {
      async query(sql, params) {
        calls.push(params.length);
        return { rowCount: params.length / 15 };
      }
    };
    const rows = Array.from({ length: 5000 }, (_, idx) => ({
      feed_id: 1,
      window: 'all',
      identity_key: `o:domain:e${idx}.com`,
      ioc_item_id: idx + 1,
      observable: `e${idx}.com`,
      observable_type: 'domain',
      recency_ts: '2026-08-09T00:00:00Z',
      confidence: 'high',
      category: 'malware',
      txt_value: `e${idx}.com`,
      item_json: null,
      content_fingerprint: 'abc'
    }));
    const n = await upsertProjectionBatch(db, rows);
    assert.equal(n, 5000);
    assert.equal(calls.length, 2);
    assert.ok(calls.every((count) => count <= 65535));
    assert.equal(calls[0], PROJECTION_UPSERT_MAX_ROWS * 15);
    assert.equal(calls[1], (5000 - PROJECTION_UPSERT_MAX_ROWS) * 15);
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

  it('collectDirtyIocIds includes hard-delete tombstones and living siblings', async () => {
    const cutoff = new Date('2026-08-01T00:00:00Z');
    const db = {
      async query(sql) {
        const s = String(sql);
        if (s.includes('published_feed_global_watermarks')) return { rows: [{ watermark: new Date('2026-07-01T00:00:00Z') }] };
        if (s.includes('published_feed_ioc_deletes')) {
          return {
            rows: [{
              ioc_item_id: 99,
              observable: 'gone.example',
              observable_type: 'domain',
              artifact_id: null,
              deleted_at: new Date('2026-08-02T00:00:00Z')
            }]
          };
        }
        if (s.includes('unnest') && s.includes('ioc_items')) {
          return { rows: [{ id: 100 }] }; // surviving sibling
        }
        return { rows: [] };
      }
    };
    const dirty = await collectDirtyIocIds(db, { include_enrichment: false }, cutoff);
    assert.equal(dirty.forceFull, false);
    assert.ok(dirty.deletes.length === 1);
    assert.equal(dirty.deletes[0].ioc_item_id, 99);
    assert.ok(dirty.ids.includes(99));
    assert.ok(dirty.ids.includes(100));
    assert.ok(dirty.sources.deletes >= 1);
  });

  it('hard delete with no surviving sibling removes projected identity', async () => {
    const existing = [
      { identity_key: 'o:domain:gone.example', ioc_item_id: 99, content_fingerprint: 'x' }
    ];
    const db = {
      async query(sql, params) {
        const s = String(sql).replace(/\s+/g, ' ');
        if (s.includes('DELETE FROM published_feed_items')) {
          assert.ok((params?.[2] || []).includes('o:domain:gone.example'));
          return { rowCount: 1 };
        }
        if (s.includes('FROM published_feed_items')) {
          if (s.includes('content_fingerprint')) return { rows: existing };
          return { rows: existing.map((e) => ({ identity_key: e.identity_key, ioc_item_id: e.ioc_item_id })) };
        }
        // No living IOC / no streaming match after hard delete
        return { rows: [] };
      }
    };
    const feed = {
      id: 11,
      format: 'txt',
      filter_mode: 'basic',
      ioc_types: ['domain'],
      time_window: 'all',
      include_enrichment: false
    };
    const result = await applyIncrementalProjectionUpdate(
      db,
      feed,
      'all',
      ['domain'],
      {
        ids: [99],
        deletes: [{ ioc_item_id: 99, observable: 'gone.example', observable_type: 'domain', artifact_id: null }],
        forceFull: false
      }
    );
    assert.equal(result.removed, 1);
    assert.equal(result.entered, 0);
    assert.equal(result.artifactDirty, true);
  });

  it('hard delete of one sibling keeps identity when another sibling still matches', async () => {
    const existing = [
      { identity_key: 'o:domain:twin.example', ioc_item_id: 1, content_fingerprint: 'old' }
    ];
    const db = {
      async query(sql) {
        const s = String(sql).replace(/\s+/g, ' ');
        if (s.includes('FROM published_feed_items') && s.includes('identity_key = ANY')) {
          return { rows: [{ identity_key: 'o:domain:twin.example' }] };
        }
        if (s.includes('FROM published_feed_items') && s.includes('content_fingerprint')) {
          return { rows: existing };
        }
        if (s.includes('FROM published_feed_items') && s.includes('ioc_item_id = ANY')) {
          return { rows: existing.map((e) => ({ identity_key: e.identity_key, ioc_item_id: e.ioc_item_id })) };
        }
        if (s.includes('unnest') || (s.includes('FROM ioc_items') && s.includes('lower(observable)'))) {
          return { rows: [{ id: 2 }] };
        }
        if (s.includes('DISTINCT ON') || s.includes('buildStreaming') || s.includes('FROM (')) {
          return {
            rows: [{
              id: 2,
              observable: 'twin.example',
              observable_type: 'domain',
              confidence: 'medium',
              category: null,
              created_at: '2026-08-01T00:00:00Z',
              recency_ts: '2026-08-09T00:00:00Z'
            }]
          };
        }
        if (s.includes('INSERT INTO published_feed_items')) return { rowCount: 1 };
        if (s.includes('DELETE FROM published_feed_items')) return { rowCount: 0 };
        return { rows: [] };
      }
    };
    const feed = {
      id: 11,
      format: 'txt',
      filter_mode: 'basic',
      ioc_types: ['domain'],
      time_window: 'all',
      include_enrichment: false
    };
    const result = await applyIncrementalProjectionUpdate(
      db,
      feed,
      'all',
      ['domain'],
      {
        ids: [1, 2],
        deletes: [{ ioc_item_id: 1, observable: 'twin.example', observable_type: 'domain', artifact_id: null }],
        forceFull: false
      }
    );
    assert.equal(result.removed, 0);
    assert.ok(result.entered + result.updated + result.unchanged >= 1);
  });
});

describe('canonical projection status semantics (suppressed vs disabled)', () => {
  const feed = {
    id: 11, format: 'txt', filter_mode: 'basic', ioc_types: ['domain'],
    time_window: 'all', include_enrichment: false, exclude_expired: false
  };

  it('standard base SQL excludes only suppressed, keeping disabled/expired publishable', () => {
    const { sql } = buildStreamingBaseSql(feed, 'all');
    const norm = sql.replace(/\s+/g, ' ');
    // Semantics: publish everything that is not suppressed (disabled + expired stay in).
    assert.ok(norm.includes("<> 'suppressed'"), 'must exclude suppressed');
    assert.ok(!/IN \('active',\s*'expired'\)/.test(norm),
      "must NOT narrow to IN ('active','expired') — that would drop publishable disabled IOCs");
  });

  it('hash-canonical base SQL also excludes only suppressed', () => {
    const hashFeed = { ...feed, ioc_types: ['file_hash'], canonicalize_hashes: true };
    const { sql } = buildStreamingHashBaseSql(hashFeed, 'all');
    const norm = sql.replace(/\s+/g, ' ');
    assert.ok(norm.includes("<> 'suppressed'"), 'must exclude suppressed');
    assert.ok(!/IN \('active',\s*'expired'\)/.test(norm),
      "must NOT narrow to IN ('active','expired')");
  });
});

describe('OPTION A identity-keyed canonical expansion (self-join removed)', () => {
  it('collectDirtyIocIds threads observable_type into typeById for partition pruning', async () => {
    const cutoff = new Date('2026-08-01T00:00:00Z');
    const db = {
      async query(sql) {
        const s = String(sql);
        if (s.includes('published_feed_global_watermarks')) return { rows: [] };
        if (s.includes('published_feed_ioc_deletes')) return { rows: [] };
        if (s.includes('FROM ioc_items') && s.includes('updated_at')) {
          return { rows: [{ id: 5, observable_type: 'domain' }, { id: 6, observable_type: 'ip' }] };
        }
        if (s.includes('FROM ioc_feed_memberships')) {
          return { rows: [{ id: 7, observable_type: 'file_hash' }] };
        }
        return { rows: [] };
      }
    };
    const dirty = await collectDirtyIocIds(db, { include_enrichment: false }, cutoff);
    assert.deepEqual(dirty.typeById, { 5: 'domain', 6: 'ip', 7: 'file_hash' });
    assert.ok(dirty.ids.includes(5) && dirty.ids.includes(6) && dirty.ids.includes(7));
  });

  it('never issues the i1 JOIN i2 canonical sibling self-join', async () => {
    const seen = [];
    const db = {
      async query(sql, params) {
        const s = String(sql).replace(/\s+/g, ' ');
        seen.push(s);
        if (s.includes('DISTINCT lower(observable)') && s.includes('FROM ioc_items')) {
          return { rows: [{ obs: 'win.example', otype: 'domain' }] };
        }
        if (s.includes('FROM published_feed_items') && s.includes('identity_key = ANY')) {
          return { rows: [{ identity_key: 'o:domain:win.example' }] };
        }
        if (s.includes('FROM published_feed_items') && s.includes('ioc_item_id = ANY')) {
          return { rows: [] };
        }
        if (s.includes('DISTINCT ON') || s.includes('FROM (')) return { rows: [] };
        return { rows: [] };
      }
    };
    const feed = { id: 11, format: 'txt', filter_mode: 'basic', ioc_types: ['domain'], time_window: 'all', include_enrichment: false };
    await applyIncrementalProjectionUpdate(db, feed, 'all', ['domain'],
      { ids: [5], typeById: { 5: 'domain' }, forceFull: false });
    assert.ok(!seen.some((s) => /JOIN ioc_items i2/.test(s)),
      'the million-row canonical sibling self-join must not be issued');
    // i1 identity resolution must be partition-pruned by observable_type.
    assert.ok(seen.some((s) => /FROM ioc_items WHERE observable_type = ANY/.test(s)),
      'dirty-id identity resolution must prune partitions by observable_type');
  });

  it('winner-switch: keeps identity when the stored representative is a non-dirty sibling', async () => {
    // Projected under representative T=2 (NOT dirty). Dirty candidate S=5 shares the identity.
    const existing = [{ identity_key: 'o:domain:win.example', ioc_item_id: 2, content_fingerprint: 'old' }];
    const db = {
      async query(sql) {
        const s = String(sql).replace(/\s+/g, ' ');
        if (s.includes('DISTINCT lower(observable)') && s.includes('FROM ioc_items')) {
          return { rows: [{ obs: 'win.example', otype: 'domain' }] };
        }
        if (s.includes('FROM published_feed_items') && s.includes('content_fingerprint')) {
          // existing-rows lookup (has ioc_item_id=ANY OR identity_key=ANY) → the projected row
          return { rows: existing };
        }
        if (s.includes('FROM published_feed_items') && s.includes('ioc_item_id = ANY')) {
          // S=5 is not the stored representative → id lookup finds nothing.
          return { rows: [] };
        }
        if (s.includes('FROM published_feed_items') && s.includes('identity_key = ANY')) {
          return { rows: [{ identity_key: 'o:domain:win.example' }] };
        }
        if (s.includes('DISTINCT ON') || s.includes('FROM (')) {
          // Still matches — winner is B=8 now.
          return { rows: [{ id: 8, observable: 'win.example', observable_type: 'domain', confidence: 'high', category: null, created_at: '2026-08-01T00:00:00Z', recency_ts: '2026-08-09T00:00:00Z' }] };
        }
        if (s.includes('INSERT INTO published_feed_items')) return { rowCount: 1 };
        if (s.startsWith('DELETE FROM published_feed_items')) return { rowCount: 0 };
        return { rows: [] };
      }
    };
    const feed = { id: 11, format: 'txt', filter_mode: 'basic', ioc_types: ['domain'], time_window: 'all', include_enrichment: false };
    const result = await applyIncrementalProjectionUpdate(db, feed, 'all', ['domain'],
      { ids: [5], typeById: { 5: 'domain' }, forceFull: false });
    assert.equal(result.removed, 0, 'identity must NOT be dropped when representative is a non-dirty sibling');
    assert.ok(result.updated + result.entered + result.unchanged >= 1);
  });

  it('leave via identity: removes projection when a non-dirty representative identity no longer matches', async () => {
    const existing = [{ identity_key: 'o:domain:gone.example', ioc_item_id: 2, content_fingerprint: 'old' }];
    let deletedKeys = null;
    const db = {
      async query(sql, params) {
        const s = String(sql).replace(/\s+/g, ' ');
        if (s.includes('DELETE FROM published_feed_items')) { deletedKeys = params?.[2] || []; return { rowCount: deletedKeys.length }; }
        if (s.includes('DISTINCT lower(observable)') && s.includes('FROM ioc_items')) {
          return { rows: [{ obs: 'gone.example', otype: 'domain' }] };
        }
        if (s.includes('FROM published_feed_items') && s.includes('content_fingerprint')) {
          return { rows: existing };
        }
        if (s.includes('FROM published_feed_items') && s.includes('ioc_item_id = ANY')) return { rows: [] };
        if (s.includes('FROM published_feed_items') && s.includes('identity_key = ANY')) {
          return { rows: [{ identity_key: 'o:domain:gone.example' }] };
        }
        if (s.includes('DISTINCT ON') || s.includes('FROM (')) return { rows: [] }; // no longer matches
        return { rows: [] };
      }
    };
    const feed = { id: 11, format: 'txt', filter_mode: 'basic', ioc_types: ['domain'], time_window: 'all', include_enrichment: false };
    const result = await applyIncrementalProjectionUpdate(db, feed, 'all', ['domain'],
      { ids: [5], typeById: { 5: 'domain' }, forceFull: false });
    assert.equal(result.removed, 1, 'identity must leave even though the representative was not dirty');
    assert.ok((deletedKeys || []).includes('o:domain:gone.example'));
  });
});

describe('clearFeedProjection batching', () => {
  it('deletes across multiple LIMIT batches until drained', async () => {
    let remaining = 23;
    const calls = [];
    const db = {
      async query(sql, params) {
        calls.push({ sql: String(sql), params });
        assert.match(String(sql), /WITH doomed AS/);
        assert.match(String(sql), /LIMIT \$2/);
        assert.match(String(sql), /p\.ctid = d\.ctid/);
        const batchSize = Number(params[1]);
        const n = Math.min(remaining, batchSize);
        remaining -= n;
        return { rowCount: n };
      }
    };
    const total = await clearFeedProjection(db, 42, { batchSize: 10 });
    assert.equal(total, 23);
    assert.equal(calls.length, 3); // 10 + 10 + 3
    assert.equal(calls[0].params[0], 42);
    assert.equal(calls[0].params[1], 10);
  });

  it('returns 0 when feed has no projection rows', async () => {
    const db = {
      async query() {
        return { rowCount: 0 };
      }
    };
    assert.equal(await clearFeedProjection(db, 7, { batchSize: 100 }), 0);
  });
});
