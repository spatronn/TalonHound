import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  persistPublishedFeedSnapshot,
  canSkipPublishedFeedRegeneration,
  watermarkKey,
  filtersHash,
  fetchIocExportFingerprint,
  fetchIocRows,
  shouldCanonicalizePublishedHashFeed
} from './feedPublisherService.js';

function createMockPool(handlers) {
  const calls = [];
  const client = {
    calls,
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      calls.push({ sql: normalized, params: [...params] });
      if (normalized === 'BEGIN' || normalized === 'COMMIT' || normalized === 'ROLLBACK') {
        return { rows: [] };
      }
      const handler = handlers.find((h) => h.match(sql));
      if (!handler) {
        throw new Error(`Unexpected query: ${sql}`);
      }
      return handler.result(params, calls);
    },
    release() {
      calls.push({ sql: 'RELEASE', params: [] });
    }
  };

  const pool = {
    async connect() {
      return client;
    },
    async query(sql, params = []) {
      return client.query(sql, params);
    }
  };

  return { pool, calls, client };
}

const baseSnapshot = {
  feedId: 7,
  itemCount: 3,
  contentHash: 'abc123',
  content: '1.2.3.4\n5.6.7.8',
  status: 'success',
  paramsJson: { ioc_type: 'ip', window: '1d', filters_hash: 'f1' }
};

describe('persistPublishedFeedSnapshot', () => {
  it('inserts a new success snapshot when none exists', async () => {
    const { pool, calls } = createMockPool([
      { match: (sql) => sql.includes('pg_advisory_xact_lock'), result: () => ({ rows: [] }) },
      {
        match: (sql) => sql.includes('FOR UPDATE') && sql.includes("status = 'success'"),
        result: () => ({ rows: [] })
      },
      { match: (sql) => sql.includes('INSERT INTO published_feed_snapshots'), result: () => ({ rows: [] }) }
    ]);

    await persistPublishedFeedSnapshot(pool, baseSnapshot);

    assert.equal(calls[0].sql, 'BEGIN');
    assert.ok(calls.some((c) => c.sql.includes('pg_advisory_xact_lock')));
    assert.ok(calls.some((c) => c.sql.includes('FOR UPDATE')));
    const insert = calls.find((c) => c.sql.startsWith('INSERT INTO published_feed_snapshots'));
    assert.ok(insert);
    assert.deepEqual(insert.params, [7, 3, 'abc123', '1.2.3.4\n5.6.7.8', JSON.stringify(baseSnapshot.paramsJson)]);
    assert.equal(calls.at(-2).sql, 'COMMIT');
    assert.equal(calls.at(-1).sql, 'RELEASE');
  });

  it('skips DB update when content hash is unchanged', async () => {
    const { pool, calls } = createMockPool([
      { match: (sql) => sql.includes('pg_advisory_xact_lock'), result: () => ({ rows: [] }) },
      {
        match: (sql) => sql.includes('FOR UPDATE') && sql.includes("status = 'success'"),
        result: () => ({ rows: [{ id: 42, content_hash: 'abc123' }] })
      }
    ]);

    const result = await persistPublishedFeedSnapshot(pool, { ...baseSnapshot, itemCount: 5 });

    assert.equal(result.skipped, true);
    assert.ok(!calls.some((c) => c.sql.startsWith('UPDATE published_feed_snapshots')));
  });

  it('updates content when content hash changes', async () => {
    const { pool, calls } = createMockPool([
      { match: (sql) => sql.includes('pg_advisory_xact_lock'), result: () => ({ rows: [] }) },
      {
        match: (sql) => sql.includes('FOR UPDATE') && sql.includes("status = 'success'"),
        result: () => ({ rows: [{ id: 99, content_hash: 'old-hash' }] })
      },
      { match: (sql) => sql.includes('UPDATE published_feed_snapshots'), result: () => ({ rows: [] }) }
    ]);

    await persistPublishedFeedSnapshot(pool, {
      ...baseSnapshot,
      contentHash: 'new-hash',
      content: '9.9.9.9'
    });

    const update = calls.find((c) => c.sql.startsWith('UPDATE published_feed_snapshots'));
    assert.ok(update);
    assert.deepEqual(update.params, [99, 3, 'new-hash', '9.9.9.9', JSON.stringify(baseSnapshot.paramsJson)]);
    assert.ok(update.sql.includes('content ='));
  });

  it('updates existing failed snapshot instead of inserting another row', async () => {
    const { pool, calls } = createMockPool([
      { match: (sql) => sql.includes('pg_advisory_xact_lock'), result: () => ({ rows: [] }) },
      {
        match: (sql) => sql.includes('FOR UPDATE') && sql.includes("status = 'failed'"),
        result: () => ({ rows: [{ id: 12 }] })
      },
      { match: (sql) => sql.includes('UPDATE published_feed_snapshots'), result: () => ({ rows: [] }) }
    ]);

    await persistPublishedFeedSnapshot(pool, {
      feedId: 7,
      status: 'failed',
      errorMessage: 'boom',
      paramsJson: { ioc_type: 'ip', window: '1d' }
    });

    const update = calls.find((c) => c.sql.startsWith('UPDATE published_feed_snapshots'));
    assert.ok(update);
    assert.deepEqual(update.params, [12, 'boom', JSON.stringify({ ioc_type: 'ip', window: '1d' })]);
    assert.ok(!calls.some((c) => c.sql.startsWith('INSERT INTO published_feed_snapshots')));
  });

  it('rolls back and rethrows when persistence fails', async () => {
    const { pool, calls } = createMockPool([
      { match: (sql) => sql.includes('pg_advisory_xact_lock'), result: () => ({ rows: [] }) },
      {
        match: (sql) => sql.includes('FOR UPDATE') && sql.includes("status = 'success'"),
        result: () => {
          throw new Error('db down');
        }
      }
    ]);

    await assert.rejects(
      () => persistPublishedFeedSnapshot(pool, baseSnapshot),
      /db down/
    );

    assert.ok(calls.some((c) => c.sql === 'ROLLBACK'));
    assert.equal(calls.at(-1).sql, 'RELEASE');
  });
});

describe('canSkipPublishedFeedRegeneration', () => {
  const feed = {
    id: 1,
    ioc_type: 'ip',
    min_confidence: null,
    include_feed_keys: null,
    include_tags: null,
    exclude_tags: null,
    exclude_false_positive: true,
    exclude_expired: true,
    max_items: null,
    updated_at: '2026-06-23T10:00:00.000Z'
  };

  const watermark = { max_id: 100, max_ts: '2026-06-23T09:00:00.000Z', active_count: 50 };
  const filters_hash = filtersHash(feed, 'all');

  it('skips when watermark and feed config unchanged and no imports since snapshot', () => {
    const result = canSkipPublishedFeedRegeneration({
      feed,
      window: 'all',
      latestSnapshot: {
        content_hash: 'abc',
        generated_at: '2026-06-23T10:05:00.000Z',
        params: {
          filters_hash,
          feed_updated_at: '2026-06-23T10:00:00.000Z',
          ioc_watermark: watermark
        }
      },
      watermark,
      latestIntegrationFinishedAt: '2026-06-23T10:04:00.000Z'
    });
    assert.equal(result.skip, true);
    assert.equal(result.reason, 'unchanged_watermark');
  });

  it('does not skip when import finished after snapshot', () => {
    const result = canSkipPublishedFeedRegeneration({
      feed,
      window: 'all',
      latestSnapshot: {
        content_hash: 'abc',
        generated_at: '2026-06-23T10:05:00.000Z',
        params: {
          filters_hash,
          feed_updated_at: '2026-06-23T10:00:00.000Z',
          ioc_watermark: watermark
        }
      },
      watermark,
      latestIntegrationFinishedAt: '2026-06-23T10:06:00.000Z'
    });
    assert.equal(result.skip, false);
  });

  it('does not skip when force=true', () => {
    const result = canSkipPublishedFeedRegeneration({
      feed,
      window: 'all',
      latestSnapshot: { content_hash: 'abc', params: {} },
      watermark,
      force: true
    });
    assert.equal(result.skip, false);
  });

  it('does not skip when feed has source filters', () => {
    const result = canSkipPublishedFeedRegeneration({
      feed: { ...feed, include_feed_keys: ['usom-trcert'] },
      window: 'all',
      latestSnapshot: {
        content_hash: 'abc',
        params: {
          filters_hash: 'x',
          feed_updated_at: feed.updated_at,
          ioc_watermark: watermark
        }
      },
      watermark,
      latestIntegrationFinishedAt: null
    });
    assert.equal(result.skip, false);
  });

  it('watermarkKey stable for identical values', () => {
    assert.equal(watermarkKey(watermark), watermarkKey({ ...watermark }));
  });
});

describe('published feed excludes suppressed IOCs', () => {
  it('fetchIocExportFingerprint SQL excludes status = suppressed', async () => {
    let capturedSql = '';
    const pool = {
      async query(sql, params = []) {
        capturedSql = String(sql).replace(/\s+/g, ' ').trim();
        return { rows: [{ item_count: 0, max_recency: null }] };
      }
    };
    await fetchIocExportFingerprint(pool, { ioc_type: 'ip', exclude_expired: true }, 'all');
    assert.match(capturedSql, /COALESCE\(i\.status, 'active'\) <> 'suppressed'/);
  });
});

describe('published hash feed artifact canonicalization', () => {
  let prevRead;
  before(() => {
    prevRead = process.env.FILE_ARTIFACTS_READ_ENABLED;
  });
  after(() => {
    if (prevRead == null) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prevRead;
  });

  it('enables canonicalize only for hash feeds when READ on', () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    assert.equal(shouldCanonicalizePublishedHashFeed({ ioc_type: 'hash' }), true);
    assert.equal(shouldCanonicalizePublishedHashFeed({ ioc_type: 'ip' }), false);
    delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    assert.equal(shouldCanonicalizePublishedHashFeed({ ioc_type: 'hash' }), false);
  });

  it('filtersHash changes when artifact canonicalization toggles', () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    const on = filtersHash({ ioc_type: 'hash' }, 'all');
    delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    const off = filtersHash({ ioc_type: 'hash' }, 'all');
    assert.notEqual(on, off);
  });

  it('fingerprint counts distinct artifact identity when READ on', async () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    let capturedSql = '';
    const pool = {
      async query(sql) {
        capturedSql = String(sql).replace(/\s+/g, ' ').trim();
        return { rows: [{ item_count: 1, max_recency: null }] };
      }
    };
    const fp = await fetchIocExportFingerprint(pool, { ioc_type: 'hash', exclude_expired: true }, 'all');
    assert.equal(fp.itemCount, 1);
    assert.match(capturedSql, /file_artifact_ioc_links/);
    assert.match(capturedSql, /COUNT\(DISTINCT/);
    assert.match(capturedSql, /'a:' \|\|/);
    assert.doesNotMatch(capturedSql, /COUNT\(DISTINCT lower\(i\.observable\)\)/);
  });

  it('fetchIocRows projects primary hash and groups by artifact identity', async () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    let capturedSql = '';
    const pool = {
      async query(sql) {
        capturedSql = String(sql).replace(/\s+/g, ' ').trim();
        return {
          rows: [{
            observable: 'aa'.repeat(32),
            observable_type: 'sha256',
            confidence: 'high',
            category: null,
            source_name: 'MalwareBazaar',
            recency_ts: new Date()
          }]
        };
      }
    };
    const rows = await fetchIocRows(pool, { ioc_type: 'hash', exclude_expired: true }, 'all');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].observable_type, 'sha256');
    assert.match(capturedSql, /DISTINCT ON \(identity_key\)/);
    assert.match(capturedSql, /primary_hash_value/);
    assert.match(capturedSql, /GROUP BY|identity_key/);
  });

  it('legacy hash fingerprint stays raw when READ off', async () => {
    delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    let capturedSql = '';
    const pool = {
      async query(sql) {
        capturedSql = String(sql).replace(/\s+/g, ' ').trim();
        return { rows: [{ item_count: 2, max_recency: null }] };
      }
    };
    await fetchIocExportFingerprint(pool, { ioc_type: 'hash', exclude_expired: true }, 'all');
    assert.match(capturedSql, /COUNT\(DISTINCT lower\(i\.observable\)\)/);
    assert.doesNotMatch(capturedSql, /file_artifact_ioc_links/);
  });
});
