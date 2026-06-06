import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { persistPublishedFeedSnapshot } from './feedPublisherService.js';

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

  it('updates metadata only when content hash is unchanged', async () => {
    const { pool, calls } = createMockPool([
      { match: (sql) => sql.includes('pg_advisory_xact_lock'), result: () => ({ rows: [] }) },
      {
        match: (sql) => sql.includes('FOR UPDATE') && sql.includes("status = 'success'"),
        result: () => ({ rows: [{ id: 42, content_hash: 'abc123' }] })
      },
      { match: (sql) => sql.includes('UPDATE published_feed_snapshots'), result: () => ({ rows: [] }) }
    ]);

    await persistPublishedFeedSnapshot(pool, { ...baseSnapshot, itemCount: 5 });

    const update = calls.find((c) => c.sql.startsWith('UPDATE published_feed_snapshots'));
    assert.ok(update);
    assert.equal(update.params.length, 4);
    assert.deepEqual(update.params, [42, 5, 'abc123', JSON.stringify(baseSnapshot.paramsJson)]);
    assert.ok(!update.sql.includes('content ='));
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
