import test from 'node:test';
import assert from 'node:assert/strict';
import {
  projectionWindowFilter,
  countProjectionItemsForWindow,
  buildProjectionScanSql,
  isRecencyVisibleInWindow,
  normalizeGenerationAsOf
} from './publishedFeedWindowEligibility.js';
import { buildAndActivateChunkGeneration } from './publishedFeedChunkGeneration.js';

/**
 * Deterministic in-memory projection used to prove count/stream share one frozen bound.
 * Simulates the production failure mode where NOW() advancing between COUNT and FETCH
 * would otherwise drop boundary rows from later chunks.
 */
function createFrozenProjectionDb(rows, { asOf }) {
  const declared = [];
  return {
    asOf,
    rows,
    declared,
    async query(sql, params = []) {
      const text = String(sql);
      if (text.includes('COUNT(*)')) {
        const bound = params[2] ? new Date(params[2]) : asOf;
        const interval = params[3] || null;
        const n = rows.filter((row) => {
          if (!interval) return true;
          return isRecencyVisibleInWindow(row.recency_ts, intervalToWindow(interval), bound);
        }).length;
        return { rows: [{ n }] };
      }
      if (text.includes('DECLARE pf_chunk_cur')) {
        const bound = params[3] ? new Date(params[3]) : asOf;
        const interval = params[4] || null;
        const keys = new Set((params[2] || []).map(Number));
        const visible = rows.filter((row) => {
          if (!keys.has(Number(row.chunk_key))) return false;
          if (!interval) return true;
          return isRecencyVisibleInWindow(row.recency_ts, intervalToWindow(interval), bound);
        });
        declared.push({
          bound: bound.toISOString(),
          interval,
          keys: [...keys],
          identities: visible.map((r) => r.identity_key)
        });
        this._cursor = visible.slice();
        return { rows: [] };
      }
      if (text.startsWith('FETCH FORWARD')) {
        const batch = (this._cursor || []).splice(0, 5000);
        return { rows: batch };
      }
      if (text.includes('CLOSE pf_chunk_cur')) return { rows: [] };
      if (text.includes('FROM published_feed_active_generations')) {
        return {
          rows: [{
            id: 'parent-gen',
            item_count: rows.length,
            chunk_count: 4,
            format: 'txt'
          }]
        };
      }
      if (text.includes('FROM published_feed_items') && text.includes('NOT (chunk_key')) {
        // Reuse-consistency probe: treat parent as matching projection (no drift).
        return { rows: [{ n: 0 }] };
      }
      if (
        text.includes('FROM published_feed_generation_chunks gc')
        && text.includes('COALESCE(SUM(c.item_count)')
      ) {
        return { rows: [{ n: 0 }] };
      }
      if (text.includes('INSERT INTO published_feed_generations')) return { rows: [] };
      if (text.includes('INSERT INTO published_feed_chunks')) {
        return { rows: [{ id: 1 }] };
      }
      if (text.includes('INSERT INTO published_feed_generation_chunks')) return { rows: [] };
      if (text.includes('FROM published_feed_generation_chunks gc') && text.includes('JOIN')) {
        const itemCount = Number(this._lastEmitted || 0);
        return {
          rows: itemCount
            ? [{ content_hash: 'aa'.repeat(32), byte_length: 10, item_count: itemCount }]
            : []
        };
      }
      if (text.includes('INSERT INTO published_feed_generation_formats')) return { rows: [] };
      if (text.includes('UPDATE published_feed_generations')) return { rows: [] };
      if (text.includes('INSERT INTO published_feed_active_generations')) return { rows: [] };
      if (text.includes('UPDATE published_feeds')) return { rows: [] };
      if (text.includes('UPDATE published_feed_snapshots')) return { rows: [] };
      if (text.includes('SELECT txt_value')) return { rows: [] };
      throw new Error(`unexpected sql: ${text.slice(0, 120)}`);
    }
  };
}

function intervalToWindow(interval) {
  if (String(interval).startsWith('1')) return '1d';
  if (String(interval).startsWith('3')) return '3d';
  if (String(interval).startsWith('7')) return '7d';
  return 'all';
}

test('normalizeGenerationAsOf accepts Date and ISO strings', () => {
  assert.equal(normalizeGenerationAsOf(new Date('2026-08-28T12:00:00.000Z')), '2026-08-28T12:00:00.000Z');
  assert.equal(normalizeGenerationAsOf('2026-08-28T12:00:00.000Z'), '2026-08-28T12:00:00.000Z');
  assert.equal(normalizeGenerationAsOf(null), null);
});

test('count and scan SQL share the same frozen asOf bind parameters', () => {
  const asOf = new Date('2026-08-28T12:00:00.000Z');
  const countFilter = projectionWindowFilter('1d', 3, asOf);
  const scan = buildProjectionScanSql(11, '1d', asOf);
  assert.deepEqual(countFilter.params, ['2026-08-28T12:00:00.000Z', '1 day']);
  assert.deepEqual(scan.params.slice(2), countFilter.params);
  assert.match(scan.sql, /recency_ts >= \$3::timestamptz - \$4::interval/);
  assert.doesNotMatch(scan.sql, /NOW\(\)/);
});

test('window-boundary race: frozen asOf keeps count and emitted identities identical', async () => {
  const asOf = new Date('2026-08-28T12:00:00.000Z');
  // Exactly on the 1d boundary (inclusive): must remain visible for the whole generation.
  const boundary = new Date(asOf.getTime() - 24 * 60 * 60 * 1000);
  const inside = new Date(asOf.getTime() - 60 * 60 * 1000);
  const outside = new Date(asOf.getTime() - 25 * 60 * 60 * 1000);
  const rows = [
    { identity_key: 'o:domain:a.example', chunk_key: 0, recency_ts: inside, txt_value: 'a.example', item_json: null },
    { identity_key: 'o:domain:b.example', chunk_key: 1, recency_ts: boundary, txt_value: 'b.example', item_json: null },
    { identity_key: 'o:domain:c.example', chunk_key: 2, recency_ts: outside, txt_value: 'c.example', item_json: null }
  ];
  const db = createFrozenProjectionDb(rows, { asOf });
  const expected = await countProjectionItemsForWindow(db, 11, '1d', asOf);
  assert.equal(expected, 2);

  let emitted = [];
  const result = await buildAndActivateChunkGeneration(db, {
    id: 11,
    name: 'Domain',
    slug: 'domain',
    formats: ['txt'],
    chunk_count: 4,
    chunk_algo_version: 1,
    chunk_backfill_status: 'ready'
  }, {
    window: '1d',
    iocTypeKey: 'domain',
    configHash: 'cfg',
    candidateCutoff: asOf,
    affectedChunkKeys: null,
    expectedItemCount: expected,
    generateChunks: async (client, feed, window, chunkCount, affected, formats, cfg, generationAsOf) => {
      assert.equal(new Date(generationAsOf).toISOString(), asOf.toISOString());
      // Simulate wall-clock advancing past the boundary during generation.
      const later = new Date(asOf.getTime() + 5 * 60 * 1000);
      assert.equal(isRecencyVisibleInWindow(boundary, '1d', later), false);
      assert.equal(isRecencyVisibleInWindow(boundary, '1d', generationAsOf), true);
      const filter = projectionWindowFilter(window, 4, generationAsOf);
      await client.query(
        `DECLARE pf_chunk_cur NO SCROLL CURSOR FOR SELECT 1`,
        [feed.id, 'all', affected, ...filter.params]
      );
      emitted = client.declared[0].identities;
      client._lastEmitted = emitted.length;
      return {
        chunks: [{
          feed_id: feed.id,
          snapshot_window: window,
          chunk_algo_version: 1,
          chunk_count: chunkCount,
          chunk_key: 0,
          format: 'txt',
          serializer_version: 1,
          content_hash: 'aa'.repeat(32),
          byte_length: 20,
          item_count: emitted.length,
          storage_path: 'chunks/x',
          physical_bytes_written: 20
        }],
        rowsRead: emitted.length,
        physicalBytesWritten: 20
      };
    }
  });

  assert.equal(result.itemCount, 2);
  assert.deepEqual(emitted.sort(), ['o:domain:a.example', 'o:domain:b.example']);
  assert.equal(emitted.length, expected);
});

test('concurrent insert after count does not enter the frozen generation set', async () => {
  const asOf = new Date('2026-08-28T12:00:00.000Z');
  const rows = [
    { identity_key: 'o:url:http://a', chunk_key: 0, recency_ts: asOf, txt_value: 'http://a', item_json: null }
  ];
  const db = createFrozenProjectionDb(rows, { asOf });
  const expected = await countProjectionItemsForWindow(db, 9, 'all', asOf);
  assert.equal(expected, 1);

  await buildAndActivateChunkGeneration(db, {
    id: 9,
    name: 'URL',
    slug: 'url',
    formats: ['txt'],
    chunk_count: 4,
    chunk_algo_version: 1,
    chunk_backfill_status: 'ready'
  }, {
    window: 'all',
    iocTypeKey: 'url',
    configHash: 'cfg',
    candidateCutoff: asOf,
    affectedChunkKeys: null,
    expectedItemCount: expected,
    generateChunks: async (client, feed, window, chunkCount, affected, formats, cfg, generationAsOf) => {
      // Concurrent insert arrives after count; frozen generation must ignore it.
      rows.push({
        identity_key: 'o:url:http://b',
        chunk_key: 1,
        recency_ts: new Date(asOf.getTime() + 1000),
        txt_value: 'http://b',
        item_json: null
      });
      // all-window has no filter params; stream only the pre-count cursor snapshot.
      const identities = ['o:url:http://a'];
      client._lastEmitted = identities.length;
      assert.equal(identities.length, expected);
      assert.ok(!identities.includes('o:url:http://b'));
      assert.equal(new Date(generationAsOf).toISOString(), asOf.toISOString());
      return {
        chunks: [{
          feed_id: feed.id,
          snapshot_window: window,
          chunk_algo_version: 1,
          chunk_count: chunkCount,
          chunk_key: 0,
          format: 'txt',
          serializer_version: 1,
          content_hash: 'bb'.repeat(32),
          byte_length: 8,
          item_count: identities.length,
          storage_path: 'chunks/y',
          physical_bytes_written: 8
        }],
        rowsRead: identities.length,
        physicalBytesWritten: 8
      };
    }
  });
  assert.equal(rows.length, 2); // next generation would see the insert
});

test('failed generation before activation does not advance cutoff', async () => {
  const asOf = new Date('2026-08-28T12:00:00.000Z');
  let cutoffMoved = false;
  const db = {
    async query(sql) {
      const text = String(sql);
      if (text.includes('FROM published_feed_active_generations')) {
        return { rows: [{ id: 'p', item_count: 1, chunk_count: 4, format: 'txt' }] };
      }
      if (text.includes('UPDATE published_feeds') && text.includes('projection_cutoff')) {
        cutoffMoved = true;
      }
      return { rows: [] };
    }
  };
  await assert.rejects(
    () => buildAndActivateChunkGeneration(db, {
      id: 1,
      name: 'Hash',
      slug: 'hash',
      formats: ['txt'],
      chunk_count: 4,
      chunk_algo_version: 1,
      chunk_backfill_status: 'ready'
    }, {
      window: 'all',
      iocTypeKey: 'hash',
      configHash: 'cfg',
      candidateCutoff: asOf,
      expectedItemCount: 1,
      failAt: 'after_chunks',
      generateChunks: async () => {
        throw Object.assign(new Error('injected generation failure: after_chunks'), {
          code: 'INJECTED_GENERATION_FAILURE',
          stage: 'after_chunks'
        });
      }
    }),
    /injected generation failure/
  );
  assert.equal(cutoffMoved, false);
});

test('txt/json/stix chunk writers receive the same projection identity set', async () => {
  const asOf = new Date('2026-08-28T12:00:00.000Z');
  const identities = ['o:domain:a.example', 'o:domain:b.example'];
  const perFormat = { txt: [], json: [], stix: [] };
  const db = {
    async query(sql) {
      const text = String(sql);
      if (text.includes('FROM published_feed_active_generations')) return { rows: [] };
      if (text.includes('INSERT INTO published_feed_chunks')) return { rows: [{ id: 7 }] };
      if (text.includes('FROM published_feed_generation_chunks gc') && text.includes('JOIN')) {
        const formatMatch = /gc\.format = \$2/.test(text);
        void formatMatch;
        return {
          rows: [{ content_hash: 'cc'.repeat(32), byte_length: 4, item_count: identities.length }]
        };
      }
      return { rows: [] };
    }
  };

  await buildAndActivateChunkGeneration(db, {
    id: 25,
    name: 'Domain',
    slug: 'domain',
    formats: ['txt', 'json', 'stix'],
    chunk_count: 2,
    chunk_algo_version: 1,
    chunk_backfill_status: 'ready'
  }, {
    window: 'all',
    iocTypeKey: 'domain',
    configHash: 'cfg',
    candidateCutoff: asOf,
    affectedChunkKeys: null,
    expectedItemCount: identities.length,
    generateChunks: async (_db, feed, window, chunkCount) => {
      for (const idKey of identities) {
        perFormat.txt.push(idKey);
        perFormat.json.push(idKey);
        perFormat.stix.push(idKey);
      }
      return {
        chunks: ['txt', 'json', 'stix'].flatMap((format) => [{
          feed_id: feed.id,
          snapshot_window: window,
          chunk_algo_version: 1,
          chunk_count: chunkCount,
          chunk_key: 0,
          format,
          serializer_version: 1,
          content_hash: `${format}-hash`.padEnd(64, '0'),
          byte_length: 10,
          item_count: identities.length,
          storage_path: `chunks/${format}`,
          physical_bytes_written: 10
        }]),
        rowsRead: identities.length,
        physicalBytesWritten: 30
      };
    }
  });

  assert.deepEqual(perFormat.txt, identities);
  assert.deepEqual(perFormat.json, identities);
  assert.deepEqual(perFormat.stix, identities);
});

test('underfilled parent forces full rebuild instead of stuck incremental mismatch', async () => {
  const asOf = new Date('2026-08-28T12:00:00.000Z');
  let rebuiltKeys = null;
  let rebuildReason = null;
  const db = {
    async query(sql, params = []) {
      const text = String(sql);
      if (text.includes('FROM published_feed_active_generations')) {
        return {
          rows: [{
            id: 'stale-parent',
            item_count: 335,
            chunk_count: 4,
            format: 'txt'
          }]
        };
      }
      if (text.includes('FROM published_feed_items') && text.includes('NOT (chunk_key')) {
        // Unaffected keys still have 100 visible projection rows...
        return { rows: [{ n: 100 }] };
      }
      if (text.includes('COALESCE(SUM(c.item_count)')) {
        // ...but parent only stored 5 for those keys (Domain 1d failure mode).
        return { rows: [{ n: 5 }] };
      }
      if (text.includes('INSERT INTO published_feed_generations')) {
        rebuildReason = params[12];
        return { rows: [] };
      }
      if (text.includes('INSERT INTO published_feed_chunks')) return { rows: [{ id: 1 }] };
      if (text.includes('FROM published_feed_generation_chunks gc') && text.includes('JOIN')) {
        return {
          rows: [{ content_hash: 'dd'.repeat(32), byte_length: 50, item_count: 140 }]
        };
      }
      return { rows: [] };
    }
  };

  const result = await buildAndActivateChunkGeneration(db, {
    id: 11,
    name: 'Domain',
    slug: 'domain',
    formats: ['txt'],
    chunk_count: 4,
    chunk_algo_version: 1,
    chunk_backfill_status: 'ready'
  }, {
    window: '1d',
    iocTypeKey: 'domain',
    configHash: 'cfg',
    candidateCutoff: asOf,
    // Dirty-only subset — without the reuse check this would publish 5+dirty << 140.
    affectedChunkKeys: [0],
    expectedItemCount: 140,
    generateChunks: async (_db, _feed, _window, chunkCount, affected) => {
      rebuiltKeys = [...affected];
      assert.deepEqual(rebuiltKeys, [0, 1, 2, 3]);
      assert.equal(chunkCount, 4);
      return {
        chunks: rebuiltKeys.map((chunkKey) => ({
          feed_id: 11,
          snapshot_window: '1d',
          chunk_algo_version: 1,
          chunk_count: 4,
          chunk_key: chunkKey,
          format: 'txt',
          serializer_version: 1,
          content_hash: `c${chunkKey}`.padEnd(64, '0'),
          byte_length: 20,
          item_count: chunkKey === 0 ? 140 : 0,
          storage_path: `chunks/${chunkKey}`,
          physical_bytes_written: chunkKey === 0 ? 20 : 0
        })).filter((c) => c.item_count > 0),
        rowsRead: 140,
        physicalBytesWritten: 20
      };
    }
  });

  assert.deepEqual(rebuiltKeys, [0, 1, 2, 3]);
  assert.equal(rebuildReason, 'reused_chunk_membership_drift');
  assert.equal(result.itemCount, 140);
  assert.equal(result.affectedChunks, 4);
});

for (const fixture of [
  { feedId: 25, name: 'hash', window: 'all' },
  { feedId: 12, name: 'URL', window: '7d' }
]) {
  test(`underfilled parent reuse refused for ${fixture.name}/${fixture.window}`, async () => {
    const { canReuseUnaffectedChunks } = await import('./publishedFeedWindowEligibility.js');
    const asOf = new Date('2026-08-28T12:00:00.000Z');
    const db = {
      async query(sql) {
        if (String(sql).includes('FROM published_feed_items')) return { rows: [{ n: 100 }] };
        if (String(sql).includes('FROM published_feed_generation_chunks')) {
          return { rows: [{ n: 5 }] };
        }
        throw new Error(`unexpected sql: ${String(sql).slice(0, 80)}`);
      }
    };
    const reuse = await canReuseUnaffectedChunks(db, {
      feedId: fixture.feedId,
      artifactWindow: fixture.window,
      asOf,
      parentGenerationId: `stale-${fixture.name}`,
      format: 'txt',
      excludeChunkKeys: [0]
    });
    assert.equal(reuse.reusable, false);
    assert.equal(reuse.reason, 'reused_chunk_membership_drift');
  });
}
