import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generationWindowsForFeed,
  resolveConfiguredFeedWindow,
  normalizeTimeWindow,
  retireObsoletePublicWindowGenerations,
  FEED_FILTER_MODES
} from './feedPublisherService.js';

test('normalizeTimeWindow accepts aliases and rejects junk', () => {
  assert.equal(normalizeTimeWindow('all'), 'all');
  assert.equal(normalizeTimeWindow('7d'), '7d');
  assert.equal(normalizeTimeWindow('last_7_days'), '7d');
  assert.equal(normalizeTimeWindow('nope'), null);
});

test('generationWindowsForFeed returns only the configured Basic window', () => {
  assert.deepEqual(
    generationWindowsForFeed({ filter_mode: 'basic', time_window: 'all' }),
    ['all']
  );
  assert.deepEqual(
    generationWindowsForFeed({ filter_mode: 'basic', time_window: '1d' }),
    ['1d']
  );
  assert.deepEqual(
    generationWindowsForFeed({ filter_mode: 'basic', time_window: '3d' }),
    ['3d']
  );
  assert.deepEqual(
    generationWindowsForFeed({ filter_mode: 'basic', time_window: '7d' }),
    ['7d']
  );
});

test('generationWindowsForFeed ignores alternate options.window', () => {
  assert.deepEqual(
    generationWindowsForFeed(
      { filter_mode: 'basic', time_window: 'all' },
      { window: '1d' }
    ),
    ['all']
  );
  assert.deepEqual(
    generationWindowsForFeed(
      { filter_mode: 'basic', time_window: '7d' },
      { window: '7d' }
    ),
    ['7d']
  );
});

test('Query-mode feeds always generate all', () => {
  assert.deepEqual(
    generationWindowsForFeed({
      filter_mode: FEED_FILTER_MODES.QUERY,
      advanced_query: 'type equals "domain"',
      time_window: '1d'
    }),
    ['all']
  );
  assert.equal(
    resolveConfiguredFeedWindow({
      filter_mode: FEED_FILTER_MODES.QUERY,
      advanced_query: 'type equals "ip"',
      time_window: '7d'
    }),
    'all'
  );
});

test('retireObsoletePublicWindowGenerations keeps only configured window', async () => {
  const calls = [];
  const db = {
    async query(sql, params = []) {
      calls.push({ sql: String(sql), params });
      if (String(sql).includes('DELETE FROM published_feed_active_generations')) {
        return {
          rows: [
            { generation_id: 'g-1d', snapshot_window: '1d' },
            { generation_id: 'g-3d', snapshot_window: '3d' }
          ]
        };
      }
      if (String(sql).includes('UPDATE published_feed_generations')) {
        return { rowCount: 1, rows: [{ id: params[0] }] };
      }
      if (String(sql).includes('UPDATE published_feed_snapshots')
        && String(sql).includes("status = 'failed'")) {
        return { rowCount: 4, rows: [] };
      }
      if (String(sql).includes('UPDATE published_feed_snapshots')
        && String(sql).includes('chunk_owned')) {
        return { rows: [] };
      }
      throw new Error(`unexpected sql: ${String(sql).slice(0, 100)}`);
    }
  };
  const result = await retireObsoletePublicWindowGenerations(db, 11, 'all');
  assert.equal(result.removedActive, 2);
  assert.deepEqual(result.windows.sort(), ['1d', '3d']);
  assert.equal(result.superseded, 2);
  assert.ok(calls.some((c) => c.sql.includes('DELETE FROM published_feed_active_generations')));
});

test('window transitions retire every alternate public window for each IOC type', async () => {
  const transitions = [
    ['all', '7d'],
    ['7d', '3d'],
    ['3d', '1d'],
    ['1d', 'all']
  ];
  for (const ioc of ['ip', 'domain', 'url', 'hash']) {
    for (const [from, to] of transitions) {
      assert.deepEqual(
        generationWindowsForFeed({ filter_mode: 'basic', time_window: from, ioc_types: [ioc] }),
        [from]
      );
      assert.deepEqual(
        generationWindowsForFeed({ filter_mode: 'basic', time_window: to, ioc_types: [ioc] }),
        [to]
      );
      const retired = [];
      const db = {
        async query(sql, params = []) {
          if (String(sql).includes('DELETE FROM published_feed_active_generations')) {
            const keep = params[1];
            const all = ['1d', '3d', '7d', 'all'];
            return {
              rows: all.filter((w) => w !== keep).map((w) => ({
                generation_id: `g-${w}`,
                snapshot_window: w
              }))
            };
          }
          if (String(sql).includes('UPDATE published_feed_generations')) {
            retired.push(params[0]);
            return { rowCount: 1, rows: [{ id: params[0] }] };
          }
          if (String(sql).includes('UPDATE published_feed_snapshots')) {
            return { rowCount: 1, rows: [] };
          }
          return { rows: [] };
        }
      };
      const result = await retireObsoletePublicWindowGenerations(db, 99, to);
      assert.equal(result.removedActive, 3, `${ioc} ${from}->${to}`);
      assert.ok(!result.windows.includes(to));
      assert.equal(retired.length, 3);
    }
  }
});
