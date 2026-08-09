import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  isPublishedFeedDue,
  regenerateAllEnabledFeeds,
  resolvePublishedFeedTickMs,
  PUBLISHED_FEED_TICK_MS_DEFAULT,
  PUBLISHED_FEED_TICK_MS_MIN
} from './feedPublisherService.js';

const MIN = 60 * 1000;

describe('resolvePublishedFeedTickMs', () => {
  it('defaults to 60s', () => {
    assert.equal(resolvePublishedFeedTickMs(undefined), PUBLISHED_FEED_TICK_MS_DEFAULT);
    assert.equal(resolvePublishedFeedTickMs(''), PUBLISHED_FEED_TICK_MS_DEFAULT);
    assert.equal(resolvePublishedFeedTickMs('nope'), PUBLISHED_FEED_TICK_MS_DEFAULT);
  });

  it('respects explicit override and clamps below floor', () => {
    assert.equal(resolvePublishedFeedTickMs('60000'), 60_000);
    assert.equal(resolvePublishedFeedTickMs('120000'), 120_000);
    assert.equal(resolvePublishedFeedTickMs('1000'), PUBLISHED_FEED_TICK_MS_MIN);
  });
});

describe('isPublishedFeedDue — cadence contract', () => {
  it('A: 5m interval / ~45s job → due near start+5m, not start+10m', () => {
    const start = Date.parse('2026-08-09T12:00:00.000Z');
    const durationMs = 45 * 1000;
    const complete = start + durationMs;
    const row = {
      enabled: true,
      refresh_interval_minutes: 5,
      last_generated_at: new Date(complete).toISOString(),
      last_refresh_ms: durationMs
    };

    // Just before start+5m: not due
    assert.equal(isPublishedFeedDue(row, start + 5 * MIN - 1), false);
    // At start+5m: due
    assert.equal(isPublishedFeedDue(row, start + 5 * MIN), true);
    // Still well before the old ~10m failure mode
    assert.equal(isPublishedFeedDue(row, start + 6 * MIN), true);
    assert.equal(isPublishedFeedDue(row, start + 9 * MIN), true);

    // Simulate successive scheduled starts at 0/5/10/15 using 1m poll resolution
    const starts = [start];
    let t = start;
    for (let i = 0; i < 3; i += 1) {
      const runStart = t;
      const runComplete = runStart + durationMs;
      const after = {
        ...row,
        last_generated_at: new Date(runComplete).toISOString(),
        last_refresh_ms: durationMs
      };
      // Advance in 1m ticks until due
      let next = runComplete;
      while (!isPublishedFeedDue(after, next)) next += MIN;
      starts.push(next);
      t = next;
    }
    const spacings = starts.slice(1).map((s, i) => s - starts[i]);
    for (const sp of spacings) {
      assert.ok(sp >= 5 * MIN && sp <= 6 * MIN, `spacing ${sp}ms not in 5–6m`);
    }
  });

  it('C: 15m feed is not due every minute', () => {
    const start = Date.parse('2026-08-09T12:00:00.000Z');
    const row = {
      enabled: true,
      refresh_interval_minutes: 15,
      last_generated_at: new Date(start + 30_000).toISOString(),
      last_refresh_ms: 30_000
    };
    assert.equal(isPublishedFeedDue(row, start + 1 * MIN), false);
    assert.equal(isPublishedFeedDue(row, start + 5 * MIN), false);
    assert.equal(isPublishedFeedDue(row, start + 14 * MIN), false);
    assert.equal(isPublishedFeedDue(row, start + 15 * MIN), true);
  });

  it('D: long-running job > interval becomes due once after completion (no backlog math)', () => {
    const start = Date.parse('2026-08-09T12:00:00.000Z');
    const durationMs = 7 * MIN; // longer than 5m interval
    const complete = start + durationMs;
    const row = {
      enabled: true,
      refresh_interval_minutes: 5,
      last_generated_at: new Date(complete).toISOString(),
      last_refresh_ms: durationMs
    };
    // Immediately due after a long job (one catch-up), not N missed slots
    assert.equal(isPublishedFeedDue(row, complete), true);
    assert.equal(isPublishedFeedDue(row, complete + 1), true);
  });

  it('E: restart with persisted timestamps yields sensible next due', () => {
    const start = Date.parse('2026-08-09T12:00:00.000Z');
    const row = {
      enabled: true,
      refresh_interval_minutes: 5,
      last_generated_at: new Date(start + 40_000).toISOString(),
      last_refresh_ms: 40_000
    };
    // Restart at start+2m: not due
    assert.equal(isPublishedFeedDue(row, start + 2 * MIN), false);
    // Restart at start+5m: due once
    assert.equal(isPublishedFeedDue(row, start + 5 * MIN), true);
  });

  it('G: disabled feed never due', () => {
    assert.equal(
      isPublishedFeedDue({
        enabled: false,
        refresh_interval_minutes: 5,
        last_generated_at: null
      }),
      false
    );
  });

  it('H: interval change 15→5 becomes due; 5→15 does not over-run', () => {
    const start = Date.parse('2026-08-09T12:00:00.000Z');
    const base = {
      enabled: true,
      last_generated_at: new Date(start + 20_000).toISOString(),
      last_refresh_ms: 20_000
    };
    assert.equal(isPublishedFeedDue({ ...base, refresh_interval_minutes: 15 }, start + 6 * MIN), false);
    assert.equal(isPublishedFeedDue({ ...base, refresh_interval_minutes: 5 }, start + 6 * MIN), true);
    assert.equal(isPublishedFeedDue({ ...base, refresh_interval_minutes: 15 }, start + 10 * MIN), false);
  });

  it('never-generated feed is due', () => {
    assert.equal(isPublishedFeedDue({ enabled: true, refresh_interval_minutes: 15, last_generated_at: null }), true);
  });

  it('completion-only rows (no last_refresh_ms) still due after full interval from completion', () => {
    const complete = Date.parse('2026-08-09T12:00:45.000Z');
    const row = {
      enabled: true,
      refresh_interval_minutes: 5,
      last_generated_at: new Date(complete).toISOString(),
      last_refresh_ms: null
    };
    assert.equal(isPublishedFeedDue(row, complete + 5 * MIN - 1), false);
    assert.equal(isPublishedFeedDue(row, complete + 5 * MIN), true);
  });
});

describe('regenerateAllEnabledFeeds — cheap due gate', () => {
  it('B: non-due feed does not invoke generation', async () => {
    const start = Date.parse('2026-08-09T12:00:00.000Z');
    let generateCalls = 0;
    const pool = {
      async query(sql) {
        if (String(sql).includes('FROM published_feeds')) {
          return {
            rows: [{
              id: 11,
              name: 'Domain',
              enabled: true,
              refresh_interval_minutes: 15,
              last_generated_at: new Date(start + 10_000).toISOString(),
              last_refresh_ms: 10_000
            }]
          };
        }
        generateCalls += 1;
        throw new Error(`unexpected query: ${String(sql).slice(0, 80)}`);
      },
      async connect() {
        generateCalls += 1;
        throw new Error('connect should not run for non-due feed');
      }
    };

    // Patch generate via a local stub: regenerateAllEnabledFeeds imports generate from same module.
    // We only assert the SELECT path + due filter by ensuring no connect/generation side effects.
    const result = await regenerateAllEnabledFeeds(pool, { nowMs: start + 2 * MIN });
    assert.equal(result.checked, 1);
    assert.equal(result.due, 0);
    assert.deepEqual(result.due_ids, []);
    assert.equal(generateCalls, 0);
  });

  it('F: due feed invokes generatePublishedFeedSnapshot once (manual/schedule share path)', async () => {
    const start = Date.parse('2026-08-09T12:00:00.000Z');
    let connects = 0;
    const client = {
      async query(sql) {
        const s = String(sql);
        if (s.includes('pg_try_advisory_lock')) return { rows: [{ ok: true }] };
        if (s.includes('pg_advisory_unlock')) return { rows: [] };
        if (s.includes('FROM published_feeds WHERE id')) {
          return {
            rows: [{
              id: 11,
              name: 'Domain',
              ioc_types: ['domain'],
              ioc_type: 'domain',
              time_window: 'all',
              max_items: 1,
              exclude_false_positive: true,
              exclude_expired: true,
              include_feed_keys: null,
              include_tags: null,
              exclude_tags: null,
              min_confidence: null,
              updated_at: '2026-08-01T00:00:00.000Z',
              enabled: true,
              format: 'txt',
              refresh_interval_minutes: 5,
              filter_mode: 'basic',
              projection_status: 'absent'
            }]
          };
        }
        if (s.includes('FROM integration_feeds') || s.includes('FROM ioc_sources') || s.includes('FROM custom_threat_feeds')) {
          return { rows: [] };
        }
        if (s.includes('FROM integration_runs') || s.includes('FROM custom_threat_feed_runs')) {
          return { rows: [{ latest_finished_at: null }] };
        }
        if (s.includes('FROM ioc_') || s.includes('octet_length') || s.includes('FROM published_feed_snapshots')) {
          return { rows: [] };
        }
        if (s.includes('COUNT(') || s.includes('DISTINCT')) return { rows: [] };
        if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') return { rows: [] };
        if (s.includes('pg_advisory_xact_lock')) return { rows: [] };
        if (s.includes('INSERT INTO published_feed_snapshots')) return { rows: [] };
        if (s.includes('UPDATE published_feeds')) return { rows: [] };
        return { rows: [] };
      },
      release() {}
    };
    const pool = {
      async query(sql) {
        if (String(sql).includes('FROM published_feeds') && String(sql).includes('enabled = TRUE')) {
          return {
            rows: [{
              id: 11,
              name: 'Domain',
              enabled: true,
              refresh_interval_minutes: 5,
              last_generated_at: new Date(start + 45_000).toISOString(),
              last_refresh_ms: 45_000
            }]
          };
        }
        return client.query(sql);
      },
      async connect() {
        connects += 1;
        return client;
      }
    };

    const result = await regenerateAllEnabledFeeds(pool, { nowMs: start + 5 * MIN });
    assert.equal(result.due, 1);
    assert.deepEqual(result.due_ids, [11]);
    assert.equal(connects, 1);
  });
});
