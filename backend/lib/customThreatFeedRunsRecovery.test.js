import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  reconcileStaleCustomThreatFeedRuns,
  STALE_CUSTOM_THREAT_FEED_RUN_MESSAGE
} from './customThreatFeedSync.js';

describe('reconcileStaleCustomThreatFeedRuns', () => {
  it('marks stale running runs as failed with the interrupted message', async () => {
    let captured = null;
    const pool = {
      async query(sql, params) {
        captured = { sql: String(sql), params };
        return { rowCount: 2, rows: [{ id: 'a' }, { id: 'b' }] };
      }
    };

    const res = await reconcileStaleCustomThreatFeedRuns(pool, {
      staleAfterMs: 900_000,
      logPrefix: '[test]'
    });

    assert.equal(res.fixedCount, 2);
    assert.equal(res.dryRun, false);
    assert.match(captured.sql, /UPDATE custom_threat_feed_runs/);
    assert.match(captured.sql, /status = 'failed'/);
    assert.match(captured.sql, /status = 'running'/);
    assert.equal(captured.params[0], STALE_CUSTOM_THREAT_FEED_RUN_MESSAGE);
    assert.equal(captured.params[1], '900000');
  });

  it('dryRun only selects without updating', async () => {
    let captured = null;
    const pool = {
      async query(sql, params) {
        captured = { sql: String(sql), params };
        return { rowCount: 1, rows: [{ id: 'x' }] };
      }
    };

    const res = await reconcileStaleCustomThreatFeedRuns(pool, {
      staleAfterMs: 120_000,
      dryRun: true
    });

    assert.equal(res.fixedCount, 1);
    assert.equal(res.dryRun, true);
    assert.match(captured.sql, /SELECT id/);
    assert.doesNotMatch(captured.sql, /UPDATE/);
    assert.equal(captured.params[0], '120000');
  });

  it('clamps staleAfterMs to at least 60s', async () => {
    let captured = null;
    const pool = {
      async query(sql, params) {
        captured = { params };
        return { rowCount: 0, rows: [] };
      }
    };
    await reconcileStaleCustomThreatFeedRuns(pool, { staleAfterMs: 1, dryRun: true });
    assert.equal(captured.params[0], '60000');
  });
});
