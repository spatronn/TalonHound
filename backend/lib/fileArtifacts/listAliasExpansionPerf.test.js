/**
 * Protect IOC-list alias expansion from the 941a811 perf regression:
 * the batch SQL must stay page-scoped (seed ANY array only) and must not
 * use an OR/subplan against file_artifact_ioc_links that nest-loops the
 * full links table × every seed.
 *
 * TEST A–G style coverage for query shape + bounded query count.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  mapIocIdsToArtifactScopedIocIds,
  resolveArtifactScopedIocIds
} from './read.js';
import { annotateItemsWatchlisted } from '../userIocWatchlist.js';
import { enrichItemsWithAnalystIntelligenceCounts } from '../../routes/analystIntelligence.js';

const READ_SRC = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), 'read.js'),
  'utf8'
);

function withReadFlag(value, fn) {
  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = value;
  return Promise.resolve(fn()).finally(() => {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  });
}

describe('mapIocIdsToArtifactScopedIocIds list perf shape', () => {
  it('TEST C/D source: batch SQL is page-scoped and avoids OR-subplan cross join', () => {
    assert.match(READ_SRC, /unnest\(\$1::bigint\[\]\)/);
    assert.match(READ_SRC, /artifact_scope AS/);
    assert.match(READ_SRC, /JOIN file_artifact_ioc_links l ON l\.artifact_id = ascope\.scope_artifact_id/);
    // The pathological 941a811 shape joined links with OR + correlated IN (subplan).
    assert.doesNotMatch(
      READ_SRC,
      /JOIN file_artifact_ioc_links l\s+ON r\.artifact_id IS NOT NULL\s+AND \(\s*l\.artifact_id = r\.artifact_id\s+OR l\.artifact_id IN \(/
    );
  });

  it('TEST C: page_size=25 issues exactly one alias-expansion SQL', async () => {
    await withReadFlag('1', async () => {
      const seeds = Array.from({ length: 25 }, (_, i) => 1000 + i);
      let aliasCalls = 0;
      const pool = {
        query: async (sql, params) => {
          const s = String(sql);
          if (s.includes('artifact_scope') || (s.includes('WITH seeds AS') && s.includes('file_artifact_ioc_links'))) {
            aliasCalls += 1;
            assert.equal(params[0].length, 25);
            return {
              rows: seeds.map((id) => ({ seed_id: id, linked_id: id })),
              rowCount: seeds.length
            };
          }
          throw new Error(`unexpected sql: ${s.slice(0, 120)}`);
        }
      };
      const map = await mapIocIdsToArtifactScopedIocIds(pool, seeds);
      assert.equal(aliasCalls, 1);
      assert.equal(map.size, 25);
    });
  });

  it('TEST D: page_size=100 still issues exactly one alias-expansion SQL', async () => {
    await withReadFlag('1', async () => {
      const seeds = Array.from({ length: 100 }, (_, i) => 2000 + i);
      let aliasCalls = 0;
      const pool = {
        query: async (sql, params) => {
          const s = String(sql);
          if (s.includes('artifact_scope')) {
            aliasCalls += 1;
            assert.equal(params[0].length, 100);
            return { rows: seeds.map((id) => ({ seed_id: id, linked_id: id })), rowCount: 100 };
          }
          throw new Error(s.slice(0, 80));
        }
      };
      await mapIocIdsToArtifactScopedIocIds(pool, seeds);
      assert.equal(aliasCalls, 1);
    });
  });

  it('TEST B/E: shared linkedBySeed preserves alias watchlist without a second expansion', async () => {
    await withReadFlag('1', async () => {
      let aliasCalls = 0;
      const linkedBySeed = new Map([
        [10, [10, 11]],
        [20, [20]]
      ]);
      const pool = {
        query: async (sql) => {
          const s = String(sql);
          if (s.includes('artifact_scope') || s.includes('WITH seeds AS')) {
            aliasCalls += 1;
            return { rows: [], rowCount: 0 };
          }
          if (s.includes('FROM user_ioc_watchlist')) {
            return { rows: [{ ioc_id: 11 }], rowCount: 1 };
          }
          if (s.includes('FROM ioc_analyst_intelligence')) {
            return {
              rows: [{ ioc_id: 11, analyst_intelligence_count: 1, supports_malicious_count: 0, needs_review_count: 0 }],
              rowCount: 1
            };
          }
          throw new Error(s.slice(0, 80));
        }
      };
      const items = [{ id: 10, observable_type: 'sha256' }, { id: 20, observable_type: 'ip' }];
      await annotateItemsWatchlisted(pool, 1, items, { linkedBySeed });
      const counts = await enrichItemsWithAnalystIntelligenceCounts(pool, items, { linkedBySeed });
      assert.equal(aliasCalls, 0, 'precomputed map must skip expansion SQL');
      assert.equal(items[0].watchlisted, true);
      assert.equal(items[1].watchlisted, false);
      assert.equal(counts.get('10|sha256')?.analyst_intelligence_count, 1);
      assert.equal(counts.get('20|ip')?.analyst_intelligence_count || 0, 0);
    });
  });

  it('TEST E: unrelated seed does not inherit another artifact alias', async () => {
    await withReadFlag('1', async () => {
      const pool = {
        query: async (sql, params) => {
          const s = String(sql);
          if (s.includes('artifact_scope')) {
            // Only seed 1 maps to alias 2; seed 99 has no link rows → stays [99]
            return {
              rows: [
                { seed_id: 1, linked_id: 1 },
                { seed_id: 1, linked_id: 2 }
              ]
            };
          }
          throw new Error(s.slice(0, 80));
        }
      };
      const map = await mapIocIdsToArtifactScopedIocIds(pool, [1, 99]);
      assert.deepEqual([...map.get(1)].sort((a, b) => a - b), [1, 2]);
      assert.deepEqual(map.get(99), [99]);
    });
  });
});
