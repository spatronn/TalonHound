/**
 * Regression: analyst-facing IOC relations that SHOULD survive file-hash
 * canonicalization (MD5 → SHA256) via shared artifact identity expansion.
 *
 * Feed memberships and per-source temporal fields intentionally stay IOC-scoped
 * (proven separately) and are not covered here.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isWatchlisted,
  removeFromWatchlist,
  annotateItemsWatchlisted
} from '../userIocWatchlist.js';
import { loadCatalogTags } from '../apiIocService.js';
import { loadEffectiveIocClassificationSlugs } from '../iocThreatClassifications.js';
import { resolveArtifactScopedIocIds } from './read.js';

const MD5_IOC = 3472708;
const SHA256_IOC = 1139687;
const OTHER_IOC = 999001;

function withReadFlag(value, fn) {
  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = value;
  return Promise.resolve(fn()).finally(() => {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  });
}

function linkedPool({ watchlistIocs = [], tagsByIoc = new Map(), classByPair = new Map() } = {}) {
  const pool = {
    queries: [],
    query: async (sql, params = []) => {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      pool.queries.push({ sql: s, params });

      if (s.includes('file_artifact_ioc_links l') && s.includes('JOIN file_artifacts a') && s.includes('ioc_item_id = $1')) {
        const id = Number(params[0]);
        if (id === SHA256_IOC || id === MD5_IOC) {
          return {
            rows: [{
              artifact_id: 'art-canon',
              status: id === MD5_IOC ? 'merged' : 'active',
              merged_into_artifact_id: id === MD5_IOC ? 'art-canon' : null
            }],
            rowCount: 1
          };
        }
        return { rows: [], rowCount: 0 };
      }
      if (s.includes('FROM file_artifacts WHERE id = $1')) {
        return { rows: [{ id: 'art-canon', status: 'active', merged_into_artifact_id: null }], rowCount: 1 };
      }
      if (s.includes('DISTINCT ON (ioc_item_id)') || (s.includes('file_artifact_ioc_links') && s.includes('ioc_public_id'))) {
        return {
          rows: [
            { ioc_item_id: SHA256_IOC, ioc_public_id: 'sha256-pid' },
            { ioc_item_id: MD5_IOC, ioc_public_id: 'md5-pid' }
          ],
          rowCount: 2
        };
      }
      if (s.includes('WITH seeds AS') && s.includes('file_artifact_ioc_links')) {
        const seeds = params[0] || [];
        const rows = [];
        for (const seed of seeds) {
          const n = Number(seed);
          if (n === SHA256_IOC || n === MD5_IOC) {
            rows.push({ seed_id: n, linked_id: SHA256_IOC });
            rows.push({ seed_id: n, linked_id: MD5_IOC });
          } else {
            rows.push({ seed_id: n, linked_id: n });
          }
        }
        return { rows, rowCount: rows.length };
      }
      if (s.includes('FROM user_ioc_watchlist')) {
        if (s.startsWith('DELETE')) {
          const ids = (params[1] || []).map(Number);
          const removed = ids.filter((id) => watchlistIocs.includes(id)).length;
          return { rowCount: removed, rows: [] };
        }
        const ids = Array.isArray(params[1]) ? params[1].map(Number) : [Number(params[2] ?? params[1])];
        const hit = ids.some((id) => watchlistIocs.includes(id));
        if (s.includes('SELECT ioc_id')) {
          return {
            rows: watchlistIocs.filter((id) => ids.includes(id)).map((ioc_id) => ({ ioc_id })),
            rowCount: hit ? 1 : 0
          };
        }
        return { rows: hit ? [{ '?column?': 1 }] : [], rowCount: hit ? 1 : 0 };
      }
      if (s.includes('FROM ioc_tags it')) {
        const ids = (params[0] || []).map(Number);
        const byName = new Map();
        for (const id of ids) {
          for (const t of tagsByIoc.get(id) || []) {
            if (!byName.has(t.name)) byName.set(t.name, { ...t, origins: [...(t.origins || [])] });
            else {
              const cur = byName.get(t.name);
              cur.origins = [...new Set([...(cur.origins || []), ...(t.origins || [])])];
            }
          }
        }
        return { rows: [...byName.values()], rowCount: byName.size };
      }
      if (s.includes('FROM ioc_items WHERE id = ANY')) {
        return {
          rows: [
            { id: SHA256_IOC, observable_type: 'sha256' },
            { id: MD5_IOC, observable_type: 'md5' }
          ]
        };
      }
      if (s.includes('FROM ioc_threat_classifications')) {
        const rows = [];
        for (const [key, slugs] of classByPair.entries()) {
          const [id, type] = key.split('|');
          for (const slug of slugs) {
            rows.push({ ioc_id: Number(id), ioc_observable_type: type, classification_slug: slug });
          }
        }
        return { rows };
      }
      if (s.includes('SELECT threat_classification FROM ioc_items')) {
        return { rows: [{ threat_classification: null }] };
      }
      if (s.includes('FROM ioc_analyst_intelligence')) {
        const ids = (params[0] || []).map(Number);
        const rows = [];
        if (ids.includes(MD5_IOC)) {
          rows.push({
            id: 1,
            ioc_id: MD5_IOC,
            title: 'md5 note',
            deleted_at: null,
            created_at: new Date().toISOString()
          });
        }
        return { rows, rowCount: rows.length };
      }
      throw new Error(`Unexpected SQL: ${s.slice(0, 140)}`);
    }
  };
  return pool;
}

describe('artifact-scoped analyst relations survive hash canonicalization', () => {
  it('resolveArtifactScopedIocIds unions MD5 + SHA256 aliases', async () => {
    await withReadFlag('1', async () => {
      const pool = linkedPool();
      const ids = await resolveArtifactScopedIocIds(pool, SHA256_IOC);
      assert.deepEqual(
        [...ids].sort((a, b) => a - b),
        [MD5_IOC, SHA256_IOC].sort((a, b) => a - b)
      );
    });
  });

  it('Watchlist: MD5 star remains visible on canonical SHA256', async () => {
    await withReadFlag('1', async () => {
      const pool = linkedPool({ watchlistIocs: [MD5_IOC] });
      assert.equal(await isWatchlisted(pool, 7, { ioc_id: SHA256_IOC, observable_type: 'sha256' }), true);
    });
  });

  it('Watchlist: unrelated artifact does not inherit the star', async () => {
    await withReadFlag('1', async () => {
      const pool = linkedPool({ watchlistIocs: [MD5_IOC] });
      // Override: OTHER has no artifact link
      const orig = pool.query.bind(pool);
      pool.query = async (sql, params = []) => {
        const s = String(sql);
        if (s.includes('file_artifact_ioc_links l') && s.includes('ioc_item_id = $1')) {
          return { rows: [], rowCount: 0 };
        }
        if (s.includes('FROM user_ioc_watchlist')) {
          const ids = Array.isArray(params[1]) ? params[1].map(Number) : [Number(params[2])];
          const hit = ids.includes(MD5_IOC);
          return { rows: hit ? [{ '?column?': 1 }] : [], rowCount: hit ? 1 : 0 };
        }
        return orig(sql, params);
      };
      assert.equal(await isWatchlisted(pool, 7, { ioc_id: OTHER_IOC, observable_type: 'md5' }), false);
    });
  });

  it('Watchlist: unstar on canonical clears alias stars exactly once group', async () => {
    await withReadFlag('1', async () => {
      const pool = linkedPool({ watchlistIocs: [MD5_IOC, SHA256_IOC] });
      const res = await removeFromWatchlist(pool, 7, { ioc_id: SHA256_IOC, observable_type: 'sha256' });
      assert.equal(res.removed, true);
    });
  });

  it('Watchlist list annotation: collapsed SHA256 identity shows star from MD5', async () => {
    await withReadFlag('1', async () => {
      const pool = linkedPool({ watchlistIocs: [MD5_IOC] });
      const items = [{ id: SHA256_IOC, observable_type: 'sha256' }];
      await annotateItemsWatchlisted(pool, 7, items);
      assert.equal(items[0].watchlisted, true);
    });
  });

  it('Tags: MD5 catalog tag surfaces on canonical SHA256 once', async () => {
    await withReadFlag('1', async () => {
      const tagsByIoc = new Map([
        [MD5_IOC, [{ name: 'dtrack', type: 'malware', origins: ['manual'], source_name: null }]],
        [SHA256_IOC, [{ name: 'dtrack', type: 'malware', origins: ['manual'], source_name: null }]]
      ]);
      const pool = linkedPool({ tagsByIoc });
      const tags = await loadCatalogTags(pool, SHA256_IOC, 'sha256');
      assert.equal(tags.length, 1);
      assert.equal(tags[0].name, 'dtrack');
    });
  });

  it('Classifications: MD5 analyst junction slug surfaces on canonical SHA256', async () => {
    await withReadFlag('1', async () => {
      const classByPair = new Map([
        [`${MD5_IOC}|md5`, ['malware']]
      ]);
      const pool = linkedPool({ classByPair });
      const slugs = await loadEffectiveIocClassificationSlugs(pool, SHA256_IOC, 'sha256', null);
      assert.deepEqual(slugs, ['malware']);
    });
  });

  it('Analyst Intelligence: MD5 reference remains listed on canonical SHA256', async () => {
    await withReadFlag('1', async () => {
      const pool = linkedPool();
      const scoped = await resolveArtifactScopedIocIds(pool, SHA256_IOC);
      const { rows } = await pool.query(
        `SELECT * FROM ioc_analyst_intelligence WHERE ioc_id = ANY($1::bigint[]) AND deleted_at IS NULL ORDER BY created_at DESC`,
        [scoped]
      );
      assert.equal(rows.length, 1);
      assert.equal(rows[0].ioc_id, MD5_IOC);
      assert.equal(rows[0].title, 'md5 note');
    });
  });
});
