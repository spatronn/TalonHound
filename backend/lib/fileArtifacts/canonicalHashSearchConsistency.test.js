/**
 * Regression: proven MD5/SHA1/SHA256 aliases must share one logical-file search
 * identity. List canonicalization may display the primary SHA256 while sources
 * remain on the MD5 IOC — enrichment must follow artifact scope, not rewritten
 * display type/value. Unrelated artifacts must never inherit memberships.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseSearchQuery, buildWhereClause } from '../iocSearchDsl/index.js';
import { enrichItemsWithActiveSourceCounts } from '../iocActiveSources.js';
import { buildDisplayConfidenceForItems } from '../iocConfidence.js';
import { canonicalizeRowsByIdentity } from './canonicalListSql.js';
import { decorateIocListItems } from '../iocListDisplay.js';

const MD5 = '821e593e80c598883433da88a5431e9d';
const SHA1 = '95ddd765865919f7328fef4d15f69b1ee67c0841';
const SHA256 = '3f5ff48aa4dc2c1af3deeb33a9cc576616dad37156ae9182831b1b2a5ae4ae20';
const OTHER_SHA256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

const MD5_IOC = 3475208;
const OTHER_IOC = 999888;

function withReadFlag(value, fn) {
  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = value;
  return Promise.resolve(fn()).finally(() => {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  });
}

function build(q, opts = {}) {
  const { ast } = parseSearchQuery(q);
  return buildWhereClause(ast, { timezone: 'UTC', fileArtifactsReadEnabled: true, ...opts });
}

describe('canonical hash search / source consistency', () => {
  it('ioc contains full MD5 expands via proven artifact aliases when FA read is on', () => {
    const { sql, params } = build(`ioc contains "${MD5}"`);
    assert.match(sql, /\(i\.observable_type, i\.id\) IN \(/);
    assert.match(sql, /file_artifact_hashes h/);
    assert.match(sql, /h\.hash_type = 'md5'/);
    assert.deepEqual(params, [MD5]);
  });

  it('ioc contains full SHA256 expands via proven artifact aliases when FA read is on', () => {
    const { sql, params } = build(`ioc contains "${SHA256}"`);
    assert.match(sql, /\(i\.observable_type, i\.id\) IN \(/);
    assert.match(sql, /file_artifact_hashes h/);
    assert.match(sql, /h\.hash_type = 'sha256'/);
    assert.deepEqual(params, [SHA256]);
  });

  it('ioc contains full SHA1 expands via proven artifact aliases when FA read is on', () => {
    const { sql, params } = build(`ioc contains "${SHA1}"`);
    assert.match(sql, /h\.hash_type = 'sha1'/);
    assert.deepEqual(params, [SHA1]);
  });

  it('ioc contains partial / domain text stays substring ILIKE (no artifact join)', () => {
    const partial = build(`ioc contains "${SHA256.slice(0, 12)}"`);
    assert.match(partial.sql, /i\.observable ILIKE/);
    assert.doesNotMatch(partial.sql, /file_artifact_hashes/);

    const domain = build('ioc contains "evil.example.com"');
    assert.match(domain.sql, /i\.observable ILIKE/);
    assert.doesNotMatch(domain.sql, /file_artifact_hashes/);
  });

  it('ioc contains full hash stays plain ILIKE when FA read is off', () => {
    const { sql } = build(`ioc contains "${SHA256}"`, { fileArtifactsReadEnabled: false });
    assert.match(sql, /i\.observable ILIKE/);
    assert.doesNotMatch(sql, /file_artifact_hashes/);
  });

  it('list canonicalization displays primary SHA256 while keeping MD5 public_id when no SHA256 IOC row', () => {
    return withReadFlag('1', () => {
      const map = new Map([['p-md5', 'art-1']]);
      const primary = new Map([['art-1', {
        hash_type: 'sha256',
        normalized_hash_value: SHA256,
        canonical_public_id: 'p-md5',
        canonical_ioc_id: MD5_IOC
      }]]);
      const out = canonicalizeRowsByIdentity([{
        id: MD5_IOC,
        public_id: 'p-md5',
        observable: MD5,
        observable_type: 'md5',
        created_at: '2026-09-21T18:18:40Z',
        source_name: 'Threat_Library'
      }], map, primary);
      assert.equal(out.length, 1);
      assert.equal(out[0].observable, SHA256);
      assert.equal(out[0].observable_type, 'sha256');
      assert.equal(out[0].id, MD5_IOC);
      assert.equal(out[0].public_id, 'p-md5');
      assert.ok(out[0].source_names.includes('Threat_Library'));
    });
  });

  it('source enrichment with rewritten SHA256 display still surfaces Threat_Library on MD5 id', async () => {
    await withReadFlag('1', async () => {
      const linkedBySeed = new Map([[MD5_IOC, [MD5_IOC]]]);
      const pool = {
        async query(sql, params) {
          if (sql.includes('FROM ioc_feed_memberships')) return { rows: [] };
          if (sql.includes('ioc_source_id IS NOT NULL')) {
            assert.deepEqual(params[0], [MD5_IOC]);
            return {
              rows: [{ ioc_item_id: MD5_IOC, observable_type: 'md5', source_name: 'Threat_Library' }]
            };
          }
          return { rows: [] };
        }
      };
      // List row after canonicalizeRowsByIdentity: display SHA256, underlying MD5 id
      const items = [{
        id: MD5_IOC,
        observable: SHA256,
        observable_type: 'sha256'
      }];
      const result = await enrichItemsWithActiveSourceCounts(pool, items, {
        byItemIds: true,
        linkedBySeed
      });
      assert.equal(result[0].active_source_count, 1);
      assert.deepEqual(result[0].source_names, ['Threat_Library']);
      const decorated = decorateIocListItems(result);
      assert.equal(decorated[0].display_source, 'Threat_Library');
      assert.notEqual(decorated[0].display_source, 'No active source');
    });
  });

  it('source enrichment aggregates across proven aliases without re-parenting', async () => {
    await withReadFlag('1', async () => {
      const shaIoc = 1139687;
      const linkedBySeed = new Map([[shaIoc, [shaIoc, MD5_IOC]]]);
      const pool = {
        async query(sql) {
          if (sql.includes('FROM ioc_feed_memberships')) return { rows: [] };
          if (sql.includes('ioc_source_id IS NOT NULL')) {
            return {
              rows: [{ ioc_item_id: MD5_IOC, observable_type: 'md5', source_name: 'Threat_Library' }]
            };
          }
          return { rows: [] };
        }
      };
      const result = await enrichItemsWithActiveSourceCounts(pool, [{
        id: shaIoc,
        observable: SHA256,
        observable_type: 'sha256'
      }], { byItemIds: true, linkedBySeed });
      assert.equal(result[0].active_source_count, 1);
      assert.deepEqual(result[0].source_names, ['Threat_Library']);
    });
  });

  it('unrelated SHA256 does not inherit Threat_Library from another artifact', async () => {
    await withReadFlag('1', async () => {
      const linkedBySeed = new Map([
        [MD5_IOC, [MD5_IOC]],
        [OTHER_IOC, [OTHER_IOC]]
      ]);
      const pool = {
        async query(sql) {
          if (sql.includes('FROM ioc_feed_memberships')) return { rows: [] };
          if (sql.includes('ioc_source_id IS NOT NULL')) {
            return {
              rows: [{ ioc_item_id: MD5_IOC, observable_type: 'md5', source_name: 'Threat_Library' }]
            };
          }
          return { rows: [] };
        }
      };
      const result = await enrichItemsWithActiveSourceCounts(pool, [
        { id: MD5_IOC, observable: SHA256, observable_type: 'sha256' },
        { id: OTHER_IOC, observable: OTHER_SHA256, observable_type: 'sha256' }
      ], { byItemIds: true, linkedBySeed });
      assert.deepEqual(result[0].source_names, ['Threat_Library']);
      assert.equal(result[1].active_source_count, 0);
      assert.equal(decorateIocListItems([result[1]])[0].display_source, 'No active source');
    });
  });

  it('confidence resolves for rewritten SHA256 display type via underlying MD5 row', async () => {
    await withReadFlag('0', async () => {
      const linkedBySeed = new Map([[MD5_IOC, [MD5_IOC]]]);
      const pool = {
        async query(sql) {
          if (sql.includes('FROM ioc_feed_memberships')) return { rows: [] };
          if (sql.includes('FROM ioc_items')) {
            return {
              rows: [{
                id: MD5_IOC,
                observable_type: 'md5',
                confidence: 'high',
                analyst_confidence_override: null,
                ioc_source_id: 19,
                source_name: 'Threat_Library'
              }]
            };
          }
          return { rows: [] };
        }
      };
      const map = await buildDisplayConfidenceForItems(pool, [{
        id: MD5_IOC,
        observable: SHA256,
        observable_type: 'sha256',
        active_source_count: 1
      }], { linkedBySeed });
      const result = map.get(`${MD5_IOC}|sha256`);
      assert.ok(result);
      assert.equal(result.confidence_effective, 'high');
    });
  });

  it('probe/page whereSql for MD5 and SHA256 share alias-aware membership shape', () => {
    const md5 = build(`ioc contains "${MD5}"`);
    const sha = build(`ioc contains "${SHA256}"`);
    assert.match(md5.sql, /file_artifact_hashes/);
    assert.match(sha.sql, /file_artifact_hashes/);
    assert.doesNotMatch(md5.sql, /\) OR \(i\.observable_type, i\.id\) IN/);
    assert.doesNotMatch(sha.sql, /\) OR \(i\.observable_type, i\.id\) IN/);
  });
});
