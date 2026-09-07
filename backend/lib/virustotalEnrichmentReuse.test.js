import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { resolveVtEnrichmentRow } from './virustotalEnrichmentReuse.js';
import { findArtifactLinkedIocsByIocId } from './fileArtifacts/read.js';

const SHA256 = 'a'.repeat(64);
const SHA1 = 'b'.repeat(40);
const MD5 = 'c'.repeat(32);

/**
 * Mock pg client. `handlers` inspects (sql, params) and returns { rows }.
 * Counts every query so we can prove the read path performs NO provider request
 * (there is no fetch here at all) and issues only the expected DB reads.
 */
function mockDb(handlers) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql: String(sql), params });
      for (const h of handlers) {
        if (h.match(String(sql), params)) return h.result(String(sql), params);
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

const vtRow = (over = {}) => ({
  ioc_id: 1, status: 'success', ioc_type: 'sha1',
  normalized_summary: { file: { sha256: SHA256, sha1: SHA1, md5: MD5 } },
  error_message: null, fetched_at: '2026-09-07T00:00:00.000Z', expires_at: null, ...over
});

describe('resolveVtEnrichmentRow', () => {
  test('direct hit: returns the IOC own row, no alias lookup, no provider request', async () => {
    let findLinkedCalls = 0;
    const db = mockDb([
      { match: (s) => s.includes('ioc_id=$2'), result: () => ({ rows: [vtRow({ ioc_id: 100, status: 'success' })], rowCount: 1 }) }
    ]);
    const res = await resolveVtEnrichmentRow(db, 100, { findLinked: async () => { findLinkedCalls++; return null; } });
    assert.equal(res.row.ioc_id, 100);
    assert.equal(res.reusedFromAlias, false);
    assert.equal(findLinkedCalls, 0, 'no alias resolution when own row exists');
    assert.equal(db.calls.length, 1, 'exactly one DB read; zero provider requests');
  });

  test('CORE BUG: canonical SHA256 with no own row reuses the SHA1 alias success row (no 2nd VT request)', async () => {
    // VT was enriched via the SHA1 alias (ioc_id 200); canonical SHA256 is ioc_id 100.
    const db = mockDb([
      { match: (s) => s.includes('ioc_id=$2'), result: () => ({ rows: [], rowCount: 0 }) }, // canonical has no own row
      { match: (s) => s.includes('ANY($2::bigint[])') && s.includes("status='success'"),
        result: (s, p) => {
          assert.deepEqual(p[1].sort(), [200], 'alias lookup targets the linked alias id only');
          return { rows: [vtRow({ ioc_id: 200, status: 'success', ioc_type: 'sha1' })], rowCount: 1 };
        } }
    ]);
    const findLinked = async () => ({ artifact_id: 'art-1', linked_ioc_ids: [100, 200], linked_ioc_public_ids: ['pid-256', 'pid-1'] });
    const res = await resolveVtEnrichmentRow(db, 100, { findLinked });
    assert.equal(res.row.ioc_id, 200);
    assert.equal(res.row.status, 'success');
    assert.equal(res.reusedFromAlias, true);
    // Read path issued only DB reads — a reused result means the frontend gets
    // status 'success' and will NOT trigger a second /refresh (== 1 VT request total).
    assert.ok(res.row.normalized_summary.file.md5 === MD5);
  });

  test('alias has only not_found/error (no success): returns null so canonical can still enrich once', async () => {
    const db = mockDb([
      { match: (s) => s.includes('ioc_id=$2'), result: () => ({ rows: [], rowCount: 0 }) },
      { match: (s) => s.includes('ANY($2::bigint[])'), result: () => ({ rows: [], rowCount: 0 }) } // no success rows
    ]);
    const findLinked = async () => ({ linked_ioc_ids: [100, 200], linked_ioc_public_ids: [] });
    const res = await resolveVtEnrichmentRow(db, 100, { findLinked });
    assert.equal(res.row, null);
    assert.equal(res.reusedFromAlias, false);
  });

  test('no artifact link (identity not proven): does not attach unrelated enrichment', async () => {
    const db = mockDb([
      { match: (s) => s.includes('ioc_id=$2'), result: () => ({ rows: [], rowCount: 0 }) }
    ]);
    const res = await resolveVtEnrichmentRow(db, 100, { findLinked: async () => null });
    assert.equal(res.row, null);
    assert.equal(db.calls.length, 1, 'no alias query when there is no linked artifact');
  });

  test('linked set is only the IOC itself: no alias query issued', async () => {
    const db = mockDb([
      { match: (s) => s.includes('ioc_id=$2'), result: () => ({ rows: [], rowCount: 0 }) },
      { match: (s) => s.includes('ANY($2::bigint[])'), result: () => { throw new Error('should not query aliases'); } }
    ]);
    const res = await resolveVtEnrichmentRow(db, 100, { findLinked: async () => ({ linked_ioc_ids: [100] }) });
    assert.equal(res.row, null);
  });
});

describe('findArtifactLinkedIocsByIocId', () => {
  function withReadFlag(value, fn) {
    const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
    process.env.FILE_ARTIFACTS_READ_ENABLED = value;
    return Promise.resolve(fn()).finally(() => {
      if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
      else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
    });
  }

  test('returns null when read flag disabled (no DB call)', async () => {
    await withReadFlag('false', async () => {
      const db = mockDb([{ match: () => true, result: () => { throw new Error('should not query'); } }]);
      const res = await findArtifactLinkedIocsByIocId(db, 100);
      assert.equal(res, null);
      assert.equal(db.calls.length, 0);
    });
  });

  test('returns linked ids + public ids for an active artifact', async () => {
    await withReadFlag('true', async () => {
      const db = mockDb([
        { match: (s) => s.includes('file_artifact_ioc_links l') && s.includes('JOIN file_artifacts a'),
          result: () => ({ rows: [{ artifact_id: 'art-1', status: 'active', merged_into_artifact_id: null }], rowCount: 1 }) },
        { match: (s) => s.includes('FROM file_artifact_ioc_links WHERE artifact_id'),
          result: () => ({ rows: [
            { ioc_item_id: '100', ioc_public_id: 'pid-256' },
            { ioc_item_id: '200', ioc_public_id: 'pid-sha1' }
          ], rowCount: 2 }) }
      ]);
      const res = await findArtifactLinkedIocsByIocId(db, 100);
      assert.equal(res.artifact_id, 'art-1');
      assert.deepEqual(res.linked_ioc_ids, [100, 200]);
      assert.deepEqual(res.linked_ioc_public_ids, ['pid-256', 'pid-sha1']);
    });
  });

  test('follows a merged tombstone to the surviving artifact', async () => {
    await withReadFlag('true', async () => {
      const db = mockDb([
        { match: (s) => s.includes('file_artifact_ioc_links l') && s.includes('JOIN file_artifacts a'),
          result: () => ({ rows: [{ artifact_id: 'old', status: 'merged', merged_into_artifact_id: 'new' }], rowCount: 1 }) },
        { match: (s) => s.includes('FROM file_artifacts WHERE id = $1'),
          result: () => ({ rows: [{ id: 'new', status: 'active', merged_into_artifact_id: null }], rowCount: 1 }) },
        { match: (s) => s.includes('FROM file_artifact_ioc_links WHERE artifact_id'),
          result: (s, p) => { assert.equal(p[0], 'new'); return { rows: [{ ioc_item_id: '300', ioc_public_id: 'pid-x' }], rowCount: 1 }; } }
      ]);
      const res = await findArtifactLinkedIocsByIocId(db, 300);
      assert.equal(res.artifact_id, 'new');
      assert.deepEqual(res.linked_ioc_ids, [300]);
    });
  });

  test('returns null when the IOC is not linked to any artifact', async () => {
    await withReadFlag('true', async () => {
      const db = mockDb([
        { match: (s) => s.includes('file_artifact_ioc_links l'), result: () => ({ rows: [], rowCount: 0 }) }
      ]);
      assert.equal(await findArtifactLinkedIocsByIocId(db, 999), null);
    });
  });

  test('fails soft (null) when the artifact schema is absent', async () => {
    await withReadFlag('true', async () => {
      const db = mockDb([
        { match: () => true, result: () => { throw Object.assign(new Error('relation "file_artifact_ioc_links" does not exist'), { code: '42P01' }); } }
      ]);
      assert.equal(await findArtifactLinkedIocsByIocId(db, 1), null);
    });
  });
});
