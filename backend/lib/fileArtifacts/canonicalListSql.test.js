import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  identityKeyForRow,
  canonicalizeRowsByIdentity,
  buildGroupedCteBody,
  buildLegacyGroupedSelectSql
} from './canonicalListSql.js';

const MD5 = '9aed790a18f214b04619837cd71546d3';
const SHA256 = '8ec6066000f5585d6fefbc1d5a30fa094ac9893456dbf4085fec81e6b71cef3b';

describe('canonicalListSql', () => {
  let prev;
  before(() => {
    prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  });
  after(() => {
    if (prev == null) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  });

  it('legacy identity key when flag off', () => {
    delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    assert.equal(
      identityKeyForRow({ observable_type: 'md5', observable: MD5, public_id: 'x' }),
      `o:md5:${MD5}`
    );
    assert.ok(buildGroupedCteBody().includes('GROUP BY observable, observable_type'));
  });

  it('artifact identity key when flag on and map present', () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    const map = new Map([['pub-a', 'art-1']]);
    assert.equal(
      identityKeyForRow({ observable_type: 'md5', observable: MD5, public_id: 'pub-a' }, map),
      'a:art-1'
    );
  });

  it('canonicalizes before pagination and prefers primary sha256', () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    const map = new Map([
      ['p-md5', 'art-1'],
      ['p-sha', 'art-1']
    ]);
    const primary = new Map([
      ['art-1', { hash_type: 'sha256', normalized_hash_value: SHA256 }]
    ]);
    const rows = [
      {
        id: 1,
        public_id: 'p-md5',
        observable: MD5,
        observable_type: 'md5',
        created_at: '2024-01-02T00:00:00Z',
        source_name: 'Custom'
      },
      {
        id: 2,
        public_id: 'p-sha',
        observable: SHA256,
        observable_type: 'sha256',
        created_at: '2024-01-01T00:00:00Z',
        source_name: 'MalwareBazaar'
      }
    ];
    const out = canonicalizeRowsByIdentity(rows, map, primary);
    assert.equal(out.length, 1);
    assert.equal(out[0].observable_type, 'sha256');
    assert.equal(out[0].observable, SHA256);
    assert.equal(out[0].public_id, 'p-sha');
    assert.equal(out[0].created_at, '2024-01-01T00:00:00Z');
    assert.ok(out[0].source_names.includes('Custom'));
    assert.ok(out[0].source_names.includes('MalwareBazaar'));
  });

  it('MD5-only match still emits SHA256 public_id via canonical map', () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    const map = new Map([['p-md5', 'art-1']]);
    const primary = new Map([
      ['art-1', {
        hash_type: 'sha256',
        normalized_hash_value: SHA256,
        canonical_public_id: 'p-sha',
        canonical_ioc_id: 99
      }]
    ]);
    const rows = [{
      id: 1,
      public_id: 'p-md5',
      observable: MD5,
      observable_type: 'md5',
      created_at: '2024-01-02T00:00:00Z',
      source_name: 'ThreatFox'
    }];
    const out = canonicalizeRowsByIdentity(rows, map, primary);
    assert.equal(out.length, 1);
    assert.equal(out[0].observable_type, 'sha256');
    assert.equal(out[0].observable, SHA256);
    assert.equal(out[0].public_id, 'p-sha');
    assert.equal(out[0].id, 99);
  });

  it('unlinked MD5 stays MD5 (no artifact map)', () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    const out = canonicalizeRowsByIdentity([{
      id: 3,
      public_id: 'p-lonely',
      observable: MD5,
      observable_type: 'md5',
      created_at: '2024-01-02T00:00:00Z'
    }], new Map(), new Map());
    assert.equal(out.length, 1);
    assert.equal(out[0].observable_type, 'md5');
    assert.equal(out[0].public_id, 'p-lonely');
  });
  it('legacy grouped SQL still available', () => {
    assert.ok(buildLegacyGroupedSelectSql('filtered').includes('GROUP BY observable, observable_type'));
  });

  it('canonical browse SQL pages after identity GROUP BY', async () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    const { buildCanonicalActiveBrowsePageSql } = await import('./canonicalListSql.js');
    const sql = buildCanonicalActiveBrowsePageSql();
    assert.match(sql, /identity_key/);
    assert.match(sql, /GROUP BY/);
    assert.match(sql, /LIMIT \$3 OFFSET \$4/);
    const groupIdx = sql.indexOf('GROUP BY');
    const pageIdx = sql.lastIndexOf('LIMIT $3 OFFSET $4');
    assert.ok(groupIdx > 0 && pageIdx > groupIdx, 'GROUP BY must precede page LIMIT/OFFSET');
  });
});
