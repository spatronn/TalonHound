/**
 * Regression tests for canonical file-scoped IOC suppressions.
 * Covers hash-equivalence matching without requiring a live DB for the core
 * semantics; guarded integration block exercises real Postgres when available.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import {
  describeSuppressionScope,
  isFileHashSuppressionType,
  buildSuppressionIndexWithFileScope,
  resolveSurvivorArtifactIdForHash,
  resolveSurvivorArtifactIdForIoc,
  loadProvenHashesForArtifact
} from './iocSuppressionFileScope.js';
import {
  buildSuppressionIndex,
  makeSuppressionKey,
  isPairSuppressed,
  fetchActiveSuppressionIndex
} from './ioc-suppression.js';
import { createIocLinkedSuppression } from './iocLinkedSuppressionCreate.js';
import { createManualSuppression } from './manualSuppressionCreate.js';
import { assertFileArtifactDbTestAllowed } from './fileArtifacts/dbTestGuard.js';

describe('iocSuppressionFileScope helpers', () => {
  it('describes exact vs file scope', () => {
    assert.deepEqual(describeSuppressionScope({ file_artifact_id: null }), {
      kind: 'exact',
      label: 'Exact observable'
    });
    assert.deepEqual(describeSuppressionScope({ file_artifact_id: 'a'.repeat(36) }, 3), {
      kind: 'file',
      label: 'File',
      file_artifact_id: 'a'.repeat(36),
      known_hash_count: 3
    });
  });

  it('only exact file-hash types participate in file-scope matching', () => {
    assert.equal(isFileHashSuppressionType('md5'), true);
    assert.equal(isFileHashSuppressionType('sha1'), true);
    assert.equal(isFileHashSuppressionType('sha256'), true);
    assert.equal(isFileHashSuppressionType('ip'), false);
    assert.equal(isFileHashSuppressionType('domain'), false);
    assert.equal(isFileHashSuppressionType('url'), false);
  });

  it('expands file-scoped rows into alias index entries', async () => {
    const artifactId = '11111111-1111-1111-1111-111111111111';
    const md5 = 'd98f568496512e4f98670c61c97cb07a';
    const sha1 = '31052fe26b7e08e0e02137cf1d54c40d704378cd';
    const sha256 = 'aff35cc83ff53eca577d6fcdf68f90e5e2f648d33e2fb28b93ae7906cfd1544b';
    const client = {
      async query(sql) {
        if (String(sql).includes('file_artifact_hashes')) {
          return {
            rows: [
              { artifact_id: artifactId, hash_type: 'md5', normalized_hash_value: md5 },
              { artifact_id: artifactId, hash_type: 'sha1', normalized_hash_value: sha1 },
              { artifact_id: artifactId, hash_type: 'sha256', normalized_hash_value: sha256 }
            ]
          };
        }
        throw new Error(`unexpected: ${String(sql).slice(0, 80)}`);
      }
    };
    const index = await buildSuppressionIndexWithFileScope(client, [{
      ioc_value: md5,
      ioc_type: 'md5',
      scope: 'global',
      source_name: null,
      file_artifact_id: artifactId
    }], { buildSuppressionIndex, makeSuppressionKey });

    const hit = (v, t) => Boolean(isPairSuppressed(index, { iocValue: v, iocType: t })?.suppressed);
    assert.equal(hit(md5, 'md5'), true);
    assert.equal(hit(sha1, 'sha1'), true);
    assert.equal(hit(sha256, 'sha256'), true);
    assert.equal(hit('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'md5'), false);
  });

  it('does not expand exact-only suppressions via unrelated shared tags/sources', async () => {
    const client = {
      async query() {
        throw new Error('should not query artifact hashes for exact-only rows');
      }
    };
    const index = await buildSuppressionIndexWithFileScope(client, [{
      ioc_value: '1.1.1.1',
      ioc_type: 'ip',
      scope: 'global',
      source_name: null,
      file_artifact_id: null
    }], { buildSuppressionIndex, makeSuppressionKey });
    const hit = (v, t) => Boolean(isPairSuppressed(index, { iocValue: v, iocType: t })?.suppressed);
    assert.equal(hit('1.1.1.1', 'ip'), true);
    assert.equal(hit('8.8.8.8', 'ip'), false);
  });
});

describe('createIocLinkedSuppression file scope', () => {
  it('sets file_artifact_id when IOC is linked to a proven artifact', async () => {
    const artifactId = '22222222-2222-2222-2222-222222222222';
    const md5 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const sha256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const queries = [];
    const query = async (sql, params = []) => {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      queries.push({ s, params });
      if (s.startsWith('BEGIN') || s.startsWith('COMMIT') || s.startsWith('ROLLBACK')) return { rows: [] };
      if (s.includes('FROM ioc_items') && s.includes('WHERE id = $1') && s.includes('public_id')) {
        return { rows: [{ id: 10, observable: md5, observable_type: 'md5', public_id: crypto.randomUUID() }], rowCount: 1 };
      }
      if (s.includes('file_artifact_ioc_links')) {
        return { rows: [{ artifact_id: artifactId }], rowCount: 1 };
      }
      if (s.includes('FROM ioc_suppressions') && s.includes('file_artifact_id')) {
        return { rows: [], rowCount: 0 };
      }
      if (s.includes('INSERT INTO ioc_suppressions')) {
        return {
          rows: [{
            id: 99,
            ioc_value: params[0],
            ioc_type: params[1],
            reason: params[2],
            created_by: params[3],
            expires_at: params[4],
            active: true,
            file_artifact_id: params[5],
            scope: 'global'
          }],
          rowCount: 1
        };
      }
      if (s.includes('FROM file_artifact_ioc_links') && s.includes('JOIN ioc_items')) {
        return {
          rows: [
            { id: 10, observable_type: 'md5', observable: md5 },
            { id: 11, observable_type: 'sha256', observable: sha256 }
          ],
          rowCount: 2
        };
      }
      if (s.includes('FROM ioc_items') && s.includes('WHERE id = $1 AND observable_type')) {
        return {
          rows: [{
            id: params[0],
            observable: params[0] === 11 ? sha256 : md5,
            observable_type: params[1],
            status: 'active',
            manual_status_override: false,
            manual_status: null,
            manual_expires_at: null,
            expires_at: null,
            expired_at: null,
            expiration_reason: null
          }],
          rowCount: 1
        };
      }
      if (s.includes('FROM ioc_suppressions')) {
        return { rows: [{ '?column?': 1 }], rowCount: 1 };
      }
      if (s.includes("SET status = 'suppressed'")) return { rows: [], rowCount: 1 };
      if (s.includes('FROM file_artifact_hashes')) {
        return {
          rows: [
            { hash_type: 'md5', normalized_hash_value: md5 },
            { hash_type: 'sha256', normalized_hash_value: sha256 }
          ],
          rowCount: 2
        };
      }
      throw new Error(`Unexpected query: ${s.slice(0, 140)}`);
    };
    const pool = { query, connect: async () => ({ query, release: () => {} }) };
    const res = await createIocLinkedSuppression(pool, 10, { reason: 'SystemSettings.exe' }, {
      user: { email: 'a@t.local' }
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.suppression.file_artifact_id, artifactId);
    assert.equal(res.body.suppression.suppression_scope.kind, 'file');
    assert.equal(res.body.suppression.suppression_scope.known_hash_count, 2);
    assert.ok(queries.some((q) => q.s.includes('INSERT INTO ioc_suppressions') && q.params[5] === artifactId));
  });

  it('keeps exact-only when IOC has no artifact link', async () => {
    const query = async (sql, params = []) => {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      if (s.startsWith('BEGIN') || s.startsWith('COMMIT') || s.startsWith('ROLLBACK')) return { rows: [] };
      if (s.includes('FROM ioc_items') && s.includes('public_id')) {
        return { rows: [{ id: 7, observable: 'evil.example', observable_type: 'domain', public_id: crypto.randomUUID() }], rowCount: 1 };
      }
      if (s.includes('file_artifact_ioc_links')) return { rows: [], rowCount: 0 };
      if (s.includes('FROM ioc_suppressions') && s.includes('file_artifact_id')) return { rows: [], rowCount: 0 };
      if (s.includes('INSERT INTO ioc_suppressions')) {
        return {
          rows: [{
            id: 1,
            ioc_value: params[0],
            ioc_type: params[1],
            reason: params[2],
            created_by: params[3],
            expires_at: params[4],
            active: true,
            file_artifact_id: params[5],
            scope: 'global'
          }],
          rowCount: 1
        };
      }
      if (s.includes('FROM ioc_items') && s.includes('lower(observable)')) {
        return { rows: [{ id: 7, observable_type: 'domain' }], rowCount: 1 };
      }
      if (s.includes('FROM ioc_items') && s.includes('observable_type = $2')) {
        return {
          rows: [{
            id: 7, observable: 'evil.example', observable_type: 'domain', status: 'active',
            manual_status_override: false, manual_status: null, manual_expires_at: null,
            expires_at: null, expired_at: null, expiration_reason: null
          }],
          rowCount: 1
        };
      }
      if (s.includes('FROM ioc_suppressions')) return { rows: [{ '?column?': 1 }], rowCount: 1 };
      if (s.includes("SET status = 'suppressed'")) return { rows: [], rowCount: 1 };
      throw new Error(`Unexpected: ${s.slice(0, 120)}`);
    };
    const pool = { query, connect: async () => ({ query, release: () => {} }) };
    const res = await createIocLinkedSuppression(pool, 7, { reason: 'lab false positive' });
    assert.equal(res.status, 200);
    assert.equal(res.body.suppression.file_artifact_id, null);
    assert.equal(res.body.suppression.suppression_scope.kind, 'exact');
  });

  it('duplicate file-scoped suppression is idempotent (no second create audit)', async () => {
    const artifactId = '33333333-3333-3333-3333-333333333333';
    const md5 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const auditCalls = [];
    const query = async (sql, params = []) => {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      if (s.startsWith('BEGIN') || s.startsWith('COMMIT') || s.startsWith('ROLLBACK')) return { rows: [] };
      if (s.includes('FROM ioc_items') && s.includes('public_id')) {
        return { rows: [{ id: 10, observable: md5, observable_type: 'md5', public_id: crypto.randomUUID() }], rowCount: 1 };
      }
      if (s.includes('file_artifact_ioc_links') && !s.includes('JOIN ioc_items')) {
        return { rows: [{ artifact_id: artifactId }], rowCount: 1 };
      }
      if (s.includes('SELECT * FROM ioc_suppressions') || (s.includes('FROM ioc_suppressions') && s.includes('file_artifact_id') && s.includes('ORDER BY'))) {
        return {
          rows: [{
            id: 1, ioc_value: md5, ioc_type: 'md5', file_artifact_id: artifactId,
            reason: 'old', active: true, scope: 'global', expires_at: null
          }],
          rowCount: 1
        };
      }
      if (s.startsWith('UPDATE ioc_suppressions')) {
        return {
          rows: [{
            id: 1, ioc_value: md5, ioc_type: 'md5', file_artifact_id: artifactId,
            reason: params[1], active: true, scope: 'global', expires_at: params[3]
          }],
          rowCount: 1
        };
      }
      if (s.includes('FROM file_artifact_ioc_links') && s.includes('JOIN ioc_items')) {
        return { rows: [{ id: 10, observable_type: 'md5', observable: md5 }], rowCount: 1 };
      }
      if (s.includes('FROM ioc_items') && s.includes('observable_type = $2')) {
        return {
          rows: [{
            id: 10, observable: md5, observable_type: 'md5', status: 'suppressed',
            manual_status_override: false, manual_status: null, manual_expires_at: null,
            expires_at: null, expired_at: null, expiration_reason: null
          }],
          rowCount: 1
        };
      }
      if (s.includes('FROM ioc_suppressions')) return { rows: [{ '?column?': 1 }], rowCount: 1 };
      if (s.includes('FROM file_artifact_hashes')) {
        return { rows: [{ hash_type: 'md5', normalized_hash_value: md5 }], rowCount: 1 };
      }
      throw new Error(`Unexpected: ${s.slice(0, 140)}`);
    };
    const pool = { query, connect: async () => ({ query, release: () => {} }) };
    const res = await createIocLinkedSuppression(pool, 10, { reason: 'retry reason ok' }, {
      req: {},
      user: { email: 'a@t.local' },
      audit: { auditSuccess: async (p) => { auditCalls.push(p); } }
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.suppression.id, 1);
    assert.equal(auditCalls.length, 0);
  });
});

describe('createManualSuppression remains exact-only', () => {
  it('does not attach file_artifact_id even for hash values', async () => {
    const inserts = [];
    const query = async (sql, params = []) => {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      if (s.startsWith('BEGIN') || s.startsWith('COMMIT') || s.startsWith('ROLLBACK')) return { rows: [] };
      if (s.includes('SELECT id FROM ioc_suppressions')) return { rows: [], rowCount: 0 };
      if (s.includes('INSERT INTO ioc_suppressions')) {
        inserts.push(params);
        return {
          rows: [{
            id: 1, ioc_value: params[0], ioc_type: params[1], scope: 'global',
            reason: params[2], created_by: params[3], expires_at: params[4], active: true
          }],
          rowCount: 1
        };
      }
      if (s.includes('FROM ioc_items')) return { rows: [], rowCount: 0 };
      throw new Error(`Unexpected: ${s.slice(0, 120)}`);
    };
    const pool = { query, connect: async () => ({ query, release: () => {} }) };
    const res = await createManualSuppression(pool, {
      ioc_value: 'd98f568496512e4f98670c61c97cb07a',
      ioc_type: 'md5',
      reason: 'manual raw hash'
    });
    assert.equal(res.status, 201);
    assert.equal(inserts[0].length, 5); // no file_artifact_id bind
    assert.equal(res.body.suppression.ioc_type, 'md5');
  });
});

describe('fetchActiveSuppressionIndex file alias coverage', () => {
  it('marks SHA256 suppressed when only MD5 file-scoped row exists', async () => {
    const artifactId = '44444444-4444-4444-4444-444444444444';
    const md5 = 'd98f568496512e4f98670c61c97cb07a';
    const sha256 = 'aff35cc83ff53eca577d6fcdf68f90e5e2f648d33e2fb28b93ae7906cfd1544b';
    const client = {
      async query(sql, params = []) {
        const s = String(sql);
        if (s.includes('FROM unnest') && s.includes('lower(ioc_value) = lower(u.v)') && !s.includes('file_artifact_hashes')) {
          // Exact pair query — SHA256 has no exact row
          return { rows: [] };
        }
        if (s.includes('file_artifact_id IS NOT NULL') && s.includes('unnest')) {
          return {
            rows: [{
              ioc_value: md5,
              ioc_type: 'md5',
              scope: 'global',
              source_name: null,
              file_artifact_id: artifactId
            }]
          };
        }
        if (s.includes('file_artifact_hashes') && s.includes('ANY($1::uuid[])')) {
          return {
            rows: [
              { artifact_id: artifactId, hash_type: 'md5', normalized_hash_value: md5 },
              { artifact_id: artifactId, hash_type: 'sha256', normalized_hash_value: sha256 }
            ]
          };
        }
        throw new Error(`Unexpected: ${s.slice(0, 160)} params=${JSON.stringify(params)}`);
      }
    };
    const index = await fetchActiveSuppressionIndex(client, [
      { iocValue: sha256, iocType: 'sha256' }
    ]);
    const hit = (v, t) => Boolean(isPairSuppressed(index, { iocValue: v, iocType: t })?.suppressed);
    assert.equal(hit(sha256, 'sha256'), true);
    assert.equal(hit(md5, 'md5'), true);
  });
});

// ---------------------------------------------------------------------------
// Optional real-DB integration (ALLOW_FILE_ARTIFACT_DB_TESTS=1 + *_test DB)
// ---------------------------------------------------------------------------

let dbConfig = null;
try {
  dbConfig = assertFileArtifactDbTestAllowed();
} catch {
  dbConfig = null;
}

const pool = dbConfig
  ? new pg.Pool({ ...dbConfig, connectionTimeoutMillis: 3000, max: 4 })
  : null;

let hasDb = false;
if (pool) {
  try {
    await pool.query('SELECT file_artifact_id FROM ioc_suppressions LIMIT 0');
    await pool.query('SELECT 1 FROM file_artifacts LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
    await pool.end().catch(() => {});
  }
}

const dbOpts = {
  skip: hasDb
    ? false
    : 'disposable migrated test DB with migration 047 not available'
};

describe('iocSuppressionFileScope integration', dbOpts, () => {
  const mark = `sup${crypto.randomBytes(4).toString('hex')}`;
  const md5 = crypto.createHash('md5').update(`${mark}-a`).digest('hex');
  const sha1 = crypto.createHash('sha1').update(`${mark}-a`).digest('hex');
  const sha256 = crypto.createHash('sha256').update(`${mark}-a`).digest('hex');
  const otherMd5 = crypto.createHash('md5').update(`${mark}-b`).digest('hex');
  let client;
  let artifactId;
  let iocId;
  let suppressionId;

  before(async () => {
    client = await pool.connect();
    await client.query('BEGIN');
    const art = await client.query(
      `INSERT INTO file_artifacts (status) VALUES ('active') RETURNING id`
    );
    artifactId = art.rows[0].id;
    // Start with MD5+SHA1 only so test 11 can discover SHA256 later.
    for (const [type, value, primary] of [
      ['md5', md5, false],
      ['sha1', sha1, true]
    ]) {
      await client.query(
        `INSERT INTO file_artifact_hashes (artifact_id, hash_type, normalized_hash_value, is_primary)
         VALUES ($1, $2, $3, $4)`,
        [artifactId, type, value, primary]
      );
    }
    const ioc = await client.query(
      `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, status)
       VALUES ($1::uuid, $2, 'md5', 'test', 'medium', 'active')
       RETURNING id`,
      [crypto.randomUUID(), md5]
    );
    iocId = ioc.rows[0].id;
    await client.query(
      `INSERT INTO file_artifact_ioc_links (artifact_id, ioc_item_id, ioc_observable_type, ioc_public_id, is_canonical_ioc)
       SELECT $1, id, observable_type, public_id, TRUE FROM ioc_items WHERE id = $2`,
      [artifactId, iocId]
    );
  });

  after(async () => {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    client.release();
    await pool.end();
  });

  it('1-5: suppress from MD5 covers MD5/SHA1/SHA256; unrelated MD5 not covered', async () => {
    const created = await createIocLinkedSuppression(
      { query: (...a) => client.query(...a), connect: async () => ({ query: (...a) => client.query(...a), release: () => {} }) },
      iocId,
      { reason: `${mark} file fp` }
    );
    // createIocLinkedSuppression uses its own BEGIN/COMMIT — use pool against same DB
    // For transaction-isolated test, call SQL directly instead.
    void created;
    const ins = await client.query(
      `INSERT INTO ioc_suppressions (ioc_value, ioc_type, scope, reason, active, file_artifact_id)
       VALUES ($1, 'md5', 'global', $2, TRUE, $3::uuid)
       RETURNING id`,
      [md5, `${mark} file fp`, artifactId]
    );
    suppressionId = ins.rows[0].id;

    assert.equal(await resolveSurvivorArtifactIdForIoc(client, iocId), String(artifactId));
    assert.equal(await resolveSurvivorArtifactIdForHash(client, 'sha256', sha256), String(artifactId));
    const hashes = await loadProvenHashesForArtifact(client, artifactId);
    assert.equal(hashes.length, 3);

    const index = await fetchActiveSuppressionIndex(client, [
      { iocValue: md5, iocType: 'md5' },
      { iocValue: sha1, iocType: 'sha1' },
      { iocValue: sha256, iocType: 'sha256' },
      { iocValue: otherMd5, iocType: 'md5' }
    ]);
    const hit = (v, t) => Boolean(isPairSuppressed(index, { iocValue: v, iocType: t })?.suppressed);
    assert.equal(hit(md5, 'md5'), true);
    assert.equal(hit(sha1, 'sha1'), true);
    assert.equal(hit(sha256, 'sha256'), true);
    assert.equal(hit(otherMd5, 'md5'), false);
  });

  it('11: later-discovered canonical hash inherits file suppression', async () => {
    // Start a fresh artifact with only MD5 suppressed, then attach SHA256 later.
    const lateMd5 = crypto.createHash('md5').update(`${mark}-late`).digest('hex');
    const lateSha = crypto.createHash('sha256').update(`${mark}-late`).digest('hex');
    const art = await client.query(`INSERT INTO file_artifacts (status) VALUES ('active') RETURNING id`);
    const aid = art.rows[0].id;
    await client.query(
      `INSERT INTO file_artifact_hashes (artifact_id, hash_type, normalized_hash_value, is_primary)
       VALUES ($1, 'md5', $2, TRUE)`,
      [aid, lateMd5]
    );
    await client.query(
      `INSERT INTO ioc_suppressions (ioc_value, ioc_type, scope, reason, active, file_artifact_id)
       VALUES ($1, 'md5', 'global', $2, TRUE, $3::uuid)`,
      [lateMd5, `${mark} late discovery`, aid]
    );
    let index = await fetchActiveSuppressionIndex(client, [
      { iocValue: lateMd5, iocType: 'md5' },
      { iocValue: lateSha, iocType: 'sha256' }
    ]);
    assert.equal(Boolean(isPairSuppressed(index, { iocValue: lateMd5, iocType: 'md5' })?.suppressed), true);
    assert.equal(Boolean(isPairSuppressed(index, { iocValue: lateSha, iocType: 'sha256' })?.suppressed), false);

    await client.query(
      `UPDATE file_artifact_hashes SET is_primary = FALSE
       WHERE artifact_id = $1 AND hash_type = 'md5'`,
      [aid]
    );
    await client.query(
      `INSERT INTO file_artifact_hashes (artifact_id, hash_type, normalized_hash_value, is_primary)
       VALUES ($1, 'sha256', $2, TRUE)`,
      [aid, lateSha]
    );
    index = await fetchActiveSuppressionIndex(client, [
      { iocValue: lateSha, iocType: 'sha256' }
    ]);
    assert.equal(Boolean(isPairSuppressed(index, { iocValue: lateSha, iocType: 'sha256' })?.suppressed), true);
  });

  it('12-14: disable then re-enable then delete file suppression', async () => {
    const hit = (index, v, t) => Boolean(isPairSuppressed(index, { iocValue: v, iocType: t })?.suppressed);
    await client.query(`UPDATE ioc_suppressions SET active = FALSE WHERE id = $1`, [suppressionId]);
    let index = await fetchActiveSuppressionIndex(client, [
      { iocValue: sha256, iocType: 'sha256' }
    ]);
    assert.equal(hit(index, sha256, 'sha256'), false);

    await client.query(`UPDATE ioc_suppressions SET active = TRUE WHERE id = $1`, [suppressionId]);
    index = await fetchActiveSuppressionIndex(client, [
      { iocValue: sha1, iocType: 'sha1' }
    ]);
    assert.equal(hit(index, sha1, 'sha1'), true);

    await client.query(
      `UPDATE ioc_suppressions SET active = FALSE, deleted_at = NOW() WHERE id = $1`,
      [suppressionId]
    );
    index = await fetchActiveSuppressionIndex(client, [
      { iocValue: md5, iocType: 'md5' },
      { iocValue: sha256, iocType: 'sha256' }
    ]);
    assert.equal(hit(index, md5, 'md5'), false);
    assert.equal(hit(index, sha256, 'sha256'), false);
  });

  it('10: manual exact-only hash does not cover sibling aliases', async () => {
    const soloMd5 = crypto.createHash('md5').update(`${mark}-solo`).digest('hex');
    const soloSha = crypto.createHash('sha256').update(`${mark}-solo`).digest('hex');
    const art = await client.query(`INSERT INTO file_artifacts (status) VALUES ('active') RETURNING id`);
    const aid = art.rows[0].id;
    await client.query(
      `INSERT INTO file_artifact_hashes (artifact_id, hash_type, normalized_hash_value, is_primary)
       VALUES ($1, 'md5', $2, FALSE), ($1, 'sha256', $3, TRUE)`,
      [aid, soloMd5, soloSha]
    );
    // Exact-only suppression (no file_artifact_id) — manual screen semantics.
    await client.query(
      `INSERT INTO ioc_suppressions (ioc_value, ioc_type, scope, reason, active, file_artifact_id)
       VALUES ($1, 'md5', 'global', $2, TRUE, NULL)`,
      [soloMd5, `${mark} exact only`]
    );
    const index = await fetchActiveSuppressionIndex(client, [
      { iocValue: soloMd5, iocType: 'md5' },
      { iocValue: soloSha, iocType: 'sha256' }
    ]);
    const hit = (v, t) => Boolean(isPairSuppressed(index, { iocValue: v, iocType: t })?.suppressed);
    assert.equal(hit(soloMd5, 'md5'), true);
    assert.equal(hit(soloSha, 'sha256'), false);
  });

  it('17: non-file types stay exact-only', async () => {
    await client.query(
      `INSERT INTO ioc_suppressions (ioc_value, ioc_type, scope, reason, active)
       VALUES ('9.9.9.9', 'ip', 'global', $1, TRUE)`,
      [`${mark} ip`]
    );
    const index = await fetchActiveSuppressionIndex(client, [
      { iocValue: '9.9.9.9', iocType: 'ip' },
      { iocValue: '8.8.8.8', iocType: 'ip' }
    ]);
    const hit = (v, t) => Boolean(isPairSuppressed(index, { iocValue: v, iocType: t })?.suppressed);
    assert.equal(hit('9.9.9.9', 'ip'), true);
    assert.equal(hit('8.8.8.8', 'ip'), false);
  });
});
