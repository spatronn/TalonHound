import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  dualWriteFileArtifactForObservable,
  shouldRethrowDualWriteError
} from './dualWrite.js';
import { withSavepoint, isControlledFileArtifactDbError, formatProviderError } from './txSavepoint.js';
import { feedKeyForSourceName } from './feedResolve.js';

const SHA256 = '094fa6d0cb7ead6c425ad9d25d5619c322445f6a32578c973a668322d0f8ba8a';
const MD5 = 'dce9ad6317ce147f1f3f74bc93d9252a';
const TF_FEED_ID = '11111111-1111-1111-1111-111111111111';
const MB_FEED_ID = '22222222-2222-2222-2222-222222222222';
const ART_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const HASH_ID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

const dualWriteSrc = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), 'dualWrite.js'),
  'utf8'
);

/**
 * Abort-aware mock client mirroring PostgreSQL transaction semantics.
 */
function createAbortAwareClient(handlers = []) {
  const state = { aborted: false, queries: [] };
  const client = {
    state,
    async query(sql, params = []) {
      const text = String(sql).replace(/\s+/g, ' ').trim();
      state.queries.push({ sql: text, params });

      if (/^SAVEPOINT\b/i.test(text)) return { rows: [], rowCount: 0 };
      if (/^RELEASE SAVEPOINT\b/i.test(text)) return { rows: [], rowCount: 0 };
      if (/^ROLLBACK TO SAVEPOINT\b/i.test(text)) {
        state.aborted = false;
        return { rows: [], rowCount: 0 };
      }

      if (state.aborted) {
        const err = new Error(
          'current transaction is aborted, commands ignored until end of transaction block'
        );
        err.code = '25P02';
        throw err;
      }

      for (const h of handlers) {
        if (h.match(text, params)) {
          if (h.fail) {
            state.aborted = true;
            const err = h.fail instanceof Error ? h.fail : new Error(String(h.fail));
            throw err;
          }
          const result = typeof h.result === 'function' ? h.result(text, params) : h.result;
          return result;
        }
      }

      throw new Error(`unexpected query: ${text.slice(0, 180)}`);
    }
  };
  return client;
}

function undefinedColumnError(column = 'source_name') {
  const err = new Error(`column "${column}" does not exist`);
  err.code = '42703';
  err.column = column;
  err.table = 'integration_feeds';
  return err;
}

function feedMetaResult() {
  return {
    rowCount: 2,
    rows: [
      {
        key: 'threatfox-abusech',
        feed_id: TF_FEED_ID,
        integration_id: TF_FEED_ID,
        feed_update_mode: 'incremental',
        name: 'ThreatFox',
        feed_kind: 'built_in'
      },
      {
        key: 'malwarebazaar-abusech',
        feed_id: MB_FEED_ID,
        integration_id: MB_FEED_ID,
        feed_update_mode: 'incremental',
        name: 'MalwareBazaar',
        feed_kind: 'built_in'
      }
    ]
  };
}

function iocRow({ observable, observableType, sourceName, note = null }) {
  return {
    rowCount: 1,
    rows: [{
      id: 9001,
      public_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      observable,
      observable_type: observableType,
      note,
      first_seen_at: '2026-07-01T00:00:00.000Z',
      last_seen_at: '2026-07-01T00:00:00.000Z',
      created_at: '2026-07-01T00:00:00.000Z',
      source_name: sourceName
    }]
  };
}

/**
 * Happy-path handlers covering attachExactHash → link → observation for an existing hash.
 */
function ensureArtifactHandlers({ observable, observableType, sourceName, note = null }) {
  return [
    {
      match: (sql) => sql.includes('FROM ioc_items') && sql.includes('observable_type'),
      result: () => iocRow({ observable, observableType, sourceName, note })
    },
    {
      match: (sql) => sql.includes('FROM integration_feeds') && /WHERE key/i.test(sql),
      result: (_sql, params) => {
        const key = params?.[0];
        const row = feedMetaResult().rows.find((r) => r.key === key);
        return {
          rowCount: row ? 1 : 0,
          rows: row ? [{ integration_id: row.feed_id }] : []
        };
      }
    },
    {
      match: (sql) => /pg_advisory_xact_lock/i.test(sql),
      result: () => ({ rows: [{ pg_advisory_xact_lock: '' }], rowCount: 1 })
    },
    {
      // findArtifactByHash JOIN query
      match: (sql) => sql.includes('file_artifact_hashes') && sql.includes('normalized_hash_value'),
      result: () => ({
        rowCount: 1,
        rows: [{
          hash_id: HASH_ID,
          artifact_id: ART_ID,
          hash_artifact_id: ART_ID,
          hash_type: observableType,
          normalized_hash_value: observable,
          is_primary: true,
          status: 'active'
        }]
      })
    },
    {
      match: (sql) => sql.includes('UPDATE file_artifact_hashes') && sql.includes('last_seen_at'),
      result: () => ({ rowCount: 1, rows: [] })
    },
    {
      // No prior link → INSERT path
      match: (sql) => sql.includes('FROM file_artifact_ioc_links') && sql.includes('ioc_item_id'),
      result: () => ({ rowCount: 0, rows: [] })
    },
    {
      match: (sql) => sql.includes('INSERT INTO file_artifact_ioc_links'),
      result: () => ({ rowCount: 1, rows: [{ id: 55 }] })
    },
    {
      match: (sql) => sql.includes('file_artifact_ioc_links'),
      result: () => ({ rowCount: 1, rows: [{ id: 55, artifact_id: ART_ID }] })
    },
    {
      match: (sql) => sql.includes('INSERT INTO file_artifact_source_observations'),
      result: () => ({ rowCount: 1, rows: [{ id: 77 }] })
    },
    {
      match: (sql) => sql.includes('FROM file_artifact_source_observations') || sql.includes('UPDATE file_artifact_source_observations'),
      result: () => ({ rowCount: 0, rows: [] })
    },
    {
      match: (sql) => sql.includes('file_artifact_non_identity_attrs'),
      result: () => ({ rowCount: 0, rows: [] })
    },
    {
      // Sibling IOC lookups inside attachProviderExactHashSet
      match: (sql) => sql.includes('FROM ioc_items') && sql.includes('WHERE observable_type'),
      result: () => ({ rowCount: 0, rows: [] })
    },
    {
      match: (sql) => sql.includes('SELECT') || sql.includes('INSERT') || sql.includes('UPDATE'),
      result: () => ({ rowCount: 0, rows: [] })
    }
  ];
}

describe('fileArtifacts/dualWrite source fix', () => {
  it('does not contain the broken integration_feeds.source_name lookup', () => {
    assert.doesNotMatch(
      dualWriteSrc,
      /integration_feeds\s+WHERE\s+source_name/i
    );
    assert.match(dualWriteSrc, /resolveFeedIdBySourceName/);
    assert.match(dualWriteSrc, /withSavepoint/);
  });

  it('maps ThreatFox / MalwareBazaar source names to feed keys', () => {
    assert.equal(feedKeyForSourceName('ThreatFox:abuse.ch'), 'threatfox-abusech');
    assert.equal(feedKeyForSourceName('MalwareBazaar:abuse.ch'), 'malwarebazaar-abusech');
  });

  it('classifies schema errors as rethrow; unique as controlled', () => {
    assert.equal(shouldRethrowDualWriteError({ code: '42703', message: 'column "source_name" does not exist' }), true);
    assert.equal(shouldRethrowDualWriteError({ code: '23505' }), false);
    assert.equal(isControlledFileArtifactDbError({ code: '25P02' }), false);
    const formatted = formatProviderError({ code: '42703', message: 'column "source_name" does not exist', column: 'source_name' });
    assert.equal(formatted.sqlState, '42703');
    assert.equal(formatted.column, 'source_name');
  });
});

describe('fileArtifacts/dualWrite feed import paths', () => {
  let prevDual;
  before(() => {
    prevDual = process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = '1';
  });
  after(() => {
    if (prevDual == null) delete process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    else process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = prevDual;
  });

  it('ThreatFox MD5 dual-write succeeds and never queries integration_feeds.source_name', async () => {
    const client = createAbortAwareClient(ensureArtifactHandlers({
      observable: MD5,
      observableType: 'md5',
      sourceName: 'ThreatFox:abuse.ch'
    }));

    const result = await dualWriteFileArtifactForObservable(client, {
      observable: MD5,
      observableType: 'md5',
      sourceName: 'ThreatFox:abuse.ch',
      logger: { warn: () => {} }
    });

    assert.equal(result.ok, true);
    assert.equal(result.artifact_id, ART_ID);
    assert.ok(client.state.queries.some((q) => /^SAVEPOINT\b/i.test(q.sql)));
    assert.equal(
      client.state.queries.filter((q) => /integration_feeds/i.test(q.sql) && /WHERE\s+source_name/i.test(q.sql)).length,
      0
    );
    assert.equal(client.state.aborted, false);
  });

  it('MalwareBazaar SHA256 dual-write succeeds (MD5+SHA256 sibling note)', async () => {
    const note = `Auto-imported from MalwareBazaar CSV | md5=${MD5} | file_name=sample.exe`;
    const client = createAbortAwareClient(ensureArtifactHandlers({
      observable: SHA256,
      observableType: 'sha256',
      sourceName: 'MalwareBazaar:abuse.ch',
      note
    }));

    const result = await dualWriteFileArtifactForObservable(client, {
      observable: SHA256,
      observableType: 'sha256',
      sourceName: 'MalwareBazaar:abuse.ch',
      note,
      attachNoteSiblings: true,
      providerMapping: true,
      logger: { warn: () => {} }
    });

    assert.equal(result.ok, true);
    assert.equal(client.state.aborted, false);
  });

  it('repeat import is idempotent (no aborted transaction)', async () => {
    const handlers = ensureArtifactHandlers({
      observable: SHA256,
      observableType: 'sha256',
      sourceName: 'MalwareBazaar:abuse.ch',
      note: `md5=${MD5}`
    });
    const client = createAbortAwareClient(handlers);

    const a = await dualWriteFileArtifactForObservable(client, {
      observable: SHA256,
      observableType: 'sha256',
      sourceName: 'MalwareBazaar:abuse.ch',
      note: `md5=${MD5}`,
      attachNoteSiblings: true,
      providerMapping: true,
      logger: { warn: () => {} }
    });
    const b = await dualWriteFileArtifactForObservable(client, {
      observable: SHA256,
      observableType: 'sha256',
      sourceName: 'MalwareBazaar:abuse.ch',
      note: `md5=${MD5}`,
      attachNoteSiblings: true,
      providerMapping: true,
      logger: { warn: () => {} }
    });
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
    assert.equal(client.state.aborted, false);
  });

  it('SHA256-only and MD5-only paths both succeed', async () => {
    for (const c of [
      { type: 'sha256', value: SHA256, source: 'ThreatFox:abuse.ch' },
      { type: 'md5', value: MD5, source: 'MalwareBazaar:abuse.ch' }
    ]) {
      const client = createAbortAwareClient(ensureArtifactHandlers({
        observable: c.value,
        observableType: c.type,
        sourceName: c.source
      }));
      const result = await dualWriteFileArtifactForObservable(client, {
        observable: c.value,
        observableType: c.type,
        sourceName: c.source,
        logger: { warn: () => {} }
      });
      assert.equal(result.ok, true, c.type);
      assert.equal(client.state.aborted, false);
    }
  });

  it('skips non-hash types without touching feeds', async () => {
    const client = createAbortAwareClient([]);
    const result = await dualWriteFileArtifactForObservable(client, {
      observable: 'evil.example',
      observableType: 'domain',
      sourceName: 'ThreatFox:abuse.ch'
    });
    assert.deepEqual(result, { skipped: true, reason: 'not_exact_hash' });
    assert.equal(client.state.queries.length, 0);
  });

  it('passes feedId through without feed meta lookup when provided', async () => {
    const client = createAbortAwareClient(ensureArtifactHandlers({
      observable: SHA256,
      observableType: 'sha256',
      sourceName: 'MalwareBazaar:abuse.ch'
    }));
    await dualWriteFileArtifactForObservable(client, {
      observable: SHA256,
      observableType: 'sha256',
      sourceName: 'MalwareBazaar:abuse.ch',
      feedId: MB_FEED_ID,
      logger: { warn: () => {} }
    });
    const feedLookups = client.state.queries.filter((q) => /FROM integration_feeds/i.test(q.sql));
    assert.equal(feedLookups.length, 0);
  });
});

describe('fileArtifacts/dualWrite transaction safety', () => {
  let prevDual;
  before(() => {
    prevDual = process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = '1';
  });
  after(() => {
    if (prevDual == null) delete process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    else process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = prevDual;
  });

  it('reproduces root cause: 42703 without savepoint poisons TX → 25P02', async () => {
    const client = createAbortAwareClient([
      {
        match: (sql) => /integration_feeds/i.test(sql) && /source_name/i.test(sql),
        fail: undefinedColumnError('source_name')
      }
    ]);

    await assert.rejects(
      () => client.query('SELECT integration_id FROM integration_feeds WHERE source_name = $1', ['MalwareBazaar:abuse.ch']),
      (err) => err.code === '42703' && /source_name/.test(err.message)
    );
    await assert.rejects(
      () => client.query('SELECT 1 AS recovery'),
      (err) => err.code === '25P02'
    );
  });

  it('with savepoint: schema error does not leave 25P02; next query works', async () => {
    const client = createAbortAwareClient([
      {
        match: (sql) => /FAIL_SCHEMA/i.test(sql),
        fail: undefinedColumnError('source_name')
      },
      {
        match: (sql) => /SELECT recovery/i.test(sql),
        result: () => ({ rows: [{ ok: true }], rowCount: 1 })
      }
    ]);

    await assert.rejects(
      () => withSavepoint(client, 'fa_test', () => client.query('SELECT FAIL_SCHEMA')),
      (err) => err.code === '42703'
    );
    const ok = await client.query('SELECT recovery');
    assert.equal(ok.rows[0].ok, true);
    assert.equal(client.state.aborted, false);
  });

  it('first DB error (42703) is preserved on rethrow — not replaced by 25P02', async () => {
    const warnings = [];
    const client = createAbortAwareClient([
      {
        match: (sql) => sql.includes('FROM ioc_items'),
        result: () => iocRow({
          observable: SHA256,
          observableType: 'sha256',
          sourceName: 'MalwareBazaar:abuse.ch'
        })
      },
      {
        match: (sql) => sql.includes('FROM integration_feeds') && /WHERE key/i.test(sql),
        result: (_sql, params) => {
          const key = params?.[0];
          const row = feedMetaResult().rows.find((r) => r.key === key);
          return {
            rowCount: row ? 1 : 0,
            rows: row ? [{ integration_id: row.feed_id }] : []
          };
        }
      },
      {
        match: (sql) => /pg_advisory_xact_lock/i.test(sql),
        fail: undefinedColumnError('source_name')
      }
    ]);

    await assert.rejects(
      () => dualWriteFileArtifactForObservable(client, {
        observable: SHA256,
        observableType: 'sha256',
        sourceName: 'MalwareBazaar:abuse.ch',
        logger: { warn: (...args) => warnings.push(args) }
      }),
      (err) => {
        assert.equal(err.code, '42703');
        assert.match(err.message, /source_name/);
        assert.notEqual(err.code, '25P02');
        return true;
      }
    );

    assert.equal(client.state.aborted, false);
    assert.ok(warnings.length >= 1);
    const payload = warnings[0][1];
    assert.equal(payload.sqlState, '42703');
    assert.match(payload.message, /source_name/);
  });

  it('controlled unique violation soft-fails; connection remains usable', async () => {
    const client = createAbortAwareClient([
      {
        match: (sql) => sql.includes('FROM ioc_items'),
        result: () => iocRow({
          observable: MD5,
          observableType: 'md5',
          sourceName: 'ThreatFox:abuse.ch'
        })
      },
      {
        match: (sql) => sql.includes('FROM integration_feeds') && /WHERE key/i.test(sql),
        result: (_sql, params) => {
          const key = params?.[0];
          const row = feedMetaResult().rows.find((r) => r.key === key);
          return {
            rowCount: row ? 1 : 0,
            rows: row ? [{ integration_id: row.feed_id }] : []
          };
        }
      },
      {
        match: (sql) => /pg_advisory_xact_lock/i.test(sql),
        fail: (() => {
          const err = new Error('duplicate key value violates unique constraint "uq_file_artifact_hashes"');
          err.code = '23505';
          err.constraint = 'uq_file_artifact_hashes';
          return err;
        })()
      },
      {
        match: (sql) => /SELECT next_item/i.test(sql),
        result: () => ({ rows: [{ ok: true }], rowCount: 1 })
      }
    ]);

    const result = await dualWriteFileArtifactForObservable(client, {
      observable: MD5,
      observableType: 'md5',
      sourceName: 'ThreatFox:abuse.ch',
      logger: { warn: () => {} }
    });
    assert.equal(result.ok, false);
    assert.equal(result.code, '23505');
    assert.equal(client.state.aborted, false);

    const next = await client.query('SELECT next_item');
    assert.equal(next.rows[0].ok, true);
  });
});
