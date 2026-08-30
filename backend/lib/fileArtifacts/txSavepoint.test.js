import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  withSavepoint,
  isControlledFileArtifactDbError,
  formatProviderError
} from './txSavepoint.js';

/**
 * Minimal client that mirrors PG: a failed statement aborts until ROLLBACK TO SAVEPOINT.
 */
function createAbortAwareClient() {
  const state = { aborted: false, ops: [] };
  const client = {
    state,
    async query(sql) {
      const s = String(sql);
      state.ops.push(s.replace(/\s+/g, ' ').trim().slice(0, 120));
      if (/^SAVEPOINT\b/i.test(s)) return { rows: [] };
      if (/^RELEASE SAVEPOINT\b/i.test(s)) return { rows: [] };
      if (/^ROLLBACK TO SAVEPOINT\b/i.test(s)) {
        state.aborted = false;
        return { rows: [] };
      }
      if (state.aborted) {
        const err = new Error(
          'current transaction is aborted, commands ignored until end of transaction block'
        );
        err.code = '25P02';
        throw err;
      }
      if (/\bFAIL_UNIQUE\b/i.test(s)) {
        state.aborted = true;
        const err = new Error('duplicate key value violates unique constraint "uq_file_artifact_hashes"');
        err.code = '23505';
        err.constraint = 'uq_file_artifact_hashes';
        throw err;
      }
      return { rows: [{ ok: true }] };
    }
  };
  return client;
}

describe('fileArtifacts/txSavepoint', () => {
  it('classifies unique / conflict as controlled, not 25P02', () => {
    assert.equal(isControlledFileArtifactDbError({ code: '23505' }), true);
    assert.equal(isControlledFileArtifactDbError({ reason: 'conflict' }), true);
    assert.equal(isControlledFileArtifactDbError({ reason: 'invalid_hash' }), true);
    assert.equal(
      isControlledFileArtifactDbError({
        code: '25P02',
        message: 'current transaction is aborted, commands ignored until end of transaction block'
      }),
      false
    );
    assert.equal(isControlledFileArtifactDbError({ code: '42P01', message: 'missing table' }), false);
  });

  it('formatProviderError keeps SQL code (not only message)', () => {
    const formatted = formatProviderError(
      { code: '23505', message: 'duplicate key', constraint: 'uq_file_artifact_hashes', table: 'file_artifact_hashes' },
      { evidence_id: 3101 }
    );
    assert.equal(formatted.code, '23505');
    assert.equal(formatted.sqlState, '23505');
    assert.equal(formatted.evidence_id, 3101);
    assert.equal(formatted.constraint, 'uq_file_artifact_hashes');
    assert.equal(formatted.table, 'file_artifact_hashes');
  });

  it('withSavepoint falls back when SAVEPOINT is unavailable (no active transaction)', async () => {
    const client = {
      async query(sql) {
        if (/^SAVEPOINT\b/i.test(String(sql))) {
          const err = new Error('SAVEPOINT can only be used in transaction blocks');
          err.code = '25P01';
          throw err;
        }
        return { rows: [{ ok: true }] };
      }
    };
    const result = await withSavepoint(client, 'fa_no_tx', async () => ({ ran: true }));
    assert.deepEqual(result, { ran: true });
  });

  it('without savepoint: first unique error then next query becomes 25P02', async () => {
    const client = createAbortAwareClient();
    await assert.rejects(() => client.query('INSERT FAIL_UNIQUE'), (err) => err.code === '23505');
    await assert.rejects(() => client.query('SELECT recovery'), (err) => err.code === '25P02');
  });

  it('with savepoint: provider record SQL error does not 25P02-chain; next record succeeds', async () => {
    const client = createAbortAwareClient();
    const results = [];

    // Record 1 — fails with unique violation inside savepoint
    await assert.rejects(
      () => withSavepoint(client, 'fa_provider_rec', async () => {
        await client.query('INSERT FAIL_UNIQUE');
      }),
      (err) => err.code === '23505'
    );
    results.push({ record: 1, code: '23505' });

    // Record 2 — must succeed on clean transaction state (no 25P02)
    const ok = await withSavepoint(client, 'fa_provider_rec', async () => {
      const r = await client.query('INSERT ok_row');
      return r.rows[0];
    });
    assert.equal(ok.ok, true);
    results.push({ record: 2, ok: true });

    assert.equal(results[0].code, '23505');
    assert.equal(results[1].ok, true);
    assert.ok(client.state.ops.some((op) => /^ROLLBACK TO SAVEPOINT/i.test(op)));
    assert.equal(client.state.aborted, false);
  });

  it('attach-style unique recovery queries work after ROLLBACK TO SAVEPOINT', async () => {
    const client = createAbortAwareClient();
    await withSavepoint(client, 'fa_hash_ins', async () => {
      await client.query('INSERT FAIL_UNIQUE');
    }).catch((err) => {
      assert.equal(err.code, '23505');
    });
    // Mimic attachExactHashInTx recovery after savepoint rollback
    const again = await client.query('SELECT find_existing_hash');
    assert.equal(again.rows[0].ok, true);
  });
});
