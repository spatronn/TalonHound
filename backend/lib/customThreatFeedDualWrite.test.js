/**
 * Release invariant (test:release): custom-feed file-artifact dual-write is
 * best-effort. A failure (missing lazy module, thrown error, `{ ok: false }`)
 * must not abort the primary feed import, must never be silent, and must log a
 * bounded, secret-free diagnostic, not one line per feed row.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import {
  runCustomThreatFeedSync,
  createFileArtifactDualWriteFailureTracker
} from './customThreatFeedSync.js';
import { insertCustomFeedSyncAudit } from './customThreatFeedWorkerAudit.js';

const FEED_ID = '22222222-2222-2222-2222-222222222222';
const INTEGRATION_FEED_ID = '33333333-3333-3333-3333-333333333333';
const RUN_ID = '44444444-4444-4444-4444-444444444444';
const SECRET_TOKEN = 'tok_SuperSecretFeedToken_9f8e7d';

const sha256 = (i) => createHash('sha256').update(`talonhound-dual-write-${i}`).digest('hex');

function makeFeedRow() {
  return {
    id: FEED_ID,
    integration_feed_id: INTEGRATION_FEED_ID,
    integration_key: 'custom_feed_dualwrite_test',
    feed_name: 'Dual-write test feed',
    url: 'https://feeds.example.test/hashes.txt',
    format: 'txt',
    ioc_type_mode: 'auto',
    fixed_ioc_type: null,
    timeout_ms: 5000,
    default_confidence: 'medium',
    credentials: { auth_type: 'bearer_token', token: SECRET_TOKEN }
  };
}

/** Fake pg client: every row is a new IOC; records the primary IOC writes. */
function makeClient() {
  let nextId = 1;
  const client = {
    iocInserts: [],
    membershipInserts: 0,
    runUpdate: null,
    integrationRun: null,
    async query(sql, params = []) {
      const s = String(sql).trim();
      if (s.startsWith('INSERT INTO ioc_items')) {
        const id = nextId++;
        client.iocInserts.push(params[0]);
        return { rows: [{ id, public_id: `ioc-${id}` }], rowCount: 1 };
      }
      if (s.startsWith('SELECT public_id FROM ioc_items')) {
        return { rows: [{ public_id: `ioc-${params[0]}` }], rowCount: 1 };
      }
      if (s.startsWith('INSERT INTO ioc_feed_memberships')) {
        client.membershipInserts += 1;
        return {
          rows: [{ id: client.membershipInserts, ioc_item_id: params[0], status: 'active' }],
          rowCount: 1
        };
      }
      if (s.startsWith('UPDATE custom_threat_feed_runs')) {
        client.runUpdate = params;
        return { rows: [], rowCount: 1 };
      }
      if (s.startsWith('INSERT INTO integration_runs')) {
        client.integrationRun = params;
        return { rows: [], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  return client;
}

/** Captures appLogger-style calls: logger.<level>(message, fields). */
function makeLogger() {
  const entries = [];
  const capture = (level) => (message, fields = {}) => entries.push({ level, message, fields });
  return {
    entries,
    debug: capture('debug'),
    info: capture('info'),
    warn: capture('warn'),
    error: capture('error')
  };
}

async function runSync({ rows = 3, loadDualWrite }) {
  const hashes = Array.from({ length: rows }, (_, i) => sha256(i));
  const client = makeClient();
  const logger = makeLogger();
  const result = await runCustomThreatFeedSync(client, makeFeedRow(), {
    runId: RUN_ID,
    triggeredBy: 'test',
    logger,
    loadDualWrite,
    fetchFeed: async () => ({
      ok: true,
      httpStatus: 200,
      fetchedBytes: hashes.join('\n').length,
      contentType: 'text/plain',
      bodyText: hashes.join('\n')
    })
  });
  return { result, client, logger, hashes };
}

const dualWriteEntries = (logger) => logger.entries.filter((e) => e.fields.operation === 'file_artifact_dual_write');

function assertPrimaryImportSucceeded({ result, client, hashes }) {
  assert.equal(result.status, 'success');
  assert.equal(result.error_message, null);
  assert.equal(result.valid_rows, hashes.length);
  assert.equal(result.inserted, hashes.length);
  assert.deepEqual(client.iocInserts, hashes);
  assert.equal(client.runUpdate[1], 'success');
  assert.equal(client.integrationRun[0], 'success');
}

function assertNoSensitiveData(text, hashes) {
  assert.ok(!text.includes(SECRET_TOKEN), 'feed credential leaked into diagnostic');
  for (const h of hashes) assert.ok(!text.includes(h), 'raw IOC value leaked into diagnostic');
}

describe('custom feed file-artifact dual-write is best-effort but observable', () => {
  it('success: feed imports normally, dual-write runs per row, no failure diagnostic', async () => {
    const calls = [];
    const run = await runSync({
      loadDualWrite: async () => ({
        dualWriteFileArtifactForObservable: async (_client, input) => {
          calls.push(input);
          return { ok: true, artifact_id: 'a1' };
        }
      })
    });
    assertPrimaryImportSucceeded(run);
    assert.equal(calls.length, run.hashes.length);
    assert.deepEqual(calls.map((c) => c.observable), run.hashes);
    assert.equal(calls[0].observableType, 'sha256');
    assert.equal(calls[0].feedId, INTEGRATION_FEED_ID);
    assert.equal(calls[0].attachNoteSiblings, false);
    assert.equal(calls[0].providerMapping, false);
    assert.equal(run.result.file_artifact_dual_write_failures, 0);
    assert.equal(run.result.file_artifact_dual_write_first_error, null);
    assert.deepEqual(run.logger.entries, []);
  });

  it('missing lazy module (ERR_MODULE_NOT_FOUND): feed import succeeds, failure is visible', async () => {
    const run = await runSync({
      // Real module-resolution failure, as in the beta.13 integration image.
      loadDualWrite: () => import('./fileArtifacts/__missing_for_test__.js')
    });
    assertPrimaryImportSucceeded(run);
    assert.equal(run.result.file_artifact_dual_write_failures, run.hashes.length);
    assert.equal(run.result.file_artifact_dual_write_first_error, 'ERR_MODULE_NOT_FOUND');
    const [first, summary, ...rest] = dualWriteEntries(run.logger);
    assert.deepEqual(rest, []);
    assert.equal(first.level, 'warn');
    assert.deepEqual(
      { ...first.fields, error_message: undefined },
      {
        component: 'custom_threat_feed',
        operation: 'file_artifact_dual_write',
        result: 'failed',
        feed_id: FEED_ID,
        integration_key: 'custom_feed_dualwrite_test',
        run_id: RUN_ID,
        observable_type: 'sha256',
        error_code: 'ERR_MODULE_NOT_FOUND',
        error_class: 'Error',
        error_message: undefined
      }
    );
    assert.match(first.fields.error_message, /__missing_for_test__/);
    assert.equal(summary.level, 'warn');
    assert.deepEqual(summary.fields, {
      component: 'custom_threat_feed',
      operation: 'file_artifact_dual_write',
      result: 'failed',
      feed_id: FEED_ID,
      integration_key: 'custom_feed_dualwrite_test',
      run_id: RUN_ID,
      failed: 3,
      attempted: 3,
      by_type: { sha256: 3 },
      error_codes: { ERR_MODULE_NOT_FOUND: 3 },
      first_error: 'ERR_MODULE_NOT_FOUND'
    });
  });

  it('thrown dual-write error: feed import succeeds, failure is visible, no secrets / raw IOC values', async () => {
    const run = await runSync({
      loadDualWrite: async () => ({
        dualWriteFileArtifactForObservable: async (_client, input) => {
          const err = new Error(
            `relation "file_artifacts" does not exist for ${input.observable} (Authorization: Bearer ${SECRET_TOKEN})`
          );
          err.code = '42P01';
          throw err;
        }
      })
    });
    assertPrimaryImportSucceeded(run);
    assert.equal(run.result.file_artifact_dual_write_failures, run.hashes.length);
    assert.equal(run.result.file_artifact_dual_write_first_error, '42P01');
    const entries = dualWriteEntries(run.logger);
    assert.equal(entries.length, 2);
    assert.equal(entries[0].fields.error_code, '42P01');
    const text = JSON.stringify(run.logger.entries);
    assert.match(text, /<observable>/);
    assert.match(text, /\[REDACTED\]/);
    assertNoSensitiveData(text, run.hashes);
  });

  it('controlled { ok: false } result is counted as a failure, not swallowed', async () => {
    const run = await runSync({
      rows: 2,
      loadDualWrite: async () => ({
        dualWriteFileArtifactForObservable: async () => ({
          ok: false,
          error: 'duplicate key value violates unique constraint "uq_file_artifact_hashes"',
          code: '23505'
        })
      })
    });
    assertPrimaryImportSucceeded(run);
    assert.equal(run.result.file_artifact_dual_write_failures, 2);
    assert.equal(run.result.file_artifact_dual_write_first_error, '23505');
    const entries = dualWriteEntries(run.logger);
    assert.equal(entries.length, 2);
    assert.equal(entries[0].fields.error_code, '23505');
    assert.equal(entries[0].fields.error_class, 'DualWriteResult');
    assert.equal(entries[1].fields.attempted, 2);
  });

  it('log storm: 2,000 failing rows emit exactly one first-failure line and one summary', async () => {
    const run = await runSync({
      rows: 2000,
      loadDualWrite: async () => ({
        dualWriteFileArtifactForObservable: async () => {
          throw Object.assign(new Error('boom'), { code: 'ECONNRESET' });
        }
      })
    });
    assertPrimaryImportSucceeded(run);
    assert.equal(run.result.file_artifact_dual_write_failures, 2000);
    assert.equal(run.logger.entries.length, 2);
    const summary = run.logger.entries[1].fields;
    assert.equal(summary.failed, 2000);
    assert.equal(summary.attempted, 2000);
    assert.deepEqual(summary.by_type, { sha256: 2000 });
    assert.deepEqual(summary.error_codes, { ECONNRESET: 2000 });
  });

  it('sync audit metadata carries the failure count only when there were failures', async () => {
    const captured = [];
    const pool = { query: async (_sql, params) => { captured.push(JSON.parse(params[7])); } };
    const base = { feed_id: FEED_ID, feed_name: 'f', run_id: RUN_ID, status: 'success' };
    await insertCustomFeedSyncAudit(pool, { ...base, file_artifact_dual_write_failures: 0 });
    await insertCustomFeedSyncAudit(pool, {
      ...base,
      file_artifact_dual_write_failures: 7,
      file_artifact_dual_write_first_error: 'ERR_MODULE_NOT_FOUND'
    });
    assert.equal('file_artifact_dual_write_failures' in captured[0], false);
    assert.equal(captured[1].file_artifact_dual_write_failures, 7);
    assert.equal(captured[1].file_artifact_dual_write_first_error, 'ERR_MODULE_NOT_FOUND');
    assert.equal(captured[1].status, 'success');
  });
});

describe('createFileArtifactDualWriteFailureTracker', () => {
  it('bounds distinct error codes and stays silent when nothing failed', () => {
    const logger = makeLogger();
    const t = createFileArtifactDualWriteFailureTracker({ feedId: 'f', logger });
    t.flush();
    assert.deepEqual(logger.entries, []);
    for (let i = 0; i < 50; i += 1) {
      t.noteAttempt();
      t.record(Object.assign(new Error('x'), { code: `E${i}` }), { observableType: 'md5' });
    }
    t.flush();
    const s = t.summary();
    assert.equal(s.failed, 50);
    assert.ok(Object.keys(s.error_codes).length <= 5);
    assert.equal(logger.entries.length, 2);
  });
});

describe('custom feed dual-write source guard', () => {
  // Supplements the behavioral tests: the critical-path file must not regain an
  // empty catch (the beta.13 `catch {}` that hid ERR_MODULE_NOT_FOUND).
  it('customThreatFeedSync.js has no empty catch block', () => {
    const src = fs.readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'customThreatFeedSync.js'),
      'utf8'
    );
    const emptyCatch = /catch\s*(?:\([^)]*\))?\s*\{(?:\s|\/\/[^\n]*|\/\*[\s\S]*?\*\/)*\}/g;
    assert.deepEqual(src.match(emptyCatch) || [], []);
  });
});
