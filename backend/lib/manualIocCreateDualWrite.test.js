/**
 * Release invariant (test:release): manual IOC create → file-artifact dual-write
 * is best-effort. A failure (missing lazy module, thrown error, `{ ok: false }`)
 * must not fail the create (201 stays 201), must never be silent, and the
 * diagnostic must not carry the raw observable or request secrets.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createManualIoc } from './manualIocCreate.js';

const FAKE_SHA256 = createHash('sha256').update('TALONHOUND-FAKE-MANUAL-IOC').digest('hex');
const FAKE_SECRET = 'tok_FakeManualSessionSecret_51c0';
const PUBLIC_ID = '22222222-2222-4222-8222-222222222222';

const SOURCE = {
  id: 7,
  name: 'Threat-Hunting',
  default_confidence: 'high',
  default_threat_classification: 'unknown',
  default_expire_policy: 'expire_after_days',
  default_expire_days: 30,
  active: true,
  archived_at: null
};

const INSERT_ROW = {
  id: 9001,
  public_id: PUBLIC_ID,
  observable: FAKE_SHA256,
  observable_type: 'sha256',
  source_name: 'Threat-Hunting',
  source_url: null,
  confidence: 'high',
  category: null,
  threat_classification: 'unknown',
  threat_actor_id: null,
  note: null,
  ioc_source_id: 7,
  status: 'active',
  expires_at: '2026-07-28T12:00:00.000Z',
  manual_status_override: true,
  manual_status: 'active',
  manual_override_reason: 'manual_custom_expire',
  manual_expires_at: '2026-07-28T12:00:00.000Z',
  created_at: new Date('2026-06-28T12:00:00.000Z')
};

function makePool() {
  const query = async (sql) => {
    const s = String(sql).replace(/\s+/g, ' ').trim();
    if (s.includes('FROM ioc_sources WHERE id = $1')) return { rows: [SOURCE] };
    if (s.includes('FROM threat_classifications')) {
      return { rows: [{ slug: 'unknown', name: 'Unknown', active: true, system_default: true, sort_order: 0 }] };
    }
    if (s.startsWith('INSERT INTO ioc_items')) return { rows: [INSERT_ROW] };
    if (s.includes('FROM ioc_items WHERE id = $1 AND observable_type = $2')) return { rows: [INSERT_ROW] };
    if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
      return { rows: [{ ...INSERT_ROW, status: 'active' }] };
    }
    return { rows: [], rowCount: 0 };
  };
  return { query, connect: async () => ({ query, release: () => {} }) };
}

function makeLogger() {
  const entries = [];
  const capture = (level) => (message, fields = {}) => entries.push({ level, message, fields });
  return { entries, debug: capture('debug'), info: capture('info'), warn: capture('warn'), error: capture('error') };
}

/** @param {{ dualWrite?: Function, loadDualWrite?: Function }} fake */
async function create({ dualWrite, loadDualWrite }) {
  const logger = makeLogger();
  const audits = [];
  const calls = [];
  const result = await createManualIoc(makePool(), { observable: FAKE_SHA256, source_id: 7 }, {
    logger,
    loadDualWrite: loadDualWrite || (async () => ({
        dualWriteFileArtifactForObservable: async (_pool, input) => {
          calls.push(input);
          return dualWrite(input);
        }
      })),
    req: { headers: { authorization: `Bearer ${FAKE_SECRET}`, cookie: `session=${FAKE_SECRET}` } },
    audit: { auditSuccess: async (entry) => { audits.push(entry); } }
  });
  return { result, logger, audits, calls };
}

function assertCreated({ result, audits }) {
  assert.equal(result.status, 201);
  assert.equal(result.body.observable, FAKE_SHA256);
  assert.equal(result.body.observable_type, 'sha256');
  assert.equal(audits.filter((a) => a.action === 'ioc.created').length, 1);
}

function assertOneSafeDiagnostic(logger, expected) {
  assert.equal(logger.entries.length, 1);
  const [entry] = logger.entries;
  assert.equal(entry.level, 'warn');
  assert.deepEqual({ ...entry.fields, error_message: undefined }, {
    component: 'manual_ioc_create',
    source: 'manual_add',
    ioc_id: '9001',
    ioc_public_id: PUBLIC_ID,
    observable_type: 'sha256',
    ioc_source_id: 7,
    operation: 'file_artifact_dual_write',
    result: 'failed',
    error_message: undefined,
    ...expected
  });
  const text = JSON.stringify(logger.entries);
  assert.ok(!text.toLowerCase().includes(FAKE_SHA256), 'raw observable leaked into diagnostic');
  assert.ok(!text.includes(FAKE_SECRET), 'request secret leaked into diagnostic');
  return entry;
}

describe('manual IOC create file-artifact dual-write is best-effort but observable', () => {
  it('success: IOC is created, dual-write runs once, no diagnostic', async () => {
    const run = await create({ dualWrite: async () => ({ ok: true, artifact_id: 'a1' }) });
    assertCreated(run);
    assert.equal(run.calls.length, 1);
    assert.equal(run.calls[0].observable, FAKE_SHA256);
    assert.equal(run.calls[0].observableType, 'sha256');
    assert.equal(run.calls[0].sourceName, 'Threat-Hunting');
    assert.equal(run.calls[0].attachNoteSiblings, false);
    assert.equal(run.calls[0].providerMapping, false);
    assert.deepEqual(run.logger.entries, []);
  });

  it('skipped dual-write (e.g. flag off / not an exact hash) is not a failure', async () => {
    const run = await create({ dualWrite: async () => ({ skipped: true, reason: 'dual_write_disabled' }) });
    assertCreated(run);
    assert.deepEqual(run.logger.entries, []);
  });

  it('thrown failure: IOC is still created and one safe diagnostic is logged', async () => {
    const run = await create({ dualWrite: async (input) => {
      const err = new Error(
        `relation "file_artifacts" does not exist for ${input.observable.toUpperCase()} (Authorization: Bearer ${FAKE_SECRET})`
      );
      err.code = '42P01';
      throw err;
    } });
    assertCreated(run);
    const entry = assertOneSafeDiagnostic(run.logger, { error_code: '42P01', error_class: 'Error' });
    assert.match(entry.fields.error_message, /relation "file_artifacts" does not exist for <observable>/);
  });

  it('missing lazy module (ERR_MODULE_NOT_FOUND): IOC is still created, failure is visible', async () => {
    const run = await create({ loadDualWrite: () => import('./fileArtifacts/__missing_for_test__.js') });
    assertCreated(run);
    assertOneSafeDiagnostic(run.logger, { error_code: 'ERR_MODULE_NOT_FOUND', error_class: 'Error' });
  });

  it('controlled { ok: false } result: IOC is still created, failure is not swallowed', async () => {
    const run = await create({ dualWrite: async () => ({
      ok: false,
      error: `duplicate key value violates unique constraint "uq_file_artifact_hashes" (${FAKE_SHA256})`,
      code: '23505'
    }) });
    assertCreated(run);
    const entry = assertOneSafeDiagnostic(run.logger, { error_code: '23505', error_class: 'DualWriteResult' });
    assert.match(entry.fields.error_message, /uq_file_artifact_hashes/);
  });
});

describe('manual IOC create dual-write source guard', () => {
  it('the only dual-write call in manualIocCreate.js runs through runBestEffortFileArtifactDualWrite', () => {
    const src = fs.readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'manualIocCreate.js'),
      'utf8'
    );
    const calls = [...src.matchAll(/dualWriteFileArtifact(?:ForObservable)?\(/g)].map((m) => m.index);
    assert.equal(calls.length, 1);
    const wrapper = src.indexOf('await runBestEffortFileArtifactDualWrite({');
    assert.ok(wrapper !== -1 && wrapper < calls[0], 'dual-write must be wrapped by runBestEffortFileArtifactDualWrite');
    assert.ok(src.indexOf('logger:', wrapper) > calls[0], 'dual-write call must sit inside the wrapper run()');
  });
});
