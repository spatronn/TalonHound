/**
 * Release invariant (test:release): VirusTotal enrichment → file-artifact
 * dual-write is best-effort. The helper never rejects (so the enrichment
 * response cannot fail because of it), never fails silently (thrown error,
 * missing lazy module or `{ ok: false }`), and the diagnostic carries no
 * hashes, VT API key or raw VT response.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { extractExactHashesFromVtRaw } from './fileArtifacts/index.js';
import { dualWriteVirusTotalFileArtifact } from './virustotalFileArtifactDualWrite.js';

const digest = (alg) => createHash(alg).update('TALONHOUND-FAKE-VT-FILE').digest('hex');
const MD5 = digest('md5');
const SHA1 = digest('sha1');
const SHA256 = digest('sha256');
const FAKE_VT_API_KEY = 'vtkey_FakeVirusTotalApiKey_7e2d';
const RAW_MARKER = 'RAW-VT-RESPONSE-MARKER-dropper.exe';

const RAW_FILE = {
  data: {
    type: 'file',
    id: SHA256,
    attributes: { md5: MD5, sha1: SHA1, sha256: SHA256, meaningful_name: RAW_MARKER }
  }
};
const RAW_URL = { data: { type: 'url', id: 'u1', attributes: { url: 'https://x.test/', last_final_url: RAW_MARKER } } };

function makeLogger() {
  const entries = [];
  const capture = (level) => (message, fields = {}) => entries.push({ level, message, fields });
  return { entries, debug: capture('debug'), info: capture('info'), warn: capture('warn'), error: capture('error') };
}

/** @param {{ dualWrite?: Function, enabled?: boolean, loadFileArtifacts?: Function, raw?: any, iocType?: string }} fake */
async function enrich({ dualWrite = async () => ({ ok: true }), enabled = true, loadFileArtifacts, raw = RAW_FILE, iocType = 'hash' } = {}) {
  const logger = makeLogger();
  const calls = [];
  const outcome = await dualWriteVirusTotalFileArtifact({ query: async () => ({ rows: [] }) }, {
    iocId: 4242,
    iocType,
    observable: SHA256,
    raw
  }, {
    logger,
    loadFileArtifacts: loadFileArtifacts || (async () => ({
      extractExactHashesFromVtRaw,
      isFileArtifactsDualWriteEnabled: () => enabled,
      dualWriteFileArtifactForObservable: async (_pool, input) => {
        calls.push(input);
        return dualWrite(input);
      }
    }))
  });
  return { outcome, logger, calls };
}

function assertOneSafeDiagnostic(logger, expected) {
  assert.equal(logger.entries.length, 1);
  const [entry] = logger.entries;
  assert.equal(entry.level, 'warn');
  assert.deepEqual({ ...entry.fields, error_message: undefined }, {
    component: 'virustotal_enrichment',
    source: 'virustotal',
    ioc_id: '4242',
    observable_type: 'hash',
    operation: 'file_artifact_dual_write',
    result: 'failed',
    error_message: undefined,
    ...expected
  });
  const text = JSON.stringify(logger.entries).toLowerCase();
  for (const h of [MD5, SHA1, SHA256]) assert.ok(!text.includes(h), 'raw hash leaked into diagnostic');
  assert.ok(!text.includes(FAKE_VT_API_KEY.toLowerCase()), 'VT API key leaked into diagnostic');
  assert.ok(!text.includes(RAW_MARKER.toLowerCase()), 'raw VT response leaked into diagnostic');
  return entry;
}

describe('VirusTotal enrichment file-artifact dual-write is best-effort but observable', () => {
  it('success: dual-writes the VT exact hash set unchanged, no diagnostic', async () => {
    const run = await enrich();
    assert.equal(run.outcome.ok, true);
    assert.equal(run.calls.length, 1);
    assert.deepEqual(run.calls[0], {
      observable: SHA256,
      observableType: 'sha256',
      sourceName: 'VirusTotal',
      note: `md5=${MD5} | sha1=${SHA1} | sha256=${SHA256}`,
      attachNoteSiblings: true,
      providerMapping: true,
      observationType: 'enrichment_derived',
      relationMethod: 'enrichment_result'
    });
    assert.deepEqual(run.logger.entries, []);
  });

  it('dual-write disabled or no exact hashes in the VT report: no write, no diagnostic', async () => {
    const off = await enrich({ enabled: false });
    assert.equal(off.outcome.ok, true);
    assert.equal(off.calls.length, 0);
    assert.deepEqual(off.logger.entries, []);
    const url = await enrich({ raw: RAW_URL, iocType: 'url' });
    assert.equal(url.outcome.ok, true);
    assert.equal(url.calls.length, 0);
    assert.deepEqual(url.logger.entries, []);
  });

  it('thrown failure: resolves (enrichment unaffected) with one safe diagnostic', async () => {
    const run = await enrich({
      dualWrite: async () => {
        const err = new Error(
          `insert failed for ${SHA256.toUpperCase()} / ${MD5} / ${SHA1} (x-apikey: ${FAKE_VT_API_KEY})`
        );
        err.code = '42P01';
        throw err;
      }
    });
    assert.deepEqual(run.outcome, { ok: false });
    const entry = assertOneSafeDiagnostic(run.logger, { error_code: '42P01', error_class: 'Error' });
    assert.match(entry.fields.error_message, /insert failed for <observable> \/ <observable> \/ <observable>/);
  });

  it('missing lazy module (ERR_MODULE_NOT_FOUND): resolves with one diagnostic', async () => {
    const run = await enrich({ loadFileArtifacts: () => import('./fileArtifacts/__missing_for_test__.js') });
    assert.deepEqual(run.outcome, { ok: false });
    assertOneSafeDiagnostic(run.logger, { error_code: 'ERR_MODULE_NOT_FOUND', error_class: 'Error' });
  });

  it('controlled { ok: false } result is logged, not swallowed', async () => {
    const run = await enrich({
      dualWrite: async () => ({ ok: false, error: `conflict on ${SHA1}`, code: '23505' })
    });
    assert.deepEqual(run.outcome, { ok: false });
    const entry = assertOneSafeDiagnostic(run.logger, { error_code: '23505', error_class: 'DualWriteResult' });
    assert.equal(entry.fields.error_message, 'conflict on <observable>');
  });
});

describe('VirusTotal enrichment dual-write source guard (server.js)', () => {
  const src = fs.readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'server.js'),
    'utf8'
  );

  it('server.js never calls the dual-write helpers directly (no new silent call site)', () => {
    assert.deepEqual(src.match(/\bdualWriteFileArtifact(?:ForObservable)?\(/g) || [], []);
  });

  it('VT refresh (shared by the route and MCP enrichment) awaits the best-effort helper before reporting success', () => {
    // The refresh logic lives in runVirusTotalRefresh; the route is a thin wrapper over it.
    const route = src.indexOf('async function runVirusTotalRefresh(');
    assert.ok(route !== -1);
    assert.ok(src.indexOf("app.post('/api/ioc/:id/enrichments/virustotal/refresh'") > route);
    const call = src.indexOf('await dualWriteVirusTotalFileArtifact(pool, {', route);
    const completed = src.indexOf('AUDIT_ACTION.VT_ENRICHMENT_COMPLETED', route);
    const success = src.indexOf("status: 'success', provider: VT_PROVIDER", route);
    assert.ok(call !== -1 && call < completed && completed < success);
    // Not wrapped in a local try/catch that could hide or re-route its outcome.
    const preceding = src.slice(src.lastIndexOf('\n', call - 1) - 200, call);
    assert.doesNotMatch(preceding, /try\s*\{\s*$/);
  });
});
