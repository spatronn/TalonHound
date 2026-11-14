/**
 * Import audit 35890–35901, through real Postgres:
 *
 *  - FN-2: the FBI FLASH PDF (pages 1, 6 and 7 of FLASH-20261113-001, a public
 *    TLP:CLEAR advisory) uploaded through the real PDF import route and run by
 *    the real job runner (a mock model that proposes nothing) persists its 25
 *    published Indicators, its cover title and its cover publication date; the
 *    legitimate LLM API endpoints of its behavioral table are not Indicators.
 *  - FN-1: a URL report whose stored document is the html_v12 8-block stub of a
 *    Vue slot-rendered article is stale under html_v13, and the read-only
 *    Refresh preview rebuilds it from the retained source HTML (no network)
 *    with every Indicator added and nothing removed.
 *
 * Every report is deleted afterwards; nothing here reaches a live system.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import pg from 'pg';

const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-audit-35890-'));
process.env.THREAT_LIBRARY_STORAGE_DIR = storage;

const here = path.dirname(fileURLToPath(import.meta.url));
const { registerThreatLibraryRoutes } = await import('../../routes/threatLibrary.js');
const { createAuditLogService } = await import('../auditLogService.js');
const { runThreatLibraryJob } = await import('./jobRunner.js');
const { storeArtifactBuffer } = await import('./artifactStore.js');
const { previewExtractionRefresh } = await import('./extractionRefresh.js');
const { isDocumentContractCurrent } = await import('./extractionStages.js');
const { getReportById } = await import('./store.js');
const { createInferenceScheduler } = await import('./ai/inferenceScheduler.js');
const { startMockOllama } = await import('../../test-support/mockOllamaServer.js');

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 3000,
  max: 6
});

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT 1 FROM threat_report_extraction_run_candidates LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };

const IC3_INDICATORS = [
  ...'38.244.50.120 144.172.64.60 144.172.64.99 144.172.64.128 187.15.88.186 187.15.90.217 187.15.89.186 101.53.80.20 205.214.59.31 124.155.252.63 154.201.79.246 23.248.249.90 23.158.220.98 103.248.148.84 203.160.133.172 209.209.85.38 199.19.95.66 199.19.95.67 199.19.95.68 91.92.240.238 85.11.168.45 178.16.54.129 31.77.229.35 85.11.167.52'
    .split(' ').map((ip) => `ip:${ip}`),
  'domain:xcai.pro'
].sort();
const LLM_API = ['api.anthropic.com', 'api.deepseek.com', 'open.bigmodel.cn', 'api.x.ai'].map((d) => `domain:${d}`);

let server;
let base;
let enqueued = [];
let savedAi;
let scheduler;
let ollama;
const created = [];
// The model answers with no candidate updates: every result below is deterministic.
const EMPTY_ANSWER = JSON.stringify({
  summary: 'Synthetic.', report_type: 'advisory', language: 'en', tlp: 'TLP:CLEAR', confidence: 0.5,
  entities: [], candidate_updates: [], relationships: []
});

test.before(async () => {
  if (!hasDb) return;
  savedAi = (await pool.query('SELECT enabled, provider, base_url, model, auto_retry_max_attempts FROM threat_library_ai_settings WHERE id = 1')).rows[0];
  ollama = await startMockOllama({ plan: () => ({ promptEvalMs: 1, genMs: 1, content: EMPTY_ANSWER }) });
  await pool.query(
    `UPDATE threat_library_ai_settings SET enabled = TRUE, provider = 'ollama', base_url = $1, model = 'itest-model', auto_retry_max_attempts = 0 WHERE id = 1`,
    [ollama.baseUrl]
  );
  scheduler = createInferenceScheduler(pool, { pollMs: 25, waitLeaseMs: 1000, holdLeaseMs: 3000, heartbeatMs: 500 });
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { id: null, role: 'admin', email: 'itest@talonhound.test' };
    next();
  });
  const queue = { add: async (_name, data) => { enqueued.push(data); return { id: String(enqueued.length) }; } };
  registerThreatLibraryRoutes(app, pool, createAuditLogService(pool), { threatLibraryQueue: queue });
  await new Promise((resolve) => { server = app.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${server.address().port}/api/threat-library`;
});

test.after(async () => {
  if (hasDb) {
    await new Promise((resolve) => server.close(resolve));
    for (const id of created) await pool.query('DELETE FROM threat_reports WHERE id = $1', [id]).catch(() => {});
    if (savedAi) {
      await pool.query(
        `UPDATE threat_library_ai_settings SET enabled = $1, provider = $2, base_url = $3, model = $4, auto_retry_max_attempts = $5 WHERE id = 1`,
        [savedAi.enabled, savedAi.provider, savedAi.base_url, savedAi.model, savedAi.auto_retry_max_attempts]
      );
    }
    scheduler?.stop?.();
    await ollama?.close?.();
  }
  await pool.end();
  fs.rmSync(storage, { recursive: true, force: true });
});

test('FN-2: the FLASH PDF through the import route persists 25 Indicators, its cover title and date', opts, async () => {
  enqueued = [];
  // A per-run byte suffix after %%EOF keeps the upload's SHA-256 unique (duplicate-import identity).
  const pdf = Buffer.concat([
    fs.readFileSync(path.join(here, 'fixtures', 'ic3-flash-261113-pages-1-6-7.pdf')),
    Buffer.from(`\n% itest ${crypto.randomUUID()}\n`)
  ]);
  const form = new FormData();
  form.append('file', new Blob([pdf], { type: 'application/pdf' }), '261113.pdf');
  const res = await fetch(`${base}/import/pdf`, { method: 'POST', body: form });
  const body = await res.json();
  assert.equal(res.status, 202, JSON.stringify(body));
  const { rows: [row] } = await pool.query('SELECT id FROM threat_reports WHERE public_id = $1', [body.report.id]);
  created.push(row.id);
  assert.equal(enqueued.length, 1);
  const result = await runThreatLibraryJob(pool, enqueued[0], { inferenceScheduler: scheduler });
  assert.equal(result.ok, true, JSON.stringify(result));

  const { rows: [report] } = await pool.query(
    `SELECT title, published_at::date::text AS published_date, published_at_source, analysis_status, failure_code, failure_reason,
            analysis_progress->'extraction_diagnostics'->'quality' AS quality
       FROM threat_reports WHERE id = $1`,
    [row.id]
  );
  assert.equal(report.title, 'Threat Overview of ARTEX Autonomous Penetration Testing Framework');
  assert.equal(report.published_date, '2026-11-13');
  assert.equal(report.published_at_source, 'pdf_visible_date');
  assert.equal(report.analysis_status, 'review_required', `${report.failure_code}: ${report.failure_reason}`);
  const codes = (report.quality?.warnings || []).map((w) => w.code);
  assert.ok(!codes.includes('ioc_section_region_dropped'), codes.join(', '));

  const { rows: run } = await pool.query(
    `SELECT rc.candidate_type || ':' || rc.normalized_value AS id, rc.is_member
       FROM threat_report_extraction_run_candidates rc
       JOIN threat_report_extraction_runs r ON r.id = rc.run_id
      WHERE r.report_id = $1 AND r.is_first_pass`,
    [row.id]
  );
  assert.deepEqual(run.filter((x) => x.is_member).map((x) => x.id).sort(), IC3_INDICATORS);
  for (const id of LLM_API) {
    const hit = run.find((x) => x.id === id);
    assert.ok(hit, `${id} not recorded`);
    assert.equal(hit.is_member, false, id);
  }
  // Persisted candidates agree with the run ledger (no duplicate identities).
  const { rows: cands } = await pool.query(
    `SELECT candidate_type || ':' || lower(normalized_value) AS id, count(*)::int AS n
       FROM threat_report_candidates WHERE report_id = $1 GROUP BY 1`,
    [row.id]
  );
  assert.ok(cands.every((c) => c.n === 1), 'duplicate candidate identity');
  for (const id of IC3_INDICATORS) assert.ok(cands.some((c) => c.id === id), `${id} not persisted`);
});

test('FN-1: a stale html_v12 stub of a Vue slot-rendered article rebuilds from retained HTML in the Refresh preview', opts, async () => {
  const url = `https://vendor-labs.example/eng/expertise/blog/slot-rendered-actor-${crypto.randomUUID()}/`;
  const stub = {
    title: 'New data reveals espionage focus of a slot-rendered actor',
    language: 'en',
    blocks: [
      { id: 'b001', type: 'heading', level: 1, text: 'New data reveals espionage focus of a slot-rendered actor', page: null, section: null },
      { id: 'b002', type: 'paragraph', text: '#research', page: null, section: null }
    ],
    meta: { extractor: 'threat_library_html_v12', adapter: 'generic_html', source_url: url }
  };
  const { rows: [r] } = await pool.query(
    `INSERT INTO threat_reports (title, source_type, source_url, canonical_document, import_status, analysis_status)
     VALUES ($1, 'url', $2, $3::jsonb, 'review_required', 'review_required') RETURNING id`,
    [stub.title, url, JSON.stringify(stub)]
  );
  created.push(r.id);
  const html = fs.readFileSync(path.join(here, 'benchmark', 'cases', 'control-vue-slot-template-article.html'));
  const stored = await storeArtifactBuffer(r.id, html, { fileName: 'source.html' });
  await pool.query(
    `INSERT INTO threat_report_artifacts (report_id, artifact_type, file_name, mime_type, size_bytes, sha256, storage_key, source_metadata)
     VALUES ($1, 'url_fetch', 'source.html', 'text/html; charset=utf-8', $2, $3, $4, $5::jsonb)`,
    [r.id, html.length, stored.sha256, stored.storageKey, JSON.stringify({ final_url: url, http_status: 200 })]
  );

  const report = await getReportById(pool, r.id);
  assert.equal(isDocumentContractCurrent(report, report.canonical_document), false, 'html_v12 document must be stale');
  const preview = await previewExtractionRefresh(pool, report);
  assert.equal(preview.preview, true);
  assert.equal(preview.document_rebuilt, true);
  assert.deepEqual(preview.membership_diff.removed_indicators, []);
  assert.deepEqual([...preview.membership_diff.added_indicators].sort(), [
    'domain:slot-relay-update.example',
    'ip:198.51.100.51',
    'ip:203.0.113.87',
    'sha256:3f1c0f4f6c1e2a9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c',
    'sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
    'url:http://198.51.100.51/agent.exe',
    'url:http://198.51.100.51:5173/api/clients/7c1e4d2b9a8f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d/stream/ws'
  ]);
  // The preview writes nothing: the stored stub and its (zero) candidates stay.
  const { rows: [after] } = await pool.query(
    `SELECT canonical_document->'meta'->>'extractor' AS extractor,
            (SELECT count(*)::int FROM threat_report_candidates WHERE report_id = $1) AS candidates
       FROM threat_reports WHERE id = $1`,
    [r.id]
  );
  assert.deepEqual(after, { extractor: 'threat_library_html_v12', candidates: 0 });
});
