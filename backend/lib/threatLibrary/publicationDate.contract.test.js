/**
 * Publication-date write path contracts: pipeline wiring, THIB round trip,
 * and the "never in a status write" rule. Source-level checks pin the wiring
 * the way pipeline.contract.test.js pins artifact reuse; the THIB checks run
 * the real codec / import against a fake pool.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { exportThibBundle, validateThibBundle } from './thib/codec.js';
import { attachThibIntegrity } from './thib/integrity.js';
import { importThibBundle } from './thibImport.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (rel) => readFileSync(path.join(here, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

test('pipeline: detection runs after the document is final and before candidates, under the write policy, non-fatally', () => {
  const pipeline = src('pipeline.js');
  assert.match(pipeline, /import \{ detectReportPublicationDate, resolvePublicationDateUpdate \} from '\.\/publicationDate\.js'/);
  const helper = pipeline.slice(pipeline.indexOf('async function applyPublicationDate('), pipeline.indexOf('export async function runAnalysisPipeline('));
  assert.match(helper, /detectReportPublicationDate\(\{/);
  assert.match(helper, /resolvePublicationDateUpdate\(current, detection\)/);
  assert.match(helper, /if \(decision\.action === 'write'\)\s*\{\s*await updateReportPublicationDate\(pool, report\.id, decision\.fields\);/);
  assert.match(helper, /catch \(err\)/, 'a date failure never fails the analysis');
  assert.doesNotMatch(helper, /updateReportStatus\(/, 'publication date is never written through a lifecycle/status update');
  assert.doesNotMatch(helper, /import_status|analysis_status/, 'no lifecycle change to set a date');

  const run = pipeline.slice(pipeline.indexOf('export async function runAnalysisPipeline('));
  const detectAt = run.indexOf('applyPublicationDate(pool, report, { document, sourceHtml })');
  const candidatesAt = run.indexOf('decideCandidateReuse(');
  const fetchAt = run.indexOf('ingestUrlToCanonicalDocument(');
  assert.ok(detectAt > 0 && fetchAt > 0 && candidatesAt > 0);
  assert.ok(fetchAt < detectAt && detectAt < candidatesAt, 'detection sits between fetch/extract and candidate extraction');
  // Raw HTML from this run (fetched or retained) feeds the extractor; PDFs only pass the document.
  assert.match(run, /sourceHtml = fetched\.bodyText \|\| null;/);
  assert.match(run, /sourceHtml = html;/);
  // Pipeline status writes never carry published_at (COALESCE would keep it anyway, but the field must not be in the patch).
  const statusPatches = run.match(/updateReportStatus\(pool, [^;]*?\{[\s\S]*?\}\);/g) || [];
  assert.ok(statusPatches.length >= 5);
  for (const patch of statusPatches) assert.doesNotMatch(patch, /published_at/);
  // The final ai_result records the outcome for audit / diagnostics.
  assert.match(run, /publication_date: publicationDate,/);
});

test('pipeline: PDF path never reads the PDF info dictionary dates', () => {
  const pdf = src('pdfIngest.js');
  assert.doesNotMatch(pdf, /CreationDate|ModDate|creationDate|modDate/);
  const pub = src('publicationDate.js');
  assert.doesNotMatch(pub, /CreationDate|ModDate/i);
});

test('store: createThreatReport only persists provenance next to a value; updateReportPublicationDate touches only the four columns', () => {
  const store = src('store.js');
  const upd = store.slice(store.indexOf('export async function updateReportPublicationDate('), store.indexOf('export async function getReportByPublicId('));
  assert.match(upd, /published_at = \$2,\s*published_at_source = \$3,\s*published_at_precision = \$4,\s*published_at_raw = \$5,\s*updated_at = NOW\(\)\s*WHERE id = \$1/);
  assert.doesNotMatch(upd, /import_status|analysis_status|tlp|title/);
  assert.match(upd, /throw Object\.assign\(new Error\('Invalid publication date fields'\)/);
  assert.match(store, /ORDER BY r\.published_at DESC NULLS LAST, r\.created_at DESC/, 'threat-context chronology: publication date first, import date as fallback');
});

const REPORT = {
  title: 'Kimsuky LNK chain',
  source_type: 'pdf',
  tlp: 'clear',
  summary: 'sum',
  portable_id: 'report--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  bundle_id: 'thib--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
};

function fakeImportPool() {
  const inserts = [];
  return {
    inserts,
    query: async (sql, params = []) => {
      const q = String(sql).replace(/\s+/g, ' ');
      if (q.startsWith('SELECT id, public_id, title, import_status FROM threat_reports')) return { rows: [] };
      if (q.startsWith('INSERT INTO threat_reports')) {
        inserts.push(params);
        return { rows: [{ id: 1, public_id: 'pub', title: params[0], published_at: params[6], published_at_source: params[18], published_at_precision: params[19], published_at_raw: params[20] }] };
      }
      return { rows: [] };
    }
  };
}

test('THIB 20: a date-only published_at round-trips with date precision and source thib (never re-derived, never an invented time)', async () => {
  const bundle = exportThibBundle({
    report: { ...REPORT, published_at: new Date('2026-09-15T00:00:00Z'), published_at_precision: 'date', published_at_source: 'pdf_visible_date' },
    entities: [], candidates: [], relationships: []
  });
  assert.equal(validateThibBundle(bundle).ok, true);
  assert.equal(bundle.report.published_at, '2026-09-15', 'calendar day travels without a time');

  const pool = fakeImportPool();
  const out = await importThibBundle(pool, bundle, {});
  assert.equal(out.ok, true);
  const params = pool.inserts[0];
  assert.equal(params[6], '2026-09-15T00:00:00.000Z');
  assert.equal(params[18], 'thib');
  assert.equal(params[19], 'date');
  assert.equal(params[20], '2026-09-15');
});

test('THIB: an instant round-trips as ISO UTC; an unreadable value imports as NULL instead of failing', async () => {
  const bundle = exportThibBundle({
    report: { ...REPORT, published_at: new Date('2026-09-15T15:00:19Z'), published_at_precision: 'datetime', published_at_source: 'json_ld' },
    entities: [], candidates: [], relationships: []
  });
  assert.equal(bundle.report.published_at, '2026-09-15T15:00:19.000Z');
  let pool = fakeImportPool();
  await importThibBundle(pool, bundle, {});
  assert.equal(pool.inserts[0][19], 'datetime');
  assert.equal(pool.inserts[0][18], 'thib');

  // A bundle from another generator may carry a free-text value; re-signed so integrity passes.
  const legacy = attachThibIntegrity({ ...bundle, report: { ...bundle.report, published_at: 'sometime in 2026' } });
  pool = fakeImportPool();
  const out = await importThibBundle(pool, legacy, {});
  assert.equal(out.ok, true);
  assert.equal(pool.inserts[0][6], null);
  assert.equal(pool.inserts[0][18], null);
});
