/**
 * Real-report labels (./real-reports): committed ground truth for retained
 * publisher sources that are NOT in the repository.
 *
 * Always (CI included): every label is valid, carries provenance and a public
 * source reference, and contains no source content. With a private source
 * store (TL_BENCHMARK_SOURCE_DIR, e.g. a CI secret mount): every available
 * label is scored and the result is ratcheted — no FN, and FPs only from
 * known-false-positives.json (a fixed FP must be retired from that file).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  REAL_REPORT_LABELS_DIR,
  caseSourceAvailable,
  loadBenchmarkCases,
  loadRealReportLabels,
  materializeCase,
  runBenchmark
} from './benchmarkRunner.js';

const labels = loadRealReportLabels();
const knownFp = JSON.parse(fs.readFileSync(path.join(REAL_REPORT_LABELS_DIR, 'known-false-positives.json'), 'utf8'));
const SOURCE_DIR = process.env.TL_BENCHMARK_SOURCE_DIR || null;

test('real-report labels: valid, referenced, provenance-bearing and free of source content', () => {
  assert.ok(labels.length >= 20, `labels loaded: ${labels.length}`);
  const shas = new Set();
  for (const c of labels) {
    assert.ok(c.id.startsWith('real-'), c.id);
    assert.equal(c.source.kind, 'private_source');
    assert.ok(!shas.has(c.source.sha256), `duplicate source ${c.source.sha256}`);
    shas.add(c.source.sha256);
    assert.ok(c.source.url || c.source.reference, `${c.id}: public reference`);
    assert.ok(c.publisher, `${c.id}: publisher`);
    // Repository distribution must rest on the publisher's own release, never
    // on TalonHound's editable TLP field.
    assert.ok(['public_web_publication', 'tlp_clear_marking'].includes(c.source.distribution?.basis), `${c.id}: distribution basis`);
    assert.ok(c.source.distribution.evidence && c.source.distribution.verified_at, `${c.id}: distribution evidence`);
    assert.ok(c.ground_truth.provenance.method && c.ground_truth.provenance.verified_at, `${c.id}: provenance`);
    assert.ok(c.ground_truth.provenance.coverage_note, `${c.id}: coverage note`);
    const file = path.join(REAL_REPORT_LABELS_DIR, `${c.id.replace(/^real-/, '')}.json`);
    const raw = fs.readFileSync(file, 'utf8');
    assert.ok(raw.length < 400_000, `${c.id}: label is identities, not a document`);
    assert.ok(!/<(?:html|body|article|script)\b/i.test(raw), `${c.id}: no markup`);
  }
});

test('known false positives reference real labels and labelled-out identities only', () => {
  const byId = new Map(labels.map((c) => [c.id, c]));
  for (const [id, entry] of Object.entries(knownFp.cases)) {
    const c = byId.get(id);
    assert.ok(c, `${id} is a label`);
    assert.ok(knownFp.causes[entry.cause], `${id}: documented cause`);
    const indicators = new Set(c.ground_truth.indicators.map((e) => `${e.type}:${String(e.value).toLowerCase()}`));
    for (const ident of entry.identities) assert.ok(!indicators.has(ident.toLowerCase()), `${ident} is not a labelled Indicator`);
  }
});

test('labels run only with a source store; a missing source is unavailable, not a failure', () => {
  assert.equal(loadBenchmarkCases({ sourceDir: null, privateDir: null }).some((c) => c.id.startsWith('real-')), false);
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-src-'));
  try {
    const subset = loadBenchmarkCases({ sourceDir: empty, privateDir: null }).filter((c) => c.id.startsWith('real-')).slice(0, 2);
    assert.equal(subset.length, 2);
    assert.equal(subset.every((c) => !caseSourceAvailable(c)), true);
    const run = runBenchmark({ cases: subset });
    assert.deepEqual(run.results, []);
    assert.deepEqual(run.unavailable, subset.map((c) => c.id));
  } finally {
    fs.rmSync(empty, { recursive: true, force: true });
  }
});

test('a store file that does not hash to the label sha256 is refused', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-src-'));
  try {
    const c = { ...labels.find((x) => x.source.format === 'html'), __sourceDir: dir };
    fs.writeFileSync(path.join(dir, `${c.source.sha256}.html`), '<html><body><p>tampered</p></body></html>');
    assert.throws(() => materializeCase(c), /does not match sha256/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('with the private source store: no FN, FPs only from known-false-positives.json (ratchet)', { skip: SOURCE_DIR ? false : 'set TL_BENCHMARK_SOURCE_DIR to a private source store to score real reports' }, () => {
  const cases = loadBenchmarkCases({ sourceDir: SOURCE_DIR, privateDir: null }).filter((c) => c.id.startsWith('real-'));
  const run = runBenchmark({ cases });
  assert.ok(run.results.length > 0, 'at least one real-report source available');
  for (const r of run.results) {
    const m = r.metrics.indicators;
    assert.deepEqual(m.false_negatives.map((x) => x.id), [], `${r.id}: false negatives`);
    const expectedFp = (knownFp.cases[r.id]?.identities || []).slice().sort();
    assert.deepEqual(m.false_positives.map((x) => x.id).sort(), expectedFp, `${r.id}: false positives differ from known-false-positives.json`);
  }
});

test('a label sha256 is the digest of the store file the runner reads (HTML)', { skip: SOURCE_DIR ? false : 'needs TL_BENCHMARK_SOURCE_DIR' }, () => {
  for (const c of labels.filter((x) => x.source.format === 'html')) {
    const file = path.join(SOURCE_DIR, `${c.source.sha256}.html`);
    if (!fs.existsSync(file)) continue;
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'), c.source.sha256);
  }
});
