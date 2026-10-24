/**
 * Offline corpus-replay acceptance for the 30-report audit remediation.
 *
 * Always (CI): the replay tool exports scoreAgainstLabels and the committed
 * 30-report labels sum to the corrected baseline (1025 Indicators, 5 ambiguous).
 *
 * With TL_CORPUS_SNAPSHOT pointing at the private production snapshot
 * (outside the repository): every labelled report is replayed with the
 * production Refresh path (deterministic extraction + retained model
 * decisions) and must match ground truth exactly (FN=0, FP=0; ambiguous
 * excluded from scoring). Discovery is not scored here — see the RC-8
 * regressions and the remediation doc.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRealReportLabels } from './benchmark/benchmarkRunner.js';
import { groundTruthIdentity } from './benchmark/benchmarkMetrics.js';
import { readSnapshot, replayEntry, scoreAgainstLabels } from '../../scripts/threat-library-corpus-replay.js';

const SNAPSHOT = process.env.TL_CORPUS_SNAPSHOT || null;
const AUDIT_VERIFIED = '2026-10-24';

function auditLabels() {
  return loadRealReportLabels().filter((l) =>
    String(l.ground_truth?.provenance?.verified_at || '').startsWith(AUDIT_VERIFIED)
  );
}

test('corrected 30-report label baseline: 1025 Indicators, 5 ambiguous, no silent empties', () => {
  const labels = auditLabels();
  assert.equal(labels.length, 30, `expected 30 audit labels, got ${labels.length}`);
  let indicators = 0;
  let ambiguous = 0;
  for (const l of labels) {
    const gt = l.ground_truth;
    assert.ok(Array.isArray(gt.indicators), l.id);
    indicators += gt.indicators.length;
    ambiguous += (gt.ambiguous || []).length;
    // Exact-match accounts for every report, including the 0-Indicator PHP CVE note.
    assert.ok(gt.provenance?.coverage_note, `${l.id}: coverage note`);
    assert.ok(l.source?.talonhound_report_id, `${l.id}: public report id`);
  }
  assert.equal(indicators, 1025);
  assert.equal(ambiguous, 5);
});

test('scoreAgainstLabels is identity-exact (not count-only)', () => {
  const sample = auditLabels().find((l) => (l.ground_truth.indicators || []).length > 0);
  assert.ok(sample);
  const expected = sample.ground_truth.indicators.map(groundTruthIdentity);
  const fake = {
    public_id: sample.source.talonhound_report_id,
    members: expected.slice(1), // drop one → FN
    error: null
  };
  const scored = scoreAgainstLabels([fake]);
  assert.ok(scored.total.fn >= 1);
  assert.ok(scored.total.exact < scored.total.reports);
});

test(
  'private corpus snapshot: 30-report replay matches corrected ground truth',
  {
    skip: SNAPSHOT
      ? false
      : 'set TL_CORPUS_SNAPSHOT to the private corpus-snapshot-*.jsonl.gz to score offline replay'
  },
  async () => {
    assert.ok(fs.existsSync(SNAPSHOT), `snapshot missing: ${SNAPSHOT}`);
    const wanted = new Set(auditLabels().map((l) => String(l.source.talonhound_report_id)));
    const reports = [];
    for (const entry of readSnapshot(SNAPSHOT)) {
      const pub = String(entry.report?.public_id || '');
      if (!wanted.has(pub)) continue;
      reports.push(await replayEntry(entry));
    }
    assert.equal(reports.length, 30, `replayed ${reports.length} of 30 audit reports`);
    assert.equal(reports.filter((r) => r.error).length, 0, JSON.stringify(reports.filter((r) => r.error)));
    const scored = scoreAgainstLabels(reports);
    assert.equal(scored.total.reports, 30);
    assert.equal(scored.total.tp, 1025, `TP ${scored.total.tp}`);
    assert.equal(scored.total.fn, 0, `FN ${scored.total.fn}: ${JSON.stringify(scored.rows.filter((r) => r.fn.length))}`);
    assert.equal(scored.total.fp, 0, `FP ${scored.total.fp}: ${JSON.stringify(scored.rows.filter((r) => r.fp.length))}`);
    assert.equal(scored.total.ambiguous, 5);
    assert.equal(scored.total.exact, 30);
  }
);

test(
  'private corpus snapshot: historical labelled reports do not gain unexpected membership (drift accounted)',
  {
    skip: SNAPSHOT
      ? false
      : 'set TL_CORPUS_SNAPSHOT to the private corpus-snapshot-*.jsonl.gz to score historical drift'
  },
  async () => {
    // Documented pre-existing baseline drifts from earlier audits (numeric
    // production report ids). Must stay explicit — never silently absorbed.
    const KNOWN_HISTORICAL_DRIFT_IDS = new Set([24456, 30328]);
    const labelled = loadRealReportLabels().filter(
      (l) => l.source?.talonhound_report_id && !String(l.ground_truth?.provenance?.verified_at || '').startsWith(AUDIT_VERIFIED)
    );
    const byPublic = new Set(labelled.map((l) => String(l.source.talonhound_report_id)));
    const reports = [];
    for (const entry of readSnapshot(SNAPSHOT)) {
      const pub = String(entry.report?.public_id || '');
      if (!byPublic.has(pub)) continue;
      reports.push(await replayEntry(entry));
    }
    const scored = scoreAgainstLabels(reports);
    for (const row of scored.rows) {
      if (!row.fn.length && !row.fp.length) continue;
      assert.ok(
        KNOWN_HISTORICAL_DRIFT_IDS.has(Number(row.report)),
        `unexpected membership drift on report ${row.report} (${row.label}): FN=${row.fn.join('|')} FP=${row.fp.join('|')}`
      );
    }
  }
);

// Keep the module path resolvable when the suite is discovered from cwd=backend.
void path.dirname(fileURLToPath(import.meta.url));
