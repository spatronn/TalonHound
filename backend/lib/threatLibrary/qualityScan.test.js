/**
 * Read-only quality scan CLI: argument parsing and aggregation (the database
 * session itself is read-only; the per-report work is previewExtractionRefresh).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseScanArgs, summarizeScan } from '../../scripts/threat-library-quality-scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));

test('scan arguments: repeated reports, bounded limit, clean list', () => {
  const a = parseScanArgs(['--report', 'r1', '--report', 'r2', '--limit', '99999', '--clean', 'r1, r3', '--json']);
  assert.deepEqual(a.reports, ['r1', 'r2']);
  assert.equal(a.limit, 5000);
  assert.deepEqual(a.clean, ['r1', 'r3']);
  assert.equal(a.json, true);
  assert.throws(() => parseScanArgs(['--apply']), /unknown argument/);
});

test('scan summary: quality status, code frequency, guard verdicts, false warnings on verified-clean reports', () => {
  const s = summarizeScan([
    { id: 'r1', quality: { status: 'warning', warnings: [{ code: 'indicator_rows_adjacent_to_authoritative_scope' }] }, guard: { decision: 'apply' }, membership_diff: { counts: {} } },
    { id: 'r2', quality: { status: 'clean', warnings: [] }, guard: { decision: 'block' }, membership_diff: { counts: { removed_indicators: 3 } } },
    { id: 'r3', quality: { status: 'info', warnings: [{ code: 'authoritative_section_empty' }] }, guard: { decision: 'apply' }, membership_diff: { counts: {} } },
    { id: 'r4', error: 'refresh_source_unavailable' }
  ], ['r1', 'r3']);
  assert.equal(s.reports, 4);
  assert.equal(s.errors, 1);
  assert.deepEqual(s.quality_status, { clean: 1, info: 1, warning: 1, high: 0 });
  assert.equal(s.codes.indicator_rows_adjacent_to_authoritative_scope, 1);
  assert.deepEqual(s.guard, { apply: 2, apply_accepted: 0, block: 1 });
  assert.equal(s.reports_with_membership_changes, 1);
  assert.deepEqual(s.verified_clean, { reports: 2, flagged: 1, flagged_ids: ['r1'] }, 'info is not a false warning');
});

test('the scan opens a read-only session and never issues writes', () => {
  const src = fs.readFileSync(path.join(here, '..', '..', 'scripts', 'threat-library-quality-scan.js'), 'utf8');
  assert.match(src, /default_transaction_read_only=on/);
  assert.equal(/\b(INSERT|UPDATE|DELETE)\s+(INTO|FROM|threat_)/i.test(src.replace(/\/\*[\s\S]*?\*\//g, '')), false);
  assert.equal(/runExtractionRefresh|reconcileReportCandidates|queue\.add/.test(src), false);
});
