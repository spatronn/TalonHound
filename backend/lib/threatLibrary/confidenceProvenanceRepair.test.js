/**
 * scripts/repair-threat-library-confidence-provenance.js: relabel the
 * confidence provenance of Threat Library-created IOCs ('manual_entry' →
 * 'source_entry') only when the Threat Library origin is provable.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  THREAT_LIBRARY_NOTE_RE,
  planConfidenceProvenanceRepair
} from '../../scripts/repair-threat-library-confidence-provenance.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const SOURCE_ID = 19;
const row = (over = {}) => ({
  ioc_source_id: 19,
  source_name: 'Threat_Library',
  created_origin: 'manual_add',
  confidence_source: 'manual_entry',
  confidence: 'high',
  note: 'Threat Library report bc112cbf-8931-4564-bc24-ab46d316fcf5: malicious_infrastructure (malicious)',
  report_exists: true,
  ...over
});

test('a provable Threat Library row is relabelled', () => {
  assert.deepEqual(planConfidenceProvenanceRepair(row(), SOURCE_ID), { decision: 'relabel', change: true });
  assert.equal(planConfidenceProvenanceRepair(row({ confidence: 'medium', note: 'Threat Library report bc112cbf-8931-4564-bc24-ab46d316fcf5: command_and_control (suspicious)' }), SOURCE_ID).change, true);
});

test('already relabelled rows are a no-op (idempotent)', () => {
  assert.deepEqual(planConfidenceProvenanceRepair(row({ confidence_source: 'source_entry' }), SOURCE_ID), { decision: 'already_source_entry', change: false });
});

test('anything not provably Threat Library is left unchanged', () => {
  const cases = [
    [{ ioc_source_id: 7 }, 'not_threat_library_source'],
    [{ source_name: 'Analyst_Notes' }, 'not_threat_library_source'],
    [{ created_origin: 'api' }, 'unexpected_origin'],
    [{ confidence_source: 'ioc_source_default' }, 'unexpected_provenance'],
    [{ confidence: 'low' }, 'unexpected_confidence'],
    [{ note: 'added by hand from the advisory' }, 'note_not_threat_library'],
    [{ note: 'Threat Library report bc112cbf-8931-4564-bc24-ab46d316fcf5: c2 (malicious) — checked' }, 'note_not_threat_library'],
    [{ report_exists: false }, 'report_missing']
  ];
  for (const [over, decision] of cases) {
    const plan = planConfidenceProvenanceRepair(row(over), SOURCE_ID);
    assert.equal(plan.change, false, decision);
    assert.equal(plan.decision, decision);
  }
});

test('note pattern is exactly the Threat Library writer format (reviewService)', () => {
  const src = fs.readFileSync(path.join(here, 'reviewService.js'), 'utf8');
  assert.match(src, /note: `Threat Library report \$\{report\.public_id\}: \$\{candidate\.role \|\| 'unknown'\} \(\$\{candidate\.assessment\}\)`/);
  assert.ok(THREAT_LIBRARY_NOTE_RE.test('Threat Library report bc112cbf-8931-4564-bc24-ab46d316fcf5: unknown (suspicious)'));
});

test('the UPDATE is guarded by every planning predicate and changes provenance columns only', () => {
  const src = fs.readFileSync(path.resolve(here, '..', '..', 'scripts', 'repair-threat-library-confidence-provenance.js'), 'utf8');
  const update = src.slice(src.indexOf('UPDATE ioc_items'), src.indexOf('[row.id, row.observable_type'));
  assert.match(update, /SET confidence_source = 'source_entry',\s+confidence_source_name = \$3\s+WHERE/);
  for (const guard of ["confidence_source = 'manual_entry'", 'confidence = $5', 'note = $6', "created_origin = 'manual_add'", 'ioc_source_id = $4']) {
    assert.ok(update.includes(guard), guard);
  }
  const setClause = update.slice(update.indexOf('SET'), update.indexOf('WHERE'));
  assert.doesNotMatch(setClause, /\bconfidence\s*=/, 'the confidence value itself is never written');
  assert.match(src, /const apply = process\.argv\.slice\(2\)\.includes\('--apply'\)/, 'dry-run by default');
});
