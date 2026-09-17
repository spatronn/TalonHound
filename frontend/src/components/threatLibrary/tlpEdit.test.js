/**
 * Manual TLP editing: canonical options, provenance labels, downgrade
 * confirmation, permission gate, and the page / banner wiring.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  TLP_OPTIONS,
  canEditTlp,
  describeTlpChangeConfirm,
  describeTlpSavedFeedback,
  isTlpDowngrade,
  tlpSourceLabel,
  tlpSourceShortLabel
} from './tlpEdit.js';
import { normalizeTlp, tlpDisplay } from './tlpValues.js';
import { buildReportDetails } from './reportOverview.js';
import { threatLibraryDetailRows } from '../../lib/auditThreatLibraryDetail.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const pageSrc = readFileSync(path.join(here, 'ThreatLibraryReportPage.jsx'), 'utf8');

test('options are exactly the canonical TalonHound TLP 2.0 set', () => {
  assert.deepEqual(TLP_OPTIONS.map((o) => o.value), ['clear', 'green', 'amber', 'amber_strict', 'red']);
  assert.deepEqual(TLP_OPTIONS.map((o) => o.label), ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']);
  for (const o of TLP_OPTIONS) assert.equal(tlpDisplay(o.value), o.label);
  assert.equal(normalizeTlp('TLP:AMBER+STRICT'), 'amber_strict');
  assert.equal(normalizeTlp('white'), 'clear');
});

test('provenance labels', () => {
  assert.equal(tlpSourceLabel('explicit'), 'Marked in the source document');
  assert.equal(tlpSourceLabel('manual'), 'Set manually');
  assert.match(tlpSourceLabel('default'), /Default/);
  assert.match(tlpSourceLabel(undefined), /Default/, 'older API responses without provenance read as default');
  assert.equal(tlpSourceShortLabel('manual'), 'Manual');
  assert.equal(tlpSourceShortLabel('explicit'), 'Source-marked');
});

test('only loosening the restriction asks for confirmation', () => {
  assert.equal(isTlpDowngrade('amber', 'clear'), true);
  assert.equal(isTlpDowngrade('clear', 'red'), false);
  const c = describeTlpChangeConfirm('amber', 'clear');
  assert.equal(c.title, 'Reduce the sharing restriction?');
  assert.match(c.description, /TLP:AMBER → TLP:CLEAR/);
  assert.equal(c.confirmLabel, 'Set TLP:CLEAR');
  assert.equal(c.variant, 'warning');
  assert.equal(describeTlpChangeConfirm('clear', 'amber'), null, 'tightening needs no dialog');
  assert.equal(describeTlpChangeConfirm('amber', 'amber'), null);
  assert.equal(describeTlpChangeConfirm('amber_strict', 'amber'). title, 'Reduce the sharing restriction?');
});

test('edit permission is the existing report-edit permission (canWrite)', () => {
  assert.equal(canEditTlp({ canWrite: true, report: { id: 'r' } }), true);
  assert.equal(canEditTlp({ canWrite: false, report: { id: 'r' } }), false);
  assert.equal(canEditTlp({ canWrite: true, report: null }), false);
  assert.equal(describeTlpSavedFeedback('clear'), 'TLP set to TLP:CLEAR.');
});

test('page: badge is not a click-to-mutate control; Edit TLP is gated and saves via PATCH { tlp }', () => {
  assert.match(pageSrc, /data-testid="report-tlp"[\s\S]*?<TlpBadge tlp=\{report\.tlp\} display=\{report\.tlp_display\} \/>/);
  assert.doesNotMatch(pageSrc, /<TlpBadge[^>]*onClick/, 'badge itself never mutates');
  assert.match(pageSrc, /\{canEditTlp\(\{ canWrite, report \}\) \? \(\s*<button[\s\S]*?aria-label="Edit TLP classification"/);
  assert.match(pageSrc, /api\.patch\(`\/threat-library\/reports\/\$\{reportId\}`, \{ tlp: nextTlp \}\)/);
  assert.match(pageSrc, /const confirm = describeTlpChangeConfirm\(report\?\.tlp, nextTlp\);[\s\S]*?await requestConfirm\(confirm\)/);
  assert.match(pageSrc, /if \(!canEditTlp\(\{ canWrite, report \}\)\) return;/);
  assert.match(pageSrc, /<TlpEditModal[\s\S]*?onSave=\{saveTlp\}/);
  // Restrictive banner keeps reading the effective value from report state.
  assert.match(pageSrc, /\{isElevatedTlp\(report\?\.tlp\) \? \(/);
  assert.match(pageSrc, /setReport\(\(prev\) => \(\{ \.\.\.prev, \.\.\.data\.report \}\)\);\s*\}\s*setFeedback\(describeTlpSavedFeedback/);
});

test('report information shows the effective TLP with its provenance', () => {
  const items = buildReportDetails({ source_name: 'www.ncsc.gov.uk', tlp: 'clear', analysis_status: 'ready' }, { tlpLabel: 'TLP:CLEAR · Manual' });
  assert.equal(items.find((i) => i.label === 'TLP').value, 'TLP:CLEAR · Manual');
  const none = buildReportDetails({ source_name: 'x', analysis_status: 'ready' }, {});
  assert.ok(!none.some((i) => i.label === 'TLP'));
});

test('audit log detail renders TLP changes', () => {
  const rows = threatLibraryDetailRows({
    action: 'threat_library.report.tlp.updated',
    entity_type: 'threat_report',
    metadata: { report_title: 'NCSC advisory', old_tlp: 'amber', new_tlp: 'clear', old_tlp_source: 'default', downgrade: true }
  });
  const byLabel = Object.fromEntries(rows);
  assert.equal(byLabel['Old TLP'], 'amber');
  assert.equal(byLabel['New TLP'], 'clear');
  assert.equal(byLabel['Previous source'], 'default');
  assert.equal(byLabel['Sharing restriction reduced'], 'yes');
});
