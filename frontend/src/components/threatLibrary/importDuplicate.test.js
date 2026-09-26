/**
 * Duplicate URL / PDF import UX: the helper branches on the machine-readable
 * API fields, and the modal shows an informational notice with a link to the
 * existing report instead of an import error.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { IMPORT_DUPLICATE_COPY, describeImportOutcome } from './importOutcome.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const modalSrc = readFileSync(path.join(here, 'ImportIntelligenceModal.jsx'), 'utf8');
const pageSrc = readFileSync(path.join(here, 'ThreatLibraryPage.jsx'), 'utf8');

const existing = { id: 'b3c1a1e2-0000-4000-8000-000000000001', title: 'APT report', created_at: '2026-09-01T10:00:00+03:00' };

test('URL duplicate -> "This report has already been imported." with the existing report id / title / import date', () => {
  assert.deepEqual(describeImportOutcome({ already_imported: true, duplicate_reason: 'url', message: 'x', report: existing }), {
    kind: 'duplicate',
    message: 'This report has already been imported.',
    reportId: existing.id,
    title: 'APT report',
    importedAt: existing.created_at
  });
});

test('PDF duplicate (sha256) -> "This PDF has already been imported."', () => {
  const o = describeImportOutcome({ already_imported: true, duplicate_reason: 'sha256', report: { id: 'r2', title: '' } });
  assert.equal(o.kind, 'duplicate');
  assert.equal(o.message, IMPORT_DUPLICATE_COPY.sha256);
  assert.equal(o.message, 'This PDF has already been imported.');
  assert.equal(o.title, 'Untitled report');
  assert.equal(o.importedAt, null);
});

test('a new import (202, already_imported false or absent) is "created" and carries the new report', () => {
  const report = { id: 'new', title: 'vendor.example' };
  assert.deepEqual(describeImportOutcome({ already_imported: false, report, job_id: 'j' }), { kind: 'created', report });
  assert.deepEqual(describeImportOutcome({ report }), { kind: 'created', report });
  assert.deepEqual(describeImportOutcome(null), { kind: 'created', report: null });
  // already_imported without a report to link to is not treated as a duplicate notice.
  assert.equal(describeImportOutcome({ already_imported: true }).kind, 'created');
  // Only the boolean true counts — never message text.
  assert.equal(describeImportOutcome({ already_imported: 'true', message: IMPORT_DUPLICATE_COPY.url, report }).kind, 'created');
});

test('modal: URL and PDF responses both go through describeImportOutcome; a duplicate keeps the modal open', () => {
  assert.equal((modalSrc.match(/finishImport\(data\);/g) || []).length, 2, 'URL + PDF submit');
  const finish = modalSrc.slice(modalSrc.indexOf('function finishImport(data)'), modalSrc.indexOf('function openExistingReport()'));
  assert.match(finish, /const outcome = describeImportOutcome\(data\);\s*if \(outcome\.kind === 'duplicate'\) \{\s*setDuplicate\(outcome\);\s*return;\s*\}\s*onImported\?\.\(outcome\.report\);\s*reset\(\);\s*onClose\?\.\(\);/);
  // The duplicate notice is not the error box and never parses error strings.
  assert.doesNotMatch(finish, /setError|setImportError|message\.includes|409/);
});

test('modal: duplicate notice = info banner with message, title, Imported date and an Open report action', () => {
  const banner = modalSrc.slice(modalSrc.indexOf('{duplicate ? ('), modalSrc.indexOf('<form id="threat-library-import-form"'));
  assert.match(banner, /style=\{\{ \.\.\.ui\.infoBanner, marginBottom: 10 \}\} role="status" data-testid="tl-import-duplicate"/);
  assert.match(banner, /\{duplicate\.message\}/);
  assert.match(banner, /\{duplicate\.title\}/);
  assert.match(banner, /Imported: \{formatUserDateTime\(duplicate\.importedAt\)\}/);
  assert.match(banner, /onClick=\{openExistingReport\}>\s*Open report\s*<\/button>/);
  assert.doesNotMatch(banner, /ui\.error|Import failed|Something went wrong/);
  const open = modalSrc.slice(modalSrc.indexOf('function openExistingReport()'), modalSrc.indexOf('async function submitUrl()'));
  assert.match(open, /reset\(\);\s*onClose\?\.\(\);\s*if \(reportId\) onOpenReport\?\.\(reportId\);/);
});

test('modal: the notice clears when the input, file, tab or a new submit changes', () => {
  assert.match(modalSrc, /onChange=\{\(e\) => \{ setUrl\(e\.target\.value\); setDuplicate\(null\); \}\}/);
  assert.match(modalSrc, /onChange=\{\(e\) => \{ setPdfFile\(e\.target\.files\?\.\[0\] \|\| null\); setDuplicate\(null\); \}\}/);
  assert.match(modalSrc, /setTab\(t\.id\); setError\(''\); setErrorCode\(''\); setDuplicate\(null\);/);
  assert.equal((modalSrc.match(/setErrorCode\(''\);\s*setDuplicate\(null\);\s*try \{/g) || []).length, 2);
});

test('page: Open report navigates to the existing report detail route', () => {
  assert.match(pageSrc, /onOpenReport=\{\(reportId\) => navigate\(`\/threat-intelligence\/threat-library\/\$\{reportId\}`\)\}/);
});
