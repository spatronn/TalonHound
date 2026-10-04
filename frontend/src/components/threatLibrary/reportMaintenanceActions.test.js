/**
 * Report maintenance actions: Retry (failure recovery) vs Refresh extraction
 * (deterministic, no AI) vs Re-run AI analysis — visibility per report state,
 * exact confirmation wording, outcome feedback and the page wiring.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  canShowRetryButton,
  canShowRefreshExtraction,
  canShowRerunAi,
  describeMaintenanceAccepted,
  describeMaintenanceOutcome,
  isRefreshExtractionInProgress,
  processingSectionTitle,
  REFRESH_EXTRACTION_CONFIRM,
  RERUN_AI_CONFIRM
} from './reportRetryUi.js';
import { buildProgressChecklist } from './stages.js';

const pageSrc = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'ThreatLibraryReportPage.jsx'), 'utf8');

function actions(report, opts = { canWrite: true, busy: false }) {
  return {
    retry: canShowRetryButton(report, opts),
    refresh: canShowRefreshExtraction(report, opts),
    rerunAi: canShowRerunAi(report, opts)
  };
}

test('failed report: Retry only', () => {
  assert.deepEqual(actions({ analysis_status: 'failed', source_type: 'url' }), { retry: true, refresh: false, rerunAi: false });
});

test('review_required report: Refresh extraction + Re-run AI analysis, no misleading Retry', () => {
  assert.deepEqual(actions({ analysis_status: 'review_required', source_type: 'url' }), { retry: false, refresh: true, rerunAi: true });
  assert.deepEqual(actions({ analysis_status: 'review_required', source_type: 'pdf' }), { retry: false, refresh: true, rerunAi: true });
});

test('finalized report: Refresh extraction only (stays finalized); AI re-run would reopen it, so it is not offered', () => {
  assert.deepEqual(actions({ analysis_status: 'ready', import_status: 'ready', source_type: 'url' }), { retry: false, refresh: true, rerunAi: false });
});

test('processing, busy, read-only and THIB reports offer none of the three', () => {
  for (const status of ['pending', 'fetching', 'extracting', 'analyzing', 'matching']) {
    assert.deepEqual(actions({ analysis_status: status, source_type: 'url' }), { retry: false, refresh: false, rerunAi: false }, status);
  }
  assert.deepEqual(actions({ analysis_status: 'review_required', source_type: 'url' }, { canWrite: true, busy: true }), { retry: false, refresh: false, rerunAi: false });
  assert.deepEqual(actions({ analysis_status: 'review_required', source_type: 'url' }, { canWrite: false }), { retry: false, refresh: false, rerunAi: false });
  assert.deepEqual(actions({ analysis_status: 'skipped', source_type: 'thib' }), { retry: false, refresh: false, rerunAi: false });
  assert.equal(canShowRefreshExtraction({ analysis_status: 'ready', source_type: 'thib' }, { canWrite: true }), false);
});

test('confirmation wording says plainly whether AI runs', () => {
  assert.equal(REFRESH_EXTRACTION_CONFIRM.title, 'Refresh extraction?');
  assert.equal(
    REFRESH_EXTRACTION_CONFIRM.description,
    'Re-runs deterministic extraction and IOC matching using the current extractor. AI analysis will not run.'
  );
  assert.equal(REFRESH_EXTRACTION_CONFIRM.confirmLabel, 'Refresh extraction');
  assert.equal(RERUN_AI_CONFIRM.title, 'Re-run AI analysis?');
  assert.equal(
    RERUN_AI_CONFIRM.description,
    'Runs AI analysis again and may change classifications, entities, tags, and relationships.'
  );
  assert.equal(RERUN_AI_CONFIRM.confirmLabel, 'Re-run AI analysis');
  assert.match(describeMaintenanceAccepted('refresh_extraction'), /AI analysis will not run/);
  assert.doesNotMatch(describeMaintenanceAccepted('rerun_ai'), /will not run/);
});

test('refresh outcome feedback from the finished job', () => {
  assert.deepEqual(
    describeMaintenanceOutcome({ job_type: 'refresh_extraction', status: 'completed', progress: { refresh: { added: 0, removed: 0, updated: 0 } } }),
    { message: 'Extraction refreshed. No indicator changes.' }
  );
  assert.deepEqual(
    describeMaintenanceOutcome({ job_type: 'refresh_extraction', status: 'completed', progress: { refresh: { added: 1, removed: 2, updated: 0 } } }),
    { message: 'Extraction refreshed: 1 indicator added, 2 indicators removed.' }
  );
  assert.match(describeMaintenanceOutcome({ job_type: 'refresh_extraction', status: 'failed', error_message: 'no retained source' }).error, /Refresh extraction failed: no retained source\. The report was not changed\./);
  assert.equal(describeMaintenanceOutcome({ job_type: 'rerun_ai', status: 'completed' }), null);
  assert.equal(describeMaintenanceOutcome({ job_type: 'refresh_extraction', status: 'running' }), null);
});

test('a running refresh does not pretend AI or a fetch ran', () => {
  const report = { analysis_status: 'matching', analysis_progress: { mode: 'refresh_extraction', stage: 'matching' } };
  const job = { job_type: 'refresh_extraction', status: 'running', stage: 'matching' };
  const keys = buildProgressChecklist(report, job).map((i) => i.key);
  assert.deepEqual(keys, ['extracting', 'candidates', 'matching', 'review_required']);
  assert.equal(isRefreshExtractionInProgress(report, job), true);
  assert.equal(processingSectionTitle(report), 'Refreshing extraction');
  // A normal analysis keeps the full checklist.
  const full = buildProgressChecklist({ analysis_status: 'matching', analysis_progress: {} }, { job_type: 'retry', stage: 'matching' }).map((i) => i.key);
  assert.ok(full.includes('analyzing') && full.includes('fetching'));
  assert.equal(processingSectionTitle({ analysis_status: 'analyzing', analysis_progress: {} }), 'Processing report');
});

test('page wiring: overflow menu items, confirmations, endpoints; Retry stays the failed-state button', () => {
  assert.match(pageSrc, /canShowRefreshExtraction\(report, \{ busy: Boolean\(busy\), canWrite \}\)\s*\?\s*\{ id: 'refresh-extraction', label: 'Refresh extraction'/);
  assert.match(pageSrc, /canShowRerunAi\(report, \{ busy: Boolean\(busy\), canWrite \}\)\s*\?\s*\{ id: 'rerun-ai', label: 'Re-run AI analysis'/);
  assert.match(pageSrc, /requestConfirm\(refresh \? REFRESH_EXTRACTION_CONFIRM : RERUN_AI_CONFIRM\)/);
  assert.match(pageSrc, /const path = refresh \? 'refresh-extraction' : 'rerun-ai';/);
  assert.match(pageSrc, /api\.post\(`\/threat-library\/reports\/\$\{reportId\}\/\$\{path\}`\)/);
  assert.match(pageSrc, /\{canShowRetryButton\(report, \{ busy: Boolean\(busy\), canWrite \}\) \? \(/);
  // Maintenance actions live in the overflow menu, not as extra header buttons.
  const header = pageSrc.slice(pageSrc.indexOf('<div className="tl-report-header__actions">'), pageSrc.indexOf('<ReportActionsMenu items={overflowItems}'));
  assert.doesNotMatch(header, /Refresh extraction|Re-run AI analysis/);
});
