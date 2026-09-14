import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AUDIT_RESULT_SAMPLE_LIMIT,
  buildAnalysisAuditEvent,
  buildDeleteAuditEvent,
  buildImportAuditEvent,
  buildSourceUrlAuditEvent,
  buildThibExportAuditEvent,
  createIocsAuditStatus,
  loadAnalysisAuditContext,
  auditAnalysisOutcome,
  safeErrorCategory,
  summarizeFinalizeCandidates
} from './audit.js';
import { AUDIT_ACTION, AUDIT_ACTION_LABELS, AUDIT_STATUS, auditActionLabel } from '../auditConstants.js';
import { redactUrlSecrets } from '../auditRedaction.js';

const REPORT = {
  id: 10,
  public_id: 'c9e28440-a25f-4149-a993-c78d8b458805',
  title: 'PurpleBravo’s Targeting of the IT Software Supply Chain',
  source_type: 'url',
  tlp: 'amber',
  source_url: 'https://intel.example.com/report?id=9&api_key=SECRET123',
  summary: 'BODY MUST NOT LEAK',
  canonical_document: { blocks: [{ text: 'DOC MUST NOT LEAK' }] }
};
const USER = { id: 7, email: 'safa@safa.com', username: 'safa@safa.com', role: 'analyst' };

test('every Threat Library action has a human-readable label (and legacy names still render)', () => {
  const tlActions = Object.values(AUDIT_ACTION).filter((a) => a.startsWith('threat_library.'));
  assert.ok(tlActions.length >= 14);
  for (const action of tlActions) {
    assert.ok(AUDIT_ACTION_LABELS[action], `missing label for ${action}`);
    assert.match(AUDIT_ACTION_LABELS[action], /^Threat Library › /);
  }
  assert.equal(auditActionLabel(AUDIT_ACTION.THREAT_LIBRARY_IOCS_CREATED), 'Threat Library › Create IOCs');
  assert.equal(auditActionLabel('threat_library.import.pdf'), 'Threat Library › Report Imported (PDF)');
  assert.equal(auditActionLabel('threat_library.import.url'), 'Threat Library › Report Imported (URL)');
});

test('createIocsAuditStatus: success / partial / failed', () => {
  assert.equal(createIocsAuditStatus({ created: 52, already_existing: 61, failed: 0 }), AUDIT_STATUS.SUCCESS);
  assert.equal(createIocsAuditStatus({ created: 50, already_existing: 61, failed: 2 }), AUDIT_STATUS.PARTIAL);
  assert.equal(createIocsAuditStatus({ created: 0, already_existing: 3, failed: 1 }), AUDIT_STATUS.PARTIAL);
  assert.equal(createIocsAuditStatus({ created: 0, already_existing: 0, failed: 4 }), AUDIT_STATUS.FAILED);
});

test('import events snapshot report identity and redact URL secrets; never content', () => {
  const ev = buildImportAuditEvent({
    sourceType: 'url',
    report: REPORT,
    user: USER,
    jobPublicId: 'job-1',
    details: { source_url: REPORT.source_url, host: 'intel.example.com' }
  });
  assert.equal(ev.action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_URL);
  assert.equal(ev.entityType, 'threat_report');
  assert.equal(ev.entityId, REPORT.public_id);
  assert.equal(ev.entityDisplay, REPORT.title);
  assert.equal(ev.metadata.report_title, REPORT.title);
  assert.equal(ev.metadata.tlp, 'amber');
  assert.equal(ev.metadata.initiated_by, 'safa@safa.com');
  assert.equal(ev.metadata.job_public_id, 'job-1');
  assert.equal(ev.metadata.source_url, 'https://intel.example.com/report?id=9&api_key=%5BREDACTED%5D');
  const json = JSON.stringify(ev);
  assert.equal(json.includes('SECRET123'), false);
  assert.equal(json.includes('MUST NOT LEAK'), false);

  const pdf = buildImportAuditEvent({ sourceType: 'pdf', report: { ...REPORT, source_type: 'pdf' }, user: USER, details: { file_name: 'x.pdf', sha256: 'abc', size_bytes: 10 } });
  assert.equal(pdf.action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_PDF);
  assert.equal(pdf.metadata.file_name, 'x.pdf');
  const thib = buildImportAuditEvent({ sourceType: 'thib', report: REPORT, user: USER, details: {} });
  assert.equal(thib.action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_THIB);
});

test('source URL event stores old/new with credentials and tokens masked', () => {
  const ev = buildSourceUrlAuditEvent({
    report: REPORT,
    oldUrl: 'https://user:pw@old.example.com/a?token=T1',
    newUrl: 'https://new.example.com/b?page=2&access_token=T2',
    user: USER
  });
  assert.equal(ev.action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_SOURCE_URL_UPDATED);
  assert.equal(ev.before.source_url, 'https://old.example.com/a?token=%5BREDACTED%5D');
  assert.equal(ev.after.source_url, 'https://new.example.com/b?page=2&access_token=%5BREDACTED%5D');
  const json = JSON.stringify(ev);
  assert.equal(json.includes('pw@'), false);
  assert.equal(json.includes('T1'), false);
  assert.equal(json.includes('T2'), false);
});

test('redactUrlSecrets keeps host/path/benign params and never throws', () => {
  assert.equal(redactUrlSecrets('https://a.example.com/x?q=1&sig=abc'), 'https://a.example.com/x?q=1&sig=%5BREDACTED%5D');
  assert.equal(redactUrlSecrets('not a url'), 'not a url');
  assert.equal(redactUrlSecrets(null), null);
  assert.equal(redactUrlSecrets(''), null);
});

test('delete event stands alone after the row is gone (title, public id, source type, actor)', () => {
  const ev = buildDeleteAuditEvent({ report: REPORT, user: USER });
  assert.equal(ev.action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_DELETED);
  assert.equal(ev.severity, 'warning');
  assert.equal(ev.entityDisplay, REPORT.title);
  assert.equal(ev.entityId, REPORT.public_id);
  assert.equal(ev.before.title, REPORT.title);
  assert.equal(ev.before.source_type, 'url');
  assert.equal(ev.metadata.report_public_id, REPORT.public_id);
  assert.equal(ev.metadata.report_title, REPORT.title);
  assert.equal(ev.metadata.initiated_by, 'safa@safa.com');
  assert.equal(JSON.stringify(ev).includes('MUST NOT LEAK'), false);
});

test('THIB export records counts and TLP, never the bundle payload', () => {
  const bundle = { thib_spec_version: '1.0', indicators: [{ value: 'PAYLOAD MUST NOT LEAK' }, { value: 'x' }], entities: [{}], relationships: [] };
  const ev = buildThibExportAuditEvent({ report: REPORT, bundle, user: USER, confirmRed: false });
  assert.equal(ev.action, AUDIT_ACTION.THREAT_LIBRARY_THIB_EXPORTED);
  assert.equal(ev.metadata.indicator_count, 2);
  assert.equal(ev.metadata.entity_count, 1);
  assert.equal(ev.metadata.tlp, 'amber');
  assert.equal(ev.metadata.confirm_red, false);
  assert.equal(JSON.stringify(ev).includes('PAYLOAD MUST NOT LEAK'), false);
  const red = buildThibExportAuditEvent({ report: { ...REPORT, tlp: 'red' }, bundle, user: USER, confirmRed: true });
  assert.equal(red.severity, 'warning');
  assert.equal(red.metadata.confirm_red, true);
});

test('analysis event: initiating user is the actor, worker is executor, source=worker', () => {
  const ev = buildAnalysisAuditEvent({
    report: REPORT,
    job: { public_id: 'job-1', job_type: 'analyze' },
    ok: true,
    summary: { total: 120, new: 100, existing: 15, context_only: 5 },
    initiator: USER
  });
  assert.equal(ev.action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_ANALYSIS_COMPLETED);
  assert.equal(ev.source, 'worker');
  assert.equal(ev.actor, USER);
  assert.equal(ev.metadata.initiated_by, 'safa@safa.com');
  assert.equal(ev.metadata.executed_by, 'threat-library-worker');
  assert.equal(ev.metadata.candidates_total, 120);
  assert.equal(ev.metadata.candidates_new, 100);
  const failed = buildAnalysisAuditEvent({ report: REPORT, job: null, ok: false, code: 'job_cancelled', initiator: null });
  assert.equal(failed.action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_ANALYSIS_FAILED);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.metadata.result, 'cancelled');
  assert.equal(failed.actor, null);
});

test('worker boundary: initiating actor is resolved from threat_library_jobs.requested_by', async () => {
  const inserted = [];
  const pool = {
    async query(sql, params) {
      if (/FROM threat_reports WHERE id/.test(sql)) return { rows: [REPORT] };
      if (/FROM threat_library_jobs j/.test(sql)) {
        assert.equal(params[0], 55);
        return { rows: [{ public_id: 'job-55', job_type: 'analyze', requested_by: 'u-pub', user_public_id: 'u-pub', user_username: 'safa@safa.com', user_role: 'analyst', user_id: 7 }] };
      }
      throw new Error(`unexpected sql ${sql}`);
    }
  };
  const ctx = await loadAnalysisAuditContext(pool, { reportId: 10, jobId: 55 });
  assert.equal(ctx.initiator.publicId, 'u-pub');
  assert.equal(ctx.initiator.email, 'safa@safa.com');
  assert.equal(ctx.initiator.role, 'analyst');

  const auditService = { async auditLog(ev) { inserted.push(ev); } };
  await auditAnalysisOutcome(pool, auditService, { reportId: 10, jobId: 55, ok: true, code: null, summary: { total: 3 } });
  assert.equal(inserted.length, 1);
  assert.equal(inserted[0].actor.email, 'safa@safa.com');
  assert.equal(inserted[0].source, 'worker');
  assert.equal(inserted[0].entityDisplay, REPORT.title);

  // Legacy job with no requested_by: no actor is fabricated.
  const legacyPool = {
    async query(sql) {
      if (/FROM threat_reports WHERE id/.test(sql)) return { rows: [REPORT] };
      return { rows: [{ public_id: 'job-1', job_type: 'analyze', requested_by: null, user_public_id: null }] };
    }
  };
  const legacy = await loadAnalysisAuditContext(legacyPool, { reportId: 10, jobId: 1 });
  assert.equal(legacy.initiator, null);
});

test('auditAnalysisOutcome never throws on audit failure', async () => {
  const pool = { async query() { throw new Error('db down'); } };
  await auditAnalysisOutcome(pool, { async auditLog() {} }, { reportId: 1, jobId: 1, ok: true });
});

test('safeErrorCategory never leaks messages', () => {
  assert.equal(safeErrorCategory(Object.assign(new Error('secret path /x'), { code: 'queue_unavailable' })), 'queue_unavailable');
  assert.equal(safeErrorCategory(new Error('relation does not exist')), 'internal_error');
  assert.equal(safeErrorCategory(Object.assign(new Error('x'), { code: 'weird code with spaces' })), 'internal_error');
  assert.equal(safeErrorCategory(Object.assign(new TypeError('x'))), 'typeerror');
});

test('summarizeFinalizeCandidates counts review states and promotion outcomes', () => {
  const s = summarizeFinalizeCandidates([
    { review_status: 'approved', promotion_outcome: 'created' },
    { review_status: 'created_ioc' },
    { review_status: 'approved', promotion_outcome: 'already_existing' },
    { review_status: 'context_only' },
    { review_status: 'ignored' },
    { review_status: 'pending' },
    { review_status: 'approved', promotion_outcome: 'unsupported' },
    { review_status: 'approved', promotion_outcome: 'failed' }
  ]);
  assert.deepEqual(s, {
    total_candidates: 8, approved: 5, context_only: 1, ignored: 1, pending: 1,
    created: 2, already_existing: 1, unsupported: 1, failed: 1
  });
});

test('sample limit is 100 (matches auditRedaction MAX_ARRAY_LEN so nothing is silently cut)', () => {
  assert.equal(AUDIT_RESULT_SAMPLE_LIMIT, 100);
});
