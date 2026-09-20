/**
 * Threat Library route permission / response contract smoke tests (no live DB).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { maskAiSettingsForClient } from '../lib/threatLibrary/ai/providers.js';

const routeSrc = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), 'threatLibrary.js'),
  'utf8'
);

test('AI settings routes are admin-gated', () => {
  assert.match(routeSrc, /\/api\/threat-library\/ai-settings[\s\S]*?requireRole\(ROLES\.ADMIN\)/);
  assert.match(routeSrc, /\/api\/threat-library\/ai-settings\/api-key[\s\S]*?requireRole\(ROLES\.ADMIN\)/);
});

test('import routes require analyst or admin', () => {
  assert.match(routeSrc, /import\/url[\s\S]*?requireRole\(ROLES\.ADMIN, ROLES\.ANALYST\)/);
  assert.match(routeSrc, /import\/pdf[\s\S]*?requireRole\(ROLES\.ADMIN, ROLES\.ANALYST\)/);
  assert.match(routeSrc, /import\/thib[\s\S]*?requireRole\(ROLES\.ADMIN, ROLES\.ANALYST\)/);
});

test('delete is admin-only', () => {
  assert.match(routeSrc, /reports\/:publicId'[\s\S]*?requireRole\(ROLES\.ADMIN\)/);
});

test('THIB import path does not call AI analyze', () => {
  assert.equal(routeSrc.includes('analyzeThreatDocument'), false);
  assert.equal(routeSrc.includes('runAnalysisPipeline'), false);
  assert.match(routeSrc, /importThibBundle/);
  assert.match(routeSrc, /previewThibImport/);
});

test('masked settings never include api_key field', () => {
  const m = maskAiSettingsForClient({ api_key: 'super-secret-key-value', provider: 'openai', enabled: true });
  assert.equal('api_key' in m, false);
  assert.ok(!JSON.stringify(m).includes('super-secret-key-value'));
});

test('retry resumes analysis without resetting checkpoints by default', () => {
  assert.match(routeSrc, /resumeAnalysis:\s*true/);
  assert.match(routeSrc, /newAnalysisRun:\s*req\.body\?\.reset_checkpoints\s*===\s*true/);
});

test('retry commits active analysis_status and clears failure before 202', () => {
  assert.match(routeSrc, /updateReportStatus/);
  assert.match(routeSrc, /clear_failure:\s*true/);
  assert.match(routeSrc, /resolveRetryStartStatus/);
  assert.match(routeSrc, /analysis_already_running/);
  assert.match(routeSrc, /already_running:\s*true/);
  assert.match(routeSrc, /resumed:\s*true/);
});

test('cancel analysis endpoint exists and is analyst-gated', () => {
  assert.match(routeSrc, /\/api\/threat-library\/reports\/:publicId\/cancel[\s\S]*?requireRole\(ROLES\.ADMIN, ROLES\.ANALYST\)/);
  assert.match(routeSrc, /requestAnalysisCancel/);
});

test('AI settings accept multi-timeout fields', () => {
  assert.match(routeSrc, /first_token_timeout_ms/);
  assert.match(routeSrc, /inactivity_timeout_ms/);
  assert.match(routeSrc, /total_analysis_timeout_ms/);
  assert.match(routeSrc, /defaultTimeoutsForProvider/);
});

test('PDF import returns structured failure codes and multer size mapping', () => {
  assert.match(routeSrc, /pdf_too_large/);
  assert.match(routeSrc, /pdf_upload_failed/);
  assert.match(routeSrc, /isAcceptablePdfUploadMeta/);
  assert.match(routeSrc, /LIMIT_FILE_SIZE/);
});

test('source URL patch is analyst-gated, validates http(s), and does not reanalyze', () => {
  assert.match(routeSrc, /app\.patch\(\s*'\/api\/threat-library\/reports\/:publicId',\s*requireRole\(ROLES\.ADMIN, ROLES\.ANALYST\)/);
  assert.match(routeSrc, /validateReportSourceUrl/);
  assert.match(routeSrc, /updateReportSourceUrl/);
  assert.match(routeSrc, /buildSourceUrlAuditEvent/);
  const patchBlock = routeSrc.slice(routeSrc.indexOf("app.patch("), routeSrc.indexOf("app.delete("));
  assert.doesNotMatch(patchBlock, /enqueueAnalyze|runAnalysisPipeline|analyzeThreatDocument/);
});

test('create IOCs passes confirm and returns structured promotion results', () => {
  assert.match(routeSrc, /confirm: req\.body\?\.confirm === true/);
  assert.match(routeSrc, /summary: result\.summary \|\| undefined/);
  assert.match(routeSrc, /pending_count: result\.pending_count/);
});

// --- Audit trail contract -------------------------------------------------

test('every Threat Library audit call carries the request (actor, IP, request id, source)', () => {
  // `actor: req.user` was silently ignored by auditLogService and produced Actor = "—".
  assert.equal(routeSrc.includes('actor: req.user'), false);
  const auditCalls = routeSrc.match(/audit\.auditSuccess\(\{[\s\S]*?\}\);/g) || [];
  for (const call of auditCalls) {
    assert.match(call, /\{\s*req,/, `audit call must pass req: ${call}`);
  }
  assert.match(routeSrc, /async function writeAudit\(req, event\)[\s\S]*?audit\.auditLog\(\{ req, \.\.\.event \}\)/);
});

test('import, delete, source URL, THIB export and finalize use the audit builders', () => {
  assert.match(routeSrc, /buildImportAuditEvent\(\{\s*sourceType: 'url'/);
  assert.match(routeSrc, /buildImportAuditEvent\(\{\s*sourceType: 'pdf'/);
  assert.match(routeSrc, /buildImportAuditEvent\(\{\s*sourceType: 'thib'/);
  assert.match(routeSrc, /buildImportFailedAuditEvent/);
  assert.match(routeSrc, /buildDeleteAuditEvent\(\{ report, user: req\.user \}\)/);
  assert.match(routeSrc, /buildThibExportAuditEvent/);
  assert.match(routeSrc, /finalizeReport\(pool, report\.id, \{ user: await actorOf\(req\), audit, req \}\)/);
});

test('review actions receive the resolved actor, audit service and request', () => {
  const block = routeSrc.slice(routeSrc.indexOf('applyCandidateReviewActions(pool, report.id, {'));
  assert.match(block.slice(0, 400), /user: await actorOf\(req\)/);
  assert.match(block.slice(0, 400), /audit,\s*req\s*\}/);
});

test('a thrown Create IOCs error is audited as failed with a safe error category', () => {
  const block = routeSrc.slice(routeSrc.indexOf("'Review action failed'") - 1500, routeSrc.indexOf("'Review action failed'"));
  assert.match(block, /AUDIT_ACTION\.THREAT_LIBRARY_IOCS_CREATED/);
  assert.match(block, /status: AUDIT_STATUS\.FAILED/);
  assert.match(block, /error_code: safeErrorCategory\(err\)/);
  assert.doesNotMatch(block, /err\.message|err\.stack/);
});

test('created_by / requested_by are stamped from the resolved actor public id, not req.user.publicId', () => {
  assert.equal(routeSrc.includes('req.user?.publicId'), false);
  assert.match(routeSrc, /created_by: actor\?\.publicId/);
  assert.match(routeSrc, /requestedBy: actor\?\.publicId/);
});

test('report PATCH accepts tlp for analyst/admin only and validates against the canonical set', () => {
  assert.match(routeSrc, /app\.patch\(\s*'\/api\/threat-library\/reports\/:publicId',\s*requireRole\(ROLES\.ADMIN, ROLES\.ANALYST\)/);
  assert.match(routeSrc, /const hasTlp = Object\.prototype\.hasOwnProperty\.call\(body, 'tlp'\)/);
  assert.match(routeSrc, /if \(!isValidTlp\(candidate\)\)[\s\S]*?code: 'invalid_tlp'/);
  assert.match(routeSrc, /updated = await updateReportTlp\(pool, report\.id, nextTlp\)/);
  assert.match(routeSrc, /buildTlpAuditEvent\(\{\s*report,\s*oldTlp: previousTlp,\s*oldSource: previousSource,\s*newTlp: nextTlp,\s*user: req\.user/);
  assert.match(routeSrc, /message: 'source_url or tlp is required'/);
});

test('THIB export uses the effective TLP and carries its provenance', () => {
  const codecSrc = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../lib/threatLibrary/thib/codec.js'),
    'utf8'
  );
  assert.match(codecSrc, /tlp: normalizeTlp\(report\.tlp\),\s*tlp_source: \['explicit', 'default', 'manual'\]\.includes\(report\.tlp_source\)/);
  const importSrc = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../lib/threatLibrary/thibImport.js'),
    'utf8'
  );
  assert.match(importSrc, /tlp_source: \['explicit', 'manual'\]\.includes\(b\.report\.tlp_source\) \? b\.report\.tlp_source : 'explicit'/);
});

// --- Report-list search contract -----------------------------------------

test('report list passes ?search= to the store and keeps the { items, total } response shape', () => {
  const block = routeSrc.slice(routeSrc.indexOf("app.get('/api/threat-library/reports',"), routeSrc.indexOf("app.get('/api/threat-library/reports/:publicId'"));
  assert.match(block, /listThreatReports\(pool, \{\s*limit: req\.query\.limit,\s*offset: req\.query\.offset,[\s\S]*?search: req\.query\.search\s*\}\)/);
  assert.match(block, /items: result\.items\.map\(publicReport\),\s*total: result\.total/);
  // No string-built SQL and no provider / AI involvement on the list path.
  assert.doesNotMatch(block, /pool\.query|ILIKE|LIKE/);
  assert.doesNotMatch(block, /analyzeThreatDocument|runAnalysisPipeline|fetch\(/);
});

test('publicReport keeps published_at and report_type in the API contract (list columns were removed UI-side only)', () => {
  const block = routeSrc.slice(routeSrc.indexOf('function publicReport(row)'), routeSrc.indexOf('\n}\n', routeSrc.indexOf('function publicReport(row)')));
  assert.match(block, /published_at: row\.published_at,/);
  assert.match(block, /report_type: row\.report_type,/);
  assert.match(block, /created_at: row\.created_at/);
  assert.match(block, /finalized_at: row\.finalized_at/, 'finalized_at stays in the API even though the Overview no longer shows it');
});
