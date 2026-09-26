import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isActiveAnalysisStatus,
  resolveRetryStartStatus,
  buildRetryProgress
} from './retryState.js';

test('failed is not active; analyzing/pending are', () => {
  assert.equal(isActiveAnalysisStatus('failed'), false);
  assert.equal(isActiveAnalysisStatus('ready'), false);
  assert.equal(isActiveAnalysisStatus('review_required'), false);
  assert.equal(isActiveAnalysisStatus('analyzing'), true);
  assert.equal(isActiveAnalysisStatus('pending'), true);
  assert.equal(isActiveAnalysisStatus('matching'), true);
});

test('resume with document+candidates starts at analyzing', () => {
  assert.equal(
    resolveRetryStartStatus({ hasDocument: true, candidateCount: 12 }),
    'analyzing'
  );
});

test('document without candidates starts at extracting', () => {
  assert.equal(
    resolveRetryStartStatus({ hasDocument: true, candidateCount: 0 }),
    'extracting'
  );
});

test('no document starts pending', () => {
  assert.equal(resolveRetryStartStatus({ hasDocument: false, candidateCount: 0 }), 'pending');
});

test('retry progress marks resume for analyzing', () => {
  const p = buildRetryProgress('analyzing');
  assert.equal(p.stage, 'analyzing');
  assert.equal(p.resumed, true);
  assert.equal(p.reused_document, true);
  assert.equal(p.reused_candidates, true);
});

test('retry progress preserves candidate_extraction_version when provided', () => {
  const p = buildRetryProgress('analyzing', { candidate_extraction_version: 'tl-candidates-v9' });
  assert.equal(p.candidate_extraction_version, 'tl-candidates-v9');
});
