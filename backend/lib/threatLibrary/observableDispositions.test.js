/**
 * Disposition accounting: every observable-shaped token is explained, including
 * tokens that never became a candidate.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import {
  DISPOSITIONS,
  OBSERVABLE_DISPOSITION_VERSION,
  buildObservableDispositions,
  candidateDisposition,
  scanObservableTokens
} from './observableDispositions.js';


const url = 'https://blog.example-research.test/post';
const SHA = '9f2c7a1be34d5c60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8';
const body = `<p>${'The operators delivered a loader through phishing messages and moved laterally across the network. '.repeat(6)}</p>`;

function extract(section) {
  const html = `<html><head><title>Fictional report</title></head><body><article><h1>Fictional report</h1><h2>Overview</h2>${body}${section}</article></body></html>`;
  const ex = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(ex.ok, true);
  const r = extractReportCandidates({ id: 1, source_url: url, source_type: 'url' }, ex.document);
  return {
    ...r,
    rows: r.candidates.map((c) => ({ ...c, evidence: buildCandidateEvidenceRecord(c) }))
  };
}

test('an asserted IOC row is accepted and carries its exact locators', () => {
  const r = extract(`<h2>Indicators of Compromise</h2><table><tr><th>Type</th><th>Indicator</th></tr><tr><td>SHA256</td><td>${SHA}</td></tr></table>`);
  const out = buildObservableDispositions({ candidates: r.rows, tokenLog: r.tokenLog, blocks: r.annotated.blocks });
  const row = out.rows.find((x) => x.normalized_value === SHA);
  assert.equal(row.disposition, DISPOSITIONS.ACCEPTED);
  assert.deepEqual(row.section_path.slice(-1), ['Indicators of Compromise']);
  assert.equal(row.table_index, 0);
  assert.equal(row.row_index, 0);
  assert.equal(row.column_index, 1);
  assert.ok(Number.isInteger(row.char_start) && row.char_end - row.char_start === SHA.length);
  assert.equal(out.counts.undispositioned, 0);
});

test('a hex run rejected before becoming a candidate still has a disposition and a reason', () => {
  const r = extract(`<h2>Accounts</h2><p>The extension was published by anonymous-${SHA.slice(0, 32)} on the store.</p>`);
  const out = buildObservableDispositions({ candidates: r.rows, tokenLog: r.tokenLog, blocks: r.annotated.blocks });
  const row = out.rows.find((x) => x.reason_code === 'hex_identifier_suffix');
  assert.ok(row, 'identifier suffix recorded');
  assert.equal(row.disposition, DISPOSITIONS.REJECTED);
  assert.equal(out.counts.undispositioned, 0);
});

test('reconciliation reports a token no extractor path accounted for', () => {
  const blocks = [{ id: 'b001', type: 'paragraph', text: `The sample ${SHA} was seen.`, zone: 'report_body', section_path: ['Overview'] }];
  const out = buildObservableDispositions({ candidates: [], tokenLog: [], blocks });
  assert.equal(out.counts.undispositioned, 1);
  const row = out.rows[0];
  assert.equal(row.reason_code, 'undispositioned_token');
  assert.equal(row.observable_type, 'sha256');
  assert.deepEqual(row.section_path, ['Overview']);
});

test('a hash or address inside a URL belongs to the URL, not a separate token', () => {
  const tokens = scanObservableTokens(`See https://evil.example/${SHA}/1.2.3.4/x and 5.6.7.8`);
  assert.deepEqual(tokens.map((t) => t.type).sort(), ['ip', 'url']);
  assert.equal(tokens.find((t) => t.type === 'ip').value, '5.6.7.8');
});

test('chrome is not reconciled, and an unreadable defang spelling goes to review, not silence', () => {
  const blocks = [
    { id: 'b001', type: 'paragraph', text: SHA, zone: 'header_footer' },
    { id: 'b002', type: 'list', text: 'evil-host( . )net', zone: 'report_body' }
  ];
  const out = buildObservableDispositions({ candidates: [], tokenLog: [], blocks });
  assert.equal(out.counts.undispositioned, 0);
  assert.equal(out.rows.length, 1);
  assert.equal(out.rows[0].disposition, DISPOSITIONS.NEEDS_REVIEW);
  assert.equal(out.rows[0].reason_code, 'unresolved_defang_spelling');
});

test('non-network artifacts are unsupported; context stays context; analyst exclusion is rejected', () => {
  assert.equal(candidateDisposition({ is_ioc: false, candidate_type: 'technical_artifact' }).disposition, DISPOSITIONS.UNSUPPORTED);
  assert.equal(candidateDisposition({ is_ioc: true, assessment: 'context_only', candidate_type: 'domain' }).disposition, DISPOSITIONS.CONTEXT_ONLY);
  assert.equal(
    candidateDisposition({
      is_ioc: true, assessment: 'unknown', review_status: 'ignored', candidate_type: 'domain',
      evidence: { document_has_authoritative_scope: true, source_assertion: 'body_mention' }
    }).disposition,
    DISPOSITIONS.REJECTED
  );
  assert.equal(candidateDisposition({ is_ioc: true, assessment: 'invalid', candidate_type: 'domain' }).disposition, DISPOSITIONS.INVALID);
});

test('the row cap keeps rows that need attention and counts stay complete', () => {
  const candidates = Array.from({ length: 5200 }, (_, i) => ({
    candidate_type: 'domain',
    normalized_value: `host${i}.example.net`,
    original_value: `host${i}.example.net`,
    assessment: 'malicious',
    is_ioc: true,
    source_assertion: 'explicit_ioc',
    evidence: { source_assertion: 'explicit_ioc', document_has_authoritative_scope: true }
  }));
  const tokenLog = [{ observable_type: 'sha256', raw_value: SHA, reason_code: 'credential_labeled_hex' }];
  const out = buildObservableDispositions({ candidates, tokenLog });
  assert.equal(out.truncated, true);
  assert.equal(out.rows.length, 5000);
  assert.equal(out.counts.total, 5201);
  assert.ok(out.rows.some((r) => r.reason_code === 'credential_labeled_hex'));
});

test('discarded page regions are inventoried by kind with their observable tokens, never their markup', () => {
  const html = `<html><head><title>Fictional report</title></head><body><article><h1>Fictional report</h1>${body}
    <textarea readonly>${SHA}</textarea><script>var x = "${SHA.replace('9', '8')}";</script>
    <button data-clipboard-text="evil-host[.]net">Copy</button></article><aside>${SHA.replace('9', '7')}</aside></body></html>`;
  const ex = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  const regions = ex.document.meta.source_accounting.dropped_regions;
  const byKind = (k) => regions.find((r) => r.region_kind === k);
  assert.equal(byKind('textarea').significant, true);
  assert.deepEqual(byKind('textarea').sample_observables, [SHA]);
  assert.equal(byKind('button').significant, true);
  // Script text is not publisher content and is never retained.
  assert.ok(!JSON.stringify(regions).includes(SHA.replace('9', '8')));
  // Observable text outside the selected content root is visible too.
  assert.ok(byKind('outside_content_root').sample_observables.includes(SHA.replace('9', '7')));
  assert.ok(!JSON.stringify(regions).includes('<textarea'));
});

test('a digest-shaped label of an accounted hostname is part of that value, not a lost hash (tl-dispositions-v2)', () => {
  assert.equal(OBSERVABLE_DISPOSITION_VERSION, 'tl-dispositions-v2');
  const label = '5ede4fc5ae051d7b1601142d283755e4';
  const r = extract(`<h2>Indicators of Compromise</h2><ul><li>${label}.loophole[.]site</li><li>tunnel-relay[.]example-c2.net</li></ul>`);
  assert.ok(r.rows.some((c) => c.normalized_value === `${label}.loophole.site`), JSON.stringify(r.rows.map((c) => c.normalized_value)));
  const out = buildObservableDispositions({ candidates: r.rows, tokenLog: r.tokenLog, blocks: r.annotated.blocks });
  assert.equal(out.counts.undispositioned, 0, JSON.stringify(out.rows.filter((x) => x.reason_code === 'undispositioned_token')));
  // Without the accounted hostname the digest-shaped label is still reported.
  const loneOut = buildObservableDispositions({ candidates: [], tokenLog: [], blocks: r.annotated.blocks });
  assert.ok(loneOut.rows.some((x) => x.reason_code === 'undispositioned_token' && x.normalized_value === label), JSON.stringify(loneOut.rows));
});
