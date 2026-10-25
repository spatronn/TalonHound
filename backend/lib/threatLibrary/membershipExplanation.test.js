/**
 * Membership explanations mirror canonical membership predicates.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  explainMembershipDecision,
  compactMembershipExplanation,
  MEMBERSHIP_OUTCOMES,
  MEMBERSHIP_REASON_CODES
} from './membershipExplanation.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { extractReportCandidates } from './extractionStages.js';
import { createCanonicalDocument } from './canonicalDocument.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

function persisted(c) {
  return { ...c, evidence: buildCandidateEvidenceRecord(c) };
}

test('explanation agrees with isReportIndicatorMember for an explicit IOC', () => {
  const x = extractReportCandidates(
    { source_url: 'https://vendor.example/a' },
    createCanonicalDocument({
      title: 'a',
      blocks: [
        { id: 'h', type: 'heading', level: 2, text: 'Indicators of Compromise' },
        { id: 'r', type: 'list_item', layout: 'observable_row', text: 'c2-explicit.evilvend.net' }
      ]
    })
  );
  const c = x.candidates.find((v) => v.normalized_value === 'c2-explicit.evilvend.net');
  assert.ok(c);
  const member = isReportIndicatorMember(persisted(c));
  const e = explainMembershipDecision(c);
  assert.equal(e.member, member);
  assert.equal(e.outcome, MEMBERSHIP_OUTCOMES.INDICATOR);
  assert.equal(e.reason_code, MEMBERSHIP_REASON_CODES.EXPLICIT_PUBLISHER_IOC);
  assert.match(e.summary, /publisher asserted/i);
  assert.equal(e.scope.mode, 'A');
});

test('benign / reference context is explained as non-member', () => {
  const html = `<article>
<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Domain</td><td>actor-c2.evilvend.net</td></tr>
</table>
<h2>References</h2>
<ul><li>https://learn.microsoft.com/security</li></ul>
</article>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: 'https://vendor.example/b',
    finalUrl: 'https://vendor.example/b',
    httpStatus: 200
  });
  const x = extractReportCandidates({ source_url: 'https://vendor.example/b' }, r.document);
  const ref = x.candidates.find((c) => String(c.normalized_value || '').includes('learn.microsoft.com'));
  assert.ok(ref);
  const e = explainMembershipDecision(ref);
  assert.equal(e.member, false);
  assert.equal(isReportIndicatorMember(persisted(ref)), false);
  assert.ok(
    [
      MEMBERSHIP_REASON_CODES.REFERENCE_ONLY,
      MEMBERSHIP_REASON_CODES.CONTEXT_ONLY_POLICY,
      MEMBERSHIP_REASON_CODES.BENIGN_OR_PROVIDER
    ].includes(e.reason_code),
    e.reason_code
  );
});

test('MODE A narrative without publisher assertion is explained as insufficient assertion', () => {
  const html = `<article>
<h2>Indicators of Compromise</h2>
<ul><li>listed-c2.evilvend.net</li></ul>
<h2>Analysis</h2>
<p>The backdoor also beacons to narrative-only.evilvend.net for command and control.</p>
</article>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: 'https://vendor.example/c',
    finalUrl: 'https://vendor.example/c',
    httpStatus: 200
  });
  const x = extractReportCandidates({ source_url: 'https://vendor.example/c' }, r.document);
  const narrative = x.candidates.find((c) => c.normalized_value === 'narrative-only.evilvend.net');
  assert.ok(narrative);
  const e = explainMembershipDecision(narrative);
  assert.equal(e.member, false);
  assert.equal(e.scope.mode, 'A');
  assert.equal(e.reason_code, MEMBERSHIP_REASON_CODES.INSUFFICIENT_PUBLISHER_ASSERTION);
});

test('linked-source-only identity is explained separately', () => {
  const c = {
    candidate_type: 'domain',
    normalized_value: 'pack-only.evilvend.net',
    assessment: 'malicious',
    is_ioc: true,
    review_status: 'pending',
    has_original_document_occurrence: false,
    has_linked_source_occurrence: true,
    source_assertion: 'linked_source_ioc',
    sources: [{ id: 'src1', canonical_url: 'https://github.com/example/iocs' }],
    evidence: {
      source_assertion: 'linked_source_ioc',
      document_has_authoritative_scope: true,
      linked_sources: [{ id: 'src1' }]
    }
  };
  const e = explainMembershipDecision(c);
  assert.equal(e.member, false);
  assert.equal(e.linked_only, true);
  assert.equal(e.outcome, MEMBERSHIP_OUTCOMES.LINKED_ONLY_INDICATOR);
  assert.equal(e.reason_code, MEMBERSHIP_REASON_CODES.LINKED_SOURCE_IOC);
});

test('compact explanation stays bounded and consistent', () => {
  const c = {
    candidate_type: 'ip',
    normalized_value: '198.51.100.10',
    assessment: 'malicious',
    is_ioc: true,
    review_status: 'pending',
    source_assertion: 'explicit_ioc',
    document_has_authoritative_scope: true,
    policy_decision: 'explicit_report_assertion',
    occurrences: [{ zone: 'explicit_ioc_section', asserted: true, block_id: 'b1' }],
    evidence: {
      source_assertion: 'explicit_ioc',
      document_has_authoritative_scope: true,
      policy_decision: 'explicit_report_assertion',
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true, block_id: 'b1' }]
    }
  };
  const full = explainMembershipDecision(c);
  const compact = compactMembershipExplanation(c);
  assert.equal(compact.member, full.member);
  assert.equal(compact.reason_code, full.reason_code);
  assert.equal(compact.outcome, full.outcome);
});
