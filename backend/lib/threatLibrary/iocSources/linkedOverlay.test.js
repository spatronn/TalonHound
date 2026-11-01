/**
 * tl-linked-overlay-v1 (52-report audit): a Talos post whose IOC section only
 * points at its GitHub pack leaves body mentions Context Only
 * (`context_only_narrative_with_authoritative_scope`). When the pack lists
 * the same identity, the overlap row used to keep the body reading, so 26
 * pack Indicators across 8 reports (35550, 35554, 35559, 35560, 35561,
 * 35564, 35572) never reached the union inventory.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFERRED_CONTEXT_POLICIES, linkedAssertionOverridesDeferral, reapplyLinkedOverlay } from './linkedOverlay.js';
import { reconcileReportCandidates } from '../store.js';
import { isUnionReportIndicatorMember } from '../indicatorMembership.js';

const deferred = (over = {}) => ({
  id: 7,
  candidate_type: 'domain',
  normalized_value: 'leaguejazire.com',
  assessment: 'context_only',
  role: 'reference',
  review_status: 'pending',
  match_state: 'context_only',
  has_original_document_occurrence: true,
  source_assertion: 'body_mention',
  evidence: { policy_decision: 'context_only_narrative_with_authoritative_scope' },
  ...over
});
const linked = { assessment: 'malicious', role: 'malicious_infrastructure', is_ioc: true, match_state: 'new' };

test('only the deferral policy yields to a linked assertion', () => {
  assert.ok(DEFERRED_CONTEXT_POLICIES.has('context_only_narrative_with_authoritative_scope'));
  assert.equal(linkedAssertionOverridesDeferral(deferred(), linked), true);
  for (const policy of [
    'context_only_benign_component',
    'context_only_provider_service',
    'context_only_reference_relation',
    'context_only_negative_zone',
    'demoted_provider_service'
  ]) {
    assert.equal(linkedAssertionOverridesDeferral(deferred({ evidence: { policy_decision: policy } }), linked), false, policy);
  }
});

test('analyst decisions and Context Only pack rows are never overridden', () => {
  assert.equal(linkedAssertionOverridesDeferral(deferred({ review_status: 'context_only' }), linked), false);
  assert.equal(linkedAssertionOverridesDeferral(deferred({ review_status: 'approved' }), linked), false);
  assert.equal(linkedAssertionOverridesDeferral(deferred(), { ...linked, assessment: 'context_only' }), false);
  assert.equal(linkedAssertionOverridesDeferral(deferred(), { ...linked, assessment: 'invalid' }), false);
  assert.equal(linkedAssertionOverridesDeferral(deferred({ assessment: 'malicious' }), linked), false, 'not Context Only: nothing to override');
});

test('source-scope reconcile writes the linked assertion onto a deferred overlap row', async () => {
  const prior = deferred();
  const updates = [];
  const client = {
    release() {},
    async query(sql, params) {
      const s = String(sql);
      if (/FROM threat_reports/.test(s) && /FOR UPDATE/.test(s)) return { rows: [{ id: 42, review_phase: 'review_ready', finalized_at: null }] };
      if (/FROM threat_report_candidates WHERE report_id = \$1 ORDER BY id FOR UPDATE/.test(s)) return { rows: [prior] };
      if (/^\s*UPDATE threat_report_candidates SET\s+assessment = \$2/.test(s)) {
        updates.push(params);
        return { rows: [{ ...prior, assessment: params[1], role: params[2], match_state: params[3], evidence: JSON.parse(params[6]) }] };
      }
      return { rows: [] };
    }
  };
  const out = await reconcileReportCandidates(client, 42, [{
    candidate_type: 'domain',
    original_value: 'leaguejazire.com',
    normalized_value: 'leaguejazire.com',
    assessment: 'malicious',
    role: 'malicious_infrastructure',
    is_ioc: true,
    match_state: 'new',
    source_assertion: 'linked_source_ioc',
    has_original_document_occurrence: false
  }], { scope: { sourceId: 238 } });
  assert.equal(updates.length, 1, 'one overlay UPDATE');
  const row = out.rows[0];
  assert.equal(row.assessment, 'malicious');
  assert.equal(row.match_state, 'new');
  assert.equal(row.evidence.linked_assertion_over_deferral.source_id, 238);
  assert.equal(row.evidence.linked_assertion_over_deferral.prior_policy_decision, 'context_only_narrative_with_authoritative_scope');
  assert.equal(row.has_original_document_occurrence, true, 'body provenance kept');
  assert.equal(isUnionReportIndicatorMember({ ...row, has_linked_source_occurrence: true }), true);
});

test('negative: a provider-demoted body row stays Context Only under source reconcile', async () => {
  const prior = deferred({ evidence: { policy_decision: 'context_only_provider_service' }, role: 'hosting_platform' });
  let overlay = 0;
  const client = {
    release() {},
    async query(sql) {
      const s = String(sql);
      if (/FROM threat_reports/.test(s) && /FOR UPDATE/.test(s)) return { rows: [{ id: 42, finalized_at: null }] };
      if (/FROM threat_report_candidates WHERE report_id = \$1 ORDER BY id FOR UPDATE/.test(s)) return { rows: [prior] };
      if (/^\s*UPDATE threat_report_candidates SET\s+assessment = \$2/.test(s)) overlay += 1;
      return { rows: [] };
    }
  };
  const out = await reconcileReportCandidates(client, 42, [{
    candidate_type: 'domain', original_value: 'leaguejazire.com', normalized_value: 'leaguejazire.com',
    assessment: 'malicious', role: 'malicious_infrastructure', is_ioc: true, match_state: 'context_only',
    source_assertion: 'linked_source_ioc', has_original_document_occurrence: false
  }], { scope: { sourceId: 238 } });
  assert.equal(overlay, 0);
  assert.equal(out.rows[0].assessment, 'context_only');
});

test('Refresh keeps the overlay when the body still defers, never over a new stance', () => {
  const marker = { source_id: 238, prior_assessment: 'context_only', prior_role: 'reference', prior_policy_decision: 'context_only_narrative_with_authoritative_scope' };
  const previous = [{ ...deferred({ assessment: 'malicious', role: 'malicious_infrastructure', match_state: 'new' }), evidence: { linked_assertion_over_deferral: marker } }];
  const fresh = {
    candidate_type: 'domain', normalized_value: 'leaguejazire.com', assessment: 'context_only', role: 'reference',
    match_state: 'context_only', review_status: 'pending', policy_decision: 'context_only_narrative_with_authoritative_scope', evidence: {}
  };
  const [kept] = reapplyLinkedOverlay([fresh], previous);
  assert.equal(kept.assessment, 'malicious');
  assert.equal(kept.match_state, 'new');
  assert.deepEqual(kept.linked_assertion_over_deferral, marker);
  const benign = { ...fresh, policy_decision: 'context_only_benign_component' };
  assert.equal(reapplyLinkedOverlay([benign], previous)[0].assessment, 'context_only');
  const analyst = { ...fresh, review_status: 'context_only' };
  assert.equal(reapplyLinkedOverlay([analyst], previous)[0].assessment, 'context_only');
});
