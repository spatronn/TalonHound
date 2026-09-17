/**
 * Display labels map canonical enum values to friendly text without touching
 * the canonical value itself.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  artifactTypeLabel,
  assessmentLabel,
  assessmentTone,
  candidateTypeLabel,
  entityTypeLabel,
  humanizeEnum,
  matchCellLabel,
  matchStateLabel,
  matchStateTone,
  promotionOutcomeTone,
  reviewStatusLabel,
  reviewStatusTone,
  roleLabel,
  sourceTypeLabel
} from './reportDisplayLabels.js';

test('role / assessment / review / match labels are friendly', () => {
  assert.equal(roleLabel('command_and_control'), 'Command & Control');
  assert.equal(roleLabel('malicious_infrastructure'), 'Malicious infrastructure');
  assert.equal(roleLabel('malware_sample'), 'Malware sample');
  assert.equal(assessmentLabel('malicious'), 'Malicious');
  assert.equal(assessmentLabel('context_only'), 'Context only');
  assert.equal(reviewStatusLabel('pending'), 'Pending');
  assert.equal(reviewStatusLabel('approved'), 'Approved');
  assert.equal(reviewStatusLabel('created_ioc'), 'Approved');
  assert.equal(matchStateLabel('needs_review'), 'Needs review');
  assert.equal(matchStateLabel('existing'), 'Existing');
});

test('entity types have singular and plural labels', () => {
  assert.equal(entityTypeLabel('threat_actor'), 'Threat actor');
  assert.equal(entityTypeLabel('threat_actor', { plural: true }), 'Threat actors');
  assert.equal(entityTypeLabel('malware', { plural: true }), 'Malware');
  assert.equal(entityTypeLabel('organization', { plural: true }), 'Organizations');
  assert.equal(entityTypeLabel('vulnerability', { plural: true }), 'Vulnerabilities');
});

test('candidate, artifact and source type labels', () => {
  assert.equal(candidateTypeLabel('ip'), 'IP');
  assert.equal(candidateTypeLabel('sha256'), 'SHA-256');
  assert.equal(candidateTypeLabel('url'), 'URL');
  assert.equal(candidateTypeLabel('attack_technique'), 'ATT&CK technique');
  assert.equal(candidateTypeLabel('technical_artifact'), 'Technical artifact');
  assert.equal(artifactTypeLabel('url_fetch'), 'Fetched source');
  assert.equal(artifactTypeLabel('canonical_document'), 'Canonical document');
  assert.equal(sourceTypeLabel('thib'), 'THIB bundle');
});

test('unknown snake_case values are humanised, never shown raw', () => {
  assert.equal(humanizeEnum('some_future_role'), 'Some future role');
  assert.equal(roleLabel('some_future_role'), 'Some future role');
  assert.equal(entityTypeLabel('sector', { plural: true }), 'Sectors');
  assert.equal(humanizeEnum(''), '');
  assert.equal(roleLabel(null), '');
});

test('labels do not mutate the canonical value on the row', () => {
  const row = Object.freeze({
    candidate_type: 'domain',
    assessment: 'malicious',
    role: 'command_and_control',
    review_status: 'approved',
    match_state: 'existing',
    matched_ioc_id: 42,
    matched_ioc_observable_type: 'domain'
  });
  const snapshot = JSON.stringify(row);
  assert.equal(roleLabel(row.role), 'Command & Control');
  assert.equal(matchCellLabel(row), 'Matched (Domain)');
  assert.equal(JSON.stringify(row), snapshot);
  assert.equal(row.role, 'command_and_control');
});

test('match cell falls back to the match state without an IOC hit', () => {
  assert.equal(matchCellLabel({ match_state: 'new' }), 'New');
  assert.equal(matchCellLabel({ match_state: 'needs_review' }), 'Needs review');
  assert.equal(matchCellLabel({ matched_ioc_id: 7, candidate_type: 'ip' }), 'Matched (IP)');
});

test('tones are restrained: only risk / attention states carry colour', () => {
  assert.equal(assessmentTone('malicious'), 'danger');
  assert.equal(assessmentTone('suspicious'), 'warning');
  assert.equal(assessmentTone('unknown'), 'neutral');
  assert.equal(reviewStatusTone('approved'), 'success');
  assert.equal(reviewStatusTone('pending'), 'warning');
  assert.equal(reviewStatusTone('ignored'), 'muted');
  assert.equal(matchStateTone('new'), 'info');
  assert.equal(matchStateTone('existing'), 'neutral');
  assert.equal(promotionOutcomeTone('created'), 'success');
  assert.equal(promotionOutcomeTone('already_existing'), 'neutral');
  assert.equal(promotionOutcomeTone(null), 'none');
  assert.equal(promotionOutcomeTone('will_create'), 'none');
});
