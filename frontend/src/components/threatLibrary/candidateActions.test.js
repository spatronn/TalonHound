/**
 * Drawer action bar mirrors the backend transition rules: no action is
 * offered that reviewService would refuse or silently no-op.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createEligibility, describeCandidateActions } from './candidateActions.js';

const pendingNew = { id: 1, candidate_type: 'domain', assessment: 'malicious', review_status: 'pending', match_state: 'new', is_ioc: true };
const approvedCreated = { id: 2, candidate_type: 'domain', assessment: 'malicious', review_status: 'approved', match_state: 'existing', matched_ioc_id: 9, promotion_outcome: 'created', is_ioc: true };
const approvedNew = { id: 3, candidate_type: 'ip', assessment: 'suspicious', review_status: 'approved', match_state: 'new', is_ioc: true };
const approvedExisting = { id: 4, candidate_type: 'ip', assessment: 'malicious', review_status: 'approved', match_state: 'existing', matched_ioc_id: 77, promotion_outcome: 'already_existing', is_ioc: true };
const ignored = { id: 5, candidate_type: 'url', assessment: 'malicious', review_status: 'ignored', match_state: 'new', is_ioc: true };
const contextOnly = { id: 6, candidate_type: 'domain', assessment: 'context_only', review_status: 'context_only', match_state: 'context_only', is_ioc: true };
const nonIoc = { id: 7, candidate_type: 'attack_technique', assessment: 'context_only', review_status: 'pending', match_state: 'context_only', is_ioc: false };
const approvedCidr = { id: 8, candidate_type: 'cidr', assessment: 'malicious', review_status: 'approved', match_state: 'new', is_ioc: true };
const approvedUnknown = { id: 9, candidate_type: 'domain', assessment: 'unknown', review_status: 'approved', match_state: 'new', is_ioc: true };

const ids = (r) => r.actions.map((a) => a.id);

test('pending IOC row: approve / context only / ignore, no create until approved', () => {
  const r = describeCandidateActions(pendingNew);
  assert.deepEqual(ids(r), ['approve', 'context_only', 'ignore']);
  assert.equal(r.note, null);
  assert.deepEqual(createEligibility(pendingNew), { eligible: false, outcome: 'not_approved' });
});

test('approved + created: no re-approve, no create, state note instead', () => {
  const r = describeCandidateActions(approvedCreated);
  assert.deepEqual(ids(r), ['context_only', 'ignore']);
  assert.equal(r.note, 'Approved · IOC record created');
  assert.equal(createEligibility(approvedCreated).outcome, 'already_existing');
});

test('approved + new + creatable: Create IOC is offered as the primary action', () => {
  const r = describeCandidateActions(approvedNew);
  assert.deepEqual(ids(r), ['context_only', 'ignore', 'create_iocs']);
  assert.equal(r.actions.find((a) => a.id === 'create_iocs').primary, true);
  assert.equal(r.actions.find((a) => a.id === 'create_iocs').label, 'Create IOC');
  assert.equal(r.note, 'Approved');
  assert.deepEqual(createEligibility(approvedNew), { eligible: true, outcome: 'will_create' });
});

test('approved but already existing: no create, existing note', () => {
  const r = describeCandidateActions(approvedExisting);
  assert.ok(!ids(r).includes('create_iocs'));
  assert.ok(!ids(r).includes('approve'));
  assert.equal(r.note, 'Approved · IOC record already exists');
});

test('ignored / context-only rows only offer the other transitions', () => {
  assert.deepEqual(ids(describeCandidateActions(ignored)), ['approve', 'context_only']);
  assert.equal(describeCandidateActions(ignored).note, 'Ignored');
  assert.deepEqual(ids(describeCandidateActions(contextOnly)), ['approve', 'ignore']);
  assert.equal(describeCandidateActions(contextOnly).note, 'Context only');
});

test('non-IOC artifacts cannot be approved (backend updates only is_ioc = true rows)', () => {
  const r = describeCandidateActions(nonIoc);
  assert.deepEqual(ids(r), ['context_only', 'ignore']);
  assert.equal(r.note, 'Not an IOC candidate');
});

test('unsupported type / non-malicious assessment never offer Create IOC, and say why', () => {
  assert.equal(createEligibility(approvedCidr).outcome, 'unsupported');
  assert.equal(describeCandidateActions(approvedCidr).note, 'Approved · type cannot be stored as an IOC record');
  assert.equal(createEligibility(approvedUnknown).outcome, 'not_applicable');
  assert.equal(describeCandidateActions(approvedUnknown).note, 'Approved · assessment is not malicious or suspicious');
});

test('read-only users and non-mutable phases get no actions', () => {
  assert.deepEqual(describeCandidateActions(pendingNew, { canWrite: false }), { actions: [], note: null });
  assert.deepEqual(describeCandidateActions(pendingNew, { mutationAllowed: false }), { actions: [], note: null });
  assert.deepEqual(describeCandidateActions(null), { actions: [], note: null });
});

test('describing actions never mutates the row', () => {
  const frozen = Object.freeze({ ...approvedCreated });
  const before = JSON.stringify(frozen);
  describeCandidateActions(frozen);
  createEligibility(frozen);
  assert.equal(JSON.stringify(frozen), before);
});
