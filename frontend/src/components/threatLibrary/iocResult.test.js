/**
 * Create IOCs feedback: IOC Result reflects what Create IOCs did (or would
 * deterministically record) from persisted row data, the existing-IOC link
 * uses only the backend-resolved public id, the no-op modal is informational
 * and the Create IOCs button needs one createable row.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NO_CREATABLE_HINT,
  applyPromotionResults,
  candidateMatchesResultFilter,
  classifyCreateOutcome,
  describeNoCreatableIocs,
  describeReviewToolbar,
  formatCreateIocSummary,
  iocResultLabel,
  iocResultLink,
  iocResultOutcome
} from './candidateReview.js';
import { matchCellLabel, promotionOutcomeTone, reviewStatusLabel } from './reportDisplayLabels.js';
import { describeCandidateDetail } from './candidateDetail.js';

const sha = (n) => String(n).padStart(64, 'a');

/** Row as GET /api/threat-library/reports/:id returns it (approved, not yet run through Create IOCs). */
function newRow(id, overrides = {}) {
  return {
    id,
    candidate_type: 'sha256',
    normalized_value: sha(id),
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    matched_ioc_id: null,
    matched_ioc_public_id: null,
    matched_ioc_observable_type: null,
    promotion_outcome: null,
    is_ioc: true,
    ...overrides
  };
}

const existingRow = (id, iocId, publicId = `ioc-pub-${iocId}`) => newRow(id, {
  match_state: 'existing',
  matched_ioc_id: iocId,
  matched_ioc_public_id: publicId,
  matched_ioc_observable_type: 'sha256'
});

const createAction = (rows) => describeReviewToolbar({ filter: 'indicators', selectedRows: rows }).actions.find((a) => a.id === 'create_iocs');

test('classifyCreateOutcome mirrors backend classifyCreateEligibility rule order', () => {
  assert.equal(classifyCreateOutcome(newRow(1)), 'will_create');
  assert.equal(classifyCreateOutcome(existingRow(2, 102)), 'already_existing');
  assert.equal(classifyCreateOutcome(newRow(3, { review_status: 'pending' })), 'not_approved');
  assert.equal(classifyCreateOutcome({ ...existingRow(4, 104), review_status: 'pending' }), 'not_approved');
  assert.equal(classifyCreateOutcome(newRow(5, { candidate_type: 'cidr', normalized_value: '10.0.0.0/24' })), 'unsupported');
  assert.equal(classifyCreateOutcome(newRow(6, { review_status: 'ignored' })), 'not_applicable');
  assert.equal(classifyCreateOutcome(newRow(7, { assessment: 'context_only' })), 'not_applicable');
  assert.equal(classifyCreateOutcome(newRow(8, { assessment: 'benign' })), 'not_applicable');
  assert.equal(classifyCreateOutcome(newRow(9, { is_ioc: false })), 'not_applicable');
});

test('existing-only selection (4 existing, 0 createable): IOC Result reads "Already exists", not "—"', () => {
  const rows = [existingRow(1, 101), existingRow(2, 102), existingRow(3, 103), existingRow(4, 104)];
  for (const r of rows) {
    assert.equal(iocResultOutcome(r), 'already_existing');
    assert.equal(iocResultLabel(r), 'Already exists');
    assert.equal(promotionOutcomeTone(iocResultOutcome(r)), 'neutral', 'existing uses secondary styling');
    // Review, Match and IOC Result stay three separate facts.
    assert.equal(reviewStatusLabel(r.review_status), 'Approved');
    assert.equal(matchCellLabel(r), 'Matched · SHA-256');
  }
});

test('existing-only modal is informational copy: no new records, N already exist', () => {
  const summary = { selected: 4, eligible: 0, already_existing: 4, not_approved: 0, unsupported: 0 };
  const info = describeNoCreatableIocs(summary);
  assert.equal(info.title, 'No new IOC records');
  assert.equal(info.description, 'No new IOC records will be created. 4 selected indicators already exist as IOC records.');
  assert.match(formatCreateIocSummary(summary), /- 0 new IOC records will be created/);
  assert.equal(describeNoCreatableIocs({ selected: 1, eligible: 0, already_existing: 1 }).description,
    'No new IOC records will be created. 1 selected indicator already exists as IOC records.');
  assert.equal(describeNoCreatableIocs({ selected: 2, eligible: 0, not_approved: 2 }).title, 'Approve indicators first');
  assert.equal(describeNoCreatableIocs({ selected: 5, eligible: 2, already_existing: 3 }), null, 'mixed selection keeps the normal confirmation');
});

test('Create IOCs eligibility: existing-only disabled, mixed and new-only enabled', () => {
  const existing = [existingRow(1, 101), existingRow(2, 102), existingRow(3, 103), existingRow(4, 104)];
  const existingOnly = createAction(existing);
  assert.equal(existingOnly.enabled, false);
  assert.equal(existingOnly.hint, NO_CREATABLE_HINT);
  assert.equal(NO_CREATABLE_HINT, 'No new approved indicators selected.');

  const mixed = createAction([newRow(10), newRow(11), existingRow(3, 103), existingRow(4, 104), existingRow(5, 105)]);
  assert.equal(mixed.enabled, true, 'existing rows never block the new ones');
  assert.equal(mixed.hint, null);

  assert.equal(createAction([newRow(10)]).enabled, true);
  assert.equal(createAction([newRow(10, { review_status: 'pending' })]).enabled, false, 'nothing approved + new');
  assert.equal(createAction([]).enabled, false);
});

test('mixed run (2 new + 3 existing): 2 rows read Created, 3 read Already exists', () => {
  const before = [newRow(1), newRow(2), existingRow(3, 103), existingRow(4, 104), existingRow(5, 105)];
  // Exact shape of the backend confirm response `results`.
  const results = [
    { candidate_id: 1, outcome: 'created', ioc_id: 501 },
    { candidate_id: 2, outcome: 'created', ioc_id: 502 },
    { candidate_id: 3, outcome: 'already_existing', ioc_id: 103, detail: 'An IOC record already exists for this indicator.' },
    { candidate_id: 4, outcome: 'already_existing', ioc_id: 104, detail: 'An IOC record already exists for this indicator.' },
    { candidate_id: 5, outcome: 'already_existing', ioc_id: 105, detail: 'An IOC record already exists for this indicator.' }
  ];
  const after = applyPromotionResults(before, results);
  assert.deepEqual(after.map(iocResultLabel), ['Created', 'Created', 'Already exists', 'Already exists', 'Already exists']);
  assert.deepEqual(after.map((r) => r.matched_ioc_id), [501, 502, 103, 104, 105]);
  assert.equal(promotionOutcomeTone(iocResultOutcome(after[0])), 'success');
});

test('new-only run: IOC Result = Created', () => {
  const [row] = applyPromotionResults([newRow(1)], [{ candidate_id: 1, outcome: 'created', ioc_id: 700 }]);
  assert.equal(iocResultLabel(row), 'Created');
});

test('after a page refresh the persisted / deterministic result is unchanged', () => {
  // Reloaded detail rows: Create IOCs persisted promotion_outcome + matched_ioc_id.
  const created = newRow(1, { promotion_outcome: 'created', match_state: 'existing', matched_ioc_id: 501, matched_ioc_public_id: 'ioc-pub-501', matched_ioc_observable_type: 'sha256' });
  const linked = { ...existingRow(3, 103), promotion_outcome: 'already_existing' };
  // Existing-only selection that was never committed: derived from the stored link.
  const neverRun = existingRow(4, 104);
  assert.equal(iocResultLabel(created), 'Created', 'Created survives even though Match now reads Matched');
  assert.equal(iocResultLabel(linked), 'Already exists');
  assert.equal(iocResultLabel(neverRun), 'Already exists');
  // No pseudo-result for rows Create IOCs would not touch.
  assert.equal(iocResultLabel(newRow(5)), '—');
  assert.equal(iocResultLabel(newRow(6, { review_status: 'pending', match_state: 'existing', matched_ioc_id: 106 })), '—');
  assert.equal(iocResultLabel(newRow(7, { promotion_outcome: 'unsupported', candidate_type: 'cidr' })), 'Not supported');
  // Result filter uses the same effective outcome.
  assert.equal(candidateMatchesResultFilter(neverRun, 'already_existing'), true);
  assert.equal(candidateMatchesResultFilter(neverRun, 'not_created'), false);
  assert.equal(candidateMatchesResultFilter(newRow(5), 'not_created'), true);
});

test('View IOC link goes to the backend-resolved public id; never guessed', () => {
  assert.equal(iocResultLink(existingRow(3, 103, 'ioc-pub-103')), '/ioc/details/ioc-pub-103');
  assert.equal(iocResultLink(newRow(1, { promotion_outcome: 'created', matched_ioc_id: 501, matched_ioc_public_id: 'ioc-pub-501' })), '/ioc/details/ioc-pub-501');
  // Backend could not resolve the record (deleted / unknown): no link.
  assert.equal(iocResultLink({ ...existingRow(3, 103), matched_ioc_public_id: null }), null);
  assert.equal(iocResultLink({ ...existingRow(3, 103), matched_ioc_public_id: '' }), null);
  // Freshly applied results carry an internal id but no public id until the reload.
  const [justCreated] = applyPromotionResults([newRow(1)], [{ candidate_id: 1, outcome: 'created', ioc_id: 501 }]);
  assert.equal(iocResultLink(justCreated), null);
  // Not created / not existing rows never link, even with a stray public id.
  assert.equal(iocResultLink(newRow(2, { matched_ioc_public_id: 'ioc-pub-x' })), null);
  assert.equal(iocResultLink(newRow(6, { review_status: 'pending', match_state: 'existing', matched_ioc_id: 106, matched_ioc_public_id: 'ioc-pub-106' })), null);
  // Value is never used to build the link.
  assert.doesNotMatch(String(iocResultLink(existingRow(3, 103))), new RegExp(sha(3)));
  assert.equal(iocResultLink(existingRow(3, 103, 'a/b')), '/ioc/details/a%2Fb');
});

test('drawer IOC result field uses the same effective outcome', () => {
  const detail = describeCandidateDetail(existingRow(3, 103));
  const field = detail.fields.find((f) => f.key === 'ioc_result');
  assert.equal(field.value, 'Already exists');
  assert.equal(field.raw, 'already_existing');
});
