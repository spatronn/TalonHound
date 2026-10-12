/**
 * Effective Indicator review progress (tl-review-progress-v1) — pure contract.
 * The SQL twin (loadReportReviewProgress) is exercised against real Postgres in
 * reviewProgress.integration.test.js with the same scenarios.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  COMPLETED_REVIEW_STATUSES,
  isAcceptedIocSource,
  isCompletedReviewDecision,
  reviewProgressSql,
  summarizeReviewProgress
} from './reviewProgress.js';
import { matchSelectionTab } from './candidateSelection.js';

const ACCEPTED = { id: 'src-a', lifecycle_status: 'extracted', approved_at: '2026-10-10T15:18:33Z' };
const ACCEPTED_B = { id: 'src-b', lifecycle_status: 'extracted', approved_at: '2026-10-11T10:00:00Z' };
const NOT_ACCEPTED = { id: 'src-c', lifecycle_status: 'inspected', approved_at: null };

let seq = 0;
function original(overrides = {}) {
  seq += 1;
  return {
    id: seq,
    candidate_type: 'domain',
    normalized_value: `orig-${seq}.example`,
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    source_assertion: 'explicit_ioc',
    has_original_document_occurrence: true,
    document_has_authoritative_scope: true,
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'explicit_ioc',
      is_direct_source_observable: true,
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row' }]
    },
    sources: [],
    ...overrides
  };
}

function linkedOnly(sources, overrides = {}) {
  seq += 1;
  return {
    id: seq,
    candidate_type: 'sha256',
    normalized_value: `${String(seq).padStart(64, 'a')}`,
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    source_assertion: 'linked_source_ioc',
    has_original_document_occurrence: false,
    evidence: { source_assertion: 'linked_source_ioc', is_direct_source_observable: true },
    sources,
    ...overrides
  };
}

const many = (n, fn) => Array.from({ length: n }, () => fn());

test('completed decisions = approved / created_ioc / ignored / rejected; pending is not', () => {
  assert.deepEqual([...COMPLETED_REVIEW_STATUSES].sort(), ['approved', 'created_ioc', 'ignored', 'rejected']);
  for (const s of COMPLETED_REVIEW_STATUSES) assert.equal(isCompletedReviewDecision({ review_status: s }), true);
  assert.equal(isCompletedReviewDecision({ review_status: 'pending' }), false);
  assert.equal(isCompletedReviewDecision({}), false);
});

test('source acceptance = persisted approved_at, never mere existence / discovery', () => {
  assert.equal(isAcceptedIocSource(ACCEPTED), true);
  assert.equal(isAcceptedIocSource(NOT_ACCEPTED), false);
  assert.equal(isAcceptedIocSource({ lifecycle_status: 'discovered' }), false);
  assert.equal(isAcceptedIocSource(null), false);
});

test('1. original-only report: 70 reviewed → 70/70', () => {
  const p = summarizeReviewProgress(many(70, () => original()));
  assert.equal(p.total, 70);
  assert.equal(p.reviewed, 70);
  assert.equal(p.pending, 0);
  assert.equal(p.original.total, 70);
  assert.equal(p.linked_only.total, 0);
});

test('2. original + accepted linked source, no overlap → 100/100', () => {
  const p = summarizeReviewProgress([
    ...many(70, () => original()),
    ...many(30, () => linkedOnly([ACCEPTED]))
  ]);
  assert.deepEqual([p.total, p.reviewed, p.pending], [100, 100, 0]);
  assert.deepEqual([p.linked_only.total, p.linked_only.reviewed], [30, 30]);
});

test('3. original + linked rows awaiting review → linked Indicators stay pending', () => {
  const p = summarizeReviewProgress([
    ...many(70, () => original()),
    ...many(30, () => linkedOnly([ACCEPTED], { review_status: 'pending' }))
  ]);
  assert.deepEqual([p.total, p.reviewed, p.pending], [100, 70, 30]);
  assert.equal(p.linked_only.pending, 30);
});

test('3b. decided linked rows whose source has no persisted acceptance are NOT reviewed', () => {
  const p = summarizeReviewProgress([
    ...many(70, () => original()),
    ...many(30, () => linkedOnly([NOT_ACCEPTED]))
  ]);
  assert.deepEqual([p.total, p.reviewed, p.pending], [100, 70, 30]);
  assert.equal(p.linked_only.decided_without_accepted_source, 30);
});

test('4. overlap: source repeats 10 originals + 20 new → union 90, no double count', () => {
  const originals = many(70, () => original());
  const overlap = originals.slice(0, 10).map((o) => ({ ...o, sources: [ACCEPTED] }));
  const rows = [...overlap, ...originals.slice(10), ...many(20, () => linkedOnly([ACCEPTED]))];
  const p = summarizeReviewProgress(rows);
  assert.equal(p.total, 90);
  assert.equal(p.reviewed, 90);
  assert.equal(p.original.total, 70);
  assert.equal(p.linked_only.total, 20);
  assert.equal(p.overlap, 10);
});

test('4b. duplicate rows for one identity are counted once (canonical identity dedupe)', () => {
  const a = original({ normalized_value: 'dup.example' });
  const p = summarizeReviewProgress([a, { ...a, id: 999, sources: [ACCEPTED] }]);
  assert.equal(p.total, 1);
  assert.equal(p.reviewed, 1);
});

test('5. multiple IOC Sources: A accepted+reviewed, B rows pending → mixed progress', () => {
  const p = summarizeReviewProgress([
    ...many(70, () => original()),
    ...many(30, () => linkedOnly([ACCEPTED])),
    ...many(25, () => linkedOnly([ACCEPTED_B], { review_status: 'pending' }))
  ]);
  assert.deepEqual([p.total, p.reviewed, p.pending], [125, 100, 25]);
});

test('6. same IOC from multiple sources is one identity; any accepted source suffices', () => {
  const row = linkedOnly([NOT_ACCEPTED, ACCEPTED]);
  const p = summarizeReviewProgress([row]);
  assert.deepEqual([p.total, p.reviewed], [1, 1]);
});

test('7. existing global IOC: matched_ioc_id alone is not an analyst decision', () => {
  const p = summarizeReviewProgress([
    original({ review_status: 'pending', match_state: 'existing', matched_ioc_id: 42 }),
    linkedOnly([ACCEPTED], { review_status: 'pending', match_state: 'existing', matched_ioc_id: 43 })
  ]);
  assert.deepEqual([p.total, p.reviewed, p.pending], [2, 0, 2]);
});

test('8. context-only / body mention never enter the denominator', () => {
  const p = summarizeReviewProgress([
    ...many(3, () => original()),
    original({ review_status: 'pending', assessment: 'context_only', match_state: 'context_only', source_assertion: 'body_mention' }),
    original({
      review_status: 'pending',
      match_state: 'existing',
      matched_ioc_id: 7,
      source_assertion: 'body_mention',
      evidence: {
        document_has_authoritative_scope: true,
        source_assertion: 'body_mention',
        occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
      }
    }),
    original({ candidate_type: 'cve', normalized_value: 'CVE-2026-0001', is_ioc: false, review_status: 'pending' })
  ]);
  assert.deepEqual([p.total, p.reviewed, p.pending], [3, 3, 0]);
});

test('9. ignored / rejected are completed decisions; rejected non-Indicators stay out', () => {
  const p = summarizeReviewProgress([
    original({ review_status: 'ignored' }),
    original({ review_status: 'rejected' }),
    original({ review_status: 'created_ioc' }),
    original({ review_status: 'context_only', assessment: 'context_only', match_state: 'context_only' }),
    original({ candidate_type: 'attack_technique', normalized_value: 'T1059', is_ioc: false, review_status: 'rejected' })
  ]);
  assert.deepEqual([p.total, p.reviewed, p.pending], [3, 3, 0]);
});

test('10. ready report: every effective Indicator decided → pending 0, reviewed == total', () => {
  const p = summarizeReviewProgress([
    ...many(68, () => original()),
    ...many(2, () => original({ sources: [ACCEPTED] })),
    ...many(3148, () => linkedOnly([ACCEPTED]))
  ]);
  assert.equal(p.total, 3218);
  assert.equal(p.reviewed, 3218);
  assert.equal(p.pending, 0);
  assert.equal(p.original.total, 70);
  assert.equal(p.linked_only.total, 3148);
  assert.equal(p.overlap, 2);
});

test('11. partial per-IOC decisions inside one accepted source: only decided rows count', () => {
  const p = summarizeReviewProgress([
    ...many(10, () => linkedOnly([ACCEPTED])),
    ...many(5, () => linkedOnly([ACCEPTED], { review_status: 'pending' }))
  ]);
  assert.deepEqual([p.total, p.reviewed, p.pending], [15, 10, 5]);
});

test('invariant 0 ≤ reviewed ≤ total and pending = total − reviewed', () => {
  const p = summarizeReviewProgress([
    ...many(4, () => original({ review_status: 'pending' })),
    ...many(6, () => linkedOnly([NOT_ACCEPTED]))
  ]);
  assert.ok(p.reviewed >= 0 && p.reviewed <= p.total);
  assert.equal(p.pending, p.total - p.reviewed);
  assert.equal(p.original.pending + p.linked_only.pending, p.pending);
});

test('Needs Review selection tab = union Indicator ∧ review pending (same set as progress pending)', () => {
  const decidedLowConfidence = original({ review_status: 'approved', match_state: 'needs_review', assessment: 'unknown' });
  const pending = original({ review_status: 'pending', match_state: 'needs_review', assessment: 'unknown' });
  const contextPending = original({ review_status: 'pending', assessment: 'context_only', match_state: 'context_only' });
  assert.equal(matchSelectionTab(decidedLowConfidence, 'needs_review'), false);
  assert.equal(matchSelectionTab(pending, 'needs_review'), true);
  assert.equal(matchSelectionTab(contextPending, 'needs_review'), false);
  const rows = [decidedLowConfidence, pending, contextPending, linkedOnly([ACCEPTED], { review_status: 'pending' })];
  const tabCount = rows.filter((r) => matchSelectionTab(r, 'needs_review')).length;
  assert.equal(tabCount, summarizeReviewProgress(rows).pending);
});

test('SQL contract: union scope from the canonical membership generators, accepted = approved_at, grouped by identity', () => {
  const sql = reviewProgressSql();
  assert.match(sql, /has_original_document_occurrence = true/);
  assert.match(sql, /threat_report_candidate_source_links/);
  assert.match(sql, /s\.approved_at IS NOT NULL/);
  assert.match(sql, /WHERE is_original OR is_linked/);
  assert.match(sql, /GROUP BY candidate_type, normalized_value/);
  assert.match(sql, /bool_or\(decided AND \(is_original OR accepted_source\)\) AS reviewed/);
  assert.doesNotMatch(sql, /ioc_items/, 'never touches the global IOC table');
  assert.doesNotMatch(sql, /matched_ioc_id/, 'a global match is not a review decision');
});

test('report detail / status responses carry review_progress from attachReportCounts', () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const storeSrc = readFileSync(path.join(here, 'store.js'), 'utf8');
  const routeSrc = readFileSync(path.join(here, '../../routes/threatLibrary.js'), 'utf8');
  assert.match(storeSrc, /const review_progress = await loadReportReviewProgress\(pool, report\.id\);/);
  assert.match(routeSrc, /review_progress: row\.review_progress \?\? null/);
});
