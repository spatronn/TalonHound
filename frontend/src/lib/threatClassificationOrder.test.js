import test from 'node:test';
import assert from 'node:assert/strict';
import {
  THREAT_CLASSIFICATION_MANAGER_COLUMNS,
  applyThreatClassificationReorder,
  buildThreatClassificationReorderPayload,
  isThreatClassificationRowLocked,
  mergeThreatClassificationPickerOptions,
  mergeVisibleThreatClassificationOrder,
  normalizeThreatClassificationDragOrder,
  sortThreatClassificationsForDisplay
} from './threatClassificationOrder.js';

const UNKNOWN = { id: 'u', slug: 'unknown', name: 'Unknown', active: true, sort_order: 0 };
const MALWARE = { id: 'm', slug: 'malware', name: 'Malware', active: true, sort_order: 10 };
const PHISHING = { id: 'p', slug: 'phishing', name: 'Phishing', active: true, sort_order: 20 };
const UNUSED = { id: 'x', slug: 'unused', name: 'Unused', active: false, sort_order: 30 };

test('manager columns omit visible Order field', () => {
  assert.ok(!THREAT_CLASSIFICATION_MANAGER_COLUMNS.includes('order'));
  assert.ok(THREAT_CLASSIFICATION_MANAGER_COLUMNS.includes('handle'));
});

test('Unknown row is locked', () => {
  assert.equal(isThreatClassificationRowLocked(UNKNOWN), true);
  assert.equal(isThreatClassificationRowLocked(MALWARE), false);
});

test('sortThreatClassificationsForDisplay puts inactive after active', () => {
  const sorted = sortThreatClassificationsForDisplay([UNUSED, PHISHING, UNKNOWN, MALWARE]);
  assert.deepEqual(sorted.map((x) => x.slug), ['unknown', 'malware', 'phishing', 'unused']);
});

test('applyThreatClassificationReorder updates order and keeps Unknown first', () => {
  const next = applyThreatClassificationReorder(
    [UNKNOWN, MALWARE, PHISHING, UNUSED],
    PHISHING.id,
    MALWARE.id
  );
  assert.deepEqual(next.map((x) => x.slug), ['unknown', 'phishing', 'malware', 'unused']);
});

test('dragging Unknown is a no-op', () => {
  const next = applyThreatClassificationReorder(
    [UNKNOWN, MALWARE, PHISHING],
    UNKNOWN.id,
    PHISHING.id
  );
  assert.deepEqual(next.map((x) => x.slug), ['unknown', 'malware', 'phishing']);
});

test('normalize moves inactive after active', () => {
  const next = normalizeThreatClassificationDragOrder([UNKNOWN, UNUSED, PHISHING, MALWARE]);
  assert.deepEqual(next.map((x) => x.slug), ['unknown', 'phishing', 'malware', 'unused']);
});

test('mergeVisibleThreatClassificationOrder appends hidden inactives', () => {
  const merged = mergeVisibleThreatClassificationOrder(
    [UNKNOWN, MALWARE, PHISHING, UNUSED],
    [UNKNOWN, PHISHING, MALWARE],
    false
  );
  assert.deepEqual(merged.map((x) => x.slug), ['unknown', 'phishing', 'malware', 'unused']);
  assert.deepEqual(buildThreatClassificationReorderPayload(merged).ordered_ids, [
    UNKNOWN.id,
    PHISHING.id,
    MALWARE.id,
    UNUSED.id
  ]);
});

test('picker merges inactive options after active options', () => {
  const merged = mergeThreatClassificationPickerOptions(
    [
      { value: 'unknown', label: 'Unknown' },
      { value: 'malware', label: 'Malware' }
    ],
    [{ value: 'legacy', label: 'Legacy' }]
  );
  assert.deepEqual(merged.map((x) => x.value), ['unknown', 'malware', 'legacy']);
});
