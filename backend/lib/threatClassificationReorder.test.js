import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  planThreatClassificationReorder,
  sortThreatClassificationsForDisplay,
  threatClassificationOrderSnapshot,
  THREAT_CLASSIFICATION_SORT_STEP
} from './threatClassificationReorder.js';

const UNKNOWN = {
  id: '00000000-0000-4000-8000-000000000001',
  slug: 'unknown',
  name: 'Unknown',
  active: true,
  sort_order: 0
};
const MALWARE = {
  id: '00000000-0000-4000-8000-000000000002',
  slug: 'malware',
  name: 'Malware',
  active: true,
  sort_order: 10
};
const PHISHING = {
  id: '00000000-0000-4000-8000-000000000003',
  slug: 'phishing',
  name: 'Phishing',
  active: true,
  sort_order: 20
};
const UNUSED = {
  id: '00000000-0000-4000-8000-000000000004',
  slug: 'unused',
  name: 'Unused',
  active: false,
  sort_order: 30
};

describe('planThreatClassificationReorder', () => {
  it('assigns deterministic unique orders and forces Unknown first', () => {
    const planned = planThreatClassificationReorder(
      [UNKNOWN, MALWARE, PHISHING, UNUSED],
      [PHISHING.id, MALWARE.id, UNKNOWN.id, UNUSED.id]
    );
    assert.equal(planned.ok, true);
    assert.deepEqual(planned.assignments, [
      { id: UNKNOWN.id, sort_order: 0 },
      { id: PHISHING.id, sort_order: 10 },
      { id: MALWARE.id, sort_order: 20 },
      { id: UNUSED.id, sort_order: 30 }
    ]);
    assert.equal(THREAT_CLASSIFICATION_SORT_STEP, 10);
  });

  it('places inactive after active while keeping relative order', () => {
    const planned = planThreatClassificationReorder(
      [UNKNOWN, MALWARE, PHISHING, UNUSED],
      [UNKNOWN.id, UNUSED.id, PHISHING.id, MALWARE.id]
    );
    assert.equal(planned.ok, true);
    assert.deepEqual(
      planned.assignments.map((a) => a.id),
      [UNKNOWN.id, PHISHING.id, MALWARE.id, UNUSED.id]
    );
  });

  it('rejects duplicate ids', () => {
    const planned = planThreatClassificationReorder(
      [UNKNOWN, MALWARE],
      [UNKNOWN.id, MALWARE.id, MALWARE.id]
    );
    assert.equal(planned.ok, false);
    assert.equal(planned.status, 400);
    assert.match(planned.error, /duplicate/i);
  });

  it('rejects missing ids', () => {
    const planned = planThreatClassificationReorder(
      [UNKNOWN, MALWARE, PHISHING],
      [UNKNOWN.id, MALWARE.id]
    );
    assert.equal(planned.ok, false);
    assert.equal(planned.status, 400);
    assert.match(planned.error, /every classification/i);
  });

  it('rejects unknown ids', () => {
    const planned = planThreatClassificationReorder(
      [UNKNOWN, MALWARE],
      [UNKNOWN.id, MALWARE.id, '00000000-0000-4000-8000-000000000099']
    );
    assert.equal(planned.ok, false);
    assert.equal(planned.status, 400);
    assert.match(planned.error, /unknown id/i);
  });

  it('rejects non-array payloads', () => {
    const planned = planThreatClassificationReorder([UNKNOWN], null);
    assert.equal(planned.ok, false);
    assert.equal(planned.status, 400);
  });
});

describe('sortThreatClassificationsForDisplay', () => {
  it('keeps Unknown first and inactive after active', () => {
    const sorted = sortThreatClassificationsForDisplay([
      { ...UNUSED, sort_order: 5 },
      { ...PHISHING, sort_order: 40 },
      { ...MALWARE, sort_order: 30 },
      { ...UNKNOWN, sort_order: 99 }
    ]);
    assert.deepEqual(
      sorted.map((r) => r.slug),
      ['unknown', 'malware', 'phishing', 'unused']
    );
  });
});

describe('threatClassificationOrderSnapshot', () => {
  it('returns compact id/order pairs in display order', () => {
    assert.deepEqual(
      threatClassificationOrderSnapshot([PHISHING, UNKNOWN, MALWARE]),
      [
        { id: UNKNOWN.id, sort_order: 0 },
        { id: MALWARE.id, sort_order: 10 },
        { id: PHISHING.id, sort_order: 20 }
      ]
    );
  });
});
