import test from 'node:test';
import assert from 'node:assert/strict';
import { isSupersededInto, rankLogicalReportMembers } from './reportSupersession.js';

const row = (id, { created, finalized = true, supersededBy = null } = {}) => ({
  id,
  created_at: new Date(created),
  finalized_at: finalized ? new Date(created) : null,
  superseded_by_report_id: supersededBy
});

test('audit primary: the existing primary wins over an older report already superseded into it (NightEagle shape)', () => {
  // 30311 (older, finalized) was superseded into 34354 (newer, finalized).
  const older = row(30311, { created: '2026-10-18', supersededBy: 34354 });
  const newer = row(34354, { created: '2026-10-28' });
  const ranked = rankLogicalReportMembers([older, newer]);
  assert.deepEqual(ranked.map((r) => r.id), [34354, 30311]);
  assert.equal(isSupersededInto(older, 34354, [older, newer]), true);
});

test('audit primary without supersession: finalized first, then oldest import, then id', () => {
  const ranked = rankLogicalReportMembers([
    row(5, { created: '2026-11-03', finalized: false }),
    row(4, { created: '2026-11-02' }),
    row(3, { created: '2026-11-02' }),
    row(2, { created: '2026-11-01', finalized: false })
  ]);
  assert.deepEqual(ranked.map((r) => r.id), [3, 4, 2, 5]);
});

test('isSupersededInto follows chains inside the group and stops on cycles or foreign primaries', () => {
  const a = row(1, { created: '2026-01-01', supersededBy: 2 });
  const b = row(2, { created: '2026-01-02', supersededBy: 3 });
  const c = row(3, { created: '2026-01-03' });
  assert.equal(isSupersededInto(a, 3, [a, b, c]), true);
  assert.equal(isSupersededInto(c, 3, [a, b, c]), false);
  assert.equal(isSupersededInto(a, 99, [a, b, c]), false);
  const x = row(7, { created: '2026-01-01', supersededBy: 8 });
  const y = row(8, { created: '2026-01-01', supersededBy: 7 });
  assert.equal(isSupersededInto(x, 9, [x, y]), false);
});
