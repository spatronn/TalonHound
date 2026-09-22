import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeReportTags,
  reportTagPickerParams,
  mergeReportPayload,
  REPORT_TAG_PICKER_LIMIT
} from './reportTags.js';

test('normalizeReportTags de-duplicates by id, drops invalid rows, sorts by name', () => {
  assert.deepEqual(
    normalizeReportTags([
      { id: 7, name: 'winpot', type: 'threat' },
      { id: 3, name: 'atm' },
      { id: 7, name: 'winpot' },
      { id: 0, name: 'bad' },
      { id: 9, name: '  ' },
      null
    ]),
    [
      { id: 3, name: 'atm', type: null },
      { id: 7, name: 'winpot', type: 'threat' }
    ]
  );
  assert.deepEqual(normalizeReportTags(undefined), []);
});

test('picker excludes tags already on the report and only asks for active tags', () => {
  assert.deepEqual(reportTagPickerParams([{ id: 7, name: 'winpot' }, { id: 3, name: 'atm' }], '  fin '), {
    active: true,
    limit: REPORT_TAG_PICKER_LIMIT,
    q: 'fin',
    exclude_ids: '3,7'
  });
  assert.deepEqual(reportTagPickerParams([], ''), { active: true, limit: REPORT_TAG_PICKER_LIMIT });
});

test('mergeReportPayload keeps tags when a response omits them, takes them when present', () => {
  const prev = { id: 'r', tags: [{ id: 1, name: 'atm' }] };
  assert.deepEqual(mergeReportPayload(prev, { id: 'r', title: 'x' }).tags, [{ id: 1, name: 'atm' }]);
  assert.deepEqual(mergeReportPayload(prev, { id: 'r', tags: [] }).tags, []);
  assert.equal(mergeReportPayload({ id: 'r' }, { id: 'r' }).tags, undefined);
  assert.equal(mergeReportPayload(prev, null), null);
});
