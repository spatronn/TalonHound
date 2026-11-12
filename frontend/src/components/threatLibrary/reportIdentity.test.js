import test from 'node:test';
import assert from 'node:assert/strict';
import { primaryReportHref, supersededVariants } from './reportIdentity.js';

test('a superseded report links to its primary; a primary does not', () => {
  assert.equal(primaryReportHref({ superseded_by: { report_id: 'p-1' } }), '/threat-intelligence/threat-library/p-1');
  assert.equal(primaryReportHref({ superseded_by: null }), null);
  assert.equal(primaryReportHref(null), null);
});

test('only superseded variants are listed under the primary', () => {
  const report = {
    source_variants: [
      { report_id: 'p-1', relation: 'primary', source_url: 'https://securelist.com/cyberstrikeai-attacks/121715/' },
      { report_id: 's-1', relation: 'superseded', source_url: 'https://securelist.com/tr/cyberstrikeai-attacks/121715/' },
      { relation: 'superseded' }
    ]
  };
  assert.deepEqual(supersededVariants(report).map((v) => v.report_id), ['s-1']);
  assert.deepEqual(supersededVariants({}), []);
});
