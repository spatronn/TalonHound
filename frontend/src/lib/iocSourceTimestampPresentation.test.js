import test from 'node:test';
import assert from 'node:assert/strict';
import { IOC_SOURCE_TIMESTAMP_PRESENTATION } from './iocSourceTimestampPresentation.js';

test('frontend last-changed presentation does not use last_seen_in_feed', () => {
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.last.label, 'Last changed in source');
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.imported.label, 'Inserted into Platform');
  assert.match(IOC_SOURCE_TIMESTAMP_PRESENTATION.first.tooltip, /observed in this source/i);
  assert.match(IOC_SOURCE_TIMESTAMP_PRESENTATION.imported.tooltip, /does not change on re-import/i);
  assert.match(IOC_SOURCE_TIMESTAMP_PRESENTATION.last.tooltip, /meaningfully changed/i);
  const blob = JSON.stringify(IOC_SOURCE_TIMESTAMP_PRESENTATION);
  assert.equal(blob.includes('last_seen_in_feed'), false);
});
