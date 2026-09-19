import test from 'node:test';
import assert from 'node:assert/strict';
import { IOC_SOURCE_TIMESTAMP_PRESENTATION } from './iocSourceTimestampPresentation.js';

test('frontend source presentation exposes Inserted / First seen / Last seen only', () => {
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.lastSeen.label, 'Last seen in source');
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.imported.label, 'Inserted into Platform');
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.first.label, 'First seen in source');
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.last, undefined);
  assert.match(IOC_SOURCE_TIMESTAMP_PRESENTATION.first.tooltip, /earliest known source observation/i);
  assert.match(IOC_SOURCE_TIMESTAMP_PRESENTATION.lastSeen.tooltip, /most recent source observation/i);
  assert.match(IOC_SOURCE_TIMESTAMP_PRESENTATION.imported.tooltip, /does not change on re-import/i);
  const blob = JSON.stringify(IOC_SOURCE_TIMESTAMP_PRESENTATION);
  assert.equal(blob.includes('last_seen_in_feed'), false);
  assert.equal(blob.includes('Last changed in source'), false);
});
