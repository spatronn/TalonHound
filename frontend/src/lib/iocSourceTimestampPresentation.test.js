import test from 'node:test';
import assert from 'node:assert/strict';
import { IOC_SOURCE_TIMESTAMP_PRESENTATION } from './iocSourceTimestampPresentation.js';

test('defines exact source timestamp labels', () => {
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.first.label, 'First seen in source');
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.last.label, 'Last confirmed in source');
});

test('first-seen tooltip describes TalonHound source observation', () => {
  assert.match(
    IOC_SOURCE_TIMESTAMP_PRESENTATION.first.tooltip,
    /TalonHound first observed this IOC in this source/i
  );
});

test('last-confirmed tooltip distinguishes presence from change or re-import', () => {
  const tooltip = IOC_SOURCE_TIMESTAMP_PRESENTATION.last.tooltip;
  assert.match(tooltip, /still present in the source/i);
  assert.match(tooltip, /does not mean the IOC changed/i);
  assert.match(tooltip, /or was re-imported/i);
});
