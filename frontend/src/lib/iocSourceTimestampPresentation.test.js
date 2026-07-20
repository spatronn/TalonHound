import test from 'node:test';
import assert from 'node:assert/strict';
import { IOC_SOURCE_TIMESTAMP_PRESENTATION } from './iocSourceTimestampPresentation.js';

test('defines exact source timestamp labels', () => {
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.first.label, 'First seen in source');
  assert.equal(IOC_SOURCE_TIMESTAMP_PRESENTATION.last.label, 'Last changed in source');
});

test('first-seen tooltip describes TalonHound source observation', () => {
  assert.match(
    IOC_SOURCE_TIMESTAMP_PRESENTATION.first.tooltip,
    /TalonHound first observed this IOC in this source/i
  );
});

test('last-changed tooltip promises unchanged re-imports do not move the date', () => {
  const tooltip = IOC_SOURCE_TIMESTAMP_PRESENTATION.last.tooltip;
  assert.match(tooltip, /actually changed/i);
  assert.match(tooltip, /unchanged does not move this date/i);
});

test('no analyst-facing label reintroduces presence/confirmation semantics', () => {
  // "Last confirmed in source" was backed by last_seen_in_feed, which advanced on every
  // poll. Reintroducing that wording would re-create the exact bug this work fixed.
  for (const entry of Object.values(IOC_SOURCE_TIMESTAMP_PRESENTATION)) {
    assert.equal(/confirmed/i.test(entry.label), false, `label must not claim confirmation: ${entry.label}`);
    assert.equal(/still present/i.test(entry.tooltip), false,
      'per-IOC tooltips must not describe feed presence; that belongs at feed/run level');
  }
});
