import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IOC_LIST_TIMESTAMP_PRESENTATION,
  resolveIocListTimestamp
} from './iocListTimestampPresentation.js';
import { formatUserDateTime } from './formatDate.js';

test('IOC List column label is Timestamp', () => {
  assert.equal(IOC_LIST_TIMESTAMP_PRESENTATION.label, 'Timestamp');
  assert.equal(IOC_LIST_TIMESTAMP_PRESENTATION.apiField, 'imported_at');
});

test('frontend resolves imported_at / created_at only — no source-change fallback', () => {
  assert.equal(
    resolveIocListTimestamp({
      imported_at: '2026-07-26T10:00:00.000Z',
      last_changed_in_source: '2026-07-26T12:00:00.000Z',
      last_seen_at: '2026-07-26T12:00:00.000Z',
      last_seen_in_feed: '2026-07-26T13:00:00.000Z'
    }),
    '2026-07-26T10:00:00.000Z'
  );
  assert.equal(
    resolveIocListTimestamp({
      created_at: '2026-07-26T10:00:00.000Z',
      last_changed_in_source: '2026-07-26T12:00:00.000Z'
    }),
    '2026-07-26T10:00:00.000Z'
  );
  assert.equal(
    resolveIocListTimestamp({
      last_changed_in_source: '2026-07-26T12:00:00.000Z',
      last_seen_in_feed: '2026-07-26T13:00:00.000Z'
    }),
    null
  );
});

test('browser timezone does not change formatted Timestamp', () => {
  const iso = '2026-07-26T10:00:00.000Z';
  assert.equal(formatUserDateTime(iso, 'UTC'), '26/07/2026, 10:00:00');
  assert.equal(formatUserDateTime(iso, 'Europe/Istanbul'), '26/07/2026, 13:00:00');
  assert.equal(formatUserDateTime(iso, 'Europe/London'), '26/07/2026, 11:00:00');
});
