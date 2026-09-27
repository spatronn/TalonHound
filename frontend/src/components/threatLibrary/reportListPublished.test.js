/**
 * Threat Library list Published column: same publication-date helper as
 * report detail, never falls back to Imported (created_at).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { formatPublicationDate } from './publicationDate.js';
import { formatUserDateTime } from '../../lib/formatDate.js';

const published = {
  published_at: '2026-09-15T18:00:19+03:00',
  published_date: '2026-09-15',
  published_at_precision: 'datetime',
  published_at_source: 'json_ld',
  created_at: '2026-09-16T00:30:21+03:00'
};

test('Published renders the source calendar day when publication date exists', () => {
  assert.equal(formatPublicationDate(published), '15/09/2026');
});

test('missing publication date is a neutral placeholder and never uses Imported', () => {
  const missing = { ...published, published_at: null, published_date: null };
  assert.equal(formatPublicationDate(missing), null);
  assert.equal(formatPublicationDate(missing) || '—', '—');
  assert.notEqual(formatPublicationDate(missing) || '—', formatUserDateTime(missing.created_at));
});

test('Imported stays independent from Published', () => {
  assert.equal(formatPublicationDate(published), '15/09/2026');
  assert.notEqual(formatPublicationDate(published), published.created_at);
  const imported = formatUserDateTime(published.created_at);
  assert.ok(imported);
  assert.notEqual(imported, formatPublicationDate(published));
});
