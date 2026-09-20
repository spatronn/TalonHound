import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReportDetails, buildSourceDetails } from './reportOverview.js';
import { formatPublicationDate, publicationDay, publicationDateTitle } from './publicationDate.js';
import { formatCalendarDate } from '../../lib/formatDate.js';

// Infoblox acceptance shape as the API returns it: the middleware rewrote the
// instant into the system timezone (+03:00); published_date is the day the
// source stated; created_at (Imported) is the ingestion instant.
const infoblox = {
  id: 'r15',
  title: 'Illegal Gambling Sites Reveal Three Types of Cybercrime',
  source_type: 'url',
  source_name: 'www.infoblox.com',
  published_at: '2026-09-15T18:00:19+03:00',
  published_date: '2026-09-15',
  published_at_precision: 'datetime',
  published_at_source: 'json_ld',
  language: 'en-us',
  analysis_status: 'ready',
  created_at: '2026-09-16T00:30:21+03:00'
};

const fmt = (v) => `fmt(${v})`;

test('UI 22: Published shown as the stated calendar day (DD/MM/YYYY) with provenance tooltip, ordered before Imported', () => {
  const items = buildReportDetails(infoblox, { formatDateTime: fmt });
  const labels = items.map((i) => i.label);
  assert.deepEqual(labels, ['Source', 'Language', 'Published', 'Imported', 'Status']);
  const published = items.find((i) => i.label === 'Published');
  assert.equal(published.value, '15/09/2026');
  assert.match(published.title, /^Publication date of the original source, from the page metadata \(JSON-LD datePublished\)$/);
  // Source tab shows the same value the same way.
  const source = buildSourceDetails(infoblox, { formatDateTime: fmt }).find((i) => i.label === 'Published');
  assert.equal(source.value, '15/09/2026');
});

test('UI 23: omitted entirely when unknown — never "Published: —"', () => {
  const unknown = { ...infoblox, published_at: null, published_date: null, published_at_precision: null, published_at_source: null };
  const items = buildReportDetails(unknown, { formatDateTime: fmt });
  assert.ok(!items.map((i) => i.label).includes('Published'));
  assert.ok(items.every((i) => i.value !== '—' && i.value !== '' && i.value !== 'null'));
  assert.equal(formatPublicationDate(unknown), null);
  assert.equal(publicationDateTitle(unknown), null);
  assert.ok(!buildSourceDetails(unknown, { formatDateTime: fmt }).map((i) => i.label).includes('Published'));
});

test('UI 24: Imported is formatted independently as an instant and is unaffected by the publication date', () => {
  const items = buildReportDetails(infoblox, { formatDateTime: fmt });
  assert.equal(items.find((i) => i.label === 'Imported').value, 'fmt(2026-09-16T00:30:21+03:00)');
  const withoutPublished = buildReportDetails({ ...infoblox, published_at: null, published_date: null }, { formatDateTime: fmt });
  assert.equal(withoutPublished.find((i) => i.label === 'Imported').value, 'fmt(2026-09-16T00:30:21+03:00)');
});

test('UI 25: date-only precision never shows a fake midnight, and no timezone shifts the day', () => {
  const dateOnly = {
    ...infoblox,
    // API instant for a date-only value, rewritten to the system timezone by the backend.
    published_at: '2026-09-15T03:00:00+03:00',
    published_date: '2026-09-15',
    published_at_precision: 'date',
    published_at_source: 'pdf_visible_date'
  };
  const value = buildReportDetails(dateOnly, { formatDateTime: fmt }).find((i) => i.label === 'Published').value;
  assert.equal(value, '15/09/2026');
  assert.doesNotMatch(value, /00:00|03:00/);
  // A late-evening instant in a negative-offset zone: the day the source stated wins.
  const late = { published_at: '2026-09-16T06:30:00+03:00', published_date: '2026-09-15', published_at_precision: 'datetime' };
  assert.equal(formatPublicationDate(late), '15/09/2026');
  // Legacy payload without published_date falls back to the instant's UTC day.
  assert.equal(publicationDay({ published_at: '2026-09-10T00:00:00.000Z' }), '2026-09-10');
  assert.equal(publicationDay({ published_at: 'garbage' }), null);
});

test('formatCalendarDate formats a plain day and rejects instants / junk', () => {
  assert.equal(formatCalendarDate('2026-09-15'), '15/09/2026');
  assert.equal(formatCalendarDate('2026-09-15T00:00:00Z'), '');
  assert.equal(formatCalendarDate(null), '');
  assert.equal(formatCalendarDate(''), '');
});
