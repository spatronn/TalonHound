/**
 * IOC Details "First / Last seen in source" for Threat Library evidence.
 * Regression: prod IOC 120.36.250.48 (only source Threat_Library) showed the
 * Create IOCs moment (2026-10-09 16:51) as its source observation; the report
 * row says the publisher observed it on 2023-05-25.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadThreatLibraryObservationClaims,
  resolveSourceObservationTimestamps,
  resolveThreatLibraryObservationWindow
} from './iocSourceObservationTimestamps.js';

const here = path.dirname(fileURLToPath(import.meta.url));

const IMPORT = '2026-10-09T16:51:33.814Z';
const tlItem = { id: 3603887, source_name: 'Threat_Library', item_first_seen_at: IMPORT, item_last_seen_at: IMPORT, created_at: IMPORT };
const claim = (obs, published = '2026-10-08T00:00:00.000Z') => ({
  matched_ioc_id: 3603887,
  source_observation: obs,
  report_public_id: 'bc112cbf',
  report_title: 'Advisory',
  published_at: published
});

test('publisher observation replaces the Threat Library import time as source observation', () => {
  const window = resolveThreatLibraryObservationWindow([claim({ earliest: '2023-05-25', latest: '2023-05-25', first_seen: '2023-05-25', last_seen: '2023-05-25' })]);
  const out = resolveSourceObservationTimestamps({ membershipRows: [], itemRows: [tlItem], window });
  assert.equal(out.first_seen_at, '2023-05-25T00:00:00.000Z');
  assert.equal(out.last_seen_in_source, '2023-05-25T00:00:00.000Z');
  assert.equal(out.first_seen_provenance.basis, 'publisher_observation');
  assert.equal(out.first_seen_provenance.precision, 'date');
  assert.equal(out.first_seen_provenance.report_id, 'bc112cbf');
});

test('no publisher date: the report publication day, never the import time', () => {
  const window = resolveThreatLibraryObservationWindow([claim(null)]);
  const out = resolveSourceObservationTimestamps({ membershipRows: [], itemRows: [tlItem], window });
  assert.equal(out.first_seen_at, '2026-10-08T00:00:00.000Z');
  assert.equal(out.first_seen_provenance.basis, 'report_publication');
});

test('feed dates keep precedence rules; a report-side date only joins the min / max', () => {
  const memberships = [{ first_seen_in_feed: '2024-01-10T00:00:00Z', last_seen_in_feed: '2026-09-01T00:00:00Z' }];
  const window = resolveThreatLibraryObservationWindow([claim({ earliest: '2023-05-25', latest: '2023-06-01' })]);
  const out = resolveSourceObservationTimestamps({ membershipRows: memberships, itemRows: [tlItem], window });
  assert.equal(out.first_seen_at, '2023-05-25T00:00:00.000Z', 'publisher observed earlier than the feed');
  assert.equal(out.first_seen_provenance.basis, 'publisher_observation');
  assert.equal(out.last_seen_in_source, '2026-09-01T00:00:00Z', 'the feed saw it more recently');
  assert.equal(out.last_seen_provenance, null);
  // Unlabelled window: no first/last naming needed, earliest/latest used.
  assert.equal(window.first.date, '2023-05-25');
  assert.equal(window.last.date, '2023-06-01');
});

test('no Threat Library claim: behaviour identical to the previous aggregate', () => {
  const manual = { source_name: 'Analyst_Notes', item_first_seen_at: '2026-01-02T10:00:00Z', item_last_seen_at: '2026-01-03T10:00:00Z', created_at: '2026-01-02T10:00:00Z' };
  assert.deepEqual(resolveSourceObservationTimestamps({ membershipRows: [], itemRows: [manual], window: null }), {
    first_seen_at: '2026-01-02T10:00:00Z',
    last_seen_in_source: '2026-01-03T10:00:00Z',
    first_seen_provenance: null,
    last_seen_provenance: null
  });
  const feed = [{ first_seen_in_feed: '2025-05-01T00:00:00Z', last_seen_in_feed: '2025-06-01T00:00:00Z' }];
  const out = resolveSourceObservationTimestamps({ membershipRows: feed, itemRows: [manual], window: null });
  assert.equal(out.first_seen_at, '2025-05-01T00:00:00Z');
  assert.equal(out.last_seen_in_source, '2025-06-01T00:00:00Z');
  // A Threat_Library row without any eligible claim keeps its stored time (nothing better known).
  const lone = resolveSourceObservationTimestamps({ membershipRows: [], itemRows: [tlItem], window: null });
  assert.equal(lone.first_seen_at, IMPORT);
});

test('a manual source next to Threat Library keeps its own observation', () => {
  const manual = { source_name: 'Analyst_Notes', item_first_seen_at: '2022-01-01T00:00:00Z', item_last_seen_at: '2026-10-09T18:00:00Z', created_at: '2022-01-01T00:00:00Z' };
  const window = resolveThreatLibraryObservationWindow([claim({ earliest: '2023-05-25', latest: '2023-05-25' })]);
  const out = resolveSourceObservationTimestamps({ membershipRows: [], itemRows: [tlItem, manual], window });
  assert.equal(out.first_seen_at, '2022-01-01T00:00:00Z');
  assert.equal(out.first_seen_provenance, null);
  assert.equal(out.last_seen_in_source, '2026-10-09T18:00:00Z');
});

test('claims query: one bounded query, approved malicious/suspicious claims of visible reports only', async () => {
  const calls = [];
  const pool = { query: async (sql, params) => { calls.push({ sql, params }); return { rows: [] }; } };
  assert.deepEqual(await loadThreatLibraryObservationClaims(pool, []), []);
  assert.equal(calls.length, 0);
  await loadThreatLibraryObservationClaims(pool, [5, '5', 7]);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].params, [[5, 7]]);
  assert.match(calls[0].sql, /c\.matched_ioc_id = ANY\(\$1::bigint\[\]\)/);
  assert.match(calls[0].sql, /r\.deleted_at IS NULL/);
  assert.match(calls[0].sql, /review_status IN \('approved', 'created_ioc'\)/);
});

test('IOC details route uses the shared resolver for First / Last seen in source', () => {
  const src = fs.readFileSync(path.resolve(here, '..', '..', 'server.js'), 'utf8');
  assert.match(src, /resolveSourceObservationTimestamps\(\{/);
  assert.match(src, /first_seen_provenance: sourceObservation\.first_seen_provenance/);
});
