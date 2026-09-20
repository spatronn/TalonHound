import test from 'node:test';
import assert from 'node:assert/strict';
import { planPublicationDateBackfill } from '../../scripts/backfill-threat-library-published-at.js';

const HTML = `<script type="application/ld+json">{"@type":"Article","datePublished":"2026-09-15T15:00:19+00:00"}</script>`;
const pdfDoc = (text) => ({ title: 'T', blocks: [{ id: 'p1-b01', type: 'paragraph', text, page: 1 }], meta: { adapter: 'pdf' } });

test('backfill plan: NULL + retained HTML metadata → update with exact provenance; populated rows are never touched', () => {
  const plan = planPublicationDateBackfill({ id: 15, source_type: 'url', source_url: 'https://x.example/a', published_at: null, canonical_document: null }, { html: HTML, htmlOrigin: 'retained HTML' });
  assert.equal(plan.decision, 'update');
  assert.equal(plan.fields.published_at, '2026-09-15T15:00:19.000Z');
  assert.equal(plan.fields.published_at_source, 'json_ld');
  assert.equal(plan.fields.published_at_precision, 'datetime');
  assert.equal(plan.reason, 'json_ld (retained HTML)');

  const populated = planPublicationDateBackfill({ id: 1, source_type: 'url', published_at: new Date('2026-01-01Z'), published_at_source: 'thib' }, { html: HTML });
  assert.equal(populated.decision, 'skip_populated');
  assert.equal(populated.detection, null);
});

test('backfill plan: PDF uses the stored canonical document only; no safe date → skip with reason, never created_at / file name', () => {
  const ok = planPublicationDateBackfill({ id: 10, source_type: 'pdf', source_file_name: 'cta-nk-2026-0121.pdf', published_at: null, created_at: new Date('2026-09-13Z'), canonical_document: pdfDoc('CYBER THREAT ANALYSIS January 21, 2026') }, { html: null });
  assert.equal(ok.decision, 'update');
  assert.equal(ok.fields.published_at, '2026-01-21T00:00:00.000Z');
  assert.equal(ok.fields.published_at_source, 'pdf_visible_date');
  assert.equal(ok.fields.published_at_precision, 'date');

  const none = planPublicationDateBackfill({ id: 11, source_type: 'pdf', source_file_name: 'report-2026-09-01.pdf', published_at: null, created_at: new Date('2026-09-13Z'), canonical_document: pdfDoc('Quarterly landscape, no dates.') }, { html: null });
  assert.equal(none.decision, 'skip');
  assert.equal(none.reason, 'no_date_in_front_matter');
  assert.equal(none.fields, undefined);
});

test('backfill plan: URL without HTML falls back to the canonical document; THIB bundles are skipped', () => {
  const doc = { title: 'T', blocks: [{ id: 'b001', type: 'paragraph', text: 'Sep 14, 2026' }], meta: { adapter: 'generic_html' } };
  const viaDoc = planPublicationDateBackfill({ id: 1, source_type: 'url', source_url: 'https://x.example/2026/08/24/p', published_at: null, canonical_document: doc }, { html: null, htmlOrigin: null });
  assert.equal(viaDoc.decision, 'update');
  assert.equal(viaDoc.fields.published_at_source, 'visible_date');
  assert.equal(viaDoc.reason, 'visible_date (canonical document)');
  const thib = planPublicationDateBackfill({ id: 2, source_type: 'thib', published_at: null }, { html: null });
  assert.equal(thib.decision, 'skip');
});
