import test from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeTaxiiCursor,
  decodeTaxiiCursor,
  parseTaxiiLimit,
  pageTaxiiObjects,
  parseStixBundleObjects,
  taxiiAcceptOk,
  isValidTaxiiCollectionId,
  TAXII_OBJECTS_MAX_LIMIT,
  TAXII_OBJECTS_DEFAULT_LIMIT
} from './taxii21.js';
import { StixBundleWriter, indicatorFromPublishedItem } from './publishedFeedStix.js';

test('collection id rejects path traversal', () => {
  assert.equal(isValidTaxiiCollectionId('temp-stix-p5'), true);
  assert.equal(isValidTaxiiCollectionId('../etc/passwd'), false);
  assert.equal(isValidTaxiiCollectionId('a/b'), false);
  assert.equal(isValidTaxiiCollectionId(''), false);
});

test('cursor round-trips offset', () => {
  const c = encodeTaxiiCursor(250);
  assert.equal(decodeTaxiiCursor(c).offset, 250);
  assert.equal(decodeTaxiiCursor('').offset, 0);
  assert.equal(decodeTaxiiCursor('%%%').ok, false);
});

test('limit defaults and caps', () => {
  assert.equal(parseTaxiiLimit(undefined).value, TAXII_OBJECTS_DEFAULT_LIMIT);
  assert.equal(parseTaxiiLimit('5').value, 5);
  assert.equal(parseTaxiiLimit(String(TAXII_OBJECTS_MAX_LIMIT + 50)).value, TAXII_OBJECTS_MAX_LIMIT);
  assert.equal(parseTaxiiLimit('0').ok, false);
  assert.equal(parseTaxiiLimit('-1').ok, false);
});

test('pageTaxiiObjects paginates without putting secrets in next', () => {
  const objects = Array.from({ length: 5 }, (_, i) => ({ id: `indicator--${i}` }));
  const first = pageTaxiiObjects(objects, { limit: 2 });
  assert.equal(first.ok, true);
  assert.equal(first.envelope.objects.length, 2);
  assert.equal(first.envelope.more, true);
  assert.ok(first.envelope.next);
  assert.doesNotMatch(first.envelope.next, /api_key|Bearer|th_pf_/);

  const second = pageTaxiiObjects(objects, { limit: 2, next: first.envelope.next });
  assert.deepEqual(second.envelope.objects.map((o) => o.id), ['indicator--2', 'indicator--3']);
  const last = pageTaxiiObjects(objects, { limit: 2, next: second.envelope.next });
  assert.equal(last.envelope.more, false);
  assert.equal(last.envelope.next, undefined);
  assert.equal(last.envelope.objects.length, 1);
});

test('parseStixBundleObjects requires a STIX 2.1 Bundle', () => {
  const w = new StixBundleWriter({ slug: 'unit' });
  const item = indicatorFromPublishedItem({
    type: 'ip',
    value: '192.0.2.1',
    timestamps: { imported_at: '2026-08-01T00:00:00.000Z' }
  });
  w.addIndicator(item);
  const { content } = w.finish();
  const objects = parseStixBundleObjects(content);
  assert.equal(objects.length, 1);
  assert.equal(objects[0].type, 'indicator');
  assert.equal(objects[0].pattern, "[ipv4-addr:value = '192.0.2.1']");
  assert.throws(() => parseStixBundleObjects('{"type":"not-a-bundle","objects":[]}'), /STIX 2\.1 Bundle/);
});

test('taxiiAcceptOk allows missing, taxii, stix, and json', () => {
  assert.equal(taxiiAcceptOk({ headers: {} }), true);
  assert.equal(taxiiAcceptOk({ headers: { accept: 'application/taxii+json;version=2.1' } }), true);
  assert.equal(taxiiAcceptOk({ headers: { accept: 'application/stix+json;version=2.1' } }), true);
  assert.equal(taxiiAcceptOk({ headers: { accept: 'text/html' } }), false);
});
