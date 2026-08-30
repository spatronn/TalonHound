import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  PUBLISHED_FEED_SCHEMA_VERSION,
  toIsoUtc,
  normalizeTimestamps,
  normalizeSourceMetadata,
  normalizeTags,
  normalizeClassification,
  normalizeEnrichment,
  normalizePublishedIoc,
  JsonFeedWriter
} from './publishedFeedJson.js';

const FLAGS_ALL = { includeSourceMetadata: true, includeClassification: true, includeEnrichment: true };

describe('publishedFeedJson normalizers', () => {
  it('schema version is 1.0', () => {
    assert.equal(PUBLISHED_FEED_SCHEMA_VERSION, '1.0');
  });

  it('toIsoUtc coerces Dates and strings, rejects garbage', () => {
    assert.equal(toIsoUtc(new Date('2026-08-09T08:42:31Z')), '2026-08-09T08:42:31.000Z');
    assert.equal(toIsoUtc('2026-08-05T14:22:10Z'), '2026-08-05T14:22:10.000Z');
    assert.equal(toIsoUtc('not-a-date'), null);
    assert.equal(toIsoUtc(null), null);
    assert.equal(toIsoUtc(''), null);
  });

  it('timestamps map only stored fields as ISO-8601 UTC; unavailable omitted', () => {
    const ts = normalizeTimestamps({
      imported_at: new Date('2026-08-07T09:15:22Z'),
      first_seen_in_source: '2026-08-05T14:22:10Z',
      last_confirmed_in_source: null
    });
    assert.deepEqual(ts, {
      imported_at: '2026-08-07T09:15:22.000Z',
      first_seen_in_source: '2026-08-05T14:22:10.000Z'
    });
    assert.equal('last_confirmed_in_source' in ts, false);
  });

  it('sources are deterministic, de-duplicated by feed_key, and never expose ids', () => {
    const sources = normalizeSourceMetadata([
      { feed_key: 'urlhaus', feed_name: 'URLhaus', first_seen_in_source: '2026-08-05T00:00:00Z', last_confirmed_in_source: '2026-08-09T00:00:00Z' },
      { feed_key: 'threatfox', feed_name: 'ThreatFox', first_seen_in_source: '2026-08-01T00:00:00Z' },
      { feed_key: 'threatfox', feed_name: 'ThreatFox (dup)' } // dedup by key
    ]);
    assert.equal(sources.length, 2);
    assert.deepEqual(sources.map((s) => s.feed_key), ['threatfox', 'urlhaus']); // sorted
    assert.equal(JSON.stringify(sources).includes('id'), false);
  });

  it('tags are de-duplicated case-insensitively (canonical spelling kept) and sorted', () => {
    assert.deepEqual(normalizeTags(['C2', 'malware', 'c2', ' malware ', '']), ['C2', 'malware']);
  });

  it('classification omits absent category cleanly and maps effective confidence', () => {
    const c = normalizeClassification({ category: 'malware', confidence: 'high' }, ['c2', 'c2']);
    assert.deepEqual(c, { category: 'malware', confidence: 100, tags: ['c2'] });
    const none = normalizeClassification({ category: null, confidence: null }, []);
    assert.equal(none, null);
  });

  it('enrichment normalizes a safe subset per provider and never leaks raw payloads', () => {
    const enr = normalizeEnrichment({
      virustotal: {
        normalized_summary: {
          stats: { malicious: 12, suspicious: 3, harmless: 48, undetected: 20 },
          last_analysis_date: '2026-08-08T17:20:10Z',
          vendor_results: [{ engine: 'X', result: 'secret' }]
        },
        raw_response: { should: 'not appear' }
      },
      abuseipdb: {
        normalized_summary: { abuseConfidenceScore: 90, countryCode: 'US', usageType: 'Data Center', totalReports: 5, lastReportedAt: '2026-08-08T00:00:00Z' },
        raw_json: { secret: true }
      }
    });
    assert.deepEqual(enr.virustotal, {
      malicious: 12, suspicious: 3, harmless: 48, undetected: 20, last_analysis_at: '2026-08-08T17:20:10.000Z'
    });
    assert.deepEqual(enr.abuseipdb, {
      abuse_confidence_score: 90, country_code: 'US', usage_type: 'Data Center', total_reports: 5, last_reported_at: '2026-08-08T00:00:00.000Z'
    });
    const asText = JSON.stringify(enr);
    assert.equal(asText.includes('secret'), false);
    assert.equal(asText.includes('vendor_results'), false);
    // Deterministic provider ordering (alphabetical).
    assert.deepEqual(Object.keys(enr), ['abuseipdb', 'virustotal']);
  });

  it('normalizePublishedIoc respects include flags', () => {
    const base = { value: 'evil.com', observable_type: 'domain', category: 'malware', confidence: 'high' };
    const meta = { imported_at: '2026-08-07T09:15:22Z', sources: [{ feed_key: 'x', feed_name: 'X' }], tags: ['c2'], enrichment: {} };

    const onlyId = normalizePublishedIoc(base, meta, { includeSourceMetadata: false, includeClassification: false, includeEnrichment: false });
    assert.deepEqual(Object.keys(onlyId).sort(), ['timestamps', 'type', 'value']);

    const withAll = normalizePublishedIoc(base, meta, FLAGS_ALL);
    assert.equal(withAll.type, 'domain');
    assert.equal(withAll.value, 'evil.com');
    assert.equal(Array.isArray(withAll.sources), true);
    assert.equal(withAll.classification.category, 'malware');
  });
});

describe('JsonFeedWriter', () => {
  it('produces valid JSON with schema_version, feed metadata, correct item_count', () => {
    const w = new JsonFeedWriter({ name: 'Malicious Domains', includeSourceMetadata: true, includeClassification: true, includeEnrichment: false });
    w.addItem({ type: 'domain', value: 'a.com', timestamps: {} });
    w.addItem({ type: 'domain', value: 'b.com', timestamps: {} });
    const { content, content_hash, item_count } = w.finish({ generatedAt: '2026-08-09T12:30:00Z' });

    const parsed = JSON.parse(content);
    assert.equal(parsed.schema_version, '1.0');
    assert.equal(parsed.feed.name, 'Malicious Domains');
    assert.equal(parsed.feed.generated_at, '2026-08-09T12:30:00.000Z');
    assert.equal(parsed.feed.item_count, 2);
    assert.equal(item_count, 2);
    assert.equal(parsed.items.length, 2);
    assert.equal(typeof content_hash, 'string');
  });

  it('empty feed is valid JSON with items: []', () => {
    const w = new JsonFeedWriter({ name: 'Empty' });
    const { content, item_count } = w.finish({ generatedAt: '2026-08-09T00:00:00Z' });
    const parsed = JSON.parse(content);
    assert.equal(item_count, 0);
    assert.deepEqual(parsed.items, []);
    assert.equal(parsed.feed.item_count, 0);
  });

  it('special characters (quotes, backslashes, unicode, control chars) stay valid JSON', () => {
    const w = new JsonFeedWriter({ name: 'x' });
    const nasty = 'evil"\\\n\t-héllo-ç';
    w.addItem({ type: 'domain', value: nasty, timestamps: {}, classification: { tags: ['a"b', 'c\\d'] } });
    const parsed = JSON.parse(w.finish().content);
    assert.equal(parsed.items[0].value, nasty);
    assert.deepEqual(parsed.items[0].classification.tags, ['a"b', 'c\\d']);
  });

  it('content_hash excludes generated_at (stable across regenerations)', () => {
    const build = (gen) => {
      const w = new JsonFeedWriter({ name: 'x' });
      w.addItem({ type: 'ip', value: '1.2.3.4', timestamps: {} });
      return w.finish({ generatedAt: gen });
    };
    const a = build('2026-08-09T00:00:00Z');
    const b = build('2026-08-09T23:59:59Z');
    assert.equal(a.content_hash, b.content_hash);
    assert.notEqual(a.content, b.content); // generated_at differs in the body
  });
});
