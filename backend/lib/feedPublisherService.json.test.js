import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildFeedContent, resolvePublishedFeedFormat, resolveJsonIncludeFlags } from './feedPublisherService.js';
import { buildPlainTextFeed } from './feedFormatter.js';

/** Mock generation client: routes each metadata query by a distinctive SQL fragment. */
function mockDb(data = {}) {
  const calls = [];
  return {
    calls,
    async query(sql) {
      const s = String(sql).replace(/\s+/g, ' ');
      calls.push(s);
      if (s.includes('FROM ioc_items i LEFT JOIN ioc_feed_memberships m')) return { rows: data.timestamps || [] };
      if (s.includes('FROM ioc_items i LEFT JOIN ioc_sources s')) return { rows: data.manual || [] };
      if (s.includes('FROM ioc_feed_memberships m JOIN ioc_items i')) return { rows: data.feedSources || [] };
      if (s.includes('FROM ioc_tags it')) return { rows: data.tags || [] };
      if (s.includes("provider = 'virustotal'")) return { rows: data.vt || [] };
      if (s.includes('FROM ioc_ip_enrichment')) return { rows: data.ipinfo || [] };
      if (s.includes('FROM ioc_abuseipdb_enrichment')) return { rows: data.abuse || [] };
      if (s.includes('FROM ioc_spamhaus_drop_enrichment')) return { rows: data.spamhaus || [] };
      if (s.includes('FROM ioc_domain_enrichment')) return { rows: data.rdap || [] };
      return { rows: [] };
    }
  };
}

const domainRows = [
  { observable: 'evil.com', observable_type: 'domain', confidence: 'high', category: 'malware', source_name: 'ThreatFox', recency_ts: '2026-08-09T08:42:31Z' },
  { observable: 'bad.com', observable_type: 'domain', confidence: 'low', category: null, source_name: 'URLhaus', recency_ts: '2026-08-08T00:00:00Z' }
];

describe('buildFeedContent — TXT parity', () => {
  it('TXT output is byte-for-byte identical to buildPlainTextFeed', async () => {
    const feed = { name: 'D', format: 'txt' };
    const got = await buildFeedContent(mockDb(), feed, domainRows, ['domain'], null);
    const expected = buildPlainTextFeed(domainRows, ['domain'], null);
    assert.equal(got.content, expected.content);
    assert.equal(got.content_hash, expected.content_hash);
    assert.equal(got.item_count, expected.item_count);
  });

  it('resolve helpers default correctly', () => {
    assert.equal(resolvePublishedFeedFormat({ format: 'json' }), 'json');
    assert.equal(resolvePublishedFeedFormat({ format: 'txt' }), 'txt');
    assert.equal(resolvePublishedFeedFormat({}), 'txt');
    assert.deepEqual(resolveJsonIncludeFlags({}), {
      includeSourceMetadata: true, includeClassification: true, includeEnrichment: false
    });
    assert.deepEqual(resolveJsonIncludeFlags({ include_source_metadata: false, include_enrichment: true }), {
      includeSourceMetadata: false, includeClassification: true, includeEnrichment: true
    });
  });
});

describe('buildFeedContent — JSON', () => {
  const meta = {
    timestamps: [
      { obs: 'evil.com', otype: 'domain', imported_at: '2026-08-07T09:15:22Z', first_seen_in_source: '2026-08-05T14:22:10Z', last_confirmed_in_source: '2026-08-09T08:42:31Z' },
      { obs: 'bad.com', otype: 'domain', imported_at: '2026-08-01T00:00:00Z', first_seen_in_source: null, last_confirmed_in_source: null }
    ],
    feedSources: [
      { obs: 'evil.com', otype: 'domain', feed_key: 'threatfox', feed_name: 'ThreatFox', first_seen_in_source: '2026-08-05T14:22:10Z', last_confirmed_in_source: '2026-08-09T08:42:31Z' },
      { obs: 'evil.com', otype: 'domain', feed_key: 'urlhaus', feed_name: 'URLhaus', first_seen_in_source: '2026-08-06T00:00:00Z', last_confirmed_in_source: '2026-08-09T00:00:00Z' }
    ],
    tags: [
      { obs: 'evil.com', otype: 'domain', tag_name: 'c2' },
      { obs: 'evil.com', otype: 'domain', tag_name: 'C2' },
      { obs: 'evil.com', otype: 'domain', tag_name: 'malware' }
    ],
    rdap: [
      { observable_value: 'evil.com', registrar: 'EvilRegistrar', registration_date: '2020-01-01T00:00:00Z', expiration_date: '2027-01-01T00:00:00Z', rdap_raw_json: { secret: 1 } }
    ]
  };

  it('parses, has schema_version 1.0, correct item_count, IOC identity, and lifecycle timestamps', async () => {
    const feed = { name: 'Malicious Domains', format: 'json', include_source_metadata: true, include_classification: true, include_enrichment: false };
    const { content, item_count } = await buildFeedContent(mockDb(meta), feed, domainRows, ['domain'], null);
    const parsed = JSON.parse(content);
    assert.equal(parsed.schema_version, '1.0');
    assert.equal(parsed.feed.item_count, 2);
    assert.equal(item_count, 2);

    const evil = parsed.items.find((i) => i.value === 'evil.com');
    assert.equal(evil.type, 'domain');
    assert.equal(evil.timestamps.imported_at, '2026-08-07T09:15:22.000Z');
    assert.equal(evil.timestamps.first_seen_in_source, '2026-08-05T14:22:10.000Z');
    assert.equal(evil.timestamps.last_confirmed_in_source, '2026-08-09T08:42:31.000Z');
  });

  it('retains multiple sources deterministically, dedups tags, and omits enrichment when disabled', async () => {
    const feed = { name: 'D', format: 'json', include_source_metadata: true, include_classification: true, include_enrichment: false };
    const parsed = JSON.parse((await buildFeedContent(mockDb(meta), feed, domainRows, ['domain'], null)).content);
    const evil = parsed.items.find((i) => i.value === 'evil.com');
    assert.deepEqual(evil.sources.map((s) => s.feed_key), ['threatfox', 'urlhaus']);
    assert.deepEqual(evil.classification.tags, ['c2', 'malware']);
    assert.equal(evil.classification.category, 'malware');
    assert.equal(evil.classification.confidence, 100);
    assert.equal('enrichment' in evil, false);
  });

  it('includes normalized enrichment (no raw payload) when enabled', async () => {
    const feed = { name: 'D', format: 'json', include_source_metadata: false, include_classification: false, include_enrichment: true };
    const content = (await buildFeedContent(mockDb(meta), feed, domainRows, ['domain'], null)).content;
    const parsed = JSON.parse(content);
    const evil = parsed.items.find((i) => i.value === 'evil.com');
    assert.deepEqual(evil.enrichment.rdap, {
      registrar: 'EvilRegistrar', registration_date: '2020-01-01T00:00:00.000Z', expiration_date: '2027-01-01T00:00:00.000Z'
    });
    assert.equal(content.includes('secret'), false);
    assert.equal(content.includes('rdap_raw_json'), false);
    // Source metadata + classification suppressed by flags.
    assert.equal('sources' in evil, false);
    assert.equal('classification' in evil, false);
  });

  it('empty feed yields valid JSON with items: []', async () => {
    const feed = { name: 'Empty', format: 'json' };
    const parsed = JSON.parse((await buildFeedContent(mockDb(), feed, [], ['domain'], null)).content);
    assert.deepEqual(parsed.items, []);
    assert.equal(parsed.feed.item_count, 0);
  });

  it('respects max_items cap', async () => {
    const feed = { name: 'D', format: 'json', include_source_metadata: false, include_classification: false, include_enrichment: false };
    const parsed = JSON.parse((await buildFeedContent(mockDb(meta), feed, domainRows, ['domain'], 1)).content);
    assert.equal(parsed.items.length, 1);
    assert.equal(parsed.feed.item_count, 1);
  });
});
