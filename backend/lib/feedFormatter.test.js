import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeFeedIocTypes,
  feedIocTypesKey,
  observableTypesForFeedIocTypes,
  buildPlainTextFeed,
  feedCategoryForObservableType
} from './feedFormatter.js';

describe('normalizeFeedIocTypes', () => {
  it('accepts a single string (legacy)', () => {
    assert.deepEqual(normalizeFeedIocTypes('domain'), { ok: true, value: ['domain'] });
  });

  it('accepts two and four types sorted in canonical order', () => {
    assert.deepEqual(
      normalizeFeedIocTypes(['url', 'domain']),
      { ok: true, value: ['domain', 'url'] }
    );
    assert.deepEqual(
      normalizeFeedIocTypes(['hash', 'url', 'ip', 'domain']),
      { ok: true, value: ['ip', 'domain', 'url', 'hash'] }
    );
  });

  it('rejects empty, unknown, and duplicate values', () => {
    assert.equal(normalizeFeedIocTypes([]).ok, false);
    assert.equal(normalizeFeedIocTypes(null).ok, false);
    assert.match(normalizeFeedIocTypes(['mutex']).error, /ip, domain, url, or hash/);
    assert.match(normalizeFeedIocTypes(['ip', 'ip']).error, /duplicates/);
  });
});

describe('feedIocTypesKey / observable union', () => {
  it('keeps single-type snapshot key identical to legacy', () => {
    assert.equal(feedIocTypesKey(['ip']), 'ip');
    assert.equal(feedIocTypesKey('domain'), 'domain');
  });

  it('joins multi types with commas for snapshot lookup', () => {
    assert.equal(feedIocTypesKey(['url', 'domain']), 'domain,url');
  });

  it('unions observable types without duplicates', () => {
    const types = observableTypesForFeedIocTypes(['domain', 'hash']);
    assert.ok(types.includes('domain'));
    assert.ok(types.includes('md5'));
    assert.ok(types.includes('sha256'));
    assert.equal(types.filter((t) => t === 'domain').length, 1);
  });
});

describe('buildPlainTextFeed multi-type', () => {
  it('preserves single-type behavior including private IP drop', () => {
    const { lines, item_count } = buildPlainTextFeed(
      [
        { observable: '8.8.8.8', observable_type: 'ip', confidence: 'high', recency_ts: '2026-01-02' },
        { observable: '10.0.0.1', observable_type: 'ip', confidence: 'high', recency_ts: '2026-01-01' }
      ],
      'ip'
    );
    assert.equal(item_count, 1);
    assert.deepEqual(lines, ['8.8.8.8']);
  });

  it('unions rows and dedupes case-insensitively across types', () => {
    const { lines, item_count } = buildPlainTextFeed(
      [
        { observable: 'Evil.COM', observable_type: 'domain', confidence: 'high', recency_ts: '2026-01-03' },
        { observable: 'evil.com', observable_type: 'domain', confidence: 'medium', recency_ts: '2026-01-02' },
        { observable: 'https://evil.com/a', observable_type: 'url', confidence: 'high', recency_ts: '2026-01-01' },
        { observable: 'HTTPS://EVIL.COM/A', observable_type: 'url', confidence: 'low', recency_ts: '2026-01-01' }
      ],
      ['domain', 'url']
    );
    assert.equal(item_count, 2);
    assert.deepEqual(lines, ['evil.com', 'https://evil.com/a']);
  });

  it('maps hash observable subtypes for normalization', () => {
    assert.equal(feedCategoryForObservableType('sha256'), 'hash');
    assert.equal(feedCategoryForObservableType('domain'), 'domain');
  });
});
