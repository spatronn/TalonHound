import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  STIX_SPEC_VERSION,
  escapeStixPatternString,
  stixPatternForIoc,
  stixIndicatorId,
  stixBundleIdForFeed,
  indicatorFromPublishedItem,
  StixBundleWriter,
  uuidv5FromNamespace,
  TALONHOUND_STIX_NAMESPACE
} from './publishedFeedStix.js';

describe('STIX 2.1 pattern construction', () => {
  it('builds patterns for ipv4, ipv6, domain, url, md5, sha1, sha256', () => {
    assert.equal(stixPatternForIoc('ip', '1.2.3.4'), "[ipv4-addr:value = '1.2.3.4']");
    assert.equal(stixPatternForIoc('ipv6', '2001:db8::1'), "[ipv6-addr:value = '2001:db8::1']");
    assert.equal(stixPatternForIoc('ip', '2001:db8::2'), "[ipv6-addr:value = '2001:db8::2']");
    assert.equal(stixPatternForIoc('domain', 'evil.example'), "[domain-name:value = 'evil.example']");
    assert.equal(
      stixPatternForIoc('url', 'https://evil.example/path'),
      "[url:value = 'https://evil.example/path']"
    );
    assert.equal(
      stixPatternForIoc('md5', 'd41d8cd98f00b204e9800998ecf8427e'),
      "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"
    );
    assert.equal(
      stixPatternForIoc('sha1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
      "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']"
    );
    assert.equal(
      stixPatternForIoc('sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
      "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
    );
  });

  it('uses ISSUBSET for CIDR values', () => {
    assert.equal(stixPatternForIoc('ip', '10.0.0.0/8'), "[ipv4-addr:value ISSUBSET '10.0.0.0/8']");
    assert.equal(stixPatternForIoc('ipv6', '2001:db8::/32'), "[ipv6-addr:value ISSUBSET '2001:db8::/32']");
  });

  it('escapes single quotes and backslashes in pattern strings', () => {
    assert.equal(escapeStixPatternString("o'reilly"), "o\\'reilly");
    assert.equal(escapeStixPatternString('a\\b'), 'a\\\\b');
    assert.equal(
      stixPatternForIoc('url', "https://evil.example/a'b"),
      "[url:value = 'https://evil.example/a\\'b']"
    );
  });

  it('returns null for unsupported types (no invented SCOs)', () => {
    assert.equal(stixPatternForIoc('ssdeep', '3:abc'), null);
    assert.equal(stixPatternForIoc('imphash', 'aa'.repeat(16)), null);
    assert.equal(stixPatternForIoc('email', 'a@b.c'), null);
    assert.equal(stixPatternForIoc('ip', ''), null);
  });

  it('infers md5/sha1/sha256 from generic hash type by hex length', () => {
    assert.equal(
      stixPatternForIoc('hash', 'd41d8cd98f00b204e9800998ecf8427e'),
      "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"
    );
    assert.equal(
      stixIndicatorId('hash', 'd41d8cd98f00b204e9800998ecf8427e'),
      stixIndicatorId('md5', 'd41d8cd98f00b204e9800998ecf8427e')
    );
  });
});

describe('deterministic STIX IDs', () => {
  it('indicator id is stable for the same type+value', () => {
    const a = stixIndicatorId('domain', 'Evil.Example');
    const b = stixIndicatorId('domain', 'evil.example');
    assert.match(a, /^indicator--[0-9a-f-]{36}$/);
    assert.equal(a, b);
  });

  it('different values produce different ids', () => {
    assert.notEqual(stixIndicatorId('ip', '1.1.1.1'), stixIndicatorId('ip', '8.8.8.8'));
  });

  it('bundle id is stable per slug', () => {
    assert.equal(stixBundleIdForFeed('domain'), stixBundleIdForFeed('DOMAIN'));
    assert.notEqual(stixBundleIdForFeed('domain'), stixBundleIdForFeed('ip'));
    assert.match(stixBundleIdForFeed('domain'), /^bundle--[0-9a-f-]{36}$/);
  });

  it('uuidv5 is RFC-shaped version 5', () => {
    const id = uuidv5FromNamespace(TALONHOUND_STIX_NAMESPACE, 'probe');
    assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

describe('indicatorFromPublishedItem', () => {
  const ts = {
    imported_at: '2026-08-01T00:00:00.000Z',
    first_seen_in_source: '2026-07-31T12:00:00.000Z',
    last_confirmed_in_source: '2026-08-02T08:00:00.000Z'
  };

  it('emits a valid Indicator with created/modified/valid_from', () => {
    const ind = indicatorFromPublishedItem({
      type: 'domain',
      value: 'evil.example',
      timestamps: ts,
      classification: { confidence: 50, tags: ['c2', 'malware'] },
      confidence: 'medium'
    });
    assert.equal(ind.type, 'indicator');
    assert.equal(ind.spec_version, STIX_SPEC_VERSION);
    assert.equal(ind.pattern_type, 'stix');
    assert.equal(ind.pattern, "[domain-name:value = 'evil.example']");
    assert.equal(ind.created, '2026-07-31T12:00:00.000Z');
    assert.equal(ind.modified, '2026-08-02T08:00:00.000Z');
    assert.equal(ind.valid_from, '2026-07-31T12:00:00.000Z');
    assert.equal(ind.confidence, 50);
    assert.deepEqual(ind.labels, ['c2', 'malware']);
    assert.equal(ind.id, stixIndicatorId('domain', 'evil.example'));
    assert.equal(ind.created_by_ref, undefined);
    assert.equal(ind.indicator_types, undefined);
  });

  it('omits labels and confidence when absent (no invented semantics)', () => {
    const ind = indicatorFromPublishedItem({
      type: 'ip',
      value: '9.9.9.9',
      timestamps: { imported_at: '2026-08-01T00:00:00.000Z' }
    });
    assert.equal(ind.labels, undefined);
    assert.equal(ind.confidence, undefined);
    assert.equal(ind.valid_from, '2026-08-01T00:00:00.000Z');
  });

  it('returns null when timestamps cannot produce valid_from', () => {
    assert.equal(indicatorFromPublishedItem({ type: 'ip', value: '1.1.1.1' }), null);
  });

  it('returns null for unsupported types', () => {
    assert.equal(indicatorFromPublishedItem({
      type: 'ssdeep',
      value: '3:abc',
      timestamps: { imported_at: '2026-08-01T00:00:00.000Z' }
    }), null);
  });
});

describe('StixBundleWriter', () => {
  it('writes a valid STIX 2.1 Bundle', () => {
    const w = new StixBundleWriter({ slug: 'test-feed' });
    const ok = w.addIndicator(indicatorFromPublishedItem({
      type: 'ip',
      value: '1.2.3.4',
      timestamps: { imported_at: '2026-08-01T00:00:00.000Z' }
    }));
    assert.equal(ok, true);
    const { content, item_count, bundle_id, content_hash } = w.finish();
    assert.equal(item_count, 1);
    assert.equal(bundle_id, stixBundleIdForFeed('test-feed'));
    const parsed = JSON.parse(content);
    assert.equal(parsed.type, 'bundle');
    assert.equal(parsed.spec_version, '2.1');
    assert.equal(parsed.id, bundle_id);
    assert.equal(parsed.objects.length, 1);
    assert.equal(parsed.objects[0].type, 'indicator');
    assert.equal(parsed.objects[0].pattern, "[ipv4-addr:value = '1.2.3.4']");
    assert.equal(typeof content_hash, 'string');
    assert.equal(content_hash.length, 64);
    assert.ok(content.endsWith(']}\n'));
  });

  it('empty bundle is still valid STIX', () => {
    const w = new StixBundleWriter({ slug: 'empty' });
    const { content, item_count } = w.finish();
    assert.equal(item_count, 0);
    const parsed = JSON.parse(content);
    assert.equal(parsed.type, 'bundle');
    assert.deepEqual(parsed.objects, []);
  });

  it('hash is stable across regenerations of the same objects', () => {
    const item = {
      type: 'domain',
      value: 'a.example',
      timestamps: { imported_at: '2026-08-01T00:00:00.000Z' }
    };
    const a = new StixBundleWriter({ slug: 's' });
    a.addIndicator(indicatorFromPublishedItem(item));
    const b = new StixBundleWriter({ slug: 's' });
    b.addIndicator(indicatorFromPublishedItem(item));
    assert.equal(a.finish().content_hash, b.finish().content_hash);
  });

  it('does not leak internal fields', () => {
    const w = new StixBundleWriter({ slug: 's' });
    w.addIndicator(indicatorFromPublishedItem({
      type: 'url',
      value: 'https://x.example/p',
      timestamps: { imported_at: '2026-08-01T00:00:00.000Z' },
      classification: { tags: ['phishing'] }
    }));
    const text = w.finish().content;
    assert.equal(text.includes('ioc_id'), false);
    assert.equal(text.includes('storage_path'), false);
    assert.equal(text.includes('raw_json'), false);
    assert.equal(text.includes('api_key'), false);
  });
});
