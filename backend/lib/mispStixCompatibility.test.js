import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mapStixIndicatorToMispAttribute,
  mapPublishedItemToMispAttribute,
  MISP_UNSUPPORTED_IOC_TYPES
} from './mispStixCompatibility.js';
import { indicatorFromPublishedItem, StixBundleWriter } from './publishedFeedStix.js';

const TS = {
  imported_at: '2026-08-01T00:00:00.000Z',
  first_seen_in_source: '2026-08-01T00:00:00.000Z'
};

const CASES = [
  { type: 'ip', value: '192.0.2.44', misp: 'ip-dst' },
  { type: 'ipv6', value: '2001:db8::44', misp: 'ip-dst' },
  { type: 'ip', value: '198.51.100.0/24', misp: 'ip-dst' },
  { type: 'domain', value: 'evil.example', misp: 'domain' },
  { type: 'url', value: "https://evil.example/a'b", misp: 'url' },
  { type: 'md5', value: 'd41d8cd98f00b204e9800998ecf8427e', misp: 'md5' },
  { type: 'sha1', value: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', misp: 'sha1' },
  { type: 'sha256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', misp: 'sha256' }
];

test('supported IOC types map through STIX Indicator patterns to MISP attributes', () => {
  for (const c of CASES) {
    const mapped = mapPublishedItemToMispAttribute({ type: c.type, value: c.value, timestamps: TS });
    assert.equal(mapped.supported, true, c.type);
    assert.equal(mapped.attribute.type, c.misp, c.type);
    assert.equal(mapped.attribute.value, c.value, c.type);
    assert.equal(mapped.attribute.to_ids, true);
    assert.equal(mapped.indicator.type, 'indicator');
    assert.equal(mapped.indicator.spec_version, '2.1');
  }
});

test('unsupported IOC types are omitted from STIX and documented as not imported', () => {
  for (const type of MISP_UNSUPPORTED_IOC_TYPES) {
    const mapped = mapPublishedItemToMispAttribute({
      type,
      value: type === 'email' ? 'a@example.com' : 'deadbeef',
      timestamps: TS
    });
    assert.equal(mapped.supported, false, type);
    assert.match(mapped.reason, /not imported into MISP/i);
  }
});

test('STIX bundle of representative types is MISP-import compatible (fixture)', () => {
  const w = new StixBundleWriter({ slug: 'misp-compat' });
  for (const c of CASES) {
    w.addIndicator(indicatorFromPublishedItem({ type: c.type, value: c.value, timestamps: TS }));
  }
  const { content } = w.finish();
  const bundle = JSON.parse(content);
  assert.equal(bundle.type, 'bundle');
  assert.equal(bundle.spec_version, '2.1');
  assert.equal(bundle.objects.length, CASES.length);
  const mapped = bundle.objects.map(mapStixIndicatorToMispAttribute);
  assert.equal(mapped.every(Boolean), true);
  assert.deepEqual(mapped.map((a) => a.type), CASES.map((c) => c.misp));
});
