import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  WEB_ANALYSIS_LIMITS,
  extractWebAnalysisFromVt,
  ensureVtWebAnalysis,
  hasUsefulWebAnalysis,
  normalizeTargetedBrand,
  normalizeBehaviorTags,
  normalizeBoundedUrlList,
  normalizeContentSha256,
  normalizeWebCategories,
  extractHttpServer
} from './virustotalWebAnalysis.js';

const FULL_SHA = '235195e7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaacd04f3e1';

function fullUrlAttributes(over = {}) {
  return {
    targeted_brand: { PhishTank: 'Allegro', Other: '' },
    tags: ['password-input', 'iframes', 'password-input', ''],
    redirection_chain: [
      'https://example.invalid/listing',
      'https://example.invalid/listing',
      'https://example.invalid/logowanie',
      '',
      null
    ],
    last_http_response_content_sha256: FULL_SHA.toUpperCase(),
    outgoing_links: [
      'https://allegro.pl/',
      'https://allegro.pl/',
      'https://cdn.example/a'
    ],
    last_http_response_code: 200,
    last_http_response_headers: {
      server: 'cloudflare',
      'set-cookie': 'session=SECRET; HttpOnly',
      'cf-ray': 'abc123'
    },
    last_http_response_content_length: 764388,
    times_submitted: 1,
    categories: { Google: 'shopping', Sophos: 'phishing', Webroot: 'shopping' },
    javascript_variables: [{ name: 'token', value: 'secret' }],
    cookies: [{ name: 'session', value: 'SECRET' }],
    console_messages: [],
    threat_names: [],
    ...over
  };
}

describe('virustotalWebAnalysis normalizer', () => {
  test('full URL response extracts Phase 1 + 1.5 fields', () => {
    const wa = extractWebAnalysisFromVt({
      iocType: 'url',
      attributes: fullUrlAttributes()
    });
    assert.ok(wa);
    assert.deepEqual(wa.targeted_brand, { value: 'Allegro', source: 'PhishTank' });
    assert.deepEqual(wa.behavior_tags, ['password-input', 'iframes']);
    assert.equal(wa.http.status_code, 200);
    assert.equal(wa.http.server, 'cloudflare');
    assert.equal(wa.http.content_length, 764388);
    assert.equal(wa.content_sha256, FULL_SHA);
    assert.equal(wa.redirection_chain.total_count, 2);
    assert.deepEqual(wa.redirection_chain.items, [
      'https://example.invalid/listing',
      'https://example.invalid/logowanie'
    ]);
    assert.equal(wa.outgoing_links.total_count, 2);
    assert.equal(wa.times_submitted, 1);
    assert.deepEqual(wa.categories, ['shopping', 'phishing']);
  });

  test('partial response keeps only available fields', () => {
    const wa = extractWebAnalysisFromVt({
      iocType: 'url',
      attributes: { tags: ['iframes'], last_http_response_code: 302 }
    });
    assert.deepEqual(wa.behavior_tags, ['iframes']);
    assert.equal(wa.http.status_code, 302);
    assert.equal(wa.targeted_brand, undefined);
    assert.equal(wa.content_sha256, undefined);
  });

  test('missing fields → null web_analysis', () => {
    assert.equal(extractWebAnalysisFromVt({ iocType: 'url', attributes: {} }), null);
    assert.equal(extractWebAnalysisFromVt({ iocType: 'url', attributes: { tags: [] } }), null);
  });

  test('malformed SHA256 is not exposed', () => {
    assert.equal(normalizeContentSha256('not-a-hash'), null);
    assert.equal(normalizeContentSha256('abc'), null);
    const wa = extractWebAnalysisFromVt({
      iocType: 'url',
      attributes: { last_http_response_content_sha256: 'zzzz', tags: ['iframes'] }
    });
    assert.equal(wa.content_sha256, undefined);
    assert.deepEqual(wa.behavior_tags, ['iframes']);
  });

  test('duplicate outgoing links are deduped with stable order', () => {
    const list = normalizeBoundedUrlList(
      ['https://a.example/', 'https://b.example/', 'https://a.example/', null, ''],
      10
    );
    assert.deepEqual(list.items, ['https://a.example/', 'https://b.example/']);
    assert.equal(list.total_count, 2);
    assert.equal(list.truncated, false);
  });

  test('huge outgoing links list is bounded for MCP', () => {
    const many = Array.from({ length: 100 }, (_, i) => `https://example.invalid/link/${i}`);
    const wa = extractWebAnalysisFromVt({
      iocType: 'url',
      attributes: { outgoing_links: many }
    });
    assert.equal(wa.outgoing_links.items.length, WEB_ANALYSIS_LIMITS.MAX_OUTGOING_LINKS);
    assert.equal(wa.outgoing_links.total_count, 100);
    assert.equal(wa.outgoing_links.truncated, true);
  });

  test('session/cookie/sensitive fields are never exposed', () => {
    const wa = extractWebAnalysisFromVt({
      iocType: 'url',
      attributes: fullUrlAttributes()
    });
    const json = JSON.stringify(wa);
    assert.equal(json.includes('SECRET'), false);
    assert.equal(json.includes('set-cookie'), false);
    assert.equal(json.includes('javascript_variables'), false);
    assert.equal(json.includes('cookies'), false);
    assert.equal(json.includes('cf-ray'), false);
    assert.equal(json.includes('console_messages'), false);
    assert.equal(json.includes('threat_names'), false);
  });

  test('vendor categories are deduplicated case-insensitively', () => {
    assert.deepEqual(
      normalizeWebCategories({ a: 'Shopping', b: 'shopping', c: 'phishing' }),
      ['shopping', 'phishing']
    );
  });

  test('non-URL IOC does not generate web_analysis', () => {
    assert.equal(
      extractWebAnalysisFromVt({ iocType: 'domain', attributes: fullUrlAttributes() }),
      null
    );
    assert.equal(
      extractWebAnalysisFromVt({ iocType: 'ip', attributes: fullUrlAttributes() }),
      null
    );
    assert.equal(
      extractWebAnalysisFromVt({ iocType: 'sha256', attributes: fullUrlAttributes() }),
      null
    );
  });

  test('ensureVtWebAnalysis self-heals from raw_response without inventing for hash', () => {
    const raw = { data: { attributes: fullUrlAttributes() } };
    const healed = ensureVtWebAnalysis(
      { ioc_type: 'url', ioc_value: 'https://example.invalid/', stats: { malicious: 1 } },
      raw
    );
    assert.equal(healed.web_analysis.targeted_brand.value, 'Allegro');
    assert.equal(healed.stats.malicious, 1);

    const hash = ensureVtWebAnalysis(
      { ioc_type: 'sha256', web_analysis: { targeted_brand: { value: 'x', source: null } } },
      raw
    );
    assert.equal(hash.web_analysis, undefined);
  });

  test('targeted_brand skips empty and sorts engines deterministically', () => {
    assert.deepEqual(
      normalizeTargetedBrand({ Zulu: 'BrandZ', Alpha: 'BrandA' }),
      { value: 'BrandA', source: 'Alpha' }
    );
    assert.equal(normalizeTargetedBrand({}), null);
    assert.equal(normalizeTargetedBrand({ x: '' }), null);
  });

  test('behavior tags normalize and bound', () => {
    assert.deepEqual(normalizeBehaviorTags(['Password-Input', 'password-input', 'iframes']), [
      'password-input',
      'iframes'
    ]);
  });

  test('http server extracted case-insensitively; header dump not retained', () => {
    assert.equal(extractHttpServer({ Server: 'nginx' }), 'nginx');
    assert.equal(extractHttpServer({ 'set-cookie': 'x=1' }), null);
  });

  test('hasUsefulWebAnalysis empty-state', () => {
    assert.equal(hasUsefulWebAnalysis(null), false);
    assert.equal(hasUsefulWebAnalysis({}), false);
    assert.equal(hasUsefulWebAnalysis({ behavior_tags: [] }), false);
    assert.equal(hasUsefulWebAnalysis({ behavior_tags: ['iframes'] }), true);
  });

  test('redirection chain preserves order, removes empties/dupes, marks truncation', () => {
    const many = Array.from({ length: 40 }, (_, i) => `https://r.example/${i}`);
    const wa = extractWebAnalysisFromVt({
      iocType: 'url',
      attributes: { redirection_chain: many }
    });
    assert.equal(wa.redirection_chain.items.length, WEB_ANALYSIS_LIMITS.MAX_REDIRECTION_CHAIN);
    assert.equal(wa.redirection_chain.truncated, true);
    assert.equal(wa.redirection_chain.items[0], 'https://r.example/0');
  });
});
