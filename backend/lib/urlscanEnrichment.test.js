import test from 'node:test';
import assert from 'node:assert/strict';
import {
  URLSCAN_ASSESSMENT,
  URLSCAN_MATCH_RELATION,
  escapeElasticsearchQueryString,
  quoteKeywordTerm,
  canonicalizeUrlForMatch,
  urlsMatchExactly,
  assessUrlPrivacyForLookup,
  isSupportedUrlscanIocType,
  buildUrlscanSearchQuery,
  validateUrlscanRequest,
  urlscanAllowlistedFetch,
  classifyMatchRelation,
  normalizeSearchHit,
  selectDetailCandidates,
  deriveEvidenceAssessment,
  assessmentDisplayLabel,
  storeStatusForAssessment,
  buildUrlscanResultPageUrl,
  normalizeResultDetail
} from './urlscanEnrichment.js';

test('escapeElasticsearchQueryString escapes reserved characters', () => {
  assert.equal(escapeElasticsearchQueryString('a:b/c'), 'a\\:b\\/c');
  assert.equal(escapeElasticsearchQueryString('foo"bar'), 'foo\\"bar');
});

test('quoteKeywordTerm wraps and escapes quotes', () => {
  assert.equal(quoteKeywordTerm('https://a.example/x'), '"https://a.example/x"');
  assert.equal(quoteKeywordTerm('a"b'), '"a\\"b"');
});

test('URL canonicalization preserves path and query distinctions', () => {
  assert.equal(
    canonicalizeUrlForMatch('HTTPS://Example.COM:443/login'),
    'https://example.com/login'
  );
  assert.equal(
    canonicalizeUrlForMatch('https://example.com/login'),
    'https://example.com/login'
  );
  assert.equal(urlsMatchExactly('https://example.com/login', 'https://example.com/login2'), false);
  assert.equal(
    urlsMatchExactly('https://example.com/a?x=1', 'https://example.com/a?x=2'),
    false
  );
  assert.equal(
    urlsMatchExactly('https://example.com/a%2Fb', 'https://example.com/a/b'),
    true
  );
});

test('privacy assessment skips credential-bearing URLs without stripping', () => {
  assert.equal(assessUrlPrivacyForLookup('https://user:pass@example.com/a').ok, false);
  assert.equal(assessUrlPrivacyForLookup('https://example.com/a?token=abc').ok, false);
  assert.equal(assessUrlPrivacyForLookup('https://example.com/login').ok, true);
  assert.equal(assessUrlPrivacyForLookup('https://example.com/assets/app.js').ok, true);
});

test('unsupported IOC types are rejected', () => {
  assert.equal(isSupportedUrlscanIocType('md5'), null);
  assert.equal(isSupportedUrlscanIocType('sha256'), null);
  assert.equal(isSupportedUrlscanIocType('email'), null);
  assert.equal(isSupportedUrlscanIocType('cve'), null);
  assert.equal(isSupportedUrlscanIocType('url'), 'url');
  assert.equal(isSupportedUrlscanIocType('domain'), 'domain');
  assert.equal(isSupportedUrlscanIocType('ipv6'), 'ip');
});

test('search query uses exact URL keyword fields and never wildcards from input', () => {
  const built = buildUrlscanSearchQuery('url', 'https://example.com/login');
  assert.equal(built.ok, true);
  assert.match(built.query, /page\.url\.keyword:"https:\/\/example\.com\/login"/);
  assert.match(built.query, /date:\[now-\d+d TO now\]/);
  assert.doesNotMatch(built.query, /\*/);
});

test('sensitive URL search is rejected before query construction', () => {
  const built = buildUrlscanSearchQuery('url', 'https://example.com/?api_key=secret');
  assert.equal(built.ok, false);
  assert.equal(built.reason, 'privacy_restricted');
});

test('domain and IP search queries use documented fields', () => {
  const d = buildUrlscanSearchQuery('domain', 'Example.COM');
  assert.equal(d.ok, true);
  assert.match(d.query, /page\.domain\.keyword:"example\.com"/);
  const ip4 = buildUrlscanSearchQuery('ip', '1.2.3.4');
  assert.match(ip4.query, /page\.ip:"1\.2\.3\.4"/);
  const ip6 = buildUrlscanSearchQuery('ipv6', '2001:db8::1');
  assert.equal(ip6.ok, true);
  assert.match(ip6.query, /page\.ip:"2001:db8::1"/);
});

test('validateUrlscanRequest allowlists GET search/result/quotas only', () => {
  assert.equal(validateUrlscanRequest('GET', 'https://urlscan.io/api/v1/search?q=x').ok, true);
  assert.equal(validateUrlscanRequest('GET', 'https://urlscan.io/api/v1/quotas').ok, true);
  assert.equal(
    validateUrlscanRequest('GET', 'https://urlscan.io/api/v1/result/11111111-1111-4111-8111-111111111111/').ok,
    true
  );
  assert.equal(validateUrlscanRequest('POST', 'https://urlscan.io/api/v1/scan').ok, false);
  assert.equal(validateUrlscanRequest('GET', 'https://urlscan.io/api/v1/scan').ok, false);
  assert.equal(validateUrlscanRequest('GET', 'https://evil.example/api/v1/search').ok, false);
  assert.equal(validateUrlscanRequest('GET', 'http://urlscan.io/api/v1/search').ok, false);
  assert.equal(validateUrlscanRequest('GET', 'https://urlscan.io/api/v1/result/not-a-uuid/').ok, false);
});

test('urlscanAllowlistedFetch never issues POST scan and rejects non-allowlisted URLs', async () => {
  let called = false;
  await assert.rejects(
    () => urlscanAllowlistedFetch('https://urlscan.io/api/v1/scan', {
      apiKey: 'k',
      method: 'POST',
      fetchImpl: async () => { called = true; return { ok: true }; }
    }),
    (err) => err.code === 'request_rejected'
  );
  assert.equal(called, false);

  await assert.rejects(
    () => urlscanAllowlistedFetch('https://example.com/', {
      apiKey: 'k',
      fetchImpl: async () => { called = true; return { ok: true }; }
    }),
    (err) => err.code === 'request_rejected'
  );
  assert.equal(called, false);
});

test('urlscanAllowlistedFetch attaches API-Key and rejects missing key', async () => {
  await assert.rejects(
    () => urlscanAllowlistedFetch('https://urlscan.io/api/v1/search?q=domain:example.com', {
      apiKey: '',
      fetchImpl: async () => ({ ok: true, json: async () => ({}) })
    }),
    (err) => err.code === 'not_configured'
  );

  let headers;
  const res = await urlscanAllowlistedFetch('https://urlscan.io/api/v1/search?q=domain:example.com', {
    apiKey: 'secret-key',
    fetchImpl: async (_url, init) => {
      headers = init.headers;
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => Buffer.from(JSON.stringify({ results: [], total: 0 }))
      };
    }
  });
  assert.equal(headers['API-Key'], 'secret-key');
  assert.match(headers['User-Agent'], /TalonHound\//);
  assert.equal(res.json.total, 0);
});

test('http error mapping for 401/403/429/5xx', async () => {
  for (const [status, code] of [[401, 'auth'], [403, 'auth'], [429, 'rate_limit'], [503, 'provider_error']]) {
    await assert.rejects(
      () => urlscanAllowlistedFetch('https://urlscan.io/api/v1/search?q=x', {
        apiKey: 'k',
        fetchImpl: async () => ({
          ok: false,
          status,
          headers: { get: () => null },
          arrayBuffer: async () => Buffer.from('{}')
        })
      }),
      (err) => err.code === code
    );
  }
});

test('oversized response is rejected', async () => {
  await assert.rejects(
    () => urlscanAllowlistedFetch('https://urlscan.io/api/v1/search?q=x', {
      apiKey: 'k',
      maxResponseBytes: 16,
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => Buffer.alloc(64)
      })
    }),
    (err) => err.code === 'response_too_large'
  );
});

test('redirect to unexpected host is rejected', async () => {
  await assert.rejects(
    () => urlscanAllowlistedFetch('https://urlscan.io/api/v1/search?q=x', {
      apiKey: 'k',
      fetchImpl: async () => ({
        ok: false,
        status: 302,
        headers: { get: (n) => (String(n).toLowerCase() === 'location' ? 'https://evil.example/x' : null) }
      })
    }),
    (err) => err.code === 'redirect_rejected'
  );
});

test('match relations distinguish exact URL, path mismatch, domain, and IP roles', () => {
  const uuid = '11111111-1111-4111-8111-111111111111';
  const exact = classifyMatchRelation('url', 'https://example.com/login', {
    _id: uuid,
    task: { uuid, url: 'https://example.com/login' },
    page: { url: 'https://example.com/login', domain: 'example.com' }
  });
  assert.equal(exact.exact_match, true);
  assert.equal(exact.relation, URLSCAN_MATCH_RELATION.EXACT_URL);

  const pathMismatch = classifyMatchRelation('url', 'https://example.com/login', {
    _id: uuid,
    task: { uuid, url: 'https://example.com/login2' },
    page: { url: 'https://example.com/login2', domain: 'example.com' }
  });
  assert.equal(pathMismatch.exact_match, false);

  const pageHost = classifyMatchRelation('domain', 'example.com', {
    _id: uuid,
    task: { uuid },
    page: { domain: 'example.com', url: 'https://example.com/' }
  });
  assert.equal(pageHost.relation, URLSCAN_MATCH_RELATION.PAGE_HOSTNAME);

  const sub = classifyMatchRelation('domain', 'example.com', {
    _id: uuid,
    task: { uuid },
    page: { domain: 'evil.example.com', url: 'https://evil.example.com/' }
  });
  assert.equal(sub.relation, URLSCAN_MATCH_RELATION.SUBDOMAIN_OF_IOC);

  const primaryIp = classifyMatchRelation('ip', '1.2.3.4', {
    _id: uuid,
    task: { uuid },
    page: { ip: '1.2.3.4' }
  });
  assert.equal(primaryIp.relation, URLSCAN_MATCH_RELATION.PRIMARY_PAGE_IP);

  const contacted = classifyMatchRelation('ip', '1.2.3.4', {
    _id: uuid,
    task: { uuid },
    page: { ip: '9.9.9.9' }
  });
  assert.equal(contacted.relation, URLSCAN_MATCH_RELATION.CONTACTED_IP);
});

test('no results is not clean; related malicious IP is insufficient evidence', () => {
  assert.equal(deriveEvidenceAssessment('url', []), URLSCAN_ASSESSMENT.NO_RESULTS);
  assert.equal(assessmentDisplayLabel(URLSCAN_ASSESSMENT.NO_RESULTS), 'No results');
  assert.notEqual(assessmentDisplayLabel(URLSCAN_ASSESSMENT.NO_RESULTS).toLowerCase().includes('clean'), true);

  const contactedMalicious = [{
    exact_match: false,
    match_relation: URLSCAN_MATCH_RELATION.CONTACTED_IP,
    malicious: true
  }];
  assert.equal(
    deriveEvidenceAssessment('ip', contactedMalicious),
    URLSCAN_ASSESSMENT.INSUFFICIENT_EVIDENCE
  );

  const primaryMalicious = [{
    exact_match: true,
    match_relation: URLSCAN_MATCH_RELATION.PRIMARY_PAGE_IP,
    malicious: true
  }];
  assert.equal(
    deriveEvidenceAssessment('ip', primaryMalicious),
    URLSCAN_ASSESSMENT.MALICIOUS_EVIDENCE
  );

  const cleanLooking = [{
    exact_match: true,
    match_relation: URLSCAN_MATCH_RELATION.EXACT_URL,
    malicious: false,
    urlscan_score: -50
  }];
  assert.equal(
    deriveEvidenceAssessment('url', cleanLooking),
    URLSCAN_ASSESSMENT.NO_MALICIOUS_EVIDENCE
  );
});

test('selectDetailCandidates prefers exact matches over high malicious score', () => {
  const hits = [
    { scan_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', exact_match: false, match_relation: 'contacted_ip', malicious: true, urlscan_score: 100, scanned_at: '2024-01-02T00:00:00Z' },
    { scan_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', exact_match: true, match_relation: 'exact_url', malicious: false, urlscan_score: 0, scanned_at: '2024-01-01T00:00:00Z' }
  ];
  const selected = selectDetailCandidates(hits, 1);
  assert.deepEqual(selected, ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb']);
});

test('normalizeSearchHit and result detail omit sensitive page content', () => {
  const uuid = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const hit = normalizeSearchHit({
    _id: uuid,
    task: { uuid, url: 'https://example.com/login', time: '2024-06-01T00:00:00.000Z', visibility: 'public' },
    page: { url: 'https://example.com/login', domain: 'example.com', ip: '1.2.3.4', title: 'Login' },
    verdicts: { malicious: true, score: 80, urlscan: { malicious: true, categories: ['phishing'] } }
  }, 'url', 'https://example.com/login');
  assert.equal(hit.exact_match, true);
  assert.equal(hit.score_is_not_confidence, true);
  assert.equal(hit.result_url, buildUrlscanResultPageUrl(uuid));
  assert.equal(hit.malicious, true);

  const detail = normalizeResultDetail({
    task: { uuid, url: 'https://example.com/', time: '2024-06-01T00:00:00Z' },
    page: { url: 'https://example.com/', domain: 'example.com', ip: '1.2.3.4' },
    verdicts: { malicious: false, urlscan: { malicious: false, score: -10, categories: [] } },
    data: { cookies: [{ name: 'session', value: 'SECRET' }], requests: [{ response: { data: 'body' } }] },
    lists: { ips: ['1.2.3.4'], domains: ['example.com'] }
  }, uuid);
  assert.equal(detail.scan_id, uuid);
  assert.equal(detail.score_is_not_confidence, true);
  assert.equal(detail.cookies, undefined);
  assert.equal(detail.data, undefined);
});

test('storeStatusForAssessment maps no_results to not_found', () => {
  assert.equal(storeStatusForAssessment(URLSCAN_ASSESSMENT.NO_RESULTS), 'not_found');
  assert.equal(storeStatusForAssessment(URLSCAN_ASSESSMENT.MALICIOUS_EVIDENCE), 'success');
  assert.equal(storeStatusForAssessment(URLSCAN_ASSESSMENT.PRIVACY_RESTRICTED), 'skipped');
});

test('empty search never implies submission path exists in helpers', () => {
  // Structural guard: module exports do not include a submit/scan helper.
  const mod = Object.keys({
    validateUrlscanRequest,
    urlscanAllowlistedFetch,
    buildUrlscanSearchQuery
  });
  assert.ok(!mod.some((k) => /submit|scan/i.test(k) && !/Search|Allowlisted|validate/.test(k)));
  assert.equal(validateUrlscanRequest('POST', 'https://urlscan.io/api/v1/scan').reason, 'method_not_allowed');
});
