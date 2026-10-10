import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  extractUrlscanResultDetail,
  normalizeUrlscanVerdicts,
  deriveScanClassification,
  buildUrlscanScanHistory,
  URLSCAN_DETAIL_VERSION
} from './urlscanResultDetail.js';
import { normalizeResultDetail } from './urlscanEnrichment.js';

// Real Result API documents (headers/timing stripped, signed tokens replaced, fake cookie sentinel added).
const http403 = JSON.parse(readFileSync(new URL('./fixtures/urlscan-result-http403.json', import.meta.url), 'utf8'));
const offDomain = JSON.parse(readFileSync(new URL('./fixtures/urlscan-result-offdomain-redirect.json', import.meta.url), 'utf8'));

const SCAN_403 = '01a12594-300b-76cc-b97f-3b9e154c93fc';
const codes = (d) => d.observations.map((o) => o.code);

function minimalRaw(overrides = {}) {
  return {
    task: { uuid: '33333333-3333-4333-8333-333333333333', url: 'https://a.example/', time: '2026-01-01T00:00:00.000Z' },
    page: { url: 'https://a.example/', domain: 'a.example' },
    ...overrides
  };
}

test('403 scan: page, hosting and status facts match the Result API document', () => {
  const d = normalizeResultDetail(http403, SCAN_403);
  assert.equal(d.detail_version, URLSCAN_DETAIL_VERSION);
  assert.equal(d.scan_id, SCAN_403);
  assert.equal(d.page.title, '403 Forbidden');
  assert.equal(d.page.status, 403);
  assert.equal(d.page.status_text, 'Forbidden');
  assert.equal(d.page.ip, '45.74.61.10');
  assert.equal(d.page.asn, 'AS205397');
  assert.equal(d.page.asn_name, 'AS-69HOST 69HOST LLC, US');
  assert.equal(d.page.country, 'US');
  assert.equal(d.page.server, 'Apache');
  assert.equal(d.page.mime_type, 'text/html');
  assert.equal(d.page.submitted_url, 'https://video-remb-annulfr.com/?r=prime/');
  assert.equal(d.page.effective_url, 'https://video-remb-annulfr.com/?r=prime/');
  assert.equal(d.page.url_changed, false);
  assert.equal(d.page.city, null, 'empty city is not invented');
  // Legacy flat keys stay populated for v1 consumers.
  assert.equal(d.page_status, '403');
  assert.equal(d.page_title, '403 Forbidden');
});

test('403 scan: network activity is aggregated, not dumped', () => {
  const { network } = normalizeResultDetail(http403, SCAN_403);
  assert.equal(network.requests, 2);
  assert.equal(network.unique_domains, 1);
  assert.equal(network.unique_ips, 1);
  assert.equal(network.redirects, 0);
  assert.equal(network.http_error_responses, 2);
  assert.equal(network.failed_requests, 0);
  assert.equal(network.console_errors, 2);
  assert.equal(network.outgoing_links, 0);
  assert.deepEqual(network.status_codes, [{ status: '403', count: 2 }]);
  assert.deepEqual(network.methods, [{ method: 'GET', count: 2 }]);
});

test('403 scan: TLS metadata from page + primary securityDetails', () => {
  const { tls } = normalizeResultDetail(http403, SCAN_403);
  assert.equal(tls.issuer, 'blackhole.invalid');
  assert.equal(tls.subject, 'blackhole.invalid');
  assert.equal(tls.valid_from, '2026-08-17T11:05:13.000Z');
  assert.equal(tls.valid_to, '2036-08-14T11:05:13.000Z');
  assert.equal(tls.valid_days, 3650);
  assert.equal(tls.age_days, 54);
  assert.equal(tls.protocol, 'TLS 1.3');
});

test('403 scan: unclassified with score 0 is never benign; ML engine conflict is surfaced', () => {
  const d = normalizeResultDetail(http403, SCAN_403);
  assert.equal(d.classification.state, 'unclassified');
  assert.equal(d.classification.label, 'Unclassified');
  assert.equal(d.classification.score, 0);
  assert.equal(d.overall_malicious, false, 'reads verdicts.overall, not a non-existent top-level flag');
  assert.equal(d.verdicts.engines.malicious, true);
  assert.equal(d.verdicts.engines.score, 60);
  assert.equal(d.verdicts.urlscan.has_verdicts, false);
  const c = codes(d);
  assert.ok(c.includes('limited_visibility_http_error'));
  assert.ok(c.includes('unclassified'));
  assert.ok(c.includes('engine_signal_conflict'));
  assert.ok(c.includes('self_issued_certificate'));
  assert.ok(c.includes('long_tls_validity'));
  const limited = d.observations.find((o) => o.code === 'limited_visibility_http_error');
  assert.equal(limited.label, 'Limited page visibility — HTTP 403 Forbidden');
  const unclassified = d.observations.find((o) => o.code === 'unclassified');
  assert.match(unclassified.detail, /not a benign or safe verdict/);
  for (const o of d.observations) assert.doesNotMatch(o.label, /\bclean\b|\bsafe\b/i);
});

test('403 scan: response-body hash keeps provenance and is not a malware sample hash', () => {
  const d = normalizeResultDetail(http403, SCAN_403);
  assert.equal(d.response_hashes.total, 1);
  const h = d.response_hashes.sample[0];
  assert.equal(h.sha256, '317123bb63824c1ec80c0dc9e19a4cfe02467432c055560b7dbb114414148909');
  assert.equal(h.context, 'primary_response_body');
  assert.equal(h.http_status, 403);
  const rel = d.related_observables.find((r) => r.type === 'sha256');
  assert.equal(rel.relationship, 'primary_response_body');
  assert.equal(rel.origin, 'data.requests[].response.hash');
  assert.match(rel.note, /HTTP 403/);
  assert.notEqual(rel.relationship, 'malware_sample');
  const ip = d.related_observables.find((r) => r.type === 'ip');
  assert.deepEqual([ip.value, ip.relationship, ip.origin], ['45.74.61.10', 'primary_page_ip', 'page.ip']);
});

test('off-domain redirect: submitted vs effective URL, chain, and destination semantics', () => {
  const d = normalizeResultDetail(offDomain, offDomain.task.uuid);
  assert.equal(d.page.submitted_url, 'https://quicksupport.fom.de/');
  assert.equal(d.page.effective_url, 'https://get.teamviewer.com/bcw-gruppe');
  assert.equal(d.page.url_changed, true);
  assert.equal(d.page.redirected, 'off-domain');
  assert.deepEqual(d.redirects, [{ from: 'https://quicksupport.fom.de/', to: 'https://get.teamviewer.com/bcw-gruppe', status: 301 }]);
  assert.ok(codes(d).includes('off_domain_redirect'));
  const finalUrl = d.related_observables.find((r) => r.relationship === 'final_url');
  assert.equal(finalUrl.value, 'https://get.teamviewer.com/bcw-gruppe');
  assert.ok(d.related_observables.some((r) => r.relationship === 'redirect_destination' && r.value === 'get.teamviewer.com'));
});

test('off-domain redirect: primary vs redirect-hop vs same-site vs third-party infrastructure', () => {
  const { infrastructure } = normalizeResultDetail(offDomain, offDomain.task.uuid);
  const role = (ip) => infrastructure.ips.find((x) => x.ip === ip)?.role;
  assert.equal(role('104.16.62.16'), 'primary');
  assert.equal(role('87.190.244.23'), 'redirect_hop');
  assert.equal(role('20.50.2.60'), 'same_site');
  assert.equal(role('151.101.193.155'), 'third_party');
  assert.equal(infrastructure.ips[0].role, 'primary', 'primary hosting listed first');
  const fastly = infrastructure.ips.find((x) => x.ip === '151.101.193.155');
  assert.equal(fastly.asn, '54113');
  assert.equal(fastly.asn_name, 'Fastly');
  assert.deepEqual(infrastructure.linked_not_contacted_domains, ['www.teamviewer.com']);
});

test('off-domain redirect: technologies, failed loads, downloads (redacted), no duplicate observables', () => {
  const d = normalizeResultDetail(offDomain, offDomain.task.uuid);
  assert.ok(d.technologies.some((t) => t.name === 'jQuery' && t.categories.includes('JavaScript libraries')));
  assert.equal(d.network.failed_requests, 1);
  assert.deepEqual(d.network.failed_request_errors, [{ error: 'net::ERR_ABORTED', count: 1 }]);
  assert.equal(d.network.redirects, 1);
  assert.equal(d.network.downloads, 1);
  assert.equal(d.downloads[0].filename, 'TeamViewerQS.tar.gz');
  assert.ok(codes(d).includes('download_attempt'));
  const keys = d.related_observables.map((r) => `${r.type}|${r.value}`);
  assert.equal(new Set(keys).size, keys.length);
  const hop = d.related_observables.find((r) => r.value === 'quicksupport.fom.de');
  assert.equal(hop.relationship, 'redirect_hop');
});

test('secrets, cookies, headers and bodies are never persisted', () => {
  for (const raw of [http403, offDomain]) {
    const json = JSON.stringify(normalizeResultDetail(raw, raw.task.uuid));
    assert.doesNotMatch(json, /FAKESIGNATURE/, 'signed URL token redacted');
    assert.doesNotMatch(json, /FAKE-COOKIE-VALUE/);
    assert.doesNotMatch(json, /fixture_session/);
    assert.doesNotMatch(json, /User-Agent|sec-ch-ua|Set-Cookie/i);
    assert.doesNotMatch(json, /screenshotURL|domURL/);
  }
});

test('detail size stays bounded even for very large scans', () => {
  assert.ok(JSON.stringify(normalizeResultDetail(offDomain, offDomain.task.uuid)).length < 16 * 1024);
  const requests = Array.from({ length: 3000 }, (_, i) => ({
    request: { type: 'Script', request: { url: `https://cdn${i}.example/x.js?token=secret${i}`, method: 'GET' } },
    response: { hash: i.toString(16).padStart(64, '0'), size: i, response: { status: 200, mimeType: 'application/javascript' } }
  }));
  const ipStats = Array.from({ length: 300 }, (_, i) => ({ ip: `198.51.100.${i % 255}`, requests: 1, domains: [`cdn${i}.example`] }));
  const raw = minimalRaw({
    data: { requests, links: [], redirects: [] },
    stats: { ipStats, domainStats: ipStats.map((s, i) => ({ domain: `cdn${i}.example`, count: 1, ips: [s.ip] })) },
    lists: { ips: ipStats.map((s) => s.ip), domains: ipStats.map((s, i) => `cdn${i}.example`), linkDomains: ipStats.map((s, i) => `l${i}.example`) }
  });
  const d = extractUrlscanResultDetail(raw, { scanId: raw.task.uuid });
  assert.ok(d.infrastructure.ips.length <= 10);
  assert.ok(d.infrastructure.domains.length <= 10);
  assert.ok(d.related_observables.length <= 25);
  assert.ok(d.response_hashes.sample.length <= 5);
  assert.ok(JSON.stringify(d).length < 16 * 1024);
  assert.doesNotMatch(JSON.stringify(d), /secret\d/);
});

test('missing optional groups never throw and never invent fields', () => {
  const d = extractUrlscanResultDetail(minimalRaw(), { scanId: 'x' });
  assert.equal(d.tls, null);
  assert.deepEqual(d.technologies, []);
  assert.deepEqual(d.redirects, []);
  assert.deepEqual(d.downloads, []);
  assert.equal(d.page.status, null);
  assert.equal(d.page.title, null);
  assert.equal(d.classification.state, 'unknown');
  assert.equal(d.verdicts, null);
  assert.equal(d.overall_malicious, null);
  assert.equal(d.network.requests, 0);
  assert.equal(extractUrlscanResultDetail(null), null);
});

test('HTTP error with a rich page is informational, not "limited visibility"', () => {
  const requests = Array.from({ length: 30 }, (_, i) => ({
    request: { type: i === 0 ? 'Document' : 'Script', primaryRequest: i === 0, request: { url: `https://a.example/${i}`, method: 'GET' } },
    response: { response: { status: i === 0 ? 404 : 200 } }
  }));
  const d = extractUrlscanResultDetail(minimalRaw({ page: { url: 'https://a.example/', domain: 'a.example', status: '404' }, data: { requests } }), { scanId: 'x' });
  assert.ok(!codes(d).includes('limited_visibility_http_error'));
  assert.ok(codes(d).includes('primary_http_error'));
});

test('failed navigation and challenge titles are visibility limitations', () => {
  const failed = extractUrlscanResultDetail(minimalRaw({
    data: { requests: [{ request: { type: 'Document', primaryRequest: true, request: { url: 'https://a.example/' } }, response: { failed: { errorText: 'net::ERR_NAME_NOT_RESOLVED' } } }] }
  }), { scanId: 'x' });
  assert.ok(codes(failed).includes('navigation_failed'));
  assert.match(failed.observations[0].detail, /ERR_NAME_NOT_RESOLVED/);

  const challenge = extractUrlscanResultDetail(minimalRaw({ page: { url: 'https://a.example/', status: '200', title: 'Just a moment...' } }), { scanId: 'x' });
  assert.ok(codes(challenge).includes('possible_challenge_page'));
});

test('verdict normalization: malicious, explicit benign, zero score, legacy flat, conflicting sources', () => {
  const malicious = deriveScanClassification(normalizeUrlscanVerdicts({
    overall: { malicious: true, score: 100, categories: ['phishing'], brands: [{ key: 'msft', name: 'Microsoft' }], hasVerdicts: true },
    urlscan: { malicious: true, score: 100, hasVerdicts: true }
  }));
  assert.equal(malicious.state, 'malicious');
  assert.deepEqual(malicious.categories, ['phishing']);
  assert.deepEqual(malicious.brands, ['Microsoft']);

  const benign = deriveScanClassification(normalizeUrlscanVerdicts({ overall: { malicious: false, score: -50, hasVerdicts: true } }));
  assert.equal(benign.state, 'benign');

  const zero = deriveScanClassification(normalizeUrlscanVerdicts({ overall: { malicious: false, score: 0, hasVerdicts: false } }));
  assert.equal(zero.state, 'unclassified');
  assert.notEqual(zero.state, 'benign');

  const flat = normalizeUrlscanVerdicts({ malicious: true, score: 80, urlscan: { malicious: true, categories: ['phishing'] } });
  assert.equal(flat.overall.malicious, true);
  assert.equal(flat.overall.score, 80);

  // Community says malicious but the overall verdict does not: classification follows overall only.
  const conflict = deriveScanClassification(normalizeUrlscanVerdicts({
    overall: { malicious: false, score: 0, hasVerdicts: true },
    community: { malicious: true, votesMalicious: 1, votesTotal: 1, hasVerdicts: true }
  }));
  assert.equal(conflict.state, 'unclassified');

  assert.equal(normalizeUrlscanVerdicts(undefined), null);
  assert.equal(deriveScanClassification(null).state, 'unknown');
});

test('history comparison uses only direct matches within the retrieved sample', () => {
  const hits = [
    { exact_match: true, scanned_at: '2026-10-10T00:00:00Z', page_ip: '1.1.1.1', page_asn: 'AS1', page_title: '403 Forbidden', page_status: '403' },
    { exact_match: true, scanned_at: '2026-09-01T00:00:00Z', page_ip: '2.2.2.2', page_asn: 'AS2', page_title: 'Sign in', page_status: '200' },
    { exact_match: false, scanned_at: '2026-09-02T00:00:00Z', page_ip: '9.9.9.9', page_asn: 'AS9', page_title: 'Other', page_status: '200' }
  ];
  const h = buildUrlscanScanHistory(hits, { totalReported: 40 });
  assert.equal(h.compared_scans, 2);
  assert.equal(h.sample_size, 3);
  assert.equal(h.total_reported, 40);
  assert.deepEqual(h.primary_ips.map((x) => x.value).sort(), ['1.1.1.1', '2.2.2.2']);
  assert.equal(h.changed.primary_ip, true);
  assert.equal(h.changed.status, true);
  assert.ok(!h.primary_ips.some((x) => x.value === '9.9.9.9'), 'contacted-only scans describe other infrastructure');

  const single = buildUrlscanScanHistory([hits[0]]);
  assert.equal(single.changed.primary_ip, false);
});
