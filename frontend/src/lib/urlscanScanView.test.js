import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildUrlscanView, scanVerdictLabel, countryLabel } from './urlscanScanView.js';

// Summaries produced by the backend normalizer from real Result API documents.
const http403 = JSON.parse(readFileSync(new URL('./fixtures/urlscan-summary-http403.json', import.meta.url), 'utf8'));
const offDomain = JSON.parse(readFileSync(new URL('./fixtures/urlscan-summary-offdomain-redirect.json', import.meta.url), 'utf8'));

const row = (rows, label) => rows.find((r) => r.label === label)?.value;

// Exact v1 row stored in production before this change (target IOC).
const legacyV1 = {
  scans: [{
    page_ip: '45.74.61.10', scan_id: '01a12594-300b-76cc-b97f-3b9e154c93fc', page_asn: 'AS205397',
    page_url: 'https://video-remb-annulfr.com/?r=prime/', task_url: 'https://video-remb-annulfr.com/?r=prime/',
    malicious: false, categories: [], page_title: '403 Forbidden',
    result_url: 'https://urlscan.io/result/01a12594-300b-76cc-b97f-3b9e154c93fc/', scanned_at: '2026-10-10T11:30:37.899Z',
    visibility: 'public', exact_match: true, page_domain: 'video-remb-annulfr.com', page_server: 'Apache', page_country: 'US',
    urlscan_score: 0, match_relation: 'exact_url', stats_requests: 2, page_redirected: null, score_is_not_confidence: true
  }],
  detail_scans: [{
    page_ip: '45.74.61.10', scan_id: '01a12594-300b-76cc-b97f-3b9e154c93fc', page_asn: 'AS205397', page_status: '403',
    page_asnname: 'AS-69HOST 69HOST LLC, US', page_country: 'US', page_title: '403 Forbidden', page_server: 'Apache',
    result_url: 'https://urlscan.io/result/01a12594-300b-76cc-b97f-3b9e154c93fc/', scanned_at: '2026-10-10T11:30:37.899Z',
    overall_malicious: false, engines_malicious: true, urlscan_score: 0
  }],
  ioc_category: 'url',
  matches_retrieved: 1,
  exact_match_count: 1,
  related_match_count: 0,
  malicious_scan_count: 0,
  results_are_exhaustive: true,
  total_reported_by_api: 1,
  evidence_assessment: 'no_malicious_evidence',
  evidence_assessment_label: 'No malicious evidence observed',
  fetched_at: '2026-10-10T11:43:09.743Z'
};

test('target 403 scan: Unclassified + limited visibility, never "clean"', () => {
  const v = buildUrlscanView(http403);
  assert.equal(v.version, 2);
  assert.equal(v.classification.state, 'unclassified');
  assert.equal(v.classification.label, 'Unclassified');
  assert.equal(v.classification.score, 0);
  const labels = v.observations.map((o) => o.label);
  assert.ok(labels.includes('Limited page visibility — HTTP 403 Forbidden'));
  assert.ok(labels.includes('Engine signal not reflected in overall verdict'));
  for (const text of [v.classification.label, ...labels]) assert.doesNotMatch(text, /\bclean\b|\bsafe\b/i);
  assert.equal(v.assessment, 'insufficient_evidence');
  const engines = v.verdictSources.find((s) => s.source === 'Engines (ML)');
  assert.equal(engines.value, 'malicious, score 60');
  assert.equal(engines.caution, true);
  assert.equal(v.verdictSources.find((s) => s.source === 'urlscan').value, 'no verdict');
  assert.equal(v.verdictSources.find((s) => s.source === 'Community').value, 'no votes');
});

test('target 403 scan: page & hosting rows show only verified fields', () => {
  const v = buildUrlscanView(http403);
  const rows = [...v.pageRows, ...v.hostingRows];
  assert.equal(row(rows, 'Page title'), '403 Forbidden');
  assert.equal(row(rows, 'HTTP status'), '403 Forbidden');
  assert.equal(row(rows, 'Primary IP'), '45.74.61.10');
  assert.equal(row(rows, 'ASN'), 'AS205397');
  assert.equal(row(rows, 'Organization'), 'AS-69HOST 69HOST LLC, US');
  assert.equal(row(rows, 'Country'), 'United States (US)');
  assert.equal(row(rows, 'Web server'), 'Apache');
  assert.equal(row(rows, 'City'), undefined, 'empty city is not rendered');
  assert.equal(row(rows, 'Reverse DNS'), undefined);
  assert.equal(row(rows, 'Scanned URL'), undefined, 'URL IOC: scanned URL equals the IOC and is not repeated');
  assert.equal(rows.find((r) => r.label === 'HTTP status').tone, 'caution');
});

test('target 403 scan: network stats, TLS, related observables with provenance', () => {
  const v = buildUrlscanView(http403);
  const stat = (label) => v.networkStats.find((s) => s.label === label)?.value;
  assert.equal(stat('HTTP requests'), 2);
  assert.equal(stat('Domains'), 1);
  assert.equal(stat('IPs'), 1);
  assert.equal(stat('Redirects'), 0);
  assert.equal(stat('HTTP ≥400'), 2);
  assert.equal(stat('Console errors'), 2);
  assert.equal(stat('Downloads'), undefined, 'zero-only optional stats are omitted');
  assert.deepEqual(v.statusCodes, ['403 ×2']);
  assert.equal(row(v.tlsRows, 'Issuer'), 'blackhole.invalid');
  assert.equal(row(v.tlsRows, 'Subject'), 'blackhole.invalid (same as issuer)');
  assert.equal(row(v.tlsRows, 'Validity period'), '3650 days');
  assert.equal(row(v.tlsRows, 'Secure requests'), '0%');
  assert.deepEqual(v.technologies, [], 'no technologies invented');
  const hash = v.related.find((r) => r.type === 'sha256');
  assert.match(hash.relationship, /not a malware sample/);
  assert.equal(hash.origin, 'data.requests[].response.hash');
  assert.equal(v.related.find((r) => r.type === 'ip').relationship, 'Primary hosting IP');
});

test('off-domain redirect: submitted vs effective URL, chain, roles, technologies', () => {
  const v = buildUrlscanView(offDomain);
  assert.equal(row(v.pageRows, 'Submitted URL'), 'https://quicksupport.fom.de/');
  assert.equal(row(v.pageRows, 'Effective URL'), 'https://get.teamviewer.com/bcw-gruppe');
  assert.equal(row(v.pageRows, 'Redirect'), 'off-domain');
  assert.equal(v.redirects.length, 1);
  assert.equal(v.redirects[0].status, 301);
  assert.ok(v.observations.some((o) => o.code === 'off_domain_redirect'));
  assert.ok(v.technologies.some((t) => t.name === 'jQuery'));
  const fastly = v.related.find((r) => r.value === '151.101.193.155');
  assert.equal(fastly.role, 'third-party resource');
  assert.ok(v.related.some((r) => r.relationship === 'Linked on page, not contacted'));
  assert.deepEqual(v.failedErrors, ['net::ERR_ABORTED ×1']);
  assert.doesNotMatch(JSON.stringify(v), /sig=[A-Za-z0-9%]{10,}/);
});

test('history: bounded sample, verdict labels distinguish "not retrieved" from "not malicious"', () => {
  const v = buildUrlscanView(offDomain);
  assert.equal(v.history.rows.length, 3);
  assert.equal(v.history.total, offDomain.total_reported_by_api);
  const detailed = v.history.rows.find((r) => r.scan_id === offDomain.primary_scan_id);
  assert.equal(detailed.verdict, 'Unclassified');
  const undetailed = v.history.rows.find((r) => r.scan_id !== offDomain.primary_scan_id);
  assert.equal(undetailed.verdict, 'Verdict not retrieved');
  assert.equal(scanVerdictLabel({ malicious: true }), 'Malicious');
  assert.equal(scanVerdictLabel({ malicious: false }), 'Not malicious');
  assert.equal(scanVerdictLabel({}), 'Verdict not retrieved');

  const changed = buildUrlscanView({
    ...http403,
    history: { compared_scans: 2, changed: { primary_ip: true }, primary_ips: [{ value: '1.1.1.1', count: 1 }, { value: '2.2.2.2', count: 1 }] }
  });
  assert.deepEqual(changed.history.changes, [{ label: 'Primary IP', values: ['1.1.1.1 ×1', '2.2.2.2 ×1'] }]);
});

test('legacy v1 cached row: renders page facts, flags refresh, never trusts the old verdict parse', () => {
  const v = buildUrlscanView(legacyV1);
  assert.equal(v.version, 1);
  assert.equal(v.needsRefreshForDetail, true);
  assert.equal(v.classification.state, 'unknown');
  assert.notEqual(v.classification.label, 'Unclassified');
  assert.equal(row(v.pageRows, 'HTTP status'), '403');
  assert.equal(row(v.hostingRows, 'Primary IP'), '45.74.61.10');
  assert.equal(row(v.hostingRows, 'Organization'), 'AS-69HOST 69HOST LLC, US');
  assert.equal(v.observations[0].code, 'limited_visibility_http_error');
  assert.deepEqual(v.networkStats, []);
  assert.deepEqual(v.related, []);
  assert.deepEqual(v.tlsRows, []);
  assert.equal(v.primaryScan.href, 'https://urlscan.io/result/01a12594-300b-76cc-b97f-3b9e154c93fc/');
  assert.equal(v.history.rows[0].verdict, 'Verdict needs refresh');
  assert.equal(v.history.rows[0].malicious, false);
});

test('empty/missing summaries and unsafe links are handled', () => {
  assert.equal(buildUrlscanView(null), null);
  const v = buildUrlscanView({ scans: [{ scan_id: 'a', result_url: 'https://evil.example/result/x' }] });
  assert.equal(v.primaryScan.href, null, 'only official urlscan result links are rendered');
  assert.equal(v.history.rows[0].href, null);
  assert.deepEqual(v.pageRows, []);
  assert.deepEqual(v.observations, []);
  assert.equal(countryLabel(''), null);
  assert.equal(countryLabel('XX'), 'XX');
});
