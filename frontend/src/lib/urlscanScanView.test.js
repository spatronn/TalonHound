import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  buildUrlscanView,
  scanVerdictLabel,
  countryLabel,
  urlscanPayloadState,
  urlscanRefreshErrorState,
  FINDING_PRIORITY
} from './urlscanScanView.js';

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
  assert.equal(row(rows, 'ASN / Organization'), 'AS205397 · AS-69HOST 69HOST LLC, US');
  assert.equal(row(rows, 'Country'), 'United States (US)');
  assert.equal(row(rows, 'Web server'), 'Apache');
  assert.equal(row(rows, 'City'), undefined, 'empty city is not rendered');
  assert.equal(row(rows, 'Reverse DNS'), undefined);
  assert.equal(row(rows, 'Scanned URL'), undefined, 'URL IOC: scanned URL equals the IOC and is not repeated');
});

test('target 403 scan: network stats, TLS, related observables with provenance', () => {
  const v = buildUrlscanView(http403);
  const stat = (label) => v.networkStats.find((s) => s.label === label)?.value;
  assert.equal(stat('HTTP requests'), 2);
  assert.equal(stat('Domains'), 1);
  assert.equal(stat('IPs'), 1);
  assert.equal(stat('Redirects'), 0);
  assert.equal(stat('HTTP errors (4xx/5xx)'), 2);
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
  assert.equal(row(v.hostingRows, 'ASN / Organization'), 'AS205397 · AS-69HOST 69HOST LLC, US');
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

// ---- Redesign: conclusion → explanation → evidence ----

const clone = (o) => JSON.parse(JSON.stringify(o));

function maliciousSummary() {
  const s = clone(offDomain);
  s.classification = { state: 'malicious', label: 'Malicious', score: 100, categories: ['phishing'], brands: ['Microsoft'] };
  s.detail_scans[0].classification = s.classification;
  s.detail_scans[0].verdicts.overall = { malicious: true, score: 100, has_verdicts: true, categories: ['phishing'], brands: ['Microsoft'], tags: [] };
  s.observations = s.observations.filter((o) => o.code !== 'unclassified');
  return s;
}

test('assessment tiles keep overall verdict, score, ML signal and visibility as separate concepts', () => {
  const v = buildUrlscanView(http403);
  assert.deepEqual(v.tiles.map((t) => t.key), ['verdict', 'score', 'ml', 'visibility', 'last_scan']);
  const tile = (k) => v.tiles.find((t) => t.key === k);
  assert.equal(tile('verdict').value, 'Unclassified');
  assert.equal(tile('verdict').tone, 'neutral', 'an ML signal never colours the overall verdict');
  assert.equal(tile('score').value, '0');
  assert.equal(tile('score').hint, 'No verdict signal — not benign');
  assert.match(tile('score').title, /not TalonHound confidence/);
  assert.equal(tile('ml').value, 'Malicious signal · 60');
  assert.equal(tile('ml').tone, 'caution');
  assert.equal(tile('visibility').value, 'Limited · HTTP 403');
  assert.equal(tile('visibility').tone, 'caution');
  assert.equal(tile('last_scan').date, true);
  for (const t of v.tiles) assert.notEqual(t.tone === 'neutral' && /safe|clean/i.test(t.value), true);
});

test('one consolidated summary sentence instead of repeated verdict messages', () => {
  const v = buildUrlscanView(http403);
  assert.equal(
    v.summarySentence,
    'Unclassified by urlscan. The scan had limited visibility (HTTP 403), and the ML engine reported a malicious signal that is not reflected in the overall verdict.'
  );
  const shown = [v.summarySentence, ...v.findings.primary.map((f) => f.title), ...v.findings.technical.map((f) => f.title)];
  assert.equal(shown.filter((t) => /No urlscan classification/.test(t)).length, 0, 'unclassified is conveyed by the verdict/score tiles only');
  assert.match(v.sampleLine, /^Sample assessment: Insufficient evidence · 1 scan retrieved · 1 exact \/ 0 related · 0 malicious$/);
});

test('analysis findings: deterministic priority — coverage, then signals, then context; TLS details are technical', () => {
  const v = buildUrlscanView(http403);
  assert.deepEqual(v.findings.primary.map((f) => [f.code, f.title, f.tone]), [
    ['limited_visibility_http_error', 'Limited page visibility', 'caution'],
    ['engine_signal_conflict', 'Conflicting ML signal', 'caution']
  ]);
  assert.deepEqual(v.findings.technical.map((f) => f.code), ['self_issued_certificate', 'long_tls_validity']);
  assert.ok(v.findings.technical.every((f) => f.tone === 'neutral'), 'unusual TLS is not escalated to a warning');
  assert.equal(FINDING_PRIORITY.unclassified.group, 'covered');

  // Context findings stay visible but neutral; unknown codes fall back by backend level.
  const s = clone(http403);
  s.observations = [
    { code: 'off_domain_redirect', level: 'info', label: 'Redirected', detail: 'd' },
    { code: 'future_caution_code', level: 'caution', label: 'New caution', detail: 'x' },
    { code: 'future_info_code', level: 'info', label: 'New info', detail: 'y' }
  ];
  const w = buildUrlscanView(s);
  assert.deepEqual(w.findings.primary.map((f) => [f.code, f.tone]), [['future_caution_code', 'caution'], ['off_domain_redirect', 'neutral']]);
  assert.deepEqual(w.findings.technical.map((f) => f.title), ['New info']);
});

test('explicit malicious verdict is the only red state; ML stays a separate tile', () => {
  const v = buildUrlscanView(maliciousSummary());
  assert.equal(v.tiles[0].value, 'Malicious');
  assert.equal(v.tiles[0].tone, 'malicious');
  assert.equal(v.tiles[0].hint, 'Brands: Microsoft');
  assert.equal(v.tiles.find((t) => t.key === 'score').tone, 'malicious');
  assert.equal(v.tiles.find((t) => t.key === 'ml').value, 'No malicious signal · -98');
  assert.equal(v.tiles.find((t) => t.key === 'ml').tone, 'neutral');
  assert.match(v.summarySentence, /^Classified malicious by urlscan \(phishing\)\./);
  assert.equal(v.tiles.find((t) => t.key === 'visibility').value, 'Page loaded · HTTP 200');
});

test('collapsed section summaries are short and data-derived', () => {
  const v = buildUrlscanView(http403);
  assert.equal(v.networkSummary, '2 requests · 1 IP · 1 domain · 2 HTTP errors');
  assert.equal(v.tlsSummary, 'TLS 1.3 · Self-issued · 3650-day validity');
  assert.equal(v.relatedSummary, '1 IP · 1 SHA256');
  assert.equal(v.technologiesSummary, null, 'no technologies → no section');
  assert.equal(v.history.latestAt, '2026-10-10T11:30:37.899Z');
  const r = buildUrlscanView(offDomain);
  assert.match(r.networkSummary, /^12 requests · 4 IPs · 4 domains · 1 redirect$/);
  assert.match(r.technologiesSummary, /^6 detected · spin\.js, Microsoft ASP\.NET, Cloudflare Bot Management…$/);
});

test('network groups use semantically accurate labels and mute zero counters', () => {
  const v = buildUrlscanView(http403);
  const errors = v.networkGroups.find((g) => g.key === 'errors').rows;
  assert.deepEqual(errors.map((r) => [r.label, r.value, r.tone]), [
    ['HTTP errors (4xx/5xx)', 2, 'caution'],
    ['Failed loads', 0, 'muted'],
    ['Console errors', 2, null]
  ]);
  const activity = v.networkGroups.find((g) => g.key === 'activity').rows.map((r) => r.label);
  assert.ok(!activity.includes('Downloads') && !activity.includes('WebSockets'), 'zero-only optional counters hidden');
  assert.doesNotMatch(JSON.stringify(v.networkGroups), /≥400|>400/);
});

test('TLS evidence carries short flags instead of repeating the full finding text', () => {
  const v = buildUrlscanView(http403);
  const issuer = v.tlsRows.find((r) => r.label === 'Issuer');
  assert.equal(issuer.flag, 'Self-issued');
  assert.equal(v.tlsRows.find((r) => r.label === 'Validity period').flag, 'Exceeds 398-day public CA limit');
  assert.equal(v.tlsRows.find((r) => r.label === 'Protocol').flag, undefined);

  const noTls = clone(http403);
  noTls.detail_scans[0].tls = null;
  const w = buildUrlscanView(noTls);
  assert.deepEqual(w.tlsRows, []);
  assert.equal(w.tlsSummary, null);
});

test('related observables are grouped by role in a fixed order', () => {
  const v = buildUrlscanView(offDomain);
  assert.deepEqual(v.relatedGroups.map((g) => g.key), ['primary', 'redirect', 'same_site', 'third_party', 'linked', 'hash', 'download']);
  assert.ok(v.relatedGroups.find((g) => g.key === 'hash').items.every((r) => /not a malware sample/.test(r.relationship)));
  assert.deepEqual(v.relatedGroups.find((g) => g.key === 'third_party').items.map((r) => r.value).sort(), ['151.101.193.155', 'code.jquery.com']);
  assert.deepEqual(buildUrlscanView(http403).relatedGroups.map((g) => g.key), ['primary', 'hash']);
});

test('legacy v1 rows: no invented ML/visibility certainty beyond stored facts', () => {
  const v = buildUrlscanView(legacyV1);
  assert.equal(v.mlSignal, null);
  assert.equal(v.summarySentence, null);
  assert.equal(v.tiles[0].hint, 'Refresh to load the scan verdict');
  assert.deepEqual(v.tiles.map((t) => t.key), ['verdict', 'visibility', 'last_scan']);
  assert.equal(v.networkGroups.length, 0);
});

test('card provider states map from GET/refresh payloads', () => {
  const s = (data) => urlscanPayloadState(data).status;
  assert.equal(s({ provider_status: 'not_configured' }), 'not_configured');
  assert.equal(s({ provider_status: 'api_key_missing' }), 'not_configured');
  assert.equal(s({ provider_status: 'disabled' }), 'disabled');
  assert.equal(s({ provider_status: 'not_run' }), 'not_run');
  assert.equal(s({ provider_status: 'rate_limited' }), 'rate_limited');
  assert.equal(s({ provider_status: 'error' }), 'error');
  assert.equal(s({ provider_status: 'auth_error' }), 'error');
  assert.equal(s({ provider_status: 'skipped', summary: {} }), 'privacy_restricted');
  assert.equal(s({ provider_status: 'unsupported_private_ip' }), 'unsupported');
  assert.equal(s({ provider_status: 'not_found', summary: { evidence_assessment: 'no_results' } }), 'no_results');
  assert.equal(s({ provider_status: 'success', summary: http403 }), 'success');
  assert.equal(urlscanPayloadState({ provider_status: 'error', error_message: 'boom' }).message, 'boom');

  assert.equal(urlscanRefreshErrorState(429, {}).status, 'rate_limited');
  assert.equal(urlscanRefreshErrorState(409, { provider_status: 'not_configured' }).status, 'not_configured');
  assert.equal(urlscanRefreshErrorState(409, {}).status, 'disabled');
  assert.deepEqual(urlscanRefreshErrorState(502, { message: 'bad gateway' }), { status: 'error', message: 'bad gateway' });
});
