/**
 * Twenty-report audit regressions (tl-candidates-v39 / tl-ipv6-tokens-v1 /
 * tl-type-resolver-v16). Generic shapes of the confirmed production defects,
 * with synthetic or documentation values:
 *
 * A. IPv6 recognition is standards-based: every valid spelling (mid-address
 *    `::`, leading / trailing compression, IPv4-mapped) is one address, an
 *    invalid run yields nothing (never a valid-looking fragment), and code /
 *    time / MAC shapes are not addresses. A bare IPv6 cell in an IOC table is
 *    an IP Indicator; narrative, documentation-range and sentinel addresses
 *    stay Context Only, as do resolver answers outside an IOC table.
 * B. A defanged mixed-case hostname in an IOC table (`EmbersAndBites[.]com`)
 *    is a domain; real code identifiers keep the artifact reading.
 *
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember, isContextOnlyCandidate } from './indicatorMembership.js';
import { findIpv6Tokens, IPV6_TOKENS_VERSION } from './ipv6Tokens.js';
import { normalizeCandidateValue } from './candidateValue.js';
import { parseIndicatorCell } from './tableSemantics.js';
import { resolveDottedToken, OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/twenty-report-audit/';

function run(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const find = (out, value) => out.candidates.find((c) => c.normalized_value === value);
const member = (out, value) => {
  const c = find(out, value);
  return Boolean(c) && isReportIndicatorMember(persisted(c));
};

const iocTable = (rows) => `<h2>Indicators of Compromise (IOCs)</h2>
<table><tr><th>Item</th><th>Description</th></tr>
${rows.map(([v, d]) => `<tr><td>${v}</td><td>${d}</td></tr>`).join('\n')}
</table>`;

test('versions: tl-candidates-v39, tl-ipv6-tokens-v1, tl-type-resolver-v16', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v45');
  assert.equal(IPV6_TOKENS_VERSION, 'tl-ipv6-tokens-v1');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v19');
});

test('A: IPv6 tokenizer accepts every valid spelling as one address', () => {
  const cases = [
    ['relay 2400:8d60:2::1:841d:5dd seen', '2400:8d60:2::1:841d:5dd'], // mid-address ::
    ['host 2001:db8::1 here', '2001:db8::1'],
    ['prefix 2001:db8:: only', '2001:db8::'], // trailing ::
    ['link-local fe80::1:2', 'fe80::1:2'], // leading group + ::
    ['mapped ::ffff:198.51.100.7 host', '::ffff:198.51.100.7'], // IPv4-mapped
    ['nat64 64:ff9b::192.0.2.33 host', '64:ff9b::192.0.2.33'],
    ['full 2001:0db8:0000:0000:0000:ff00:0042:8329 form', '2001:0db8:0000:0000:0000:ff00:0042:8329'],
    ['the relay 2001:db8::5: was', '2001:db8::5'], // label punctuation after
    ['sentence 2001:4998:44:3507::8000.', '2001:4998:44:3507::8000']
  ];
  for (const [text, expected] of cases) {
    assert.deepEqual(findIpv6Tokens(text).map((t) => t.value), [expected], text);
  }
});

test('A: IPv6 tokenizer never emits fragments, code, times or MAC addresses', () => {
  for (const text of [
    'b479:2771:8df4:b5eb:d007:63b0:2838', // 7 groups, no :: — invalid as a whole
    'at 12:34:56 UTC',
    'mac aa:bb:cc:dd:ee:ff',
    'C++ Bad::Face and std::vector and dead::beef',
    'glued host2001:db8::1',
    'suffix 2001:db8::1.example.com',
    '::ffff:1.2.3.4.5',
    'lone 1:: and ::'
  ]) {
    assert.deepEqual(findIpv6Tokens(text), [], text);
  }
});

test('A: a bare IPv6 value is an IP, not a hostname (typed table cells)', () => {
  const n = normalizeCandidateValue('2400:8d60:2::1:841d:5dd', null);
  assert.equal(n.ok, true);
  assert.equal(n.candidateType, 'ipv6');
  assert.equal(n.normalizedValue, '2400:8d60:2::1:841d:5dd');
  const trailing = parseIndicatorCell('2001:db8:85::', null);
  assert.deepEqual(trailing.values.map((v) => v.normalized_value), ['2001:db8:85::']);
});

test('A: compressed IPv6 in an IOC table is an Indicator (31389 shape)', () => {
  const out = run(iocTable([
    ['185.238.2[.]195', 'AiTM relay that captured the session.'],
    ['2400:8d60:2::1:841d:5dd', 'AiTM relay, hosting provider (Phase 4).'],
    ['::ffff:185.238.2.196', 'Mapped relay address.']
  ]));
  assert.equal(member(out, '185.238.2.195'), true);
  assert.equal(member(out, '2400:8d60:2::1:841d:5dd'), true);
  const c = find(out, '2400:8d60:2::1:841d:5dd');
  assert.equal(c.candidate_type, 'ipv6');
  // The mapped form is one IPv6 identity; its IPv4 tail is not a second value.
  assert.ok(out.candidates.some((x) => x.candidate_type === 'ipv6' && /^::ffff:/.test(x.normalized_value)));
  assert.equal(find(out, '185.238.2.196'), undefined);
});

test('A: an IPv6 URL keeps one URL identity and no duplicate bare address', () => {
  const out = run(iocTable([['hxxp://[2a03:90c0:85::28a]:8080/gate', 'C2 URL']]));
  assert.equal(member(out, 'http://[2a03:90c0:85::28a]:8080/gate'), true);
  assert.equal(find(out, '2a03:90c0:85::28a'), undefined);
});

test('A: narrative sentinel / documentation IPv6 stay Context Only (18652 shape)', () => {
  const out = run(`<p>The module resolves an AAAA record and compares the answer with the hard-coded sentinel 2001:4998:44:3507::8000; the documentation address 2001:db8::1 is never contacted.</p>
${iocTable([['185.238.2[.]195', 'C2 server']])}`);
  for (const v of ['2001:4998:44:3507::8000', '2001:db8::1']) {
    const c = find(out, v);
    assert.ok(c, v);
    assert.equal(isReportIndicatorMember(persisted(c)), false, v);
  }
  assert.equal(member(out, '185.238.2.195'), true);
});

// 30270 shape: the formal IOC section only points elsewhere (delegated body
// scope) and an infrastructure table lists each domain with its DNS answer.
const resolutionTable = (resolvedHeader) => `<h2>Infrastructure and victimology</h2>
<p>The operators rotated infrastructure across campaigns; the table lists each domain or server with the address it resolved to.</p>
<table><tr><th>Domain / IP</th><th>First Campaign / DNS Observation (UTC)</th><th>${resolvedHeader}</th><th>Geo</th></tr>
<tr><td>codec-video[.]example</td><td>2025-06-17</td><td>NA</td><td>Cloudflare</td></tr>
<tr><td>185.221.23[.]133</td><td>2025-06-30</td><td>NA</td><td>Finland</td></tr>
<tr><td>version.checker.workers[.]example</td><td>2025-07-30</td><td>172.67.200[.]134</td><td>Cloudflare</td></tr>
<tr><td>version.checker.workers[.]example</td><td>2025-07-31</td><td>2606:4700:3035::6815[:]44fa</td><td>Cloudflare</td></tr>
<tr><td>version.checker.workers[.]example</td><td>2025-07-31</td><td>2606:4700:3037::ac43[:]c886</td><td>Cloudflare</td></tr>
<tr><td>176.98.187[.]47</td><td>2025-09-12</td><td>NA</td><td>Russia</td></tr>
<tr><td>codec-audio[.]example</td><td>2025-09-12</td><td>176.98.187[.]47</td><td>Russia</td></tr>
<tr><td>seguranca.version-nova[.]example</td><td>2026-06-30</td><td>188.114.96[.]0</td><td>Cloudflare</td></tr>
</table>
<h2>Indicators of compromise</h2>
<p>The indicators for this research are available in our GitHub repository release.</p>`;

test('A: DNS answers in a resolution column never become Indicators (30270 shape)', () => {
  for (const header of ['Resolved IP', 'Resolves to', 'A record']) {
    const out = run(resolutionTable(header));
    for (const v of ['2606:4700:3035::6815:44fa', '2606:4700:3037::ac43:c886', '172.67.200.134', '188.114.96.0']) {
      const c = find(out, v);
      if (c) assert.equal(isReportIndicatorMember(persisted(c)), false, `${header}: ${v}`);
    }
    // The row's own indicators keep their delegated-scope membership.
    for (const v of ['185.221.23.133', '176.98.187.47']) {
      assert.equal(member(out, v), true, `${header}: ${v}`);
    }
  }
});

test('B: a defanged PascalCase hostname in an IOC table is a domain Indicator (31388 shape)', () => {
  const out = run(iocTable([
    ['EmbersAndBites[.]com', 'Attacker infrastructure'],
    ['Thegrilljournal[.]com', 'Attacker infrastructure']
  ]));
  const c = find(out, 'embersandbites.com');
  assert.ok(c, 'embersandbites.com extracted as a domain');
  assert.equal(c.candidate_type, 'domain');
  assert.equal(isReportIndicatorMember(persisted(c)), true);
  assert.equal(member(out, 'thegrilljournal.com'), true);
  assert.equal(out.candidates.some((x) => x.candidate_type === 'technical_artifact' && /embersandbites/i.test(x.normalized_value)), false);
});

test('B: the resolver keeps code identifiers as artifacts without a defang marker', () => {
  assert.equal(resolveDottedToken('EmbersAndBites[.]com').kind, 'domain');
  assert.equal(resolveDottedToken('EmbersAndBites[.]com').reason, 'defanged_mixed_case');
  for (const token of ['Socket.IO', 'embed.FS', 'bytes.Index', 'Loader.Program.Main', 'System.Net.Http', 'MyApp.Config']) {
    assert.notEqual(resolveDottedToken(token).kind, 'domain', token);
  }
  // A defang marker never rescues a value without a delegated DNS suffix.
  assert.notEqual(resolveDottedToken('Loader[.]Program[.]Main').kind, 'domain');
});

test('B: code identifiers written in prose keep the artifact reading', () => {
  const out = run(`<p>The loader calls Loader.Program.Main and reads embed.FS before opening Socket.IO.</p>
${iocTable([['185.238.2[.]195', 'C2 server']])}`);
  for (const c of out.candidates) {
    if (/^(?:loader\.program\.main|embed\.fs|socket\.io)$/i.test(c.normalized_value)) {
      assert.notEqual(c.candidate_type, 'domain', c.normalized_value);
      assert.equal(isReportIndicatorMember(persisted(c)), false, c.normalized_value);
    }
  }
});

test('A/B: Context Only classification is preserved for benign narrative values', () => {
  const out = run(`<p>Documentation range 2001:db8::7 appears in the vendor sample configuration.</p>${iocTable([['EmbersAndBites[.]com', 'Attacker infrastructure']])}`);
  const doc = find(out, '2001:db8::7');
  assert.ok(doc);
  assert.equal(isContextOnlyCandidate(doc) || !isReportIndicatorMember(persisted(doc)), true);
});
