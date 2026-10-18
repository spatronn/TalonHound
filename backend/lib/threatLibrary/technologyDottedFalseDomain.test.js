/**
 * Regression: technology / runtime dotted names (Node.js) must never become
 * publisher-asserted domain Indicators merely because they look hostname-shaped
 * or appear in post-IOC article tag metadata.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { annotateDocumentZones, THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from './documentZones.js';
import {
  extractCandidatesWithDiagnostics,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { isObservableOnlyLine } from './pdfLayout.js';
import { isIndicatorValueLine } from './indicatorScope.js';
import {
  OBSERVABLE_TYPE_RESOLVER_VERSION,
  hasDelegatedDnsSuffix,
  resolveDottedToken
} from './observableTypeResolver.js';

assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v13');
assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v30');
assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v10');

function extract(html) {
  const { document } = extractCanonicalDocumentFromHtml(html, {
    url: 'https://vendor.example/report/1'
  });
  const zoned = annotateDocumentZones(document, {
    sourceUrl: 'https://vendor.example/report/1',
    sourceHost: 'vendor.example'
  });
  return extractCandidatesWithDiagnostics(zoned);
}

function keyOf(c) {
  return `${c.candidate_type}:${String(c.normalized_value).toLowerCase()}`;
}

test('Node.js is not an observable-only / indicator value line', () => {
  assert.equal(isObservableOnlyLine('Node.js'), false);
  assert.equal(isIndicatorValueLine('Node.js'), false);
  assert.equal(isObservableOnlyLine('payload.js'), false);
  assert.equal(isIndicatorValueLine('evil.example.com'), true);
  assert.equal(isIndicatorValueLine('example[.]com'), true);
});

test('heading-inherited Domains label cannot promote Node.js; typed Domain table cell still can for unusual suffixes', () => {
  assert.equal(hasDelegatedDnsSuffix('node.js'), false);
  const heading = resolveDottedToken('Node.js', {
    typeLabel: 'Domains and IPs',
    declaredType: 'domain',
    form: 'list_row',
    strongZone: true,
    indicatorRow: true
  });
  assert.equal(heading.kind, 'technical_artifact');
  assert.equal(heading.reason, 'file_extension');

  const table = resolveDottedToken('archive-sync.war', {
    typeLabel: 'Domain',
    declaredType: 'domain',
    form: 'table_row',
    strongZone: true
  });
  assert.equal(table.kind, 'domain');
  assert.equal(table.reason, 'declared_network_type');
});

test('1. prose "built with Node.js" is not a domain Indicator', () => {
  const { candidates } = extract(`<!doctype html><html><body><article>
<p>NodeRabbit is a cross-platform remote access trojan (RAT) built with Node.js.</p>
</article></body></html>`);
  assert.equal(
    candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'node.js'),
    false
  );
  assert.equal(
    candidates.some((c) => String(c.normalized_value).toLowerCase() === 'node.js' && isReportIndicatorMember(c)),
    false
  );
});

test('2. repeated Node.js prose does not produce a domain Indicator', () => {
  const { candidates } = extract(`<!doctype html><html><body><article>
<p>Node.js</p>
<p>Node.js</p>
<p>Node.js</p>
</article></body></html>`);
  assert.equal(
    candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'node.js'),
    false
  );
});

test('3. formal IOC section then article tags: evil.example.com stays Indicator; Node.js does not inherit IOC scope', () => {
  const html = `<!doctype html><html><body><article>
<p>Background analysis of the campaign.</p>
<h2>Indicators of compromise</h2>
<h3>Domains and IPs</h3>
<p>evil.example.com</p>
<ul>
<li>Targeted attacks</li>
<li>NodeRabbit</li>
<li>PollCat</li>
<li>Mirage Kitten</li>
<li>Node.js</li>
<li>JavaScript</li>
<li>Malware</li>
</ul>
<p>Your email address will not be published. Required fields are marked *</p>
</article></body></html>`;
  const { document } = extractCanonicalDocumentFromHtml(html, { url: 'https://vendor.example/r' });
  const zoned = annotateDocumentZones(document, {
    sourceUrl: 'https://vendor.example/r',
    sourceHost: 'vendor.example'
  });
  const tag = zoned.blocks.find((b) => b.text === 'Node.js');
  assert.ok(tag, 'Node.js tag block present');
  assert.notEqual(tag.zone, 'explicit_ioc_section');
  assert.notEqual(tag.zone, 'sample_table');
  assert.notEqual(tag.declared_type_label, 'domain');
  assert.ok(
    tag.zone === 'source_metadata' || tag.zone === 'report_body',
    `tag zone should be outside IOC scope, got ${tag.zone}`
  );

  const { candidates } = extractCandidatesWithDiagnostics(zoned);
  const evil = candidates.find((c) => keyOf(c) === 'domain:evil.example.com');
  assert.ok(evil, 'publisher domain remains');
  assert.equal(evil.source_assertion, 'explicit_ioc');
  assert.equal(isReportIndicatorMember(evil), true);

  assert.equal(
    candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'node.js'),
    false,
    'Node.js must not be a domain candidate'
  );
  assert.equal(
    candidates.some((c) => String(c.normalized_value).toLowerCase() === 'node.js' && isReportIndicatorMember(c)),
    false
  );
});

test('4. valid delegated domains still extract normally', () => {
  const { candidates } = extract(`<!doctype html><html><body><article>
<h2>Indicators of compromise</h2>
<ul>
<li>relay-cache.example.com</li>
<li>panel-sync.online</li>
<li>drop.example.net</li>
</ul>
</article></body></html>`);
  for (const d of ['relay-cache.example.com', 'panel-sync.online', 'drop.example.net']) {
    const hit = candidates.find((c) => keyOf(c) === `domain:${d}`);
    assert.ok(hit, d);
    assert.equal(isReportIndicatorMember(hit), true, d);
  }
});

test('5. defanged publisher domains continue to work', () => {
  const { candidates } = extract(`<!doctype html><html><body><article>
<h2>Indicators of compromise</h2>
<ul>
<li>example[.]com</li>
<li>cdn-stage[.]example[.]net</li>
</ul>
</article></body></html>`);
  assert.ok(candidates.find((c) => keyOf(c) === 'domain:example.com'));
  assert.ok(candidates.find((c) => keyOf(c) === 'domain:cdn-stage.example.net'));
  assert.equal(candidates.find((c) => keyOf(c) === 'domain:example.com').source_assertion, 'explicit_ioc');
});

test('7. Securelist-shaped Mirage Kitten fixture: Node.js tag after Domains and IPs is not an Indicator', () => {
  const html = `<!doctype html><html><body><article>
<h1>Mirage Kitten switches to Node.js and JavaScript malware</h1>
<p>NodeRabbit is a cross-platform remote access trojan (RAT) built with Node.js.</p>
<p>NodeRabbit and PollCat represent the first publicly documented use of Node.js- and JavaScript-based malware.</p>
<h2>Indicators of compromise</h2>
<h3>File hashes</h3>
<p>CBAAF0900A13F28E380F49ADECEC932C FrontEnd-Task.zip</p>
<p>1EA83E4E4592B01E4ACAB63EB867BEE5 Front-Technical-Challenge.zip</p>
<h3>Domains and IPs</h3>
<p>oracle-challenge.s3[.]us-east-1.amazonaws[.]com</p>
<p>mens-health-online[.]com</p>
<ul class="tags">
<li>Targeted attacks</li>
<li>NodeRabbit</li>
<li>PollCat</li>
<li>Mirage Kitten</li>
<li>Node.js</li>
<li>Cross-platform malware</li>
<li>Backdoor</li>
<li>Trojan</li>
<li>APT</li>
<li>Malware</li>
<li>JavaScript</li>
</ul>
</article></body></html>`;
  const { candidates } = extract(html);
  const keys = new Set(candidates.filter((c) => isReportIndicatorMember(c)).map(keyOf));
  assert.ok(keys.has('domain:mens-health-online.com'));
  assert.ok(keys.has('domain:oracle-challenge.s3.us-east-1.amazonaws.com'));
  assert.ok(keys.has('md5:cbaaf0900a13f28e380f49adecec932c') || keys.has('md5:1ea83e4e4592b01e4acab63eb867bee5'));
  assert.equal(keys.has('domain:node.js'), false);
  assert.equal(
    candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'node.js'),
    false
  );
});
