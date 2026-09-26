/**
 * Candidate identity vs. occurrence provenance (tl-candidates-v4).
 *
 * Rules under test:
 *  - a URL occurrence creates a URL candidate only; its host is parsed metadata
 *  - a standalone host candidate needs an independent source occurrence
 *  - IP:port endpoints are IP candidates with port evidence (never fake URLs)
 *  - explicit IOC / C&C rows are authoritative; references stay context-only
 *  - duplicates aggregate occurrences under one canonical identity
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCanonicalDocument } from './canonicalDocument.js';
import {
  extractCandidatesFromDocument,
  summarizeCandidateSet,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import { applyEvidencePolicy, buildCandidateEvidenceRecord, SOURCE_ASSERTIONS } from './evidencePolicy.js';
import { annotateDocumentZones } from './documentZones.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(fs.readFileSync(path.join(here, 'fixtures', 'kimsuky-appendix-canonical.json'), 'utf8'));

function doc(blocks, extra = {}) {
  return createCanonicalDocument({
    title: 'Provenance test',
    language: 'en',
    blocks: blocks.map((b, i) => ({ id: b.id || `b${i + 1}`, type: b.type || 'paragraph', page: b.page ?? 1, text: b.text, ...(b.layout ? { layout: b.layout } : {}) })),
    ...extra
  });
}

function keyOf(c) {
  return `${c.candidate_type}:${c.normalized_value}`;
}

test('extraction contract version bumped for evidence model', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v9');
});

test('URL with IP host only → URL candidate, no parser-derived IP candidate', () => {
  const cands = extractCandidatesFromDocument(doc([{ text: 'Malware downloaded from http://1.2.3.4/a.exe' }]));
  const keys = cands.map(keyOf);
  assert.ok(keys.includes('url:http://1.2.3.4/a.exe'));
  assert.equal(keys.includes('ip:1.2.3.4'), false, 'host must not be exploded into a separate IP');
  const url = cands.find((c) => c.candidate_type === 'url');
  assert.equal(url.parsed.host, '1.2.3.4');
  assert.equal(url.parsed.host_kind, 'ip');
  assert.equal(url.parsed.host_independently_asserted, false);
  assert.equal(url.is_direct_source_observable, true);
  assert.equal(url.occurrences.length, 1);
  assert.equal(url.occurrences[0].form, 'url');
});

test('same URL + standalone IP assertion → URL and IP with independent provenance', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'p1', page: 3, text: 'Malware downloaded from http://1.2.3.4/a.exe' },
      { id: 'p2', page: 7, text: 'C2 server: 1.2.3.4' }
    ])
  );
  const url = cands.find((c) => c.candidate_type === 'url');
  const ip = cands.find((c) => c.candidate_type === 'ip' && c.normalized_value === '1.2.3.4');
  assert.ok(url && ip);
  assert.equal(url.parsed.host_independently_asserted, true);
  assert.equal(ip.occurrences.length, 1);
  assert.equal(ip.occurrences[0].block_id, 'p2', 'IP provenance is the standalone span, not the URL block');
  assert.equal(ip.occurrences[0].form, 'standalone');
  assert.deepEqual(ip.parsed.also_url_host_of, ['http://1.2.3.4/a.exe']);
  assert.equal(ip.ai_needed, true, 'body mention still needs semantic judgement');
});

test('URL with domain host only → URL only unless domain separately asserted', () => {
  const only = extractCandidatesFromDocument(doc([{ text: 'Payload staged at https://evil-stage.example-c2.io/payload' }]));
  assert.equal(only.some((c) => c.candidate_type === 'domain'), false);
  assert.ok(only.some((c) => c.candidate_type === 'url' && c.parsed.host === 'evil-stage.example-c2.io'));

  const both = extractCandidatesFromDocument(
    doc([
      { id: 'a', text: 'Payload staged at https://evil-stage.example-c2.io/payload' },
      { id: 'b', text: 'The implant resolves evil-stage.example-c2.io every hour.' }
    ])
  );
  const dom = both.find((c) => c.candidate_type === 'domain');
  assert.ok(dom, 'independent standalone mention creates the domain candidate');
  assert.equal(dom.occurrences[0].block_id, 'b');
  assert.equal(dom.typing_reason, 'url_host');
});

test('reference URL is context-only and yields no domain candidate', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'h', type: 'heading', text: 'References' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', text: '[1] https://research.vendor-blog.example.org/kimsuky-lnk' }
    ])
  );
  assert.equal(cands.length, 1);
  const ref = cands[0];
  assert.equal(ref.candidate_type, 'url');
  assert.equal(ref.assessment, 'context_only');
  assert.equal(ref.source_assertion, SOURCE_ASSERTIONS.REFERENCE_ONLY);
  assert.equal(ref.ai_needed, false);
  assert.equal(ref.match_state, 'context_only');
});

test('explicit C2 appendix URL → malicious asserted, no automatic host candidate', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'h', type: 'heading', text: 'C&C:' },
      { id: 'c1', type: 'list_item', layout: 'observable_row', text: 'http[:]//203[.]0[.]113[.]9/gate/mort[.]php' }
    ])
  );
  assert.equal(cands.length, 1);
  const url = cands[0];
  assert.equal(url.candidate_type, 'url');
  assert.equal(url.normalized_value, 'http://203.0.113.9/gate/mort.php');
  assert.equal(url.assessment, 'malicious');
  assert.equal(url.role, 'command_and_control');
  assert.equal(url.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_C2);
  assert.equal(url.evidence_strength, 'strong');
  assert.equal(url.ai_needed, false);
  assert.equal(url.decision_source, 'deterministic');
  assert.ok(url.confidence >= 0.9);
});

test('explicit IP:port → standalone IP candidate with port evidence, not a URL', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'body', page: 11, text: 'Program.Main creates a Socket and connects to 107.172.249.140:443.' },
      { id: 'h', type: 'heading', page: 17, text: 'C&C:' },
      { id: 'row', type: 'list_item', layout: 'observable_row', page: 17, text: '107[.]172[.]249[.]140[:]443' }
    ])
  );
  assert.equal(cands.length, 1, 'one canonical identity for the endpoint');
  const ip = cands[0];
  assert.equal(ip.candidate_type, 'ip');
  assert.equal(ip.normalized_value, '107.172.249.140');
  assert.equal(ip.original_value, '107.172.249.140:443');
  assert.deepEqual(ip.parsed.ports, [443]);
  assert.equal(ip.occurrences.length, 2);
  assert.ok(ip.occurrences.every((o) => o.form === 'ip_port' && o.port === 443));
  assert.equal(ip.assessment, 'malicious');
  assert.equal(ip.role, 'command_and_control');
  assert.equal(ip.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_C2);
  assert.equal(cands.some((c) => c.candidate_type === 'url'), false, 'no fake URL');
});

test('duplicate values aggregate occurrences under one canonical identity', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'a', page: 2, text: 'MD5 7479bedf5813a1527199f8958e898d19' },
      { id: 'h', type: 'heading', page: 16, text: 'MD5' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', page: 16, text: '7479BEDF5813A1527199F8958E898D19' },
      { id: 'r2', type: 'list_item', layout: 'observable_row', page: 16, text: '7479bedf5813a1527199f8958e898d19' }
    ])
  );
  assert.equal(cands.length, 1);
  assert.equal(cands[0].occurrence_count, 3);
  assert.equal(cands[0].role, 'malware_sample');
  assert.equal(cands[0].source_assertion, SOURCE_ASSERTIONS.EXPLICIT_IOC);
  const rec = buildCandidateEvidenceRecord(cands[0]);
  assert.equal(rec.occurrence_count, 3);
  assert.deepEqual(rec.zones.sort(), ['report_body', 'sample_table']);
});

test('structural IOC list (no recognised heading) is still an explicit assertion', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'p', text: 'The following were observed during the intrusion:' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', text: '198.51.100.7' },
      { id: 'r2', type: 'list_item', layout: 'observable_row', text: '198.51.100.8' },
      { id: 'r3', type: 'list_item', layout: 'observable_row', text: 'update-check.badactor-example.net' }
    ])
  );
  assert.equal(cands.length, 3);
  for (const c of cands) {
    assert.equal(c.assessment, 'malicious', c.normalized_value);
    assert.equal(c.ai_needed, false);
  }
});

test('report source URL / printed footer is provenance, never a finding', () => {
  const footer = 'https://publisher.example-news.com/s/abc123 3/18';
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'f1', page: 1, layout: 'page_edge', text: footer },
      { id: 'b1', page: 1, text: 'Body text without indicators.' },
      { id: 'f2', page: 2, layout: 'page_edge', text: footer },
      { id: 'f3', page: 3, layout: 'page_edge', text: footer }
    ])
  );
  assert.equal(cands.length, 1);
  assert.equal(cands[0].assessment, 'context_only');
  assert.equal(cands[0].source_assertion, SOURCE_ASSERTIONS.SOURCE_METADATA);
  assert.equal(cands[0].role, 'reference');
  assert.equal(cands.some((c) => c.candidate_type === 'domain'), false);
});

test('AI cannot downgrade an explicit report assertion; may refine role', () => {
  const c = extractCandidatesFromDocument(
    doc([
      { id: 'h', type: 'heading', text: '附录 IOC' },
      { id: 'r', type: 'list_item', layout: 'observable_row', text: 'http://203.0.113.5/drop/x.bin' }
    ])
  )[0];
  applyEvidencePolicy(c, { assessment: 'context_only', role: 'reference', confidence: 0.2 });
  assert.equal(c.assessment, 'malicious');
  assert.notEqual(c.role, 'reference');
  applyEvidencePolicy(c, { assessment: 'malicious', role: 'payload_hosting', confidence: 0.95 });
  assert.equal(c.role, 'payload_hosting');
  assert.equal(c.confidence, 0.95);
});

test('body mention takes the AI decision; weak-evidence malicious is demoted', () => {
  const c = extractCandidatesFromDocument(doc([{ id: 'b', text: 'Traffic to 198.51.100.44 was blocked by the proxy.' }]))[0];
  assert.equal(c.ai_needed, true);
  applyEvidencePolicy(c, { assessment: 'suspicious', role: 'malicious_infrastructure', confidence: 0.6 });
  assert.equal(c.assessment, 'suspicious');
  assert.equal(c.decision_source, 'ai');
  assert.equal(c.ai_needed, false);
});

// --- Fixture regression: sanitized Kimsuky appendix report ----------------

const EXPECTED_MD5 = [
  '04272144d33668f99f7cf2255289e351',
  '3c64c75c9e6a3da7fbc766deb2081219',
  '7479bedf5813a1527199f8958e898d19',
  '9ae48e0ce0dfcac0245237fa220dd52d'
];
const EXPECTED_C2_URLS = [
  'http://217.60.36.94/unicorn/uni.txt',
  'http://217.60.36.94/unicorn/mort.php',
  'http://38.180.204.13/unicorn/mort.php',
  'http://38.180.204.13/unicorn/uni.txt'
];

test('fixture zones: appendix rows strong, references negative, footers header_footer', () => {
  const a = annotateDocumentZones(FIXTURE, {});
  const byId = new Map(a.blocks.map((b) => [b.id, b]));
  assert.equal(byId.get('p16-b79').zone, 'explicit_ioc_section');
  for (const id of ['p16-b81', 'p16-b82', 'p16-b83', 'p16-b84', 'p16-b85']) assert.equal(byId.get(id).zone, 'sample_table', id);
  for (const id of ['p17-b89', 'p17-b90', 'p17-b91', 'p17-b92', 'p17-b93']) assert.equal(byId.get(id).zone, 'c2_section', id);
  for (const id of ['p17-b95', 'p17-b96', 'p17-b97']) assert.equal(byId.get(id).zone, 'reference_section', id);
  const footers = a.blocks.filter((b) => b.layout === 'page_edge');
  assert.ok(footers.length >= 30);
  assert.ok(footers.every((b) => b.zone === 'header_footer'));
  // Title mentioning 远控木马 (RAT) must not open a C2 zone over the intro
  assert.equal(byId.get('p1-b02').zone, 'report_body');
  assert.equal(byId.get('p1-b07').zone, 'report_body');
});

test('fixture: every explicit appendix value is extracted, deduped and asserted', () => {
  const cands = extractCandidatesFromDocument(FIXTURE, {});
  const byKey = new Map(cands.map((c) => [keyOf(c), c]));

  for (const h of EXPECTED_MD5) {
    const c = byKey.get(`md5:${h}`);
    assert.ok(c, `missing MD5 ${h}`);
    assert.equal(c.assessment, 'malicious');
    assert.equal(c.role, 'malware_sample');
    assert.equal(c.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_IOC);
    assert.equal(c.ai_needed, false);
  }
  assert.equal(cands.filter((c) => c.candidate_type === 'md5').length, 4, 'repeated MD5 deduped to 4 identities');
  assert.equal(byKey.get('md5:7479bedf5813a1527199f8958e898d19').occurrence_count, 3);

  for (const u of EXPECTED_C2_URLS) {
    const c = byKey.get(`url:${u}`);
    assert.ok(c, `missing C2 URL ${u}`);
    assert.equal(c.assessment, 'malicious');
    assert.equal(c.role, 'command_and_control');
    assert.equal(c.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_C2);
  }
  const endpoint = byKey.get('ip:107.172.249.140');
  assert.ok(endpoint, 'direct C2 endpoint');
  assert.deepEqual(endpoint.parsed.ports, [443]);
  assert.equal(endpoint.assessment, 'malicious');
  assert.equal(endpoint.occurrence_count, 2, 'body "固定连接到 …:443" + appendix row');
});

test('fixture: URL-derived hosts and reference/source links never become IOC candidates', () => {
  const cands = extractCandidatesFromDocument(FIXTURE, {});
  const keys = new Set(cands.map(keyOf));
  assert.equal(keys.has('ip:217.60.36.94'), false, 'URL host only → no standalone IP');
  assert.equal(keys.has('ip:38.180.204.13'), false, 'URL host only → no standalone IP');
  assert.equal(cands.some((c) => c.candidate_type === 'domain'), false, 'no reference/source domains');

  const refs = cands.filter((c) => c.source_assertion === SOURCE_ASSERTIONS.REFERENCE_ONLY);
  assert.equal(refs.length, 3);
  assert.ok(refs.every((c) => c.assessment === 'context_only' && c.ai_needed === false));
  const source = cands.filter((c) => c.source_assertion === SOURCE_ASSERTIONS.SOURCE_METADATA);
  assert.equal(source.length, 1, 'printed footer URL is one context-only candidate');
  assert.equal(source[0].occurrence_count, 18);

  const s = summarizeCandidateSet(cands);
  assert.deepEqual(
    { total: s.total, ioc: s.ioc_candidates, explicit: s.explicit_assertions, ctx: s.context_only, ai: s.ai_needed },
    { total: 13, ioc: 9, explicit: 9, ctx: 4, ai: 0 }
  );
  // Nothing is left for a reviewer to reject by hand: no needs_review, no derived duplicates.
  assert.equal(cands.filter((c) => c.assessment === 'unknown').length, 0);
});
