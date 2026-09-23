/**
 * Numeric DNS prefix must not become a standalone IPv4 candidate.
 *
 * The model (and a `\b`-only IPv4 regex) can carve `128.200.178.68` out of
 * `128.200.178.68.host.secureserver.net`. Extraction and AI merge both refuse
 * that split unless the IP also has an independent source span.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument } from './canonicalDocument.js';
import { extractCandidatesFromDocument } from './candidateExtraction.js';
import { mergeAiCandidateUpdates } from './pipeline.js';
import { applyEvidencePolicy } from './evidencePolicy.js';

function doc(texts) {
  return createCanonicalDocument({
    title: 'Numeric hostname prefix',
    language: 'en',
    blocks: texts.map((text, i) => ({
      id: `b${i + 1}`,
      type: 'paragraph',
      page: 1,
      text
    }))
  });
}

function keys(cands) {
  return new Set(cands.map((c) => `${c.candidate_type}:${c.normalized_value}`));
}

function ips(cands) {
  return cands.filter((c) => c.candidate_type === 'ip').map((c) => c.normalized_value);
}

function domains(cands) {
  return cands.filter((c) => c.candidate_type === 'domain').map((c) => c.normalized_value);
}

test('1. defanged hostname with numeric prefix → domain, no standalone IP', () => {
  const cands = extractCandidatesFromDocument(
    doc(['128[.]200[.]178[.]68[.]host[.]secureserver[.]net'])
  );
  assert.ok(
    domains(cands).includes('128.200.178.68.host.secureserver.net'),
    `expected hostname, got ${[...keys(cands)].join(',')}`
  );
  assert.equal(ips(cands).includes('128.200.178.68'), false);
});

test('2. refanged hostname must not emit the IPv4 prefix', () => {
  const cands = extractCandidatesFromDocument(doc(['128.200.178.68.host.secureserver.net']));
  assert.ok(domains(cands).includes('128.200.178.68.host.secureserver.net'));
  assert.equal(ips(cands).includes('128.200.178.68'), false);
});

test('3. genuine standalone defanged IP is extracted', () => {
  const cands = extractCandidatesFromDocument(doc(['C2 server: 128[.]200[.]178[.]68']));
  assert.ok(ips(cands).includes('128.200.178.68'));
});

test('4. both standalone IP and hostname when each occurs independently', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      'C2 IP: 128[.]200[.]178[.]68',
      'Host: 128[.]200[.]178[.]68[.]host[.]secureserver[.]net'
    ])
  );
  assert.ok(ips(cands).includes('128.200.178.68'));
  assert.ok(domains(cands).includes('128.200.178.68.host.secureserver.net'));
});

test('5. AI hallucinated hostname split is rejected by merge grounding', () => {
  const source = '128[.]200[.]178[.]68[.]host[.]secureserver[.]net';
  const document = doc([source]);
  const deterministic = extractCandidatesFromDocument(document);
  assert.equal(ips(deterministic).includes('128.200.178.68'), false);

  const aiHallucination = {
    candidate_updates: [
      {
        candidate_type: 'ip',
        normalized_value: '128.200.178.68',
        assessment: 'malicious',
        role: 'command_and_control',
        confidence: 0.99
      }
    ]
  };
  const mergedUnknown = mergeAiCandidateUpdates(deterministic, aiHallucination, { document });
  assert.equal(ips(mergedUnknown).includes('128.200.178.68'), false, 'unknown AI IP is not inserted');

  // Simulate a stale/buggy extractor or a future model-added identity already
  // sitting in the candidate set. Merge must still drop it when the source
  // only contains the larger hostname.
  const poisoned = applyEvidencePolicy({
    candidate_type: 'ip',
    original_value: '128.200.178.68',
    normalized_value: '128.200.178.68',
    assessment: 'unknown',
    role: 'unknown',
    is_ioc: true,
    occurrences: [{ form: 'standalone', zone: 'report_body', surrounding_text: source }],
    parsed: {}
  });
  const mergedPoisoned = mergeAiCandidateUpdates([...deterministic, poisoned], aiHallucination, {
    sourceText: source
  });
  assert.equal(
    ips(mergedPoisoned).includes('128.200.178.68'),
    false,
    'embedded-only IP is dropped even if already in the set'
  );
});

test('6. other numeric-prefix hostnames never create standalone IPv4', () => {
  const cands = extractCandidatesFromDocument(
    doc(['10[.]20[.]30[.]40[.]foo[.]example[.]com', '1[.]2[.]3[.]4[.]subdomain[.]example[.]org'])
  );
  assert.ok(domains(cands).includes('10.20.30.40.foo.example.com'));
  assert.ok(domains(cands).includes('1.2.3.4.subdomain.example.org'));
  assert.equal(ips(cands).includes('10.20.30.40'), false);
  assert.equal(ips(cands).includes('1.2.3.4'), false);
});

test('7. punctuation boundaries still extract standalone IPs', () => {
  const cands = extractCandidatesFromDocument(doc(['(1.2.3.4)', '1.2.3.4,', '"1.2.3.4"']));
  const found = ips(cands);
  assert.ok(found.includes('1.2.3.4'), `expected 1.2.3.4, got ${found.join(',')}`);
  assert.equal(found.filter((v) => v === '1.2.3.4').length, 1, 'deduped to one identity');
});

test('8. IP-host URL keeps existing URL-only semantics (no exploded IP)', () => {
  const cands = extractCandidatesFromDocument(doc(['https://1.2.3.4/path']));
  const k = keys(cands);
  assert.ok(k.has('url:https://1.2.3.4/path'));
  assert.equal(k.has('ip:1.2.3.4'), false, 'URL host must not become a standalone IP');
});
