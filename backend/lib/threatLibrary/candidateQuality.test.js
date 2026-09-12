/**
 * Candidate typing + zone/evidence policy regressions (no vendor allowlists).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument } from './canonicalDocument.js';
import { extractCandidatesFromDocument } from './candidateExtraction.js';
import { resolveDottedTokenType } from './candidateTyping.js';
import { annotateDocumentZones, classifyHeadingText } from './documentZones.js';
import {
  applyEvidencePolicy,
  isEligibleForHighConfidenceMalicious,
  summarizeOccurrenceEvidence
} from './evidencePolicy.js';
import { buildSystemPrompt, formatCandidateEvidenceLine } from './ai/prompts.js';
import { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './ai/contract.js';

test('dotted filenames are not domains', () => {
  for (const token of [
    'OrionSetup.payload.enc',
    'guide.url.lnk',
    'mort.php',
    'uni.txt'
  ]) {
    const r = resolveDottedTokenType(token, {
      surroundingText: 'filename resource payload download 文件名',
      urlPathBasenames: new Set(['mort.php', 'uni.txt'])
    });
    assert.equal(r.kind, 'file_artifact', token);
  }
});

test('URL path basename does not become standalone domain', () => {
  const doc = createCanonicalDocument({
    title: 'C2 report',
    language: 'zh',
    blocks: [
      {
        id: 'p1-b01',
        type: 'paragraph',
        page: 1,
        text: '样本回连 http://217.60.36.94/unicorn/mort.php 与 http://217.60.36.94/unicorn/uni.txt'
      }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  const types = cands.map((c) => `${c.candidate_type}:${c.normalized_value}`);
  assert.ok(types.some((t) => t.startsWith('url:http://217.60.36.94/unicorn/mort.php')));
  // URL host is parser-derived metadata — no standalone IP without independent evidence
  assert.equal(types.some((t) => t === 'ip:217.60.36.94'), false);
  assert.equal(types.includes('domain:mort.php'), false);
  assert.equal(types.includes('domain:uni.txt'), false);
});

test('.NET style identifiers are not domains', () => {
  for (const token of ['loader.Program.Main', 'Program.Main']) {
    const r = resolveDottedTokenType(token, {
      surroundingText: '.NET class method Program.Main 反编译'
    });
    assert.equal(r.kind, 'code_identifier', token);
  }
  const doc = createCanonicalDocument({
    blocks: [
      {
        id: 'b1',
        type: 'paragraph',
        text: '调用 loader.Program.Main 与 Program.Main 入口'
      }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  assert.equal(
    cands.some((c) => c.candidate_type === 'domain' && /program\.main/i.test(c.normalized_value)),
    false
  );
});

test('real hostname still extracted as domain', () => {
  const r = resolveDottedTokenType('evil-c2.example.net', {
    surroundingText: 'malware connects to host evil-c2.example.net over HTTPS'
  });
  // example.net is RFC — extraction marks context_only but type is domain
  assert.equal(r.kind, 'domain');
  const doc = createCanonicalDocument({
    blocks: [
      {
        id: 'b1',
        type: 'heading',
        text: 'C2 Infrastructure'
      },
      {
        id: 'b2',
        type: 'paragraph',
        text: 'Beaconing to malware-c2.attacker.io was observed.'
      }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  assert.ok(cands.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'malware-c2.attacker.io'));
});

test('Chinese IOC appendix vs References section zones', () => {
  assert.equal(classifyHeadingText('附录 IOC'), 'explicit_ioc_section');
  assert.equal(classifyHeadingText('C&C'), 'c2_section');
  assert.equal(classifyHeadingText('参考链接'), 'reference_section');
  assert.equal(classifyHeadingText('References'), 'reference_section');

  const doc = createCanonicalDocument({
    language: 'zh',
    meta: { source_url: 'https://mp.weixin.qq.com/s/abc', source_host: 'mp.weixin.qq.com' },
    blocks: [
      { id: 'h1', type: 'heading', page: 10, text: '附录 IOC' },
      { id: 'b1', type: 'paragraph', page: 10, text: 'C2 http://217.60.36.94/unicorn/mort.php MD5 04272144d33668f99f7cf2255289e351' },
      { id: 'h2', type: 'heading', page: 11, text: '参考链接' },
      {
        id: 'b2',
        type: 'paragraph',
        page: 11,
        text: 'https://www.fortinet.com/blog/threat-research/example https://dev.to/excalibra/article'
      },
      {
        id: 'f1',
        type: 'paragraph',
        page: 1,
        text: 'https://mp.weixin.qq.com/s/abc'
      },
      {
        id: 'f2',
        type: 'paragraph',
        page: 2,
        text: 'https://mp.weixin.qq.com/s/abc'
      },
      {
        id: 'f3',
        type: 'paragraph',
        page: 3,
        text: 'https://mp.weixin.qq.com/s/abc'
      }
    ]
  });
  const annotated = annotateDocumentZones(doc, {
    sourceUrl: 'https://mp.weixin.qq.com/s/abc',
    sourceHost: 'mp.weixin.qq.com'
  });
  assert.equal(annotated.blocks.find((b) => b.id === 'b1').zone, 'explicit_ioc_section');
  assert.equal(annotated.blocks.find((b) => b.id === 'b2').zone, 'reference_section');

  const cands = extractCandidatesFromDocument(doc, { sourceUrl: 'https://mp.weixin.qq.com/s/abc' });
  const fortinet = cands.find((c) => c.normalized_value.includes('fortinet.com'));
  const weixin = cands.find((c) => c.normalized_value === 'mp.weixin.qq.com' || c.normalized_value.includes('mp.weixin.qq.com/s/abc'));
  const c2url = cands.find((c) => c.normalized_value.includes('217.60.36.94/unicorn/mort.php'));
  assert.ok(c2url);
  assert.ok(fortinet);
  assert.equal(fortinet.assessment, 'context_only');
  assert.ok(weixin);
  assert.equal(weixin.assessment, 'context_only');
});

test('same observable in reference + IOC section: strong evidence wins aggregation', () => {
  const candidate = {
    candidate_type: 'domain',
    normalized_value: 'dual.example.net',
    is_ioc: true,
    occurrences: [
      { zone: 'reference_section', section_kind: 'reference_section' },
      { zone: 'explicit_ioc_section', section_kind: 'explicit_ioc_section' }
    ]
  };
  const summary = summarizeOccurrenceEvidence(candidate);
  assert.equal(summary.hasStrong, true);
  assert.equal(summary.onlyNegative, false);
  assert.equal(summary.tier, 'A');
});

test('AI high confidence + weak evidence is not batch-approvable', () => {
  const c = applyEvidencePolicy({
    candidate_type: 'domain',
    normalized_value: 'vendor.example.org',
    assessment: 'malicious',
    confidence: 0.95,
    is_ioc: true,
    occurrences: [{ zone: 'reference_section' }]
  });
  assert.equal(c.assessment, 'context_only');
  assert.equal(isEligibleForHighConfidenceMalicious({ ...c, confidence: 0.95 }), false);
});

test('explicit IOC zone candidate remains eligible when malicious + strong evidence', () => {
  const c = {
    candidate_type: 'ip',
    normalized_value: '217.60.36.94',
    assessment: 'malicious',
    confidence: 0.95,
    is_ioc: true,
    occurrences: [{ zone: 'c2_section' }],
    policy_decision: 'pass'
  };
  applyEvidencePolicy(c);
  assert.equal(isEligibleForHighConfidenceMalicious(c), true);
});

test('semantic prompt teaches evidence rules and uses v4 contract', () => {
  const sys = buildSystemPrompt();
  assert.match(sys, /NOT malicious merely/i);
  assert.match(sys, /context_only/);
  assert.match(sys, /any language/i);
  assert.ok(sys.includes(THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION));
  assert.match(THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION, /v4$/);
  assert.match(sys, /parser-derived metadata/i);
  assert.match(sys, /authoritative/i);
  const line = formatCandidateEvidenceLine({
    candidate_id: 'cand-001',
    candidate_type: 'url',
    normalized_value: 'http://1.2.3.4/a.php',
    original_value: 'http://1.2.3.4/a.php',
    zone: 'c2_section',
    evidence_tier: 'A',
    occurrences: [{ zone: 'c2_section', page: 12, surrounding_text: 'C2 beacon URL' }]
  });
  assert.match(line, /c2_section/);
  assert.match(line, /cand-001/);
});

test('English references section mirrors Chinese behavior', () => {
  const doc = createCanonicalDocument({
    language: 'en',
    blocks: [
      { id: 'h1', type: 'heading', text: 'Indicators of Compromise' },
      { id: 'b1', type: 'paragraph', text: 'C2 IP 203.0.113.50' },
      { id: 'h2', type: 'heading', text: 'References' },
      { id: 'b2', type: 'paragraph', text: 'See https://research.example.org/report for prior work.' }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  const refUrl = cands.find((c) => c.candidate_type === 'url' && c.normalized_value.includes('research.example.org'));
  const ip = cands.find((c) => c.candidate_type === 'ip' && c.normalized_value === '203.0.113.50');
  assert.ok(ip);
  assert.ok(refUrl);
  assert.equal(refUrl.assessment, 'context_only');
});
