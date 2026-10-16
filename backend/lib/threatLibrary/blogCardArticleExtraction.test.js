/**
 * Blog themes that reuse `<article>` for hero/related cards while the real
 * post body lives under `<main>` / entry-content must not produce chrome-only
 * documents or silent zero-Indicator imports.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  extractCanonicalDocumentFromHtml,
  extractGenericArticleDocument,
  extractStructuredFallbackDocument,
  isSubstantiallyDenser,
  pickBestContentRoot
} from './extract/extractHtml.js';
import { assessDocumentQuality, meaningfulCharCount } from './extract/quality.js';
import { annotateDocumentZones } from './documentZones.js';
import {
  extractCandidatesFromDocument,
  extractCandidatesWithDiagnostics
} from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), 'extract', 'fixtures');
const load = (name) => readFileSync(join(fixtureDir, name), 'utf8');

const URL =
  'https://www.vendor.example/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/';

const EXPECTED = Object.freeze({
  sha256: [
    '54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668',
    'fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb',
    '9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc'
  ],
  domains: ['npm-cache.com', 'pypi-get.com', 'js-mirror.com'],
  // Default HTTPS port 443 is stripped by existing URL canonicalization.
  url: 'https://npm-cache.com/router'
});

const member = (c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) });
const find = (cands, type, value) =>
  cands.find((c) => c.candidate_type === type && String(c.normalized_value || '').toLowerCase() === value.toLowerCase());

function extractPipeline(html, url = URL) {
  const extracted = extractCanonicalDocumentFromHtml(html, {
    url,
    finalUrl: url,
    httpStatus: 200
  });
  assert.equal(extracted.ok, true, extracted.message || extracted.code);
  const annotated = annotateDocumentZones(extracted.document);
  const { candidates, diagnostics } = extractCandidatesWithDiagnostics(annotated);
  return { extracted, annotated, candidates, diagnostics };
}

test('pickBestContentRoot prefers denser main over thin card article', () => {
  const chosen = pickBestContentRoot([
    { kind: 'article', score: 259, blocks: [] },
    { kind: 'main', score: 15972, blocks: [] },
    { kind: 'article', score: 180, blocks: [] }
  ]);
  assert.equal(chosen.kind, 'main');
  assert.equal(isSubstantiallyDenser(15972, 259), true);
  assert.equal(isSubstantiallyDenser(300, 259), false);
});

test('thin card <article> + entry-content: layered extraction recovers body and IOC table', () => {
  const html = load('blog-card-article-thin.html');
  const { extracted, annotated, candidates } = extractPipeline(html);

  assert.ok(meaningfulCharCount(extracted.document) > 800);
  assert.ok(
    extracted.document.blocks.length >= 8,
    `expected a multi-section body, got ${extracted.document.blocks.length} blocks`
  );
  assert.ok(
    extracted.document.blocks.some((b) => /indicators of compromise/i.test(b.text || '')),
    'IOC heading must survive'
  );
  assert.ok(
    annotated.blocks.some((b) => b.type === 'table'),
    'Indicator|Description table must survive normalization'
  );
  assert.ok(
    extracted.path.includes('generic_html') || extracted.path.includes('structured_fallback_preferred'),
    `path=${JSON.stringify(extracted.path)}`
  );

  for (const hash of EXPECTED.sha256) {
    const c = find(candidates, 'sha256', hash);
    assert.ok(c, `missing sha256 ${hash}`);
    assert.equal(member(c), true, `sha256 ${hash} must be MODE A Indicator`);
    assert.ok(c.evidence || buildCandidateEvidenceRecord(c));
  }
  for (const domain of EXPECTED.domains) {
    const c = find(candidates, 'domain', domain);
    assert.ok(c, `missing domain ${domain}`);
    assert.equal(member(c), true, `domain ${domain} must be MODE A Indicator`);
  }
  const urlCand = find(candidates, 'url', EXPECTED.url);
  assert.ok(urlCand, `missing defanged URL ${EXPECTED.url}`);
  assert.equal(member(urlCand), true);
  const urlEvidence = buildCandidateEvidenceRecord(urlCand);
  assert.ok(
    /npm-cache/i.test(JSON.stringify(urlCand)) || /npm-cache/i.test(JSON.stringify(urlEvidence)),
    'publisher evidence for C2 URL must remain'
  );

  const indicators = candidates.filter(member);
  assert.equal(indicators.length, 7, `expected 7 Indicators, got ${indicators.map((c) => `${c.candidate_type}:${c.normalized_value}`).join(', ')}`);

  // Narrative platform mentions must not auto-promote.
  assert.equal(member(find(candidates, 'domain', 'github.com') || { is_ioc: false }), false);
  assert.equal(member(find(candidates, 'domain', 'registry.npmjs.org') || { is_ioc: false }), false);
});

test('idempotent: repeating extraction yields the same Indicator set', () => {
  const html = load('blog-card-article-thin.html');
  const a = extractPipeline(html).candidates.filter(member).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();
  const b = extractPipeline(html).candidates.filter(member).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();
  assert.equal(a.length, 7);
  assert.deepEqual(a, b);
});

test('hunting-query code blocks are not treated as the IOC table', () => {
  const html = load('blog-card-article-thin.html');
  const { annotated, candidates } = extractPipeline(html);
  const codeBlocks = annotated.blocks.filter((b) => b.type === 'code' || /DeviceFileEvents/.test(b.text || ''));
  assert.ok(codeBlocks.length >= 1, 'hunting query fixture must include a code block');
  // The SHA256 inside the hunting query is the same as a formal IOC — membership
  // still comes from the IOC table, not from inventing extras out of the query.
  const shaMembers = candidates.filter((c) => c.candidate_type === 'sha256' && member(c));
  assert.equal(shaMembers.length, 3);
  assert.equal(candidates.filter(member).length, 7);
});

test('negative: technical guidance with no formal IOC section yields no Indicators', () => {
  const html = load('technical-no-formal-iocs.html');
  const { extracted, candidates } = extractPipeline(
    html,
    'https://www.vendor.example/security/blog/hardening-ci-runners/'
  );
  assert.ok(meaningfulCharCount(extracted.document) > 200);
  assert.ok(extracted.document.blocks.some((b) => /hardening ci runners/i.test(b.text || '') || b.type === 'heading'));
  const indicators = candidates.filter(member);
  assert.equal(
    indicators.length,
    0,
    `expected zero Indicators, got ${indicators.map((c) => `${c.candidate_type}:${c.normalized_value}`).join(', ')}`
  );
});

test('byline-chrome-only document fails quality gate (no silent zero success)', () => {
  const chrome = extractGenericArticleDocument(
    `<html><body><article class="card-block">
      <p>Research</p><p>August 4</p><p>10 min read</p>
      <h1>Some Title About a Worm</h1>
      <p>By Vendor Security Research</p>
      <p>view all posts by this author</p>
      <p>, Alice Analyst</p>
      <p>view all posts by this author</p>
    </article></body></html>`,
    { url: 'https://vendor.example/x' }
  );
  // Force-assess the thin card alone (as the pre-fix layered path did).
  const q = assessDocumentQuality(chrome);
  assert.equal(q.ok, false);
  assert.equal(q.code, 'document_below_quality_threshold');
  assert.ok(q.reasons.includes('byline_chrome_only'));
});

test('structured fallback alone recovers entry-content when generic is thin', () => {
  const html = load('blog-card-article-thin.html');
  // Simulate legacy first-article-only behaviour by scoring the thin card path
  // against structured fallback density.
  const firstArticleOnly = extractGenericArticleDocument(
    html.replace(/<main[\s\S]*?<\/main>/i, ''),
    { url: URL }
  );
  // Without main, related cards may remain — still should be short vs full page fallback.
  const fallback = extractStructuredFallbackDocument(html, { url: URL });
  assert.ok(isSubstantiallyDenser(meaningfulCharCount(fallback), meaningfulCharCount(firstArticleOnly)));
  assert.ok(fallback.blocks.some((b) => /indicators of compromise/i.test(b.text || '')));
});
