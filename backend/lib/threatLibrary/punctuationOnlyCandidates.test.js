/**
 * tl-candidates-v22: a value with no letter or digit is never an observable.
 * Report 18651's MITRE cell "T1497.001 / T1497.003" produced a Context Only
 * `relative_path "/"`; real paths, URL paths and indicators are unaffected.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { normalizeCandidateValue } from './candidateValue.js';
import { classifyPathLikeShape } from './observableTypeResolver.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';

test('contract bumped for the punctuation-only rule', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v40');
});

test('separators and punctuation fragments are rejected', () => {
  for (const v of ['/', '//', './', '../', '\\', '--', '|', '.', '…', '::', '/ /', '-/-']) {
    const r = normalizeCandidateValue(v);
    assert.equal(r.ok, false, JSON.stringify(v));
  }
  for (const v of ['/', './', '../']) assert.equal(classifyPathLikeShape(v), 'other', v);
});

test('real relative paths, URL paths and indicators are preserved', () => {
  const path = (v) => normalizeCandidateValue(v);
  for (const v of ['/api/auto-register', '/ws/agent', './run.sh', '../lib/loader.so', '/payload.txt']) {
    const r = path(v);
    assert.equal(r.ok, true, v);
    assert.equal(r.candidateType, 'relative_path', v);
    assert.equal(r.normalizedValue, v);
  }
  assert.equal(classifyPathLikeShape('/payload.bin'), 'relative_path');
  assert.equal(path('https://workinghardo.link/download-agent').candidateType, 'url');
  assert.equal(path('workinghardo[.]link').candidateType, 'domain');
  assert.equal(path('103.193.173[.]199').candidateType, 'ip');
  assert.equal(path('T1497.001').candidateType, 'attack_technique');
  assert.equal(path('5fff61dff1fe18f59ebabe729c5ff9c42de64911248fb424815755fc7e76d5a1').candidateType, 'sha256');
});

test('18651-shaped report: 23 publisher Indicators unchanged, MITRE separator is not a candidate, GitHub org link is not an observable', () => {
  const html = fs.readFileSync(new URL('./extract/fixtures/vendor-blog-site-wide-og.html', import.meta.url), 'utf8');
  const url = 'https://hatching.io/blog/triage-insights-ep5-short/';
  const out = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(out.ok, true);
  const { candidates } = extractReportCandidates({ id: 1, source_type: 'url', source_url: url, title: out.document.title }, out.document);

  const members = candidates.filter((c) => isReportIndicatorMember(c));
  const byType = members.reduce((acc, c) => ({ ...acc, [c.candidate_type]: (acc[c.candidate_type] || 0) + 1 }), {});
  assert.equal(members.length, 23);
  assert.deepEqual(byType, { sha256: 18, domain: 2, ip: 3 });
  for (const v of ['workinghardo.link', 'havefunnn.win', '103.193.173.199', '103.193.173.83', '47.108.192.193',
    'c1dfd3712d6f927acf98a78f1b77367d0b57aefbcd6ea8a7120d61a2b8a76525']) {
    assert.ok(members.some((c) => c.normalized_value === v), v);
  }

  const values = candidates.map((c) => `${c.candidate_type}:${c.normalized_value}`);
  assert.equal(values.includes('relative_path:/'), false, 'no "/" candidate from "T1497.001 / T1497.003"');
  assert.ok(values.includes('attack_technique:T1497.001') && values.includes('attack_technique:T1497.003'));
  assert.equal(candidates.some((c) => /github\.com/.test(c.normalized_value)), false, 'navigation links are not observables');
});
