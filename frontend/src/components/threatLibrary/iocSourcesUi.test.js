import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildReportTabs, REPORT_VIEWS, parseReportView } from './reportTabs.js';
import {
  isReviewIndicator,
  isUnionReviewIndicator,
  isLinkedOnlyReviewIndicator,
  matchReviewFilter,
  REVIEW_FILTERS
} from './candidateReview.js';
import {
  lifecycleBadge,
  shortSourceTitle,
  sourceCardMeta,
  sourceTypeLabel,
  isAttachedLifecycle,
  isPendingLifecycle
} from './iocSourcesUi.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const panelSrc = fs.readFileSync(path.join(__dirname, 'IocSourcesPanel.jsx'), 'utf8');
const pageCss = fs.readFileSync(path.join(__dirname, 'reportPage.css'), 'utf8');

test('IOC Sources tab is present with optional count', () => {
  const tabs = buildReportTabs({
    indicatorCount: 70,
    indicatorCountStable: true,
    entityCount: 3,
    iocSourceCount: 2
  });
  const ioc = tabs.find((t) => t.id === REPORT_VIEWS.IOC_SOURCES);
  assert.ok(ioc);
  assert.equal(ioc.label, 'IOC Sources');
  assert.equal(ioc.count, 2);
  assert.equal(parseReportView('view=ioc_sources'), REPORT_VIEWS.IOC_SOURCES);
});

test('default Original filter preserves MODE A membership; total/linked filters extend', () => {
  assert.ok(REVIEW_FILTERS.some((f) => f.id === 'total_unique'));
  assert.ok(REVIEW_FILTERS.some((f) => f.id === 'linked_only'));

  const original = {
    candidate_type: 'ip',
    normalized_value: '203.0.113.1',
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'pending',
    match_state: 'new',
    source_assertion: 'explicit_ioc',
    has_original_document_occurrence: true,
    document_has_authoritative_scope: true,
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'explicit_ioc',
      is_direct_source_observable: true,
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true }]
    }
  };
  const linked = {
    candidate_type: 'domain',
    normalized_value: 'extra.example',
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'pending',
    match_state: 'new',
    source_assertion: 'linked_source_ioc',
    has_original_document_occurrence: false,
    sources: [{ id: 's1' }],
    evidence: { source_assertion: 'linked_source_ioc', is_direct_source_observable: true }
  };

  assert.equal(isReviewIndicator(original), true);
  assert.equal(isReviewIndicator(linked), false);
  assert.equal(isUnionReviewIndicator(linked), true);
  assert.equal(isLinkedOnlyReviewIndicator(linked), true);
  assert.equal(matchReviewFilter(linked, 'indicators'), false);
  assert.equal(matchReviewFilter(linked, 'total_unique'), true);
  assert.equal(matchReviewFilter(linked, 'linked_only'), true);
  assert.equal(matchReviewFilter(linked, 'source:s1'), true);
  assert.equal(matchReviewFilter(linked, 'source:other'), false);
});

test('source card title and type helpers for GitHub Warden pack', () => {
  const url = 'https://github.com/gendigitalinc/ioc/tree/master/WardenStealer';
  assert.equal(
    shortSourceTitle({ canonical_url: url, source_type: 'github_dir' }),
    'gendigitalinc/ioc · WardenStealer'
  );
  assert.equal(sourceTypeLabel('github_dir'), 'GitHub directory');
  assert.equal(lifecycleBadge('extracted').label, 'Extracted');
  assert.equal(isAttachedLifecycle('extracted'), true);
  assert.equal(isPendingLifecycle('inspected'), true);
  assert.match(
    sourceCardMeta({
      source_type: 'github_dir',
      extraction_status: 'succeeded',
      preview: { unique_count: 3150 },
      discovery_method: 'manual'
    }),
    /3150 unique indicators/
  );
});

test('IOC Sources panel uses Threat Library dark surface classes, not light fallbacks', () => {
  assert.match(panelSrc, /className="tl-ioc-sources"/);
  assert.match(panelSrc, /tl-ioc-source-card/);
  assert.doesNotMatch(panelSrc, /--th-surface/);
  assert.doesNotMatch(panelSrc, /background:\s*#fff|#ffffff|white/i);
  assert.doesNotMatch(panelSrc, /<style>/);

  assert.match(pageCss, /\.tl-ioc-source-card \{/);
  assert.match(pageCss, /background:\s*#0f172a/);
  assert.doesNotMatch(pageCss, /\.tl-ioc-source-card[^{]*\{[^}]*background:\s*#fff/);
  assert.doesNotMatch(pageCss, /var\(--th-surface/);
});
