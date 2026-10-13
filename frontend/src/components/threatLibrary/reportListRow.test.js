/**
 * Threat Library list row presentation: status tone, Intelligence metrics
 * (canonical API counters only), source display safety, tag chips and the
 * Imported cell.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REPORT_LIST_VISIBLE_TAGS,
  describeReportImported,
  describeReportIntelligence,
  describeReportListStatus,
  describeReportSource,
  formatReportMetric,
  splitReportListTags
} from './reportListRow.js';
import { indicatorListCell } from './reportPhase.js';
import { formatPublicationDate } from './publicationDate.js';

const metric = (row, key) => describeReportIntelligence(row).find((m) => m.key === key);

test('status pill: label text from statusLabel (Title Case), tone from the report phase', () => {
  assert.deepEqual(describeReportListStatus({ analysis_status: 'ready' }), { phase: 'finalized', tone: 'ready', label: 'Ready' });
  assert.deepEqual(describeReportListStatus({ analysis_status: 'skipped' }), { phase: 'finalized', tone: 'ready', label: 'Imported (Bundle)' });
  assert.deepEqual(describeReportListStatus({ analysis_status: 'review_required' }), { phase: 'review_ready', tone: 'review', label: 'Needs Review' });
  assert.deepEqual(describeReportListStatus({ analysis_status: 'failed' }), { phase: 'failed', tone: 'failed', label: 'Failed' });
  assert.equal(describeReportListStatus({ analysis_status: 'pending' }).tone, 'processing');
  assert.equal(describeReportListStatus({ analysis_status: 'pending' }).label, 'Queued');
  const analyzing = describeReportListStatus({ analysis_status: 'analyzing', analysis_progress: { analysis_chunks_total: 34, current_chunk_index: 12 } });
  assert.deepEqual(analyzing, { phase: 'preparing', tone: 'processing', label: 'Analyzing 12/34' });
  // The API phase wins (same rule as resolveReportPhase).
  assert.equal(describeReportListStatus({ analysis_status: 'ready', review_phase: 'review_ready' }).tone, 'review');
});

test('Indicators = Total Unique (Original ∪ linked) for review-ready / finalized reports, never the raw roster', () => {
  const row = {
    analysis_status: 'ready',
    raw_candidate_count: 260,
    indicator_count: 260,
    review_candidate_count: 140,
    original_indicator_count: 140,
    total_unique_indicator_count: 148,
    linked_only_indicator_count: 8,
    matched_count: 61,
    entity_count: 12
  };
  const ind = metric(row, 'indicators');
  assert.equal(ind.value, '148');
  assert.equal(ind.label, 'Indicators');
  assert.equal(ind.muted, false);
  assert.equal(ind.title, '148 unique Indicators · 140 original · 8 linked only');
  // Same number the previous list cell showed (no semantic change).
  assert.equal(indicatorListCell(row), '148');
  assert.equal(metric(row, 'matched').value, '61', 'matched_count as served (union-scoped), never recomputed');
  assert.equal(metric(row, 'entities').value, '12');
  assert.deepEqual(describeReportIntelligence(row).map((m) => m.key), ['entities', 'indicators', 'matched']);
});

test('preparing / failed reports show preliminary observables, never an Indicator count', () => {
  const preparing = metric({ analysis_status: 'analyzing', raw_candidate_count: 40, total_unique_indicator_count: 35 }, 'indicators');
  assert.deepEqual([preparing.value, preparing.label, preparing.muted], ['40', 'Preliminary', true]);
  assert.match(preparing.title, /preliminary observables/);
  const empty = metric({ analysis_status: 'pending', raw_candidate_count: 0 }, 'indicators');
  assert.deepEqual([empty.value, empty.label], ['—', 'Analyzing']);
  const failed = metric({ analysis_status: 'failed', raw_candidate_count: 218, total_unique_indicator_count: 218 }, 'indicators');
  assert.deepEqual([failed.value, failed.label], ['218', 'Preliminary']);
  const failedEmpty = metric({ analysis_status: 'failed', raw_candidate_count: 0 }, 'indicators');
  assert.deepEqual([failedEmpty.value, failedEmpty.label], ['—', 'Indicators']);
  // Legacy payload without raw_candidate_count still reads indicator_count.
  assert.equal(metric({ analysis_status: 'matching', indicator_count: 7 }, 'indicators').value, '7');
});

test('legacy payloads without total_unique fall back to the original Indicators, then raw rows', () => {
  assert.equal(metric({ analysis_status: 'ready', review_candidate_count: 9, indicator_count: 20 }, 'indicators').value, '9');
  assert.equal(metric({ analysis_status: 'ready', indicator_count: 20 }, 'indicators').value, '20');
  assert.equal(metric({ analysis_status: 'ready' }, 'indicators').value, '0');
  assert.equal(metric({ analysis_status: 'ready' }, 'matched').value, '0');
});

test('large counts stay narrow: grouped below 10,000, compact above, exact value in the tooltip', () => {
  assert.equal(formatReportMetric(0), '0');
  assert.equal(formatReportMetric(3218), '3,218');
  assert.equal(formatReportMetric(9999), '9,999');
  assert.equal(formatReportMetric(12345), '12.3K');
  assert.equal(formatReportMetric(123456), '123.5K');
  assert.equal(formatReportMetric(2500000), '2.5M');
  assert.equal(formatReportMetric(null), '—');
  assert.equal(formatReportMetric(-1), '—');
  const big = metric({ analysis_status: 'ready', total_unique_indicator_count: 123456, matched_count: 98765 }, 'matched');
  assert.equal(big.value, '98.8K');
  assert.match(big.title, /^98,765 unique Indicators matched/);
});

test('source: stored name, else URL host / PDF file name / bundle; only http(s) URLs are links', () => {
  const named = describeReportSource({ source_type: 'url', source_name: 'hatching.io', source_url: 'https://hatching.io/blog/x' });
  assert.deepEqual([named.label, named.href, named.typeLabel], ['hatching.io', 'https://hatching.io/blog/x', 'URL']);
  assert.equal(named.title, 'hatching.io\nhttps://hatching.io/blog/x');
  const longUrl = 'https://www.huntress.com/blog/' + 'a'.repeat(300);
  const host = describeReportSource({ source_type: 'url', source_url: longUrl });
  assert.equal(host.label, 'www.huntress.com', 'long URLs collapse to the host; the full URL stays in the tooltip');
  assert.ok(host.title.includes(longUrl));
  const pdf = describeReportSource({ source_type: 'pdf', source_file_name: 'joint-advisory.pdf' });
  assert.deepEqual([pdf.label, pdf.href, pdf.typeLabel], ['joint-advisory.pdf', null, 'PDF']);
  assert.deepEqual([describeReportSource({ source_type: 'thib' }).label, describeReportSource({ source_type: 'thib' }).typeLabel], ['THIB bundle', 'THIB bundle']);
  for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', 'not a url']) {
    const r = describeReportSource({ source_type: 'url', source_url: bad });
    assert.equal(r.href, null, bad);
  }
  assert.equal(describeReportSource({}).label, '—');
});

test('tag chips: at most three, name-sorted, with one "+N" per visible-chip count for narrow cells', () => {
  assert.equal(REPORT_LIST_VISIBLE_TAGS, 3);
  const tags = ['ukraine', 'git', 'kimsuky', 'n.korea', 'apt'].map((name, i) => ({ id: i + 1, name }));
  const split = splitReportListTags(tags);
  assert.deepEqual(split.visible.map((t) => t.name), ['apt', 'git', 'kimsuky']);
  assert.deepEqual(split.hidden.map((t) => t.name), ['n.korea', 'ukraine']);
  assert.equal(split.hiddenTitle, 'n.korea, ukraine');
  assert.deepEqual(split.overflow, [
    { shown: 1, count: 4, title: 'git, kimsuky, n.korea, ukraine' },
    { shown: 2, count: 3, title: 'kimsuky, n.korea, ukraine' },
    { shown: 3, count: 2, title: 'n.korea, ukraine' }
  ]);
  const two = splitReportListTags([{ id: 1, name: 'b' }, { id: 2, name: 'a' }]);
  assert.deepEqual(two.overflow, [{ shown: 1, count: 1, title: 'b' }], 'no "+N" when every chip is visible');
  assert.deepEqual(splitReportListTags(undefined), { visible: [], hidden: [], hiddenTitle: '', overflow: [] });
  // Malformed entries are dropped, never rendered (no fabricated tags).
  assert.equal(splitReportListTags([{ id: 0, name: 'x' }, { id: 3, name: '' }, null]).visible.length, 0);
});

test('Imported = created_at instant split for a two-line cell; never the publication date', () => {
  const row = { created_at: '2026-10-12T17:38:45Z', published_date: '2026-10-08', published_at: '2026-10-08T00:00:00Z' };
  const imported = describeReportImported(row, 'Europe/Istanbul');
  assert.deepEqual([imported.date, imported.time], ['12/10/2026', '20:38:45']);
  assert.match(imported.title, /^Imported into TalonHound 12\/10\/2026, 20:38:45$/);
  assert.equal(formatPublicationDate(row), '08/10/2026');
  assert.notEqual(imported.date, formatPublicationDate(row));
  assert.equal(describeReportImported({ created_at: null }), null);
  assert.equal(describeReportImported({ published_at: '2026-10-08T00:00:00Z' }), null, 'no fallback to the publication date');
});
