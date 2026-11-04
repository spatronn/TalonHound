import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReferenceRows, isRelevantRejection, MAX_RECORDED_REFERENCES, packageCoverage } from './discoveryLedger.js';
import { examineReportReferences } from './runDiscovery.js';
import { fileNameReportEvidence, resolveGitHubCampaignFiles } from './campaignScope.js';
import { selectListedFiles } from './github.js';
import { IOC_SOURCE_FETCH } from './constants.js';
import { withLinkedSourceQuality } from './linkedSourceStatus.js';

const REPORT = {
  reportUrl: 'https://publisher.example/blog/vane-viper-adtech',
  reportTitle: 'Vane Viper adtech infrastructure exposed',
  headings: ['Indicators', 'UAC-0099 overlap'],
  publishedAt: '2026-03-10T00:00:00Z'
};

const accepted = (url, score = 8) => ({ original_url: url, canonical_url: url, score, reference_method: 'html_anchor', discovery_evidence: { link_text: 'IOCs', matched_cues: ['ioc list'] } });

test('a link accepted in one place and rejected in another is one accepted row', () => {
  const url = 'https://github.com/publisher/iocs';
  const { rows } = buildReferenceRows({
    accepted: [accepted(url)],
    rejected: [{ href: url, score: 0, rejected: 'no_anchor_local_evidence', matchedCues: [] }],
    reportUrl: REPORT.reportUrl
  });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].decision, 'accepted');
  assert.equal(rows[0].publisher_host, 'publisher.example');
});

test('a rejected reference keeps its reason, and one with no reason says why it fell short', () => {
  const { rows } = buildReferenceRows({
    rejected: [
      { href: 'https://other.example/a', rejected: 'destination_not_a_pack', matchedCues: ['ioc list'], score: 0 },
      { href: 'https://other.example/b', matchedCues: [], score: 2 }
    ]
  });
  const byUrl = new Map(rows.map((r) => [r.url, r]));
  assert.equal(byUrl.get('https://other.example/a').rejection_reason, 'destination_not_a_pack');
  assert.equal(byUrl.get('https://other.example/b').rejection_reason, 'below_score_threshold');
});

test('over the cap every accepted row stays and the shortfall is counted', () => {
  const rejected = Array.from({ length: MAX_RECORDED_REFERENCES + 20 }, (_, i) => ({ href: `https://x.example/${i}`, rejected: 'no_anchor_local_evidence', score: 0 }));
  const { rows, notRecorded, examined } = buildReferenceRows({ accepted: [accepted('https://github.com/p/iocs')], rejected });
  assert.equal(rows.length, MAX_RECORDED_REFERENCES);
  assert.ok(rows.some((r) => r.decision === 'accepted'));
  assert.equal(examined, MAX_RECORDED_REFERENCES + 21);
  assert.equal(notRecorded, 21);
});

test('navigation is not a relevant reference; an off-site link is', () => {
  assert.equal(isRelevantRejection({ rejected: 'same_site_navigation', matchedCues: [] }), false);
  assert.equal(isRelevantRejection({ rejected: 'same_site_navigation', matchedCues: ['ioc list'] }), true);
  assert.equal(isRelevantRejection({ rejected: 'per_indicator_link', matchedCues: [] }), false);
  assert.equal(isRelevantRejection({ rejected: 'no_anchor_local_evidence', matchedCues: [] }), true);
});

test('coverage is never complete while a declared source is open', () => {
  const run = { status: 'completed' };
  const s = (lifecycle_status, skipped_files = []) => ({ lifecycle_status, skipped_files });
  assert.equal(packageCoverage({ latestRun: run, sources: [s('extracted'), s('inspected')] }).status, 'pending');
  assert.equal(packageCoverage({ latestRun: run, sources: [s('extracted'), s('failed')] }).status, 'unresolved');
  assert.equal(packageCoverage({ latestRun: run, sources: [s('extracted')] }).status, 'complete');
  assert.equal(packageCoverage({ latestRun: run, sources: [s('dismissed')] }).status, 'dismissed');
  assert.equal(packageCoverage({ latestRun: run, sources: [] }).status, 'no_package_declared');
  assert.equal(packageCoverage({ latestRun: run, sources: [], announced: true }).status, 'announced_not_found');
});

test('a file not read is partial coverage; a nested directory alone is not', () => {
  const run = { status: 'completed' };
  const partial = packageCoverage({ latestRun: run, sources: [{ lifecycle_status: 'extracted', skipped_files: [{ reason: 'too_large' }] }] });
  assert.equal(partial.status, 'partial');
  assert.equal(partial.files_not_read, 1);
  assert.equal(packageCoverage({ latestRun: run, sources: [{ lifecycle_status: 'extracted', skipped_files: [{ reason: 'nested_directory' }] }] }).status, 'complete');
});

test('a report without a ledger row is not recorded, never "no package"', () => {
  assert.equal(packageCoverage({ latestRun: null, sources: [] }).status, 'not_recorded');
  assert.equal(packageCoverage({ latestRun: null, sources: [{ lifecycle_status: 'extracted' }] }).status, 'complete');
});

test('a discovery failure is distinct from an extraction failure', () => {
  const failed = packageCoverage({ latestRun: { status: 'failed' }, sources: [] });
  assert.equal(failed.status, 'discovery_incomplete');
  const q = withLinkedSourceQuality({ status: 'clean', warnings: [] }, { pending: 0, unresolved: 0, scope_mismatch: 0, declared: 0, dismissed: 0, discovery_status: 'failed' });
  assert.ok(q.warnings.some((w) => w.code === 'ioc_source_discovery_incomplete'));
  assert.ok(q.warnings.every((w) => !/extraction_/.test(w.code)));
});

test('one unreadable artifact leaves the pass partial and the document still read', async () => {
  const report = {
    canonical_document: {
      blocks: [{ id: 'b1', type: 'paragraph', text: 'The full IOC list is available at https://github.com/publisher/iocs/blob/main/full.csv' }]
    }
  };
  const artifacts = [{ artifact_type: 'url_fetch', storage_key: 'k' }];
  const { accepted: found, readErrors } = await examineReportReferences(report, artifacts, async () => { throw new Error('disk'); }, REPORT.reportUrl);
  assert.equal(readErrors.length, 1);
  assert.ok(found.some((d) => d.canonical_url.includes('full.csv')));
});

test('file name evidence: names, designators and slugs count; a date or one word alone does not', () => {
  const ev = (p) => fileNameReportEvidence(p, REPORT);
  assert.equal(ev('indicators/csv/vane-viper-adtech.csv').evidence, 'report_slug');
  assert.equal(ev('indicators/csv/2026-vane-viper.csv').evidence, 'title_names');
  assert.equal(ev('indicators/csv/uac-0099.csv').evidence, 'designator');
  assert.equal(ev('indicators/csv/20260310-viper.csv').evidence, 'date_and_name');
  assert.equal(ev('indicators/csv/20260310-other-campaign.csv').matched, false);
  assert.equal(ev('indicators/csv/viper.csv').matched, false);
  assert.equal(ev('indicators/csv/all-domains.csv').matched, false);
  assert.equal(ev('indicators/csv/infrastructure.csv').matched, false);
});

function fakeRepo(tree) {
  const calls = [];
  return {
    calls,
    listDir: async (p) => {
      calls.push(p);
      return tree[p] || [];
    },
    readFile: async () => { throw new Error('the root walk reads names only'); }
  };
}

const dir = (path) => ({ name: path.split('/').pop(), type: 'dir', path });
const file = (path, size = 100) => ({ name: path.split('/').pop(), type: 'file', path, size });

test('a repository root resolves to the files named for the report, from a shared CSV folder', async () => {
  const io = fakeRepo({
    '': [dir('indicators'), dir('tools'), file('README.md')],
    indicators: [dir('indicators/csv'), dir('indicators/stix')],
    'indicators/csv': [file('indicators/csv/vane-viper-adtech.csv'), file('indicators/csv/hazy-hawk.csv'), file('indicators/csv/all.csv', 99_000_000)],
    'indicators/stix': [file('indicators/stix/vane-viper-adtech.json')],
    tools: [file('tools/vane-viper-adtech.csv')]
  });
  const r = await resolveGitHubCampaignFiles({ path: '' }, REPORT, io);
  assert.equal(r.ok, true);
  assert.deepEqual(r.files.map((f) => f.path).sort(), ['indicators/csv/vane-viper-adtech.csv', 'indicators/stix/vane-viper-adtech.json']);
  assert.ok(!io.calls.includes('tools'), 'a folder that is not inventory-shaped is not walked');
});

test('a root with nothing named for the report stays unresolved, whatever its files hold', async () => {
  const io = fakeRepo({ '': [dir('indicators')], indicators: [file('indicators/all-domains.csv'), file('indicators/2026.csv')] });
  const r = await resolveGitHubCampaignFiles({ path: '' }, REPORT, io);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no_file_named_for_report');
  assert.equal(r.files_seen, 2);
});

test('the root walk is bounded and says when it stopped early', async () => {
  const tree = { '': Array.from({ length: 40 }, (_, i) => dir(`${2000 + i}`)) };
  const io = fakeRepo(tree);
  const r = await resolveGitHubCampaignFiles({ path: '' }, REPORT, io, { maxDirs: 5 });
  assert.equal(io.calls.length, 5);
  assert.equal(r.truncated, true);
});

test('each file left out of a listing keeps its reason', () => {
  const big = IOC_SOURCE_FETCH.GITHUB_MAX_FILE_BYTES + 1;
  const { files, skippedFiles } = selectListedFiles([
    { type: 'file', path: 'a/iocs.csv', size: 100 },
    { type: 'file', path: 'a/huge.csv', size: big },
    { type: 'dir', path: 'a/sub' },
    { type: 'file', path: 'a/tool.exe', size: 5 }
  ], { owner: 'o', repo: 'r' }, 'abc');
  assert.deepEqual(files.map((f) => f.path), ['a/iocs.csv']);
  assert.deepEqual(Object.fromEntries(skippedFiles.map((s) => [s.path, s.reason])), {
    'a/huge.csv': 'too_large',
    'a/sub': 'nested_directory',
    'a/tool.exe': 'ineligible_type'
  });
});

test('resource limits are explicit and allow a large pack', () => {
  assert.ok(IOC_SOURCE_FETCH.MAX_BYTES >= 16 * 1024 * 1024);
  assert.ok(IOC_SOURCE_FETCH.GITHUB_MAX_FILE_BYTES >= 16 * 1024 * 1024);
});

test('a file named by date and a word of the report slug resolves; the date alone does not', () => {
  const report = { reportUrl: 'https://www.infoblox.com/blog/threat-intelligence/dropcatch-scavengers-expired-malicious-domains-become-cash-cows/', reportTitle: 'Expired Malicious Domains Bring New Threats to Life', publishedAt: '2026-08-13T12:58:48Z' };
  assert.equal(fileNameReportEvidence('indicators/csv/drop_catch_iii_20260813.csv', report).evidence, 'date_and_slug_word');
  assert.equal(fileNameReportEvidence('indicators/csv/hazy_hawk_20260813.csv', report).matched, false);
  assert.equal(fileNameReportEvidence('indicators/csv/20260813_iocs.csv', report).matched, false);
  assert.equal(fileNameReportEvidence('indicators/csv/drop_catch_iii_20250101.csv', report).matched, false, 'a slug word without the date is not enough');
});

test('a folder named for the report resolves to its files; a heading word or short name does not', async () => {
  const io = fakeRepo({
    '': [dir('webworm'), dir('other'), dir('indicators')],
    webworm: [file('webworm/README.adoc'), file('webworm/samples.sha256'), file('webworm/tool.exe')],
    indicators: [dir('indicators/shellter')],
    'indicators/shellter': [file('indicators/shellter/iocs.txt')]
  });
  const web = await resolveGitHubCampaignFiles({ path: '' }, { reportTitle: 'Webworm: New burrowing techniques', publishedAt: '2026-01-01' }, io);
  assert.deepEqual(web.files.map((f) => f.path).sort(), ['webworm/README.adoc', 'webworm/samples.sha256']);
  assert.equal(web.files[0].evidence, 'folder_named_for_report');
  const nested = await resolveGitHubCampaignFiles({ path: '' }, { reportTitle: 'Taking SHELLTER: a commercial evasion framework', publishedAt: '2026-01-01' }, io);
  assert.deepEqual(nested.files.map((f) => f.path), ['indicators/shellter/iocs.txt']);
  const none = await resolveGitHubCampaignFiles({ path: '' }, { reportTitle: 'An unrelated campaign report', publishedAt: '2026-01-01' }, io);
  assert.equal(none.ok, false);
});

test('two posts on one actor: the better-supported file is chosen and the other is named', async () => {
  const io = fakeRepo({ '': [dir('2026')], 2026: [dir('2026/08')], '2026/08': [file('2026/08/UAT-10147 deploys SPECTRE.txt'), file('2026/08/UAT-10147 integrates agentic AI.txt')] });
  const r = await resolveGitHubCampaignFiles({ path: '' }, { reportTitle: 'UAT-10147 deploys SPECTRE backdoor', publishedAt: '2026-08-01' }, io);
  assert.deepEqual(r.files.map((f) => f.path), ['2026/08/UAT-10147 deploys SPECTRE.txt']);
  assert.deepEqual(r.set_aside.map((f) => f.path), ['2026/08/UAT-10147 integrates agentic AI.txt']);
});

test('publication-year folders are walked first, so a long history stays inside the limit', async () => {
  const tree = { '': Array.from({ length: 30 }, (_, i) => dir(String(1996 + i))).concat(dir('2026')) };
  tree['2026'] = [dir('2026/03')];
  tree['2026/03'] = [file('2026/03/uat-8837.txt')];
  const r = await resolveGitHubCampaignFiles({ path: '' }, { reportTitle: 'UAT-8837 targets infrastructure', publishedAt: '2026-03-10' }, fakeRepo(tree), { maxDirs: 4 });
  assert.deepEqual(r.files.map((f) => f.path), ['2026/03/uat-8837.txt']);
});
