/**
 * IOC Source parsing regressions from the 20-report audit (synthetic values,
 * publisher file shapes):
 *
 * S-5  A CSV's reference column (`Link` → vendor portal) is metadata, never
 *      an Indicator; a portal host is not suppressed globally either.
 * S-6  CSV values never cross a field boundary (quoted fields, escaped quotes,
 *      embedded newlines, `ip_port` rows); non-IOC row types are skipped.
 * S-1  NDJSON / ECS records are read by field: no trailing `}` from a
 *      `{value}` description, no reference links, every source-only hash kept
 *      with its provenance; `.ndjson` files are eligible pack files.
 * S-3  A single-campaign ESET README with `== ESET detection names` resolves;
 *      multi-campaign isolation is unchanged (old and new layouts).
 * S-4  A STIX file-hash OR pattern keeps its supported digests when it also
 *      lists SSDEEP.
 * S-2  STIX `valid_until` is judged at the report's publication date.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseIocSourceContent } from './parseContent.js';
import { isEligibleIocFilePath } from './github.js';
import { parseStixPattern } from './stix/pattern.js';
import { isLinkedSourceIndicatorMember } from '../indicatorMembership.js';

const values = (r) => (r.candidates || []).map((c) => c.normalized_value).sort();
const parse = (body, path, extra = {}) => parseIocSourceContent({ body, contentType: 'text/plain', url: `https://raw.githubusercontent.com/vendor/iocs/main/${path}`, path, ...extra });

test('S-5: a CSV reference column is metadata, the IOC column is the inventory', async () => {
  const csv = [
    'IOC, Valid From, Valid Until, Link',
    'lure-one.example,2026-08-29T00:00:00Z,2026-12-13T00:00:00Z,https://intel-portal.example/objects/indicator--801b99df-c0c5-44ca-81c7-e998e0257f49',
    'lure-two.example,2026-08-20T00:00:00Z,2027-02-16T00:00:00Z,https://intel-portal.example/objects/indicator--586db6f8-d7ab-4b20-8d2b-d81433737f43',
    '203.0.113.45,2026-08-20T00:00:00Z,2027-02-16T00:00:00Z,https://intel-portal.example/objects/indicator--1629eb9e-33fc-444e-b69c-f1d1a6585118'
  ].join('\n');
  const r = await parse(csv, 'IOCs/campaign/campaign_iocs.csv');
  assert.equal(r.ok, true);
  assert.equal(r.format, 'csv');
  assert.deepEqual(values(r), ['203.0.113.45', 'lure-one.example', 'lure-two.example']);
  assert.equal(r.candidates.some((c) => /intel-portal/.test(c.normalized_value)), false);
  // The same portal host listed AS an indicator is still kept (no global suppression).
  const listed = await parse('IOC,Link\nintel-portal.example,https://intel-portal.example/x\n', 'iocs.csv');
  assert.deepEqual(values(listed), ['intel-portal.example']);
});

test('S-6: typed CSV rows keep field boundaries and skip non-IOC row types', async () => {
  const csv = [
    'type,data,info',
    'description,https://vendor-research.example/blog/campaign,Indicators from components of an attack',
    'domain,orders-shop-com.lure[.]example,ClickFix URL',
    'url,hxxps://198.51.100.106:725/fakeurl.htm,NetSupport C2',
    'url,hxxps://payload-host[.]example/AbCdEf/sqr-viewer6,"Stealer, loader and ""package"" URL"',
    'ip,198.51.100[.]106,NetSupport C2 address',
    'port,725/tcp,NetSupport port',
    'ip_port,198.51.100[.]107:725,NetSupport C2',
    'filename,1572cef1-df62-4594-a3aa-a9db91b9d7db.tmp,payload',
    'file_path,C:\\ProgramData\\NodeView,delivery location',
    'sha256,24a293a662600b2292d9259baebba1c09b41df82a5c9c20f8572625ae759696f,"payload,\ndecrypted"',
    'user_agent,Mozilla/5.0 (Windows NT 10.0; Win64; x64),UA used'
  ].join('\r\n');
  const r = await parse(csv, '2026/2026-10/20261021_IoC_campaign.csv', { reportScope: { reportUrl: 'https://vendor-research.example/blog/campaign' } });
  assert.equal(r.ok, true);
  assert.deepEqual(values(r), [
    '198.51.100.106',
    '198.51.100.107',
    '24a293a662600b2292d9259baebba1c09b41df82a5c9c20f8572625ae759696f',
    'https://198.51.100.106:725/fakeurl.htm',
    'https://payload-host.example/AbCdEf/sqr-viewer6',
    'orders-shop-com.lure.example'
  ]);
  for (const c of r.candidates) {
    assert.doesNotMatch(c.normalized_value, /,/);
    assert.equal(c.source_assertion, 'linked_source_ioc');
    assert.equal(isLinkedSourceIndicatorMember(c), true, c.normalized_value);
  }
  const url = r.candidates.find((c) => c.normalized_value === 'https://payload-host.example/AbCdEf/sqr-viewer6');
  assert.equal(url.evidence.structured_source.column_header, 'data');
  assert.equal(url.evidence.structured_source.row_type, 'url');
});

test('S-6: a headerless single-column CSV is still an indicator list', async () => {
  const r = await parse('lure-one.example\n203.0.113.9\n', 'list.csv');
  assert.deepEqual(values(r), ['203.0.113.9', 'lure-one.example']);
});

const ecs = (indicator) => JSON.stringify({ threat: { indicator: { reference: ['https://vendor-research.example/blog/campaign', 'https://www.virustotal.example/gui/url/abc'], provider: 'identity--x', ...indicator } } });

test('S-1: ECS NDJSON is read by field — no `}` tails, no reference links, all hashes kept', async () => {
  const body = [
    ecs({ type: 'url', url: 'http://lure-one.example:8080/stage1', description: 'Simple indicator of observable {http://lure-one.example:8080/stage1}' }),
    ecs({ type: 'domain-name', url: { domain: 'files.lure-two.example' }, description: 'Simple indicator of observable {files.lure-two.example}' }),
    ecs({ type: 'ipv4-addr', ip: '203.0.113.77', description: 'Simple indicator of observable {203.0.113.77}' }),
    ecs({
      type: 'file',
      file: { hash: { sha256: '09f935acbac36d224acfb809ad82c475d53d74ab505f057f5ac40611d7c3dbe7', sha1: '85e022c4844e61924aef2ceb762e413cecf1f55c', md5: '69fbc5a9a30e443e66f0c4d290ace01f' } },
      description: 'Simple indicator of observable {09f935acbac36d224acfb809ad82c475d53d74ab505f057f5ac40611d7c3dbe7}'
    }),
    ecs({ type: 'cryptocurrency-wallet', 'cryptocurrency-wallet': '1CSUkd5FZMis5NDauKLDkcpvvgV1zrBCBz' }),
    '{not json'
  ].join('\n');
  const r = await parse(body, 'indicators/campaign/ecs-indicators.ndjson', { reportScope: { reportUrl: 'https://vendor-research.example/blog/campaign' } });
  assert.equal(r.ok, true);
  assert.equal(r.format, 'ndjson');
  assert.deepEqual(values(r), [
    '09f935acbac36d224acfb809ad82c475d53d74ab505f057f5ac40611d7c3dbe7',
    '203.0.113.77',
    '69fbc5a9a30e443e66f0c4d290ace01f',
    '85e022c4844e61924aef2ceb762e413cecf1f55c',
    'files.lure-two.example',
    'http://lure-one.example:8080/stage1'
  ]);
  assert.equal(r.candidates.some((c) => /[{}]|%7d|virustotal/i.test(c.normalized_value)), false);
  const md5 = r.candidates.find((c) => c.normalized_value === '69fbc5a9a30e443e66f0c4d290ace01f');
  assert.equal(md5.evidence.structured_source.field, 'file.hash.md5');
  assert.equal(md5.evidence.linked_source_path, 'indicators/campaign/ecs-indicators.ndjson');
  assert.ok(r.warnings.includes('ndjson_unparsable_lines'));
  assert.equal(isEligibleIocFilePath('indicators/campaign/ecs-indicators.ndjson'), true);
  assert.equal(isEligibleIocFilePath('indicators/campaign/records.jsonl'), true);
});

const esetReadme = (extraCampaign = '') => `[separator=::]
= Operation Lantern: A new backdoor -- Indicators of Compromise

The blog post on Operation Lantern: A new backdoor is available on WeLiveSecurity at
https://www.vendor-research.example/en/research/

== ESET detection names

- WinGo/Agent.ZO
- WinGo/TrojanProxy.Agent.I

== Files

|===
|SHA-1|Filename|Detection|Description
|\`+D5F9288DAEBF87AE4579945F8DC6CF235B093CFD+\`|Act64.exe|WinGo/Agent.ZO|Lantern backdoor.
|\`+B69EF0E45B401440C0FDE22046775D0C57E87415+\`|ie.exe|WinGo/Agent.ZO|Lantern backdoor.
|===

== Network

|====
|IP|Domain|First seen|Details
|203.0.113[.]201|N/A|2025-07-17|Lantern C&C server.
|====
${extraCampaign}`;

test('S-3: a single-campaign ESET README with a detection-names section resolves (new layout)', async () => {
  const r = await parse(esetReadme(), 'lantern/README.adoc', {
    reportScope: { reportUrl: 'https://www.vendor-research.example/en/research/operation-lantern-new-backdoor/', reportTitle: 'Operation Lantern: A new backdoor' }
  });
  assert.equal(r.ok, true, r.code);
  assert.equal(r.scope.status, 'single_campaign');
  assert.ok(r.scope.excluded_sections.includes('ESET detection names'));
  assert.deepEqual(values(r), ['203.0.113.201', 'b69ef0e45b401440c0fde22046775d0c57e87415', 'd5f9288daebf87ae4579945f8dc6cf235b093cfd']);
  assert.equal(r.candidates.some((c) => /wingo|agent\.zo/i.test(c.normalized_value)), false);
});

test('S-3: multi-campaign isolation is unchanged (old layout and unmatched campaigns)', async () => {
  const old = `= Lantern -- Indicators of Compromise

== Lantern: New burrowing techniques

=== Files

|===
|SHA-1|Filename
|\`+D5F9288DAEBF87AE4579945F8DC6CF235B093CFD+\`|a.exe
|===

== Other operation: Unrelated campaign

=== Files

|===
|SHA-1|Filename
|\`+B69EF0E45B401440C0FDE22046775D0C57E87415+\`|b.exe
|===
`;
  const r = await parse(old, 'lantern/README.adoc', { reportScope: { reportUrl: 'https://www.vendor-research.example/en/research/lantern-new-burrowing-techniques/', reportTitle: 'Lantern: New burrowing techniques' } });
  assert.equal(r.ok, true, r.code);
  assert.equal(r.scope.status, 'campaign_section');
  assert.deepEqual(values(r), ['d5f9288daebf87ae4579945f8dc6cf235b093cfd']);
  // A README tied to neither campaign contributes nothing.
  const none = await parse(old, 'lantern/README.adoc', { reportScope: { reportUrl: 'https://www.vendor-research.example/en/research/something-else/', reportTitle: 'Something else entirely' } });
  assert.equal(none.ok, false);
  assert.equal(none.code, 'campaign_scope_unresolved');
  // Two named campaigns plus a detection-names section: still isolated.
  const multi = await parse(esetReadme('== Second campaign: Unrelated operation\n\n|===\n|SHA-1\n|`+8CEB5F8BCDF4995B7164996F1629D682613BB17B+`\n|===\n'), 'lantern/README.adoc', {
    reportScope: { reportUrl: 'https://www.vendor-research.example/en/research/unrelated/', reportTitle: 'Unrelated report title words' }
  });
  assert.equal(multi.ok, false);
  assert.equal(multi.code, 'campaign_scope_unresolved');
});

test('S-4: a STIX file-hash OR pattern listing SSDEEP keeps its supported digests', () => {
  const p = parseStixPattern("[file:hashes.'SHA-1' = 'C13BC01D6630D6E51F5DC3D3B0D90D8D499FF240' OR file:hashes.'SHA-256' = 'BBDD3620A67AEDEC4B9A68B2C9CC880B6631215E129816AEA19902A6F4BC6F41' OR file:hashes.MD5 = '37C1E6931A14601BB136DF5985BEB0A1' OR file:hashes.SSDEEP = '384:px+JDZS7:pxeiJK4']");
  assert.equal(p.ok, true);
  assert.deepEqual(p.observables.map((o) => o.type), ['sha1', 'sha256', 'md5']);
  assert.deepEqual(p.dropped_properties, ['file:hashes.SSDEEP']);
  // Mixed object types in OR are still refused.
  assert.equal(parseStixPattern("[ipv4-addr:value = '203.0.113.1' OR domain-name:value = 'x.example']").ok, false);
  // SSDEEP alone is not an indicator.
  assert.equal(parseStixPattern("[file:hashes.SSDEEP = '384:px+JDZS7:pxeiJK4' OR file:hashes.TLSH = 'T1ABC']").ok, false);
});

const stixBundle = (validUntil, revoked = false) => JSON.stringify({
  type: 'bundle',
  id: 'bundle--1',
  objects: [
    {
      type: 'indicator', spec_version: '2.1', id: 'indicator--1', pattern_type: 'stix', revoked,
      pattern: "[ipv4-addr:value = '203.0.113.88']", valid_from: '2024-09-26T00:00:00Z', valid_until: validUntil
    }
  ]
});

test('S-2: STIX validity is judged at report publication, revocation still excludes', async () => {
  const path = 'indicators/campaign/stix-bundle.json';
  const atPublication = await parse(stixBundle('2025-09-26T00:00:00Z'), path, { reportScope: { publishedAt: '2024-09-27T00:00:00Z' } });
  assert.deepEqual(values(atPublication), ['203.0.113.88']);
  // Expired before the report was published → Context Only (not an Indicator).
  const before = await parse(stixBundle('2024-01-01T00:00:00Z'), path, { reportScope: { publishedAt: '2024-09-27T00:00:00Z' } });
  assert.deepEqual(values(before), []);
  // No publication date → judged now (unchanged behaviour).
  const unknown = await parse(stixBundle('2025-09-26T00:00:00Z'), path, { reportScope: {} });
  assert.deepEqual(values(unknown), []);
  const revoked = await parse(stixBundle('2030-01-01T00:00:00Z', true), path, { reportScope: { publishedAt: '2024-09-27T00:00:00Z' } });
  assert.deepEqual(values(revoked), []);
});

test('PR #37 compatibility: every persisted source_type is allowed by migration 050', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const { persistableSourceType } = await import('./sourceType.js');
  const sql = fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../migrations/050_threat_report_ioc_source_stix_types.sql'), 'utf8');
  const allowed = new Set([...sql.matchAll(/'([a-z_]+)'::text/g)].map((m) => m[1]));
  // Every format the parser reports (incl. ndjson / asciidoc) maps into the constraint.
  for (const format of ['txt', 'csv', 'json', 'ndjson', 'jsonl', 'stix_json', 'stix_xml', 'xml', 'markdown', 'asciidoc', 'html', 'pdf', 'github_dir', 'github_file', 'something-new']) {
    assert.ok(allowed.has(persistableSourceType(format)), `${format} → ${persistableSourceType(format)}`);
  }
  assert.equal(persistableSourceType(null), null);
});
