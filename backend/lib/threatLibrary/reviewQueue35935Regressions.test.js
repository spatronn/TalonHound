/**
 * Review queue 35935–35959 (tl-candidates-v73): defects found auditing the 24
 * Need Review reports against their publisher pages.
 *
 * A. 35952 (Proofpoint): IOC-table digests with a footnote marker
 *    ("<sha256>*", "*First Uploaded to VirusTotal by Proofpoint") were dropped.
 * B. 35955 (Proofpoint TA416): a URL whose path is percent-encoded UTF-8
 *    ("/%e0%a6%a8…_%e0%a7%a8….html") read as a "%NAME%" template placeholder.
 * C. 35957 (Trend): "server09.mentality.cloud | FTP Server |" under a
 *    "File | SHA256 | Detection name" header was typed by the File header.
 * D. 35946 (Proofpoint): "hardcoded AES-256-GCM key: <hex>" was a sha256.
 * E. 35956 (Trend): "Name servers | dns1.registrar-servers.com, …" of a C2
 *    domain's "Property | Value" profile table became C2 Indicators.
 * F. 35938 (Unit 42): the first 64 hex of SHA-512("") listed as a SHA-256.
 * G. 35957: "Trojan.Win32.DOWNLOADER.CM" (detection name) read as a .cm host.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractReportCandidates } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { DIGEST_KINDS, classifyHexDigest, wellKnownDigest } from './digestSemantics.js';
import { parseIndicatorCell, interpretIocTable, TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import {
  OBSERVABLE_TYPE_RESOLVER_VERSION,
  resolveDottedToken,
  urlContainsTemplatePlaceholder,
  validateUrlCandidate
} from './observableTypeResolver.js';

const STARRED = '7f54cf5e2beb3f1f5d2b3ba1c6a16ce1927ffecd20a9d635329b1e16cb74fb14';
const PLAIN = 'd9832d9208b2c4a34cf5220b1ebaf11f0425cf638ac67bf4669b11c80e460f58';
const BENGALI_URL =
  'https://gooledives.z48.web.core.windows.net/%e0%a6%a8%e0%a6%bf%e0%a6%b0%e0%a7%8d%e0%a6%ac%e0%a6%be%e0%a6%9a%e0%a6%a8_%e0%a7%a8%e0%a7%a6%e0%a7%a8%e0%a7%ac.html';
const AES_KEY = '4f7a8c3d2e1b5f9071a6b2c8d4e3f50a92b1c7d6e8f4a30b5c2d9e1f7a6b8c4d';
const SHA512_EMPTY_PREFIX = 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce';
const EVELYN = 'aba7133f975a0788dd2728b4bbb1d7d948e50571a033a1e8f47a2691e98600c5';

test('review queue 35935 contracts', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v75');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v24');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v30');
});

function extract(blocks) {
  return extractReportCandidates(
    { source_type: 'url', source_url: 'https://publisher.example/report' },
    createCanonicalDocument({ title: 'Review queue 35935 fixture', blocks })
  );
}
const find = (r, type, value) => r.candidates.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const member = (r, type, value) => {
  const c = find(r, type, value);
  return Boolean(c && isReportIndicatorMember(c));
};

test('A: a footnote marker glued to a full digest is notation, not part of the value', () => {
  const parsed = parseIndicatorCell(`${STARRED}*`, null);
  assert.equal(parsed.values.length, 1);
  assert.equal(parsed.values[0].candidate_type, 'sha256');
  assert.equal(parsed.values[0].normalized_value, STARRED);
  // Only a whole digest qualifies: a short hex run with a star is not one.
  assert.equal(parseIndicatorCell('7f54cf5e2beb*', null).values.length, 0);

  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise*' },
    { id: 'p1', type: 'paragraph', text: '*First Uploaded to VirusTotal by Proofpoint' },
    createTableBlock({
      id: 't1',
      headers: ['Indicator', 'Description', 'First Seen'],
      rows: [
        [PLAIN, 'SHA256 Pulseway RMM', '2026-02-27'],
        [`${STARRED}*`, 'SHA256 ScreenConnect', '2026-02-27'],
        ['officcee404[.]com', 'Domain ScreenConnect C2', '2026-02-27']
      ]
    })
  ]);
  assert.ok(member(result, 'sha256', PLAIN));
  assert.ok(member(result, 'sha256', STARRED), 'the starred digest is an Indicator of its row');
  assert.ok(member(result, 'domain', 'officcee404.com'));
});

test('B: percent-encoded UTF-8 in a URL path is not a %NAME% placeholder', () => {
  assert.equal(urlContainsTemplatePlaceholder(BENGALI_URL), false);
  assert.equal(validateUrlCandidate(BENGALI_URL).ok, true);
  // Real placeholders keep their reading.
  assert.equal(urlContainsTemplatePlaceholder('https://cdn.example/%APPDATA%/x.exe'), true);
  assert.equal(urlContainsTemplatePlaceholder('https://cdn.example/%USER_NAME%/x'), true);
  assert.equal(urlContainsTemplatePlaceholder('https://cdn.example/a%20b%20c.pdf'), false);

  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    createTableBlock({
      id: 't1',
      headers: ['Indicator', 'Type', 'Description', 'First Seen'],
      rows: [
        ['hxxps://gooledives.z48.web.core.windows[.]net/election_2026.html', 'URL', 'Fake Cloudflare Turnstile challenge page', 'Jan-26'],
        [BENGALI_URL.replace('https://', 'hxxps://').replace('.windows.net', '.windows[.]net'), 'URL', 'Fake Cloudflare Turnstile challenge page', 'Jan-26']
      ]
    })
  ]);
  assert.ok(member(result, 'url', 'https://gooledives.z48.web.core.windows.net/election_2026.html'));
  assert.ok(member(result, 'url', BENGALI_URL), 'the percent-encoded URL is an Indicator');
});

test('C: an in-row network role label types the row value in place of a File column header', () => {
  const block = createTableBlock({
    id: 't1',
    headers: ['File', 'SHA256', 'Detection name'],
    rows: [
      ['EvelynStealer.exe', EVELYN, 'Trojan.Win64.EVELYNSTEALER.A'],
      ['Lightshot.dll', '369479bd9a248c9448705c222d81ff1a0143343a138fc38fc0ea00f54fcc1598', 'Trojan.Win32.DOWNLOADER.CM'],
      ['server09.mentality.cloud', 'FTP Server', ''],
      ['syn1112223334445556667778889990.org', 'HTTP Server', '']
    ]
  });
  const interp = interpretIocTable(block, { inAuthoritativeScope: true });
  const typed = interp.rows.flatMap((r) => r.values).map((v) => `${v.candidate_type}:${v.normalized_value}`);
  assert.ok(typed.includes('domain:server09.mentality.cloud'));
  assert.ok(typed.includes('domain:syn1112223334445556667778889990.org'));
  // The file rows keep their file reading.
  assert.ok(typed.includes('technical_artifact:EvelynStealer.exe'));

  const result = extract([{ id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise (IoCs)' }, block]);
  assert.ok(member(result, 'domain', 'server09.mentality.cloud'));
  assert.ok(member(result, 'domain', 'syn1112223334445556667778889990.org'));
  assert.ok(member(result, 'sha256', EVELYN));
});

test('D: a cipher key with size / mode qualifiers is key material, not a file hash', () => {
  const line = `The three encrypted payloads are decrypted at runtime using the hardcoded AES-256-GCM key: ${AES_KEY}.`;
  assert.equal(classifyHexDigest(line, AES_KEY).kind, DIGEST_KINDS.CRYPTO_KEY);
  assert.equal(classifyHexDigest(`AES 128 CBC IV: ${AES_KEY}`, AES_KEY).kind, DIGEST_KINDS.CRYPTO_KEY);
  // A file-hash label that mentions the cipher stays a file hash.
  assert.equal(classifyHexDigest(`SHA256 of the AES-256 encrypted payload: ${AES_KEY}`, AES_KEY).kind, DIGEST_KINDS.FILE);

  const result = extract([{ id: 'p1', type: 'paragraph', text: line }]);
  assert.equal(find(result, 'sha256', AES_KEY), null);
  assert.equal(find(result, 'technical_artifact', AES_KEY)?.digest_kind, DIGEST_KINDS.CRYPTO_KEY);
});

test('E: registration-profile rows of a key-value table stay Context Only provenance', () => {
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'C&C infrastructure analysis' },
    { id: 'p1', type: 'paragraph', text: 'The C&C domain sfrclak[.]com was registered shortly before the attack.' },
    createTableBlock({
      id: 't1',
      headers: ['Property', 'Value'],
      rows: [
        ['Domain registered', 'March 30, 2026 16:03:46 UTC'],
        ['Registrar', 'Namecheap Inc'],
        ['Name servers', 'dns1.registrar-servers.com, dns2.registrar-servers.com'],
        ['Hosting provider', 'Hostwinds LLC (AS54290)'],
        ['DNS SPF record', 'v=spf1 include:spf.efwd.registrar-servers.com ~all'],
        ['DNS MX records', 'eforward[1-5].registrar-servers.com (Namecheap default email forwarding)']
      ]
    }),
    { id: 'h2', type: 'heading', level: 2, text: 'Indicators of compromise' },
    createTableBlock({
      id: 't2',
      headers: ['Indicator', 'Value', 'Detection'],
      rows: [
        ['C&C Domain', 'sfrclak[.]com', '91. C&C server'],
        ['C&C IP', '142[.]11[.]206[.]73', '91. C&C server']
      ]
    })
  ]);
  for (const ns of ['dns1.registrar-servers.com', 'dns2.registrar-servers.com', 'spf.efwd.registrar-servers.com']) {
    assert.equal(member(result, 'domain', ns), false, `${ns} is registration provenance, not an Indicator`);
  }
  assert.ok(member(result, 'domain', 'sfrclak.com'));
  assert.ok(member(result, 'ip', '142.11.206.73'));
});

test('F: a trivial SHA-512 cut to SHA-256 width is a well-known digest', () => {
  assert.equal(wellKnownDigest(SHA512_EMPTY_PREFIX)?.algorithm, 'sha512_prefix');
  assert.equal(classifyHexDigest(`${SHA512_EMPTY_PREFIX} (file_save.php)`, SHA512_EMPTY_PREFIX).kind, DIGEST_KINDS.WELL_KNOWN);
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
    { id: 'l1', type: 'list', text: '98442387d466f27357d727b3706037a4df12a78602b93df973b063462a677761 (aws.php)' },
    { id: 'l2', type: 'list', text: `${SHA512_EMPTY_PREFIX} (file_save.php)` }
  ]);
  assert.ok(member(result, 'sha256', '98442387d466f27357d727b3706037a4df12a78602b93df973b063462a677761'));
  assert.equal(find(result, 'sha256', SHA512_EMPTY_PREFIX), null);
});

test('G: an anti-malware detection name is never a hostname', () => {
  for (const name of ['Trojan.Win32.DOWNLOADER.CM', 'Backdoor.MacOS.NUKESPED.MANP', 'Trojan.JS.AXIOSDROP.THCCABF']) {
    assert.equal(resolveDottedToken(name, { form: 'table_row' }).kind, 'technical_artifact', name);
  }
  // A real host is not caught by the category / platform shape.
  assert.equal(resolveDottedToken('trojan.example.com', { form: 'table_row' }).kind, 'domain');
});
