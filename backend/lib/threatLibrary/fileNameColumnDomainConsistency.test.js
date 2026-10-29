/**
 * Filename-column consistency (tl-table-v11 / tl-candidates-v39): mixed
 * Item|Description IOC tables must not discard clear publisher-asserted
 * domains merely because sibling cells are filenames. Ambiguous file/TLD
 * collisions (`back.pl`) and rows with explicit file evidence still demote.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import {
  interpretIocTable,
  isFilenameDomainCollisionSuffix,
  TABLE_SEMANTICS_VERSION
} from './tableSemantics.js';
import {
  assessExtractionQuality,
  EXTRACTION_QUALITY_VERSION,
  QUALITY_CODES
} from './extractionQuality.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/filename-column-domain/';
const md5 = (s) => createHash('md5').update(s).digest('hex');

function run(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}

const persisted = (c) => ({
  ...c,
  has_original_document_occurrence: true,
  review_status: 'pending',
  evidence: buildCandidateEvidenceRecord(c)
});
const find = (out, value) => out.candidates.find((c) => String(c.normalized_value).toLowerCase() === String(value).toLowerCase());
const member = (out, value) => {
  const c = find(out, value);
  return Boolean(c) && isReportIndicatorMember(persisted(c));
};
const qualityCodes = (out) => (out.diagnostics?.quality?.warnings || []).map((w) => w.code);

const iocItemTable = (rows) => `<h2>IoC Table</h2>
<table><thead><tr><th>Item</th><th>Description</th></tr></thead><tbody>
${rows.map(([v, d]) => `<tr><td>${v}</td><td>${d}</td></tr>`).join('\n')}
</tbody></table>`;

test('versions: tl-candidates-v39 / tl-table-v11 / tl-quality-v13', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v47');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v13');
  assert.equal(EXTRACTION_QUALITY_VERSION, 'tl-quality-v14');
  assert.equal(isFilenameDomainCollisionSuffix('back.pl'), true);
  assert.equal(isFilenameDomainCollisionSuffix('tool.py'), true);
  assert.equal(isFilenameDomainCollisionSuffix('throughoutes.net'), false);
  assert.equal(isFilenameDomainCollisionSuffix('evil.com'), false);
});

test('1. Huntress INC shape: mixed Item table keeps contacted domain + C2 IP as Indicators', () => {
  const out = run(
    iocItemTable([
      ['INC-README.txt', 'First INC ransom note'],
      ['DATALEAK_PRESS_RELEASE.txt', 'Second INC ransom note'],
      ['C:\\ProgramData\\Vendettister\\jocularities.ps1', 'Obfuscated PowerShell implant referenced by an early scheduled task'],
      ['throughoutes[.]net', 'Domain contacted by the obfuscated PowerShell implant'],
      ['213.111.185[.]108', 'Command-and-control IP associated with the observed AnyDesk installation'],
      ['hwau.exe', 'EDR/AV killer component found in C:\\Users\\Public\\ on a domain controller'],
      ['HealthUpdater.exe', 'Renamed Vicarius vRx executable, observed in C:\\Program Files\\7-Zip\\'],
      ['HWAuidoOs2Ec.sys', 'Driver loaded by the HwAudio kernel-driver service']
    ])
  );
  const domain = find(out, 'throughoutes.net');
  assert.ok(domain, 'throughoutes.net extracted');
  assert.equal(domain.candidate_type, 'domain');
  assert.notEqual(domain.typing_reason, 'file_name_column');
  assert.equal(member(out, 'throughoutes.net'), true);
  assert.equal(member(out, '213.111.185.108'), true);
  assert.equal(member(out, 'hwau.exe'), false);
  assert.equal(member(out, 'INC-README.txt'), false);
  assert.equal(qualityCodes(out).includes(QUALITY_CODES.FILE_NAME_COLUMN_NETWORK_CONFLICT), false);
});

test('2. Historical filename collision: back.pl among webshells stays a file', () => {
  const rows = [
    ['b374.php', `MD5: ${md5('1')}`],
    ['back.pl', `MD5: ${md5('2')}`],
    ['error.jsp', `MD5: ${md5('3')}`]
  ];
  const interp = interpretIocTable({ id: 't', table: { headers: ['Name', 'Hashes'], rows } });
  const back = interp.rows.flatMap((r) => r.values).find((v) => v.refanged === 'back.pl');
  assert.equal(back.candidate_type, 'technical_artifact');
  assert.equal(back.typing_reason, 'file_name_column');
  assert.equal(back.is_ioc, false);

  const out = run(`<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Name</th><th>Hashes</th></tr></thead><tbody>
${rows.map(([n, h]) => `<tr><td>${n}</td><td>${h}</td></tr>`).join('\n')}
</tbody></table>`);
  const c = find(out, 'back.pl');
  assert.ok(c);
  assert.equal(c.candidate_type, 'technical_artifact');
  assert.equal(member(out, 'back.pl'), false);
});

test('3. Settra control: two C2 IPs + filenames → exactly two network Indicators', () => {
  const out = run(
    `<h2>Indicators of Compromise (IOCs)</h2>
<table><thead><tr><th>Item</th><th>Description</th></tr></thead><tbody>
<tr><td>45.13.122[.]7</td><td>MeshAgent C2 address in July incident; MeshAgent renamed to mvtcs.exe.</td></tr>
<tr><td>193.5.65[.]114</td><td>MeshAgent C2 address in September incident.</td></tr>
<tr><td>WIN-LIVFRVQFMKO</td><td>Malicious workstation linked to the September incident and previous incidents.</td></tr>
<tr><td>RESTORE_FILES.txt</td><td>Ransom note created in both incidents.</td></tr>
<tr><td>gdrv.sys</td><td>BYOVD filename observed in September incident.</td></tr>
<tr><td>.locked_wip</td><td>Encrypted file extension in September incident.</td></tr>
<tr><td>.locked</td><td>Encrypted file extension in July incident.</td></tr>
</tbody></table>`
  );
  assert.equal(member(out, '45.13.122.7'), true);
  assert.equal(member(out, '193.5.65.114'), true);
  const networkMembers = out.candidates.filter((c) => isReportIndicatorMember(persisted(c)));
  assert.equal(networkMembers.length, 2);
  assert.equal(qualityCodes(out).includes(QUALITY_CODES.FILE_NAME_COLUMN_NETWORK_CONFLICT), false);
});

test('4. Strong TLD with explicit file evidence stays a file, not a domain', () => {
  const out = run(
    `<h2>Indicators of Compromise</h2>
<table><thead><tr><th>File Name</th><th>Description</th></tr></thead><tbody>
<tr><td>stage.exe</td><td>Stager binary</td></tr>
<tr><td>payload.com</td><td>Dropped payload filename recovered from the temp directory</td></tr>
<tr><td>helper.dll</td><td>Side-loaded library</td></tr>
</tbody></table>`
  );
  const c = find(out, 'payload.com');
  assert.ok(c, 'payload.com present');
  assert.equal(c.candidate_type, 'technical_artifact');
  assert.equal(member(out, 'payload.com'), false);
});

test('5. Defanging alone does not bypass filename-collision demotion', () => {
  const interp = interpretIocTable({
    id: 't',
    table: {
      headers: ['Name', 'Hashes'],
      rows: [
        ['b374.php', `MD5: ${md5('a')}`],
        ['back[.]pl', `MD5: ${md5('b')}`],
        ['error.jsp', `MD5: ${md5('c')}`]
      ]
    }
  });
  const back = interp.rows.flatMap((r) => r.values).find((v) => /back\.pl/i.test(v.refanged || v.normalized_value || ''));
  assert.ok(back);
  assert.equal(back.candidate_type, 'technical_artifact');
  assert.equal(back.typing_reason, 'file_name_column');
});

test('6. Publisher network evidence preserves domain in a mixed Item column', () => {
  const out = run(
    iocItemTable([
      ['dropper.exe', 'First-stage dropper'],
      ['loader.dll', 'Injected library'],
      ['relay-panel[.]shop', 'C2 domain contacted by the dropper'],
      ['notes.txt', 'Ransom note name']
    ])
  );
  const c = find(out, 'relay-panel.shop');
  assert.ok(c);
  assert.equal(c.candidate_type, 'domain');
  assert.equal(member(out, 'relay-panel.shop'), true);
  assert.equal(member(out, 'dropper.exe'), false);
});

test('7. Quality: silent file_name_column demotion with network evidence warns; fixed path stays clean', () => {
  const conflict = assessExtractionQuality({
    candidates: [
      {
        candidate_type: 'technical_artifact',
        normalized_value: 'throughoutes.net',
        original_value: 'throughoutes[.]net',
        is_ioc: false,
        typing_reason: 'file_name_column',
        type_resolution: { reason: 'file_name_column' },
        assessment: 'context_only',
        evidence_text: 'throughoutes[.]net | Domain contacted by the obfuscated PowerShell implant',
        table_rows: [
          {
            description: 'Domain contacted by the obfuscated PowerShell implant',
            column_header: 'Item'
          }
        ],
        occurrences: [{ block_id: 'b036', zone: 'explicit_ioc_section', form: 'table_row' }],
        __member: false
      },
      {
        candidate_type: 'ip',
        normalized_value: '213.111.185.108',
        is_ioc: true,
        assessment: 'malicious',
        source_assertion: 'explicit_ioc',
        evidence: { document_has_authoritative_scope: true, source_assertion: 'explicit_ioc' },
        occurrences: [{ block_id: 'b036', zone: 'explicit_ioc_section', form: 'table_row' }],
        __member: true
      }
    ],
    blocks: [{ id: 'b036', type: 'table', zone: 'explicit_ioc_section', text: 'IoC Table' }],
    diagnostics: {}
  });
  assert.equal(conflict.status, 'warning');
  assert.ok(conflict.warnings.some((w) => w.code === QUALITY_CODES.FILE_NAME_COLUMN_NETWORK_CONFLICT));

  const fixed = run(
    iocItemTable([
      ['dropper.exe', 'First-stage dropper'],
      ['throughoutes[.]net', 'Domain contacted by the obfuscated PowerShell implant'],
      ['helper.dll', 'Side library']
    ])
  );
  assert.equal(member(fixed, 'throughoutes.net'), true);
  assert.equal(qualityCodes(fixed).includes(QUALITY_CODES.FILE_NAME_COLUMN_NETWORK_CONFLICT), false);
  assert.notEqual(fixed.diagnostics.quality.status, 'high');
});

test('blast-radius: Field|Source|Purpose analysis table does not promote a clear domain among filenames', () => {
  const out = run(`<h2>C2 beacon and victim management</h2>
<p>The following table represents this request data and its associated fields:</p>
<table><thead><tr><th>Field</th><th>Source</th><th>Purpose</th></tr></thead><tbody>
<tr><td>machine_name</td><td>$env:COMPUTERNAME</td><td>Victim identification</td></tr>
<tr><td>client_id</td><td>GUID in client_id.txt</td><td>Unique implant ID</td></tr>
<tr><td>ip_public</td><td>api.ipify.org</td><td>External IP for geolocation and targeting</td></tr>
<tr><td>comentario</td><td>comentario.txt</td><td>Operator notes</td></tr>
<tr><td>comando</td><td>comando.txt</td><td>Last command received</td></tr>
<tr><td>remoto</td><td>agent.txt</td><td>RAT installation status</td></tr>
</tbody></table>
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Type</th><th>Indicator</th></tr></thead><tbody>
<tr><td>Domain</td><td>evil-c2[.]example</td></tr>
</tbody></table>`);
  const ipify = find(out, 'api.ipify.org');
  if (ipify) {
    assert.notEqual(ipify.candidate_type, 'domain', 'api.ipify.org must not be a domain Indicator from Source column');
    assert.equal(member(out, 'api.ipify.org'), false);
  }
  assert.equal(member(out, 'evil-c2.example'), true);
});

test('8. Reviewed-data protection: identity correction of a demoted domain does not migrate analyst state', async () => {
  // Contract pin: refresh treats technical_artifact → domain as a new identity
  // (pending), never copying ignored/approved state across types. Covered in
  // depth by extractionRefresh.test.js ("identity correction"); this asserts
  // the production INC shape would become a domain Indicator identity.
  const out = run(
    iocItemTable([
      ['a.exe', 'tool'],
      ['b.dll', 'tool'],
      ['throughoutes[.]net', 'Domain contacted by the implant'],
      ['c.sys', 'driver']
    ])
  );
  const domain = find(out, 'throughoutes.net');
  assert.equal(domain.candidate_type, 'domain');
  assert.equal(domain.assessment === 'context_only' && domain.is_ioc === false, false);
  assert.equal(isReportIndicatorMember(persisted(domain)), true);
});
