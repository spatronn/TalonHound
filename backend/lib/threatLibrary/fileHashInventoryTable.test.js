/**
 * Filename|MD5 component inventories in technical-analysis sections must not
 * become self-proving publisher IOC tables (tl-table-v7 / tl-candidates-v27).
 * Formal IOC appendices, sample-hash headings, typed IOC tables, and network
 * Indicator tables remain asserted.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { annotateDocumentZones, THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from './documentZones.js';
import {
  extractCandidatesWithDiagnostics,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import {
  interpretIocTable,
  isFileHashInventoryTable,
  TABLE_SEMANTICS_VERSION,
  headerIntent
} from './tableSemantics.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';

assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v16');
assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v44');
assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v13');
assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v19');

const LEGIT_EXE = 'd98f568496512e4f98670c61c97cb07a';
const MAL_DLL = 'aa3086be652c8b20b0b29b2730d57119';
const MAL_MUI = 'a514d1bb62d7916475946fe7c07ac0aa';
const MAL_DAT = '9cbd560f820c95d7c38342cd558cb5c6';
const IOC_INSTALLER = 'c559cc68986933200fd5d9e4388e2f58';
const IOC_DROPPER = 'b3352b42432dedc4a519f011dc8b5d5a';
const IOC_DROPPER2 = '24fcebdeecba65004fdb0923763d74fd';
const IOC_DLL2 = '9c872a0d5d5a38950e8b9ac9b488be3f';
const NARRATIVE_MD5 = '1f65544978b8ea0e745e573b8ee9684b';

function extract(html) {
  const { document } = extractCanonicalDocumentFromHtml(html, {
    url: 'https://securelist.example/strikeshark/1'
  });
  const zoned = annotateDocumentZones(document, {
    sourceUrl: 'https://securelist.example/strikeshark/1',
    sourceHost: 'securelist.example'
  });
  return extractCandidatesWithDiagnostics(zoned);
}

function persisted(c) {
  return { ...c, evidence: buildCandidateEvidenceRecord(c) };
}

function isMember(c) {
  return Boolean(c) && isReportIndicatorMember(persisted(c));
}

function find(candidates, type, value) {
  const v = String(value).toLowerCase();
  return candidates.find(
    (c) => c.candidate_type === type && String(c.normalized_value).toLowerCase() === v
  );
}

function strikeSharkShapedHtml() {
  return `
<html><body><article>
<h1>StrikeShark: investigating a new campaign</h1>
<h2>Initial infection</h2>
<p>One of the earliest observed actions involved copying the legitimate Windows
application SystemSettings.exe to a new location before executing it.</p>
<pre>cd C:\\Windows\\ImmersiveControlPanel\\
copy SystemSettings.exe C:\\ProgramData\\
SystemSettings.exe</pre>
<p>Alternative side-loading targets included msedge.dll, PrintDialog.dll, and
miracastview.dll. Encrypted modules used filenames such as GameInputInboxs32.mui,
diagerr.xml, NtfsLog.etl, Ignored.Dat, and VistaCompat.nls.</p>
<p>In one dropper sample, discovered on a machine located in Lebanon
(MD5: ${NARRATIVE_MD5}), the dropper extracts SystemSettings.dll.</p>
<h2>SharkLoader installation</h2>
<table>
<tr><th>Filename</th><th>Description</th></tr>
<tr><td>SystemSettings.exe</td><td>Legitimate Windows application abused for DLL side-loading of the malicious DLL SystemSettings.dll.</td></tr>
<tr><td>SystemSettings.dll</td><td>Main malicious SharkLoader DLL responsible for the core loader functionality.</td></tr>
<tr><td>DscCoreR.mui</td><td>An encrypted module that contains an embedded Cobalt Strike Beacon.</td></tr>
<tr><td>SyncRes.dat</td><td>An encrypted DLL that is used to install multiple API hooks.</td></tr>
</table>
<h2>SharkLoader DLL – Main implant</h2>
<p>For detailed analysis we focus on components deployed by a malicious dropper
named sample.pdf.exe (MD5: ${IOC_DROPPER2}).</p>
<table>
<tr><th>Filename</th><th>MD5</th></tr>
<tr><td>SystemSettings.exe</td><td>${LEGIT_EXE.toUpperCase()}</td></tr>
<tr><td>SystemSettings.dll</td><td>${MAL_DLL.toUpperCase()}</td></tr>
<tr><td>DscCoreR.mui</td><td>${MAL_MUI.toUpperCase()}</td></tr>
<tr><td>SyncRest.dat</td><td>${MAL_DAT.toUpperCase()}</td></tr>
</table>
<h2>Post-compromise activity</h2>
<pre>systeminfo
ipconfig /all
tasklist /svc</pre>
<h2>Indicators of compromise</h2>
<p>Additional information is available via intelreports@kaspersky.com.</p>
<p>${IOC_INSTALLER.toUpperCase()} Installer</p>
<p>${IOC_DROPPER.toUpperCase()} Dropper</p>
<p>${IOC_DROPPER2.toUpperCase()} Dropper</p>
<p>${IOC_DLL2.toUpperCase()} SharkLoader DLL</p>
<p>${MAL_DLL.toUpperCase()} SharkLoader DLL</p>
<p>${MAL_MUI.toUpperCase()} Encrypted file</p>
<p>${MAL_DAT.toUpperCase()} Encrypted file</p>
<p>connect-microsoft[.]com</p>
<p>ms-record[.]com</p>
<p>ms-record[.]top</p>
<p>ms-tray[.]top</p>
<ul>
<li>APT</li>
<li>Malware</li>
<li>Node.js</li>
</ul>
</article></body></html>`;
}

test('Filename|MD5 under analysis is a non-explicit file-hash inventory', () => {
  assert.equal(headerIntent('Filename'), 'description');
  assert.equal(headerIntent('MD5'), 'indicator');
  const block = {
    id: 't1',
    section_heading: 'SharkLoader DLL – Main implant',
    zone: 'report_body',
    table: {
      headers: ['Filename', 'MD5'],
      rows: [
        ['SystemSettings.exe', LEGIT_EXE],
        ['SystemSettings.dll', MAL_DLL]
      ]
    }
  };
  const r = interpretIocTable(block);
  assert.equal(r.file_hash_inventory, true);
  assert.equal(isFileHashInventoryTable(r.columns, r.rows, null), true);
  assert.equal(r.explicit, false);
  assert.equal(r.reason, 'file_hash_inventory_outside_ioc_scope');
  // Filename cells may still be read as indicator-shaped tokens for artifact
  // provenance, but the MD5 header alone must not self-prove an IOC appendix.
  assert.equal(r.columns.find((c) => c.header === 'MD5')?.intent, 'indicator');
});

test('Filename|MD5 under Indicators of compromise remains explicit', () => {
  const block = {
    id: 't2',
    section_heading: 'Indicators of compromise',
    zone: 'explicit_ioc_section',
    table: {
      headers: ['Filename', 'MD5'],
      rows: [
        ['loader.dll', MAL_DLL],
        ['dropper.exe', IOC_DROPPER]
      ]
    }
  };
  const r = interpretIocTable(block, { inAuthoritativeScope: true });
  assert.equal(r.file_hash_inventory, true);
  assert.equal(r.explicit, true);
  assert.equal(r.reason, 'structural_ioc_table');
});

test('Filename|MD5 under Malicious samples heading remains explicit', () => {
  const block = {
    id: 't3',
    section_heading: 'Malicious samples',
    zone: 'sample_table',
    table: {
      headers: ['Filename', 'SHA-256'],
      rows: [
        ['a.exe', '005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f'],
        ['b.dll', '2d338ffc8cc80293575c6800c059e33eb41e967907c20ba7687b2231c50837db']
      ]
    }
  };
  const r = interpretIocTable(block, { inAuthoritativeScope: true });
  assert.equal(r.file_hash_inventory, true);
  assert.equal(r.explicit, true);
});

test('Type|Indicator|Description tables under body headings still self-prove', () => {
  const block = {
    id: 't4',
    section_heading: 'Frequently Asked Questions',
    zone: 'report_body',
    table: {
      headers: ['Type', 'Indicator', 'Description'],
      rows: [
        ['MD5', MAL_DLL, 'payload'],
        ['Domain', 'evil.example.com', 'c2']
      ]
    }
  };
  const r = interpretIocTable(block);
  assert.equal(r.file_hash_inventory, false);
  assert.equal(r.explicit, true);
  assert.equal(r.reason, 'structural_ioc_table');
});

test('A. Formal IOC section: seven MD5 + four domains remain Indicators', () => {
  const { candidates } = extract(strikeSharkShapedHtml());
  const expected = [
    ['md5', IOC_INSTALLER],
    ['md5', IOC_DROPPER],
    ['md5', IOC_DROPPER2],
    ['md5', IOC_DLL2],
    ['md5', MAL_DLL],
    ['md5', MAL_MUI],
    ['md5', MAL_DAT],
    ['domain', 'connect-microsoft.com'],
    ['domain', 'ms-record.com'],
    ['domain', 'ms-record.top'],
    ['domain', 'ms-tray.top']
  ];
  for (const [type, value] of expected) {
    const c = find(candidates, type, value);
    assert.ok(c, `missing ${type}:${value}`);
    assert.equal(isMember(c), true, `${type}:${value} must remain Indicator`);
    assert.equal(c.source_assertion, 'explicit_ioc', `${type}:${value} assertion`);
  }
});

test('B. Malware sample Filename|MD5 table: legitimate host hash is not Indicator; malicious hashes kept via IOC appendix', () => {
  const { candidates, diagnostics } = extract(strikeSharkShapedHtml());
  const inventory = diagnostics.explicit_tables.tables.find(
    (t) => t.reason === 'file_hash_inventory_outside_ioc_scope'
  );
  assert.ok(inventory, 'component Filename|MD5 must be non-explicit inventory');
  assert.equal(inventory.explicit, false);
  assert.notEqual(inventory.zone, 'explicit_ioc_section');

  const legit = find(candidates, 'md5', LEGIT_EXE);
  assert.ok(legit, 'legitimate SystemSettings.exe hash still extracted');
  assert.equal(isMember(legit), false, 'legitimate host binary hash must not be Indicator');
  assert.notEqual(legit.source_assertion, 'explicit_ioc');

  for (const h of [MAL_DLL, MAL_MUI, MAL_DAT]) {
    assert.equal(isMember(find(candidates, 'md5', h)), true, `${h} kept via IOC section`);
  }
});

test('C. Technical filename list tokens are not network domains', () => {
  const { candidates } = extract(strikeSharkShapedHtml());
  const files = [
    'SystemSettings.exe',
    'SystemSettings.dll',
    'DscCoreR.mui',
    'SyncRes.dat',
    'msedge.dll',
    'PrintDialog.dll',
    'miracastview.dll',
    'diagerr.xml',
    'NtfsLog.etl',
    'VistaCompat.nls',
    'GameInputInboxs32.mui'
  ];
  for (const name of files) {
    const asDomain = find(candidates, 'domain', name.toLowerCase());
    assert.equal(asDomain, undefined, `${name} must not be a domain`);
    const art = candidates.find(
      (c) => c.candidate_type === 'technical_artifact' &&
        String(c.normalized_value).toLowerCase() === name.toLowerCase()
    );
    if (art) {
      assert.equal(isMember(art), false, `${name} artifact is never Indicator`);
    }
  }
});

test('D. Technical commands do not become network IOCs', () => {
  const { candidates } = extract(strikeSharkShapedHtml());
  for (const name of ['systeminfo', 'ipconfig', 'tasklist']) {
    assert.equal(find(candidates, 'domain', name), undefined);
  }
});

test('E. Narrative MD5 outside IOC appendix is not Indicator under MODE A', () => {
  const { candidates, diagnostics } = extract(strikeSharkShapedHtml());
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, true);
  const narrative = find(candidates, 'md5', NARRATIVE_MD5);
  assert.ok(narrative);
  assert.equal(isMember(narrative), false);
  assert.equal(narrative.source_assertion, 'body_mention');
});

test('F. IOC boundary: post-IOC tags do not extend scope; Node.js stays out', () => {
  const { candidates } = extract(strikeSharkShapedHtml());
  assert.equal(
    candidates.some((c) => String(c.normalized_value).toLowerCase() === 'node.js' && isMember(c)),
    false
  );
  assert.equal(find(candidates, 'domain', 'kaspersky.com') == null ||
    isMember(find(candidates, 'domain', 'kaspersky.com')) === false, true);
});

test('G/H. Positive controls: defanged domains, structural typed table, C2 section', () => {
  const html = `
<html><body><article>
<h2>Network</h2>
<p>Beacon contacted update-check[.]example-cdn[.]net.</p>
<h2>Command and Control</h2>
<p>hxxps://relay.evil-c2[.]example/gate</p>
<p>203[.]0[.]113[.]50</p>
<h2>IOCs</h2>
<table>
<tr><th>Type</th><th>Indicator</th><th>Description</th></tr>
<tr><td>Domain</td><td>payload-host.example</td><td>C2</td></tr>
<tr><td>MD5</td><td>${MAL_DLL}</td><td>implant</td></tr>
</table>
</article></body></html>`;
  const { candidates } = extract(html);
  assert.equal(isMember(find(candidates, 'domain', 'payload-host.example')), true);
  assert.equal(isMember(find(candidates, 'md5', MAL_DLL)), true);
  assert.equal(isMember(find(candidates, 'domain', 'update-check.example-cdn.net')), false);
  assert.equal(isMember(find(candidates, 'url', 'https://relay.evil-c2.example/gate')), true);
  assert.equal(isMember(find(candidates, 'ip', '203.0.113.50')), true);
});
