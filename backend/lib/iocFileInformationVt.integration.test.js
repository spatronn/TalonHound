/**
 * Integration-level regression for VirusTotal → File Information promotion.
 *
 * This exercises the REAL IOC-detail assembly boundary: it composes the same two
 * production functions, in the same order, that the IOC detail serializer in
 * server.js runs — buildFileInformation() over the ioc_items note rows, then
 * promoteVtFileMetadataIntoFileInformation() over the persisted VirusTotal
 * normalized_summary.file block. It proves the end-to-end contract without a live
 * database.
 *
 * Limitation: server.js is an Express bootstrap module and cannot be imported in
 * isolation, and this repo's test harness has no Postgres fixture for the IOC
 * detail route, so the DB read of ioc_enrichments and the row-to-note mapping are
 * represented by realistic in-memory inputs rather than a real query. The
 * transformation logic under test is exactly the shipped code path.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { buildFileInformation } from './iocFileInformation.js';
import { promoteVtFileMetadataIntoFileInformation } from './virustotalFileMetadata.js';

const SHA256 = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const SHA1 = 'b'.repeat(40);
const MD5 = 'c'.repeat(32);

/** Mirror server.js: build FI from rows, then promote the persisted VT summary.file. */
function assembleIocDetailFileInformation({ rows, observable, observableType, vtNormalizedSummary }) {
  const fileInformation = buildFileInformation(rows, observable, observableType, []);
  if (!fileInformation) return null;
  const vtFileMeta = vtNormalizedSummary?.file || null;
  if (!vtFileMeta) return fileInformation;
  return promoteVtFileMetadataIntoFileInformation(fileInformation, vtFileMeta, {
    primaryType: observableType,
    primaryValue: observable
  }).file_information;
}

/** Shape of ioc_enrichments.normalized_summary written by normalizeVtSummary in server.js. */
function persistedVtSummary(fileOverrides = {}) {
  return {
    provider: 'virustotal',
    ioc_type: 'sha256',
    file: {
      md5: MD5,
      sha1: SHA1,
      sha256: SHA256,
      names: ['setup.exe', 'invoice.exe'],
      type_description: 'Win32 EXE',
      file_type: 'Win32 EXE',
      mime: 'application/x-dosexec',
      imphash: 'd'.repeat(32),
      tlsh: 'T1ABCDEF0123',
      ssdeep: '3072:abcd:efgh',
      meaningful_name: 'setup.exe',
      ...fileOverrides
    }
  };
}

describe('IOC detail: VirusTotal File Information promotion (assembly boundary)', () => {
  it('a SHA256-only OTX IOC + persisted VT enrichment yields SHA256/SHA1/MD5 + technical fields', () => {
    // Ingested from OTX with only the SHA256 in the note; no md5/sha1/type.
    const rows = [{ note: `Auto-imported from OTX | sha256=${SHA256}` }];

    const fi = assembleIocDetailFileInformation({
      rows,
      observable: SHA256,
      observableType: 'sha256',
      vtNormalizedSummary: persistedVtSummary()
    });

    assert.ok(fi, 'file_information present');
    assert.equal(fi.sha256, SHA256);
    assert.equal(fi.sha1, SHA1);   // learned from VT
    assert.equal(fi.md5, MD5);     // learned from VT
    assert.equal(fi.mime, 'application/x-dosexec');
    assert.equal(fi.file_type, 'Win32 EXE');
    assert.equal(fi.imphash, 'd'.repeat(32));
    assert.equal(fi.tlsh, 'T1ABCDEF0123');
    assert.equal(fi.ssdeep, '3072:abcd:efgh');
    // Provenance attributes the newly-learned values to VirusTotal.
    assert.equal(fi.provenance.md5, 'virustotal');
    assert.equal(fi.provenance.sha1, 'virustotal');
    // SHA256 came from the IOC itself, not VT.
    assert.equal(fi.provenance.sha256, undefined);
  });

  it('observed VT filenames appear as observations, never as canonical file_name', () => {
    const rows = [{ note: `Auto-imported from OTX | sha256=${SHA256}` }];
    const fi = assembleIocDetailFileInformation({
      rows,
      observable: SHA256,
      observableType: 'sha256',
      vtNormalizedSummary: persistedVtSummary()
    });
    assert.equal(fi.file_name, null);                            // canonical untouched
    assert.deepEqual(fi.observed_file_names, ['setup.exe', 'invoice.exe']);
    assert.equal(fi.provenance.observed_file_names, 'virustotal');
  });

  it('existing canonical values (from the ingesting source) are NOT overwritten by VT', () => {
    // MalwareBazaar-style richer note already carries md5 + file_type + mime.
    const existingMd5 = '9'.repeat(32);
    const rows = [{
      note: `Auto-imported from MalwareBazaar | sha256=${SHA256} | md5=${existingMd5}`
        + ' | file_type=exe | mime=application/vnd.custom | file_name=canonical.exe'
    }];

    const fi = assembleIocDetailFileInformation({
      rows,
      observable: SHA256,
      observableType: 'sha256',
      vtNormalizedSummary: persistedVtSummary()
    });

    assert.equal(fi.md5, existingMd5);                 // kept the source's md5
    assert.equal(fi.file_type, 'exe');                 // kept the source's type
    assert.equal(fi.mime, 'application/vnd.custom');   // kept the source's mime
    assert.equal(fi.file_name, 'canonical.exe');       // canonical name preserved
    assert.equal(fi.sha1, SHA1);                       // still filled the genuinely-empty sha1
    assert.equal(fi.provenance?.md5, undefined);       // md5 not attributed to VT
    assert.equal(fi.provenance?.sha1, 'virustotal');
  });

  it('VT identity mismatch attaches nothing (no wrong-file metadata)', () => {
    const otherSha = 'f'.repeat(64);
    const rows = [{ note: `Auto-imported from OTX | sha256=${SHA256}` }];
    const fi = assembleIocDetailFileInformation({
      rows,
      observable: SHA256,
      observableType: 'sha256',
      vtNormalizedSummary: persistedVtSummary({ sha256: otherSha })
    });
    assert.equal(fi.sha1, null);
    assert.equal(fi.md5, null);
    assert.equal(fi.provenance, undefined);
  });

  it('re-running enrichment is idempotent at the assembly boundary', () => {
    const rows = [{ note: `Auto-imported from OTX | sha256=${SHA256}` }];
    const first = assembleIocDetailFileInformation({
      rows, observable: SHA256, observableType: 'sha256', vtNormalizedSummary: persistedVtSummary()
    });
    // Second detail assembly over the same persisted data.
    const second = assembleIocDetailFileInformation({
      rows, observable: SHA256, observableType: 'sha256', vtNormalizedSummary: persistedVtSummary()
    });
    assert.deepEqual(second, first);
  });

  it('non-file IOC (domain) is unaffected — no file_information fabricated', () => {
    const fi = assembleIocDetailFileInformation({
      rows: [{ note: 'Auto-imported from OTX' }],
      observable: 'evil.example.com',
      observableType: 'domain',
      vtNormalizedSummary: { file: { sha256: SHA256, md5: MD5 } }
    });
    assert.equal(fi, null);
  });
});
