import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  FILE_METADATA_PLACEHOLDERS,
  pickFileMetadataValue,
  buildFileInformation
} from './iocFileInformation.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function row(note) {
  return { note };
}

function makeOtxRow() {
  // OTX imports sha256 but without file metadata fields
  return row('Auto-imported from OTX | sha256=abc123def456abc123def456abc123def456abc123def456abc123def456abcd');
}

function makeMalwareBazaarEvidenceRow() {
  return row(
    'Auto-imported from MalwareBazaar CSV | external_id=abc123def456abc123def456abc123def456abc123def456abc123def456abcd'
    + ' | file_name=agent.exe | file_type=exe | mime=application/x-dosexec'
    + ' | reporter=abuse.ch | signature=AgentTesla'
    + ' | md5=aabbccddeeff00112233445566778899 | sha1=aabbccddeeff001122334455667788990011aabb'
    + ' | imphash=112233445566778899aabbccddeeff00 | ssdeep=12288:abc:def | tlsh=T1abc'
    + ' | vtpercent=87'
  );
}

// ---------------------------------------------------------------------------
// FILE_METADATA_PLACEHOLDERS
// ---------------------------------------------------------------------------

describe('FILE_METADATA_PLACEHOLDERS', () => {
  it('contains expected placeholder values', () => {
    assert.ok(FILE_METADATA_PLACEHOLDERS.has('-'));
    assert.ok(FILE_METADATA_PLACEHOLDERS.has('Unknown'));
    assert.ok(FILE_METADATA_PLACEHOLDERS.has('unknown'));
    assert.ok(FILE_METADATA_PLACEHOLDERS.has('n/a'));
    assert.ok(FILE_METADATA_PLACEHOLDERS.has('N/A'));
    assert.ok(FILE_METADATA_PLACEHOLDERS.has('none'));
    assert.ok(FILE_METADATA_PLACEHOLDERS.has('None'));
    assert.ok(FILE_METADATA_PLACEHOLDERS.has('null'));
    assert.ok(FILE_METADATA_PLACEHOLDERS.has(''));
  });
});

// ---------------------------------------------------------------------------
// pickFileMetadataValue
// ---------------------------------------------------------------------------

describe('pickFileMetadataValue', () => {
  it('returns current when current is real', () => {
    assert.equal(pickFileMetadataValue('real.exe', 'other.exe'), 'real.exe');
  });

  it('returns next when current is null', () => {
    assert.equal(pickFileMetadataValue(null, 'other.exe'), 'other.exe');
  });

  it('returns next when current is a placeholder', () => {
    assert.equal(pickFileMetadataValue('-', 'real.exe'), 'real.exe');
    assert.equal(pickFileMetadataValue('Unknown', 'real.exe'), 'real.exe');
    assert.equal(pickFileMetadataValue('n/a', 'real.exe'), 'real.exe');
    assert.equal(pickFileMetadataValue('None', 'real.exe'), 'real.exe');
    assert.equal(pickFileMetadataValue('null', 'real.exe'), 'real.exe');
  });

  it('returns null when both are null', () => {
    assert.equal(pickFileMetadataValue(null, null), null);
  });

  it('returns placeholder (current) when both are placeholders', () => {
    // Falls back gracefully rather than losing data
    assert.equal(pickFileMetadataValue('-', 'unknown'), '-');
  });
});

// ---------------------------------------------------------------------------
// buildFileInformation
// ---------------------------------------------------------------------------

describe('buildFileInformation', () => {
  it('returns null for non-file IOC type with no data', () => {
    const result = buildFileInformation([row('')], '1.2.3.4', 'ip', []);
    assert.equal(result, null);
  });

  it('populates sha256 from observable when type is sha256 and note has no sha256', () => {
    const sha256 = 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd';
    const result = buildFileInformation([row('')], sha256, 'sha256', []);
    assert.ok(result);
    assert.equal(result.sha256, sha256);
  });

  it('preserves existing file_information when no evidence rows provided', () => {
    const sha256 = 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd';
    const result = buildFileInformation([makeOtxRow()], sha256, 'sha256');
    assert.ok(result);
    assert.equal(result.sha256, sha256);
    assert.equal(result.file_name, null);
  });

  it('enriches file metadata from evidence rows when primary row lacks them', () => {
    const sha256 = 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd';
    const result = buildFileInformation(
      [makeOtxRow()],
      sha256,
      'sha256',
      [makeMalwareBazaarEvidenceRow()]
    );
    assert.ok(result);
    assert.equal(result.file_name, 'agent.exe');
    assert.equal(result.file_type, 'exe');
    assert.equal(result.mime, 'application/x-dosexec');
    assert.equal(result.reporter, 'abuse.ch');
    assert.equal(result.md5, 'aabbccddeeff00112233445566778899');
    assert.equal(result.sha1, 'aabbccddeeff001122334455667788990011aabb');
    assert.equal(result.imphash, '112233445566778899aabbccddeeff00');
    assert.equal(result.ssdeep, '12288:abc:def');
    assert.equal(result.tlsh, 'T1abc');
    assert.equal(result.vtpercent, '87');
  });

  it('does not overwrite existing real metadata with evidence row values', () => {
    const primaryNote =
      'Auto-imported | file_name=legit.exe | file_type=pe | reporter=primary-source'
      + ' | sha256=abc123def456abc123def456abc123def456abc123def456abc123def456abcd';
    const evidenceNote = 'file_name=other.exe | reporter=bazaar | file_type=pdf';

    const result = buildFileInformation(
      [row(primaryNote)],
      'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
      'sha256',
      [row(evidenceNote)]
    );
    assert.equal(result.file_name, 'legit.exe');
    assert.equal(result.file_type, 'pe');
    assert.equal(result.reporter, 'primary-source');
  });

  it('overwrites placeholder values in primary row with real values from evidence', () => {
    const primaryNote =
      'file_name=- | file_type=Unknown | reporter=n/a'
      + ' | sha256=abc123def456abc123def456abc123def456abc123def456abc123def456abcd';
    const evidenceNote = 'file_name=real.exe | file_type=exe | reporter=bazaar';

    const result = buildFileInformation(
      [row(primaryNote)],
      'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
      'sha256',
      [row(evidenceNote)]
    );
    assert.equal(result.file_name, 'real.exe');
    assert.equal(result.file_type, 'exe');
    assert.equal(result.reporter, 'bazaar');
  });

  it('first non-placeholder value wins across multiple evidence rows', () => {
    const ev1 = row('file_name=first.exe | reporter=source1');
    const ev2 = row('file_name=second.exe | reporter=source2');

    const result = buildFileInformation(
      [row('')],
      'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
      'sha256',
      [ev1, ev2]
    );
    assert.equal(result.file_name, 'first.exe');
    assert.equal(result.reporter, 'source1');
  });

  it('returns object with all expected keys for sha256 type', () => {
    const sha256 = 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd';
    const result = buildFileInformation([row('')], sha256, 'sha256', []);
    const expectedKeys = ['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh', 'file_name', 'file_type', 'mime', 'reporter', 'vtpercent'];
    for (const key of expectedKeys) {
      assert.ok(Object.prototype.hasOwnProperty.call(result, key), `missing key: ${key}`);
    }
  });
});
