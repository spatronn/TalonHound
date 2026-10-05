import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  describeFileArtifactDualWriteFailure,
  runBestEffortFileArtifactDualWrite
} from './fileArtifactDualWriteDiagnostics.js';

describe('describeFileArtifactDualWriteFailure', () => {
  it('redacts observables (case-insensitive), hashes and credential-shaped fragments', () => {
    const err = Object.assign(new Error(
      'failed for EVIL.Example.test d41d8cd98f00b204e9800998ecf8427e '
      + 'Authorization: Bearer tok_abc x-apikey: K9xyz password=hunter2 postgres://u:p@db:5432/th'
    ), { code: '42P01' });
    const d = describeFileArtifactDualWriteFailure(err, { redactValues: ['evil.example.test'] });
    assert.equal(d.error_code, '42P01');
    assert.equal(d.error_class, 'Error');
    for (const leaked of ['evil.example', 'd41d8cd9', 'tok_abc', 'K9xyz', 'hunter2', 'u:p@db']) {
      assert.ok(!d.error_message.toLowerCase().includes(leaked.toLowerCase()), leaked);
    }
    assert.match(d.error_message, /^failed for <observable> <hash> /);
  });

  it('describes { ok: false } results and bounds the message', () => {
    const d = describeFileArtifactDualWriteFailure({ ok: false, error: 'x'.repeat(1000), code: '23505' });
    assert.equal(d.error_code, '23505');
    assert.equal(d.error_class, 'DualWriteResult');
    assert.equal(d.error_message.length, 300);
  });
});

describe('runBestEffortFileArtifactDualWrite', () => {
  it('never rejects; logs once on failure, never on success or skip', async () => {
    const entries = [];
    const logger = { warn: (message, fields) => entries.push({ message, fields }) };
    const fields = { component: 'test' };
    assert.deepEqual(await runBestEffortFileArtifactDualWrite({ run: async () => ({ skipped: true }), logger, fields }),
      { ok: true, result: { skipped: true } });
    assert.equal(entries.length, 0);
    assert.deepEqual(await runBestEffortFileArtifactDualWrite({ run: async () => { throw new Error('boom'); }, logger, fields }),
      { ok: false });
    assert.deepEqual(await runBestEffortFileArtifactDualWrite({ run: async () => ({ ok: false, code: 'E1' }), logger, fields }),
      { ok: false });
    assert.equal(entries.length, 2);
    assert.equal(entries[0].fields.operation, 'file_artifact_dual_write');
    assert.equal(entries[0].fields.result, 'failed');
    assert.equal(entries[1].fields.error_code, 'E1');
  });
});
