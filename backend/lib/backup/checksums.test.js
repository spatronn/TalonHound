import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sha256Buffer, sha256File, writeChecksumsFile, verifyChecksumsFile } from './checksums.js';

describe('backup checksums', () => {
  let dir;
  before(async () => {
    dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-ck-'));
    await fs.promises.writeFile(path.join(dir, 'a.bin'), 'hello');
  });
  after(async () => {
    await fs.promises.rm(dir, { recursive: true, force: true });
  });

  it('hashes buffers and files', async () => {
    const h1 = sha256Buffer(Buffer.from('hello'));
    const h2 = await sha256File(path.join(dir, 'a.bin'));
    assert.equal(h1, h2);
    assert.match(h1, /^[0-9a-f]{64}$/);
  });

  it('writes and verifies checksums.sha256', async () => {
    await writeChecksumsFile(dir, ['a.bin']);
    const ok = await verifyChecksumsFile(dir);
    assert.equal(ok.ok, true);
  });

  it('detects mismatch', async () => {
    await writeChecksumsFile(dir, ['a.bin']);
    await fs.promises.writeFile(path.join(dir, 'a.bin'), 'tampered');
    const bad = await verifyChecksumsFile(dir);
    assert.equal(bad.ok, false);
    assert.ok(bad.mismatches.includes('a.bin'));
  });
});
