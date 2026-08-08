import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { assertSafeTarMembers, extractTarGz, listTarGz, safeRmRf } from './archive.js';

test('assertSafeTarMembers rejects .. and absolute members', () => {
  assert.throws(() => assertSafeTarMembers(['ok/a.txt', '../escape.txt']), /Unsafe/);
  assert.throws(() => assertSafeTarMembers(['/etc/passwd']), /Unsafe/);
  assert.throws(() => assertSafeTarMembers(['C:/Windows/Temp/x']), /Unsafe/);
  assert.doesNotThrow(() => assertSafeTarMembers(['bundle/manifest.json', 'bundle/database/postgres.dump']));
});

function pythonWriteArchive(archivePath, members) {
  // members: [{ name, data? | link? }]
  const script = `
import tarfile, io, json, sys
arch = sys.argv[1]
members = json.loads(sys.argv[2])
with tarfile.open(arch, 'w:gz') as tf:
    for m in members:
        info = tarfile.TarInfo(name=m['name'])
        if m.get('link') is not None:
            info.type = tarfile.SYMTYPE
            info.linkname = m['link']
            info.size = 0
            tf.addfile(info)
        else:
            data = (m.get('data') or '').encode()
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
`;
  const r = spawnSync(
    'python',
    ['-c', script, archivePath, JSON.stringify(members)],
    { encoding: 'utf8' }
  );
  if (r.status !== 0) {
    throw new Error(`python archive write failed: ${r.stderr || r.stdout}`);
  }
}

test('extractTarGz rejects ZipSlip member and does not write outside dest', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'th-extract-'));
  const dest = path.join(root, 'dest');
  const arch = path.join(root, 'evil.tar.gz');
  try {
    pythonWriteArchive(arch, [
      { name: '../escape.txt', data: 'PWNED' },
      { name: 'safe.txt', data: 'ok' }
    ]);
    await assert.rejects(() => extractTarGz(arch, dest), (err) => err.code === 'UNSAFE_ARCHIVE_MEMBER');
    const escaped = path.resolve(dest, '../escape.txt');
    assert.equal(fs.existsSync(escaped), false);
    assert.equal(fs.existsSync(path.join(dest, 'safe.txt')), false);
  } finally {
    await safeRmRf(root);
  }
});

test('extractTarGz extracts a confined safe archive', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'th-extract-ok-'));
  const dest = path.join(root, 'dest');
  const arch = path.join(root, 'ok.tar.gz');
  try {
    pythonWriteArchive(arch, [
      { name: 'bundle/manifest.json', data: '{"ok":true}' },
      { name: 'bundle/safe.txt', data: 'hello' }
    ]);
    await extractTarGz(arch, dest);
    const members = await listTarGz(arch);
    assert.ok(members.some((m) => m.includes('manifest.json')));
    assert.equal(fs.readFileSync(path.join(dest, 'bundle', 'safe.txt'), 'utf8'), 'hello');
  } finally {
    await safeRmRf(root);
  }
});
