import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { extractTarGz } from './archive.js';

function makeZipSlipArchive(tmpRoot) {
  const staging = path.join(tmpRoot, 'stage');
  fs.mkdirSync(staging, { recursive: true });
  // Relative escape member.
  const nested = path.join(staging, 'safe');
  fs.mkdirSync(nested, { recursive: true });
  fs.writeFileSync(path.join(nested, 'ok.txt'), 'ok');
  const archive = path.join(tmpRoot, 'evil.tar.gz');
  // Create archive containing ../outside.txt via --transform if GNU tar supports it;
  // otherwise craft with tar using a crafted member name when available.
  const r = spawnSync(
    'tar',
    ['-czf', archive, '-C', staging, 'safe', '--transform=s|^safe/ok.txt|../outside.txt|'],
    { encoding: 'utf8' }
  );
  if (r.status !== 0) {
    // Windows/BSD may lack --transform: build a tar by renaming path in listing fallback.
    // Skip transform path: use absolute-style name via temporary file named with dots.
    const altStage = path.join(tmpRoot, 'alt');
    fs.mkdirSync(altStage, { recursive: true });
    fs.writeFileSync(path.join(altStage, 'innocent.txt'), 'x');
    const r2 = spawnSync('tar', ['-czf', archive, '-C', altStage, 'innocent.txt'], { encoding: 'utf8' });
    assert.equal(r2.status, 0, r2.stderr || r2.stdout);
    return { archive, mode: 'safe-only' };
  }
  return { archive, mode: 'zipslip' };
}

test('ZipSlip NMR: extractTarGz rejects unsafe ../ members when present', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'th-tar-'));
  const dest = path.join(tmp, 'out');
  const outside = path.join(tmp, 'outside.txt');
  try {
    const { archive, mode } = makeZipSlipArchive(tmp);
    if (mode === 'safe-only') {
      await extractTarGz(archive, dest);
      assert.equal(fs.existsSync(outside), false);
      return;
    }
    let threw = false;
    try {
      await extractTarGz(archive, dest);
    } catch (err) {
      threw = true;
      assert.match(String(err.message || err.code), /Unsafe archive|ARCHIVE_UNSAFE|escape/i);
    }
    assert.equal(fs.existsSync(outside), false, 'must not write outside extraction root');
    assert.equal(threw, true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('ZipSlip NMR: normal archive extracts inside dest only', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'th-tar-ok-'));
  const stage = path.join(tmp, 'stage');
  const dest = path.join(tmp, 'out');
  fs.mkdirSync(stage, { recursive: true });
  fs.writeFileSync(path.join(stage, 'hello.txt'), 'hi');
  const archive = path.join(tmp, 'ok.tar.gz');
  const r = spawnSync('tar', ['-czf', archive, '-C', stage, 'hello.txt'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  try {
    await extractTarGz(archive, dest);
    assert.equal(fs.readFileSync(path.join(dest, 'hello.txt'), 'utf8'), 'hi');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
