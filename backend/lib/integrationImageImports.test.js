/**
 * Guard: the integration image (integration/Dockerfile) bakes copies of selected
 * backend/lib modules into /app/lib. Every static relative import of a module in
 * that image must resolve to a file the image actually contains, or the
 * integration worker/scheduler crash-loop with ERR_MODULE_NOT_FOUND on start.
 *
 * Lazy `await import()` calls are not checked here: they sit behind feature
 * flags / best-effort try-catch and are resolved at call time.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const dockerfilePath = path.join(repoRoot, 'integration', 'Dockerfile');

/** Map of image path → repo source path, mirroring `COPY integration/ ./` + backend COPYs. */
function simulateImage() {
  const image = new Map();
  const addTree = (srcRel, dst) => {
    const src = path.join(repoRoot, srcRel);
    if (fs.statSync(src).isDirectory()) {
      for (const entry of fs.readdirSync(src)) {
        if (entry === 'node_modules') continue;
        addTree(path.posix.join(srcRel, entry), path.posix.join(dst, entry));
      }
    } else {
      image.set(dst, src);
    }
  };
  addTree('integration', '/app');
  const dockerfile = fs.readFileSync(dockerfilePath, 'utf8');
  for (const m of dockerfile.matchAll(/^COPY (backend\/\S+) (\S+)$/gm)) {
    addTree(m[1], m[2].startsWith('/') ? m[2] : path.posix.join('/app', m[2]));
  }
  return image;
}

const STATIC_RELATIVE_IMPORT = /^\s*(?:import|export)\s[^;]*?from\s+['"](\.{1,2}\/[^'"]+)['"]/gm;

test('integration image: every static relative import resolves inside the image', (t) => {
  // dockerized backend `npm test` only has /app (backend); skip there.
  if (!fs.existsSync(dockerfilePath)) {
    t.skip('integration/Dockerfile not present');
    return;
  }
  const image = simulateImage();
  const missing = [];
  for (const [imagePath, srcPath] of image) {
    if (!imagePath.endsWith('.js') || imagePath.includes('.test.')) continue;
    const code = fs.readFileSync(srcPath, 'utf8');
    for (const m of code.matchAll(STATIC_RELATIVE_IMPORT)) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(imagePath), m[1]));
      if (!image.has(target)) missing.push(`${imagePath} -> ${m[1]}`);
    }
  }
  assert.deepEqual(missing, [], 'add the missing backend/lib modules to integration/Dockerfile');
});

test('integration image ships the source-import history module iocExpiration depends on', (t) => {
  if (!fs.existsSync(dockerfilePath)) {
    t.skip('integration/Dockerfile not present');
    return;
  }
  const image = simulateImage();
  assert.ok(image.has('/app/lib/iocExpiration.js'));
  assert.ok(image.has('/app/lib/iocSourceImportHistory.js'));
});
