/**
 * Guard: the integration image (integration/Dockerfile) bakes copies of selected
 * backend/lib modules into /app/lib. Every relative import of a module in that
 * image must resolve to a file the image actually contains, or the integration
 * worker/scheduler crash-loop with ERR_MODULE_NOT_FOUND on start (static
 * imports) or skip work behind a best-effort try/catch (lazy
 * `await import('./…')`, e.g. custom feed file-artifact dual-write, whose
 * failure must stay observable: customThreatFeedDualWrite.test.js).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const dockerfilePath = path.join(repoRoot, 'integration', 'Dockerfile');

/**
 * Image layout mirroring `COPY integration/ ./`, the backend COPYs and
 * `RUN ln -s <target> <link>` symlinks.
 * @returns {{ files: Map<string, string>, realpath: (p: string) => string }}
 */
function simulateImage() {
  const files = new Map(); // image path → repo source path
  const addTree = (srcRel, dst) => {
    const src = path.join(repoRoot, srcRel);
    if (fs.statSync(src).isDirectory()) {
      for (const entry of fs.readdirSync(src)) {
        if (entry === 'node_modules') continue;
        addTree(path.posix.join(srcRel, entry), path.posix.join(dst, entry));
      }
    } else {
      files.set(dst, src);
    }
  };
  addTree('integration', '/app');
  const dockerfile = fs.readFileSync(dockerfilePath, 'utf8');
  for (const m of dockerfile.matchAll(/^COPY (backend\/\S+) (\S+)$/gm)) {
    addTree(m[1], m[2].startsWith('/') ? m[2] : path.posix.join('/app', m[2]));
  }
  const links = [...dockerfile.matchAll(/^RUN ln -s (\/\S+) (\/\S+)$/gm)]
    .map((m) => ({ target: m[1], link: m[2] }));
  const realpath = (p) => {
    for (const { target, link } of links) {
      if (p === link || p.startsWith(`${link}/`)) return target + p.slice(link.length);
    }
    return p;
  };
  return { files, realpath };
}

const STATIC_RELATIVE_IMPORT = /^\s*(?:import|export)\s[^;]*?from\s+['"](\.{1,2}\/[^'"]+)['"]/gm;
const LAZY_RELATIVE_IMPORT = /\bimport\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g;

function unresolvedImports(pattern) {
  const { files, realpath } = simulateImage();
  const missing = [];
  for (const [imagePath, srcPath] of files) {
    if (!imagePath.endsWith('.js') || imagePath.includes('.test.')) continue;
    const code = fs.readFileSync(srcPath, 'utf8');
    for (const m of code.matchAll(pattern)) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(imagePath), m[1]));
      if (!files.has(realpath(target))) missing.push(`${imagePath} -> ${m[1]}`);
    }
  }
  return missing;
}

test('integration image: every static relative import resolves inside the image', (t) => {
  // dockerized backend `npm test` only has /app (backend); skip there.
  if (!fs.existsSync(dockerfilePath)) {
    t.skip('integration/Dockerfile not present');
    return;
  }
  assert.deepEqual(unresolvedImports(STATIC_RELATIVE_IMPORT), [],
    'add the missing backend/lib modules to integration/Dockerfile');
});

test('integration image: every lazy relative import() resolves inside the image', (t) => {
  if (!fs.existsSync(dockerfilePath)) {
    t.skip('integration/Dockerfile not present');
    return;
  }
  assert.deepEqual(unresolvedImports(LAZY_RELATIVE_IMPORT), [],
    'lazy imports run inside best-effort try/catch; a missing module skips that work at runtime');
});

test('integration image ships the source-import history module iocExpiration depends on', (t) => {
  if (!fs.existsSync(dockerfilePath)) {
    t.skip('integration/Dockerfile not present');
    return;
  }
  const { files } = simulateImage();
  assert.ok(files.has('/app/lib/iocExpiration.js'));
  assert.ok(files.has('/app/lib/iocSourceImportHistory.js'));
});

test('custom feed dual-write resolves to the same fileArtifacts module as the importer bridge', (t) => {
  if (!fs.existsSync(dockerfilePath)) {
    t.skip('integration/Dockerfile not present');
    return;
  }
  const { files, realpath } = simulateImage();
  // /app/lib/customThreatFeedSync.js is the backend copy (it overwrites the shim).
  assert.equal(
    files.get('/app/lib/customThreatFeedSync.js'),
    path.join(repoRoot, 'backend', 'lib', 'customThreatFeedSync.js')
  );
  // Its lazy './fileArtifacts/dualWrite.js' and the bridge's
  // '../../backend/lib/fileArtifacts/index.js' must land in one directory, so the
  // worker loads a single module instance.
  const lazy = realpath('/app/lib/fileArtifacts/dualWrite.js');
  const bridgeDir = path.posix.dirname(
    path.posix.normalize(path.posix.join('/app/lib', '../../backend/lib/fileArtifacts/index.js'))
  );
  assert.equal(path.posix.dirname(lazy), bridgeDir);
  assert.ok(files.has(lazy));
});
