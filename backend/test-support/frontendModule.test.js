import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CANDIDATE_REVIEW_FIXTURE,
  CANDIDATE_REVIEW_MODULE,
  frontendModuleCandidates,
  importFrontendModule,
  resolveFrontendModule
} from './frontendModule.js';

const BACKEND_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('resolution order: env frontend root, backend test fixture, sibling frontend — never a host absolute path', () => {
  const env = { TALONHOUND_FRONTEND_DIR: path.join(os.tmpdir(), 'fe-root') };
  const list = frontendModuleCandidates(CANDIDATE_REVIEW_MODULE, { fixtureName: CANDIDATE_REVIEW_FIXTURE, env });
  assert.deepEqual(list, [
    path.resolve(env.TALONHOUND_FRONTEND_DIR, 'src', 'components', 'threatLibrary', 'candidateReview.js'),
    path.join(BACKEND_ROOT, 'test-fixtures', CANDIDATE_REVIEW_FIXTURE),
    path.resolve(BACKEND_ROOT, '..', 'frontend', 'src', 'components', 'threatLibrary', 'candidateReview.js')
  ]);
  assert.ok(list.every((p) => !p.startsWith('/opt/')));
  assert.deepEqual(frontendModuleCandidates(CANDIDATE_REVIEW_MODULE, { env: {} }), [list[2]]);
});

test('the sibling frontend of this checkout resolves from any working directory', async () => {
  const cwd = process.cwd();
  try {
    process.chdir(os.tmpdir());
    const resolved = resolveFrontendModule(CANDIDATE_REVIEW_MODULE, { env: {} });
    assert.equal(resolved, path.resolve(BACKEND_ROOT, '..', 'frontend', 'src', 'components', 'threatLibrary', 'candidateReview.js'));
    const mod = await importFrontendModule(CANDIDATE_REVIEW_MODULE, { env: {} });
    assert.equal(typeof mod.isReviewIndicator, 'function');
  } finally {
    process.chdir(cwd);
  }
});

test('TALONHOUND_FRONTEND_DIR wins over the sibling checkout', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'th-fe-'));
  try {
    const file = path.join(dir, 'src', 'lib', 'probe.js');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, 'export const probe = 1;\n');
    assert.equal(resolveFrontendModule('src/lib/probe.js', { env: { TALONHOUND_FRONTEND_DIR: dir } }), file);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a missing module fails loudly with every location tried (parity tests never silently skip)', () => {
  assert.throws(
    () => resolveFrontendModule('src/does/not/exist.js', { env: {} }),
    (err) => /not found; looked in/.test(err.message) && err.message.includes(path.join('frontend', 'src', 'does', 'not', 'exist.js'))
  );
});
