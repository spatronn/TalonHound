/**
 * The gate itself: integration tests that nothing runs, and a CI step that passes
 * because everything skipped, both look like success.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const repoRoot = path.resolve(backendRoot, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(backendRoot, 'package.json'), 'utf8'));
const ci = fs.readFileSync(path.join(repoRoot, '.github/workflows/ci.yml'), 'utf8');

function integrationTests(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) integrationTests(full, out);
    else if (/\.integration\.test\.js$/.test(e.name)) out.push(path.relative(backendRoot, full).replace(/\\/g, '/'));
  }
  return out;
}

test('every Threat Library integration test is run by a script or a CI step', () => {
  const runners = `${Object.values(pkg.scripts).join(' ')} ${ci}`;
  const orphaned = integrationTests(path.join(backendRoot, 'lib/threatLibrary')).filter((f) => !runners.includes(f));
  assert.deepEqual(orphaned, [], 'add these to test:threat-library-integration or to a CI step');
});

test('the Threat Library integration step fails when any test is skipped', () => {
  const step = ci.slice(ci.indexOf('Threat Library integration tests (real Postgres)'));
  const body = step.slice(0, step.indexOf('- name:', 10));
  assert.match(body, /pipefail/);
  assert.match(body, /test:threat-library-integration/);
  assert.match(body, /skipped 0/);
});

test('the evaluation gate and the contract gate run in CI', () => {
  assert.match(ci, /npm run test:threat-library-benchmark && npm run benchmark:threat-library -- --scorecard/);
  assert.match(ci, /check-extraction-contract-change\.js/);
});
