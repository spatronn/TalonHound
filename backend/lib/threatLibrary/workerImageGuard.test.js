/**
 * Guard: Threat Library worker must ship with the streaming AI modules.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test('threat-library-worker refuses to start without streaming AI modules', () => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const workerSrc = fs.readFileSync(path.join(root, 'threat-library-worker.js'), 'utf8');
  assert.match(workerSrc, /client\.js/);
  assert.match(workerSrc, /stale threat-library-worker image/);
  assert.match(workerSrc, /streaming-v2/);
  for (const f of ['client.js', 'analyze.js', 'timeouts.js']) {
    assert.equal(fs.existsSync(path.join(root, 'lib', 'threatLibrary', 'ai', f)), true, f);
  }
});

test('compose shares backend image across threat-library-worker', () => {
  const compose = fs.readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'docker-compose.yml'),
    'utf8'
  );
  assert.match(compose, /x-backend-image:\s*&backend-image\s+talonhound-backend:local/);
  assert.match(compose, /threat-library-worker:[\s\S]*?image:\s*\*backend-image/);
  assert.match(compose, /backend:[\s\S]*?image:\s*\*backend-image/);
});
