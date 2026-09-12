/**
 * Source-level guard: PDF import must not force multipart Content-Type without boundary.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const modalSrc = readFileSync(join(here, 'ImportIntelligenceModal.jsx'), 'utf8');
const frontendNginx = readFileSync(join(here, '../../../nginx.conf'), 'utf8');
const proxyNginxPath = join(here, '../../../../proxy/nginx.conf');

test('ImportIntelligenceModal uses multipartFormConfig and does not hardcode multipart Content-Type', () => {
  assert.match(modalSrc, /multipartFormConfig/);
  assert.equal(modalSrc.includes("'Content-Type': 'multipart/form-data'"), false);
  assert.equal(modalSrc.includes('"Content-Type": "multipart/form-data"'), false);
});

test('nginx client_max_body_size raised above default 1m for PDF uploads', () => {
  assert.match(frontendNginx, /client_max_body_size\s+32m/);
  // Repo-root proxy conf is available in full checkouts; frontend-only CI mounts skip it.
  if (existsSync(proxyNginxPath)) {
    const proxyNginx = readFileSync(proxyNginxPath, 'utf8');
    assert.match(proxyNginx, /client_max_body_size\s+32m/);
  }
});
