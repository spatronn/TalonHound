/**
 * Source-level guard: PDF import must not force multipart Content-Type without boundary.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const modalSrc = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ImportIntelligenceModal.jsx'),
  'utf8'
);
const proxyNginx = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '../../../../proxy/nginx.conf'),
  'utf8'
);
const frontendNginx = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '../../nginx.conf'),
  'utf8'
);

test('ImportIntelligenceModal uses multipartFormConfig and does not hardcode multipart Content-Type', () => {
  assert.match(modalSrc, /multipartFormConfig/);
  assert.equal(modalSrc.includes("'Content-Type': 'multipart/form-data'"), false);
  assert.equal(modalSrc.includes('"Content-Type": "multipart/form-data"'), false);
});

test('nginx client_max_body_size raised above default 1m for PDF uploads', () => {
  assert.match(proxyNginx, /client_max_body_size\s+32m/);
  assert.match(frontendNginx, /client_max_body_size\s+32m/);
});
