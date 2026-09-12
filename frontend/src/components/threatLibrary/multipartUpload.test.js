/**
 * Multipart upload helper tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { formatUploadBytes, importErrorMessage, multipartFormConfig } from './multipartUpload.js';

test('multipartFormConfig clears Content-Type so boundary can be set', () => {
  const cfg = multipartFormConfig({
    headers: { 'Content-Type': 'multipart/form-data', 'X-Test': '1' }
  });
  assert.equal(cfg.headers['Content-Type'], undefined);
  assert.equal(cfg.headers['X-Test'], '1');
});

test('importErrorMessage prefers backend message and maps 413', () => {
  assert.equal(
    importErrorMessage({ response: { data: { message: 'PDF is password-protected' } } }, 'fallback'),
    'PDF is password-protected'
  );
  assert.match(
    importErrorMessage({ response: { status: 413, data: '<html>413</html>' } }, 'PDF import failed'),
    /size limit/i
  );
  assert.equal(importErrorMessage({}, 'PDF import failed'), 'PDF import failed');
});

test('formatUploadBytes', () => {
  assert.equal(formatUploadBytes(25_165_824), '24 MB');
});
