import test from 'node:test';
import assert from 'node:assert/strict';
import { testThreatFoxConnection } from './threatfoxIntegration.js';

test('testThreatFoxConnection returns missing key without fetch', async () => {
  const out = await testThreatFoxConnection({ authKey: '' });
  assert.equal(out.ok, false);
  assert.match(out.message, /missing/i);
});

test('testThreatFoxConnection aborts on timeout', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (_url, opts = {}) => new Promise((_resolve, reject) => {
    opts.signal.addEventListener('abort', () => {
      const err = new Error('aborted');
      err.name = 'AbortError';
      reject(err);
    });
  });
  try {
    const out = await testThreatFoxConnection({
      authKey: 'test-key',
      apiUrl: 'https://threatfox-api.example.test/api/v1/',
      timeoutMs: 40
    });
    assert.equal(out.ok, false);
    assert.match(out.message, /timed out/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('testThreatFoxConnection respects external AbortSignal', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (_url, opts = {}) => new Promise((_resolve, reject) => {
    opts.signal.addEventListener('abort', () => {
      const err = new Error('aborted');
      err.name = 'AbortError';
      reject(err);
    });
  });
  const controller = new AbortController();
  const pending = testThreatFoxConnection({
    authKey: 'test-key',
    apiUrl: 'https://threatfox-api.example.test/api/v1/',
    timeoutMs: 30_000,
    signal: controller.signal
  });
  controller.abort();
  try {
    const out = await pending;
    assert.equal(out.ok, false);
    assert.match(out.message, /timed out/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
