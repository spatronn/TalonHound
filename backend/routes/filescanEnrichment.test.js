import test from 'node:test';
import assert from 'node:assert/strict';

// Minimal smoke tests for the filescan enrichment route module.
// Full integration tests require a running Postgres instance; these cover
// the pure-logic helpers that the route re-exports.

test('maskApiKey re-export from route module', async () => {
  const { maskApiKey } = await import('./filescanEnrichment.js');
  assert.equal(typeof maskApiKey, 'function');
  assert.equal(maskApiKey('abcd1234'), 'abcd********'); // 8-char key → first 4 + max(8, 4) stars
  assert.equal(maskApiKey(''), null);
  assert.equal(maskApiKey(null), null);
});

test('route module can be imported without throwing (no pool required at import time)', async () => {
  const mod = await import('./filescanEnrichment.js');
  assert.equal(typeof mod.registerFilescanEnrichmentRoutes, 'function');
});
