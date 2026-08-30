/**
 * Noop refresh must clear stale failed/partial and must not invent alternate windows.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FEED_IOC_TYPES, FEED_WINDOWS } from './feedFormatter.js';
import { generationWindowsForFeed } from './feedPublisherService.js';

test('noop status UPDATE always writes success + clears last_error when allSkipped', () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const src = fs.readFileSync(path.join(here, 'feedPublisherService.js'), 'utf8');
  // Locate the allSkipped branch and assert it no longer preserves prior failed status.
  const idx = src.indexOf('if (!allSkipped)');
  assert.ok(idx > 0);
  const branch = src.slice(idx, idx + 1200);
  assert.ok(branch.includes("last_status = 'success'"));
  assert.ok(branch.includes('last_error = NULL'));
  assert.equal(
    /CASE WHEN last_status = 'processing' THEN 'success'\s+ELSE COALESCE\(last_status/.test(branch),
    false,
    'stale COALESCE(last_status) path must stay removed'
  );
});

test('noop path still selects only the configured public window per IOC type', () => {
  for (const ioc of FEED_IOC_TYPES) {
    for (const window of FEED_WINDOWS) {
      assert.deepEqual(
        generationWindowsForFeed({
          filter_mode: 'basic',
          time_window: window,
          ioc_types: [ioc],
          formats: ['txt', 'json', 'stix']
        }),
        [window]
      );
    }
  }
});
