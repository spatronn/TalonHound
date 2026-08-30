/**
 * Permanent anti-regression for the Published Feeds single-window contract.
 *
 * VALID windows (FEED_WINDOWS) must never be treated as "generate all of these".
 * Every Basic feed IOC type × every configured window must resolve to exactly one
 * public generation window equal to feed.time_window.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FEED_WINDOWS, FEED_IOC_TYPES } from './feedFormatter.js';
import {
  generationWindowsForFeed,
  resolveConfiguredFeedWindow,
  resolvePublishedFeedFormats,
  FEED_FILTER_MODES
} from './feedPublisherService.js';

const FORMAT_COMBOS = [
  ['txt'],
  ['json'],
  ['stix'],
  ['txt', 'json'],
  ['txt', 'stix'],
  ['json', 'stix'],
  ['txt', 'json', 'stix']
];

test('VALID windows are fixed and must not be confused with generation targets', () => {
  assert.deepEqual(FEED_WINDOWS, ['1d', '3d', '7d', 'all']);
  assert.deepEqual(FEED_IOC_TYPES, ['ip', 'domain', 'url', 'hash']);
});

test('generationWindowsForFeed: every IOC type × every window yields exactly [configured]', () => {
  for (const ioc of FEED_IOC_TYPES) {
    for (const window of FEED_WINDOWS) {
      for (const formats of FORMAT_COMBOS) {
        const feed = {
          filter_mode: FEED_FILTER_MODES.BASIC,
          time_window: window,
          ioc_types: [ioc],
          formats
        };
        const got = generationWindowsForFeed(feed);
        assert.deepEqual(
          got,
          [window],
          `ioc=${ioc} window=${window} formats=${formats.join('+')}`
        );
        assert.equal(got.length, 1);
        assert.equal(resolveConfiguredFeedWindow(feed), window);
        // Alternate options.window must never expand the matrix.
        assert.deepEqual(
          generationWindowsForFeed(feed, { window: FEED_WINDOWS.find((w) => w !== window) }),
          [window]
        );
        assert.deepEqual(generationWindowsForFeed(feed, { window }), [window]);
        const resolvedFormats = resolvePublishedFeedFormats(feed);
        assert.equal(resolvedFormats.length, formats.length);
        for (const f of formats) assert.ok(resolvedFormats.includes(f));
      }
    }
  }
});

test('Query-mode always generates all regardless of stored time_window / IOC type', () => {
  for (const ioc of FEED_IOC_TYPES) {
    for (const window of FEED_WINDOWS) {
      const feed = {
        filter_mode: FEED_FILTER_MODES.QUERY,
        advanced_query: `type equals "${ioc === 'hash' ? 'sha256' : ioc}"`,
        time_window: window,
        ioc_types: [ioc],
        formats: ['txt']
      };
      assert.deepEqual(generationWindowsForFeed(feed), ['all']);
      assert.equal(resolveConfiguredFeedWindow(feed), 'all');
    }
  }
});

test('source guard: FEED_WINDOWS iteration is cleanup-only, not generation', () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const src = fs.readFileSync(path.join(here, 'feedPublisherService.js'), 'utf8');
  // The only intentional FEED_WINDOWS loop retires legacy monolithic snapshots per window.
  const loops = [...src.matchAll(/for\s*\(\s*const\s+\w+\s+of\s+FEED_WINDOWS\s*\)/g)];
  assert.equal(loops.length, 1, 'expected exactly one FEED_WINDOWS for-of loop');
  assert.ok(
    src.includes('retireLegacyMonolithicSnapshotsForWindow'),
    'FEED_WINDOWS loop must remain tied to legacy retirement, not generation'
  );
  assert.ok(
    src.includes('const windows = generationWindowsForFeed(feed, options);'),
    'generation must call generationWindowsForFeed'
  );
  // Guard against reintroducing the old multi-window generate loop.
  assert.equal(
    /for\s*\(\s*const\s+window\s+of\s+FEED_WINDOWS\s*\)/.test(src),
    false,
    'must not iterate FEED_WINDOWS as generation windows'
  );
});
