import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  FEED_SYNC_CONCURRENCY_DEFAULT,
  resolveFeedSyncConcurrency,
  feedSyncLockIdentity
} from './feedSyncConcurrency.js';

// Test G — configuration validation (undefined->2, 2->2, 3->3, 1->1,
// 0/negative/non-numeric -> safe fallback), following the repo's readPositiveInt
// convention of falling back rather than throwing.
describe('resolveFeedSyncConcurrency (Test G)', () => {
  it('defaults to 2 when unset', () => {
    assert.equal(FEED_SYNC_CONCURRENCY_DEFAULT, 2);
    assert.equal(resolveFeedSyncConcurrency(undefined), 2);
    assert.equal(resolveFeedSyncConcurrency(null), 2);
    assert.equal(resolveFeedSyncConcurrency(''), 2);
    assert.equal(resolveFeedSyncConcurrency('   '), 2);
  });

  it('passes through valid positive integers (string or number)', () => {
    assert.equal(resolveFeedSyncConcurrency('2'), 2);
    assert.equal(resolveFeedSyncConcurrency('3'), 3);
    assert.equal(resolveFeedSyncConcurrency('1'), 1);
    assert.equal(resolveFeedSyncConcurrency(4), 4);
    assert.equal(resolveFeedSyncConcurrency('  5 '), 5);
  });

  it('rejects zero and negatives, falling back to the default', () => {
    assert.equal(resolveFeedSyncConcurrency('0'), 2);
    assert.equal(resolveFeedSyncConcurrency(0), 2);
    assert.equal(resolveFeedSyncConcurrency('-1'), 2);
    assert.equal(resolveFeedSyncConcurrency(-3), 2);
  });

  it('rejects non-integer and non-numeric input', () => {
    assert.equal(resolveFeedSyncConcurrency('3.5'), 2);
    assert.equal(resolveFeedSyncConcurrency(2.5), 2);
    assert.equal(resolveFeedSyncConcurrency('abc'), 2);
    assert.equal(resolveFeedSyncConcurrency('2x'), 2);
    assert.equal(resolveFeedSyncConcurrency(NaN), 2);
    assert.equal(resolveFeedSyncConcurrency(Infinity), 2);
  });

  it('invokes the logger on malformed input only', () => {
    const seen = [];
    const logger = (m) => seen.push(m);
    assert.equal(resolveFeedSyncConcurrency('0', { logger }), 2);
    assert.equal(resolveFeedSyncConcurrency('abc', { logger }), 2);
    assert.equal(resolveFeedSyncConcurrency('2', { logger }), 2);
    assert.equal(resolveFeedSyncConcurrency(undefined, { logger }), 2);
    assert.equal(seen.length, 2);
  });

  it('honours a custom fallback but never returns an unsafe one', () => {
    assert.equal(resolveFeedSyncConcurrency('0', { fallback: 1 }), 1);
    assert.equal(resolveFeedSyncConcurrency('bad', { fallback: 4 }), 4);
    // An unsafe custom fallback is itself replaced by the module default.
    assert.equal(resolveFeedSyncConcurrency('bad', { fallback: 0 }), 2);
    assert.equal(resolveFeedSyncConcurrency('bad', { fallback: -5 }), 2);
  });
});

// Test C (identity) + Test F (identity): same feed collides, distinct feeds do not.
describe('feedSyncLockIdentity (Test C / Test F exclusion identity)', () => {
  it('gives every trigger of the same feed the same identity', () => {
    // Same feed reached via scheduled vs manual vs retry -> identical identity,
    // so the advisory lock guarantees they never overlap.
    assert.equal(feedSyncLockIdentity('threatfox-abusech', 'threatfox-import'), 'threatfox-abusech');
    assert.equal(
      feedSyncLockIdentity('threatfox-abusech', 'threatfox-import'),
      feedSyncLockIdentity('threatfox-abusech', 'threatfox-import')
    );
  });

  it('gives distinct built-in feeds distinct identities', () => {
    const ids = [
      feedSyncLockIdentity('threatfox-abusech', 'threatfox-import'),
      feedSyncLockIdentity('urlhaus-abusech', 'urlhaus-import'),
      feedSyncLockIdentity('alienvault-otx', 'alienvault-otx-import'),
      feedSyncLockIdentity('certpl-warning-list', 'certpl-import')
    ];
    assert.equal(new Set(ids).size, ids.length);
  });

  it('gives distinct custom feeds distinct identities (Test F)', () => {
    // Custom feeds share the job name custom-threat-feed-sync but carry unique
    // integration keys, so they participate in the global pool independently and
    // never wrongly exclude each other.
    const a = feedSyncLockIdentity('custom-threat-feed:11', 'custom-threat-feed-sync');
    const b = feedSyncLockIdentity('custom-threat-feed:12', 'custom-threat-feed-sync');
    assert.notEqual(a, b);
  });

  it('lets MalwareBazaar recent-import and historical-recovery coexist', () => {
    const recent = feedSyncLockIdentity('malwarebazaar-abusech', 'malwarebazaar-import');
    const recovery = feedSyncLockIdentity('malwarebazaar-abusech', 'malwarebazaar-historical-recovery');
    assert.notEqual(recent, recovery);
  });

  it('falls back to a stable identity for unknown keys', () => {
    assert.equal(feedSyncLockIdentity(null, 'x'), 'unknown');
    assert.equal(feedSyncLockIdentity('  ', 'x'), 'unknown');
  });
});
