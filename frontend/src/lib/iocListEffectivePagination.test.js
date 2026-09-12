import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IOC_LIST_PAGINATION_MODE_NORMAL,
  IOC_LIST_PAGINATION_MODE_DEEP_SEARCH,
  buildIocListEffectivePagination
} from './iocListEffectivePagination.js';

// Reproduces the reported bug: while browsing a completed Deep Search result set, the bottom
// pagination control read the (idle) normal offset model and showed Previous/Next both
// disabled, even though the top Deep Search control had Next enabled. After the fix, ONE
// effective model drives both areas, so the assertions below describe both the top and bottom
// controls simultaneously.

function deepModel({ hasPrevious, hasNext, loading = false }, handlers = {}) {
  return buildIocListEffectivePagination({
    deepSearchReady: true,
    deep: { hasPrevious, hasNext, loading, ...handlers },
    // The normal model is intentionally "idle" (page 1 of 1) to mimic the real component,
    // where offset paging is set aside during Deep Search browsing. If the effective model
    // ever fell back to it, canGoNext would be false and the test would fail.
    normal: { page: 1, pageCount: 1 }
  });
}

test('deep search first page: Previous disabled, Next enabled (both areas)', () => {
  const p = deepModel({ hasPrevious: false, hasNext: true });
  assert.equal(p.mode, IOC_LIST_PAGINATION_MODE_DEEP_SEARCH);
  assert.equal(p.canGoPrevious, false);
  assert.equal(p.canGoNext, true);
});

test('deep search middle page: Previous enabled, Next enabled (both areas)', () => {
  const p = deepModel({ hasPrevious: true, hasNext: true });
  assert.equal(p.canGoPrevious, true);
  assert.equal(p.canGoNext, true);
});

test('deep search final page: Previous enabled, Next disabled (both areas)', () => {
  const p = deepModel({ hasPrevious: true, hasNext: false });
  assert.equal(p.canGoPrevious, true);
  assert.equal(p.canGoNext, false);
});

test('deep search: in-flight page transition disables both directions (dup-request guard)', () => {
  const p = deepModel({ hasPrevious: true, hasNext: true, loading: true });
  assert.equal(p.canGoPrevious, false);
  assert.equal(p.canGoNext, false);
});

test('bottom controls invoke Deep Search handlers, not normal list paging', () => {
  const calls = [];
  const p = deepModel(
    { hasPrevious: true, hasNext: true },
    {
      goPrevious: () => calls.push('deep-prev'),
      goNext: () => calls.push('deep-next')
    }
  );
  // Simulate clicking the BOTTOM Next then Previous.
  p.goNext();
  p.goPrevious();
  assert.deepEqual(calls, ['deep-next', 'deep-prev']);
  // And it must never fall through to normal offset paging.
  assert.equal(p.mode, IOC_LIST_PAGINATION_MODE_DEEP_SEARCH);
});

test('normal list first page: Previous disabled, Next enabled', () => {
  const p = buildIocListEffectivePagination({
    deepSearchReady: false,
    normal: { page: 1, pageCount: 5 }
  });
  assert.equal(p.mode, IOC_LIST_PAGINATION_MODE_NORMAL);
  assert.equal(p.canGoPrevious, false);
  assert.equal(p.canGoNext, true);
});

test('normal list middle page: both enabled', () => {
  const p = buildIocListEffectivePagination({
    deepSearchReady: false,
    normal: { page: 3, pageCount: 5 }
  });
  assert.equal(p.canGoPrevious, true);
  assert.equal(p.canGoNext, true);
});

test('normal list final page: Previous enabled, Next disabled', () => {
  const p = buildIocListEffectivePagination({
    deepSearchReady: false,
    normal: { page: 5, pageCount: 5 }
  });
  assert.equal(p.canGoPrevious, true);
  assert.equal(p.canGoNext, false);
});

test('normal list single page: both disabled', () => {
  const p = buildIocListEffectivePagination({
    deepSearchReady: false,
    normal: { page: 1, pageCount: 1 }
  });
  assert.equal(p.canGoPrevious, false);
  assert.equal(p.canGoNext, false);
});

test('normal controls invoke normal handlers', () => {
  const calls = [];
  const p = buildIocListEffectivePagination({
    deepSearchReady: false,
    normal: {
      page: 2,
      pageCount: 5,
      goPrevious: () => calls.push('normal-prev'),
      goNext: () => calls.push('normal-next')
    }
  });
  p.goPrevious();
  p.goNext();
  assert.deepEqual(calls, ['normal-prev', 'normal-next']);
});

test('missing handlers degrade to no-ops (never throw)', () => {
  const p = buildIocListEffectivePagination({ deepSearchReady: true, deep: { hasNext: true } });
  assert.doesNotThrow(() => { p.goNext(); p.goPrevious(); });
});
