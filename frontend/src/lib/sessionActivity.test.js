import test from 'node:test';
import assert from 'node:assert/strict';

// Minimal window/document shims so the module can register listeners under node:test.
function installDom() {
  const handlers = new Map();
  const add = (map) => (evt, fn) => {
    if (!map.has(evt)) map.set(evt, new Set());
    map.get(evt).add(fn);
  };
  const remove = (map) => (evt, fn) => { map.get(evt)?.delete(fn); };
  const winHandlers = handlers;
  const docHandlers = new Map();
  global.window = { addEventListener: add(winHandlers), removeEventListener: remove(winHandlers) };
  global.document = {
    visibilityState: 'visible',
    addEventListener: add(docHandlers),
    removeEventListener: remove(docHandlers)
  };
  return {
    fireWindow(evt) { winHandlers.get(evt)?.forEach((fn) => fn()); },
    fireDoc(evt) { docHandlers.get(evt)?.forEach((fn) => fn()); },
    winCount(evt) { return winHandlers.get(evt)?.size || 0; }
  };
}

function cleanupDom() {
  delete global.window;
  delete global.document;
}

test('heartbeat: leading-edge throttle — one post per interval of genuine activity', async () => {
  const dom = installDom();
  const posts = [];
  const api = { post: (url) => { posts.push(url); return Promise.resolve(); } };
  let clock = 1_000_000;
  const { startSessionActivityTracking } = await import('./sessionActivity.js');

  const stop = startSessionActivityTracking(api, { minIntervalMs: 4 * 60 * 1000, now: () => clock });

  // Immediately after start: no heartbeat until a full interval elapses.
  dom.fireWindow('pointerdown');
  assert.equal(posts.length, 0, 'fresh session is not heartbeated immediately');

  // After the interval, the next genuine interaction sends exactly one.
  clock += 4 * 60 * 1000 + 1;
  dom.fireWindow('keydown');
  assert.equal(posts.length, 1);
  assert.equal(posts[0], '/auth/activity');

  // A burst within the same window sends nothing more (throttled).
  dom.fireWindow('pointerdown');
  dom.fireWindow('keydown');
  dom.fireWindow('submit');
  assert.equal(posts.length, 1, 'burst within window is throttled to a single post');

  // Next window → one more.
  clock += 4 * 60 * 1000 + 1;
  dom.fireWindow('pointerdown');
  assert.equal(posts.length, 2);

  stop();
  cleanupDom();
});

test('heartbeat: idle (no interaction) produces zero posts across many intervals', async () => {
  const dom = installDom();
  const posts = [];
  const api = { post: (url) => { posts.push(url); return Promise.resolve(); } };
  let clock = 5_000_000;
  const { startSessionActivityTracking } = await import('./sessionActivity.js');

  const stop = startSessionActivityTracking(api, { minIntervalMs: 60_000, now: () => clock });

  // Advance time far beyond the idle window WITHOUT dispatching any interaction.
  // Background polling would look like this to the session: time passes, no DOM events.
  clock += 60 * 60 * 1000;
  assert.equal(posts.length, 0, 'no genuine interaction → no heartbeat → session goes idle');

  stop();
  cleanupDom();
});

test('heartbeat: stop() detaches listeners', async () => {
  const dom = installDom();
  const posts = [];
  const api = { post: (url) => { posts.push(url); return Promise.resolve(); } };
  let clock = 9_000_000;
  const { startSessionActivityTracking } = await import('./sessionActivity.js');

  const stop = startSessionActivityTracking(api, { minIntervalMs: 1000, now: () => clock });
  stop();
  assert.equal(dom.winCount('pointerdown'), 0, 'listeners removed on stop');
  clock += 10_000;
  dom.fireWindow('pointerdown');
  assert.equal(posts.length, 0);
  cleanupDom();
});
