import test from 'node:test';
import assert from 'node:assert/strict';
import { getWithTransientRetry, isTransientLoadError } from './apiRetry.js';

const noSleep = async () => {};
const httpError = (status) => Object.assign(new Error(`status ${status}`), { response: { status } });
const networkError = () => Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' });

test('isTransientLoadError: network errors and 502/503/504 are transient', () => {
  assert.equal(isTransientLoadError(networkError()), true);
  assert.equal(isTransientLoadError(httpError(502)), true);
  assert.equal(isTransientLoadError(httpError(503)), true);
  assert.equal(isTransientLoadError(httpError(504)), true);
});

test('isTransientLoadError: 4xx and 500 are NOT transient (never masked)', () => {
  assert.equal(isTransientLoadError(httpError(400)), false);
  assert.equal(isTransientLoadError(httpError(401)), false);
  assert.equal(isTransientLoadError(httpError(403)), false);
  assert.equal(isTransientLoadError(httpError(404)), false);
  assert.equal(isTransientLoadError(httpError(500)), false);
});

test('succeeds on first attempt without retrying', async () => {
  let calls = 0;
  const result = await getWithTransientRetry(async () => { calls += 1; return 'ok'; }, { sleep: noSleep });
  assert.equal(result, 'ok');
  assert.equal(calls, 1);
});

test('retries a transient failure then succeeds', async () => {
  let calls = 0;
  const result = await getWithTransientRetry(async () => {
    calls += 1;
    if (calls === 1) throw httpError(503);
    return 'recovered';
  }, { sleep: noSleep });
  assert.equal(result, 'recovered');
  assert.equal(calls, 2);
});

test('stops after the retry cap and rethrows the last transient error', async () => {
  let calls = 0;
  await assert.rejects(
    getWithTransientRetry(async () => { calls += 1; throw networkError(); }, { retries: 2, sleep: noSleep }),
    /Network Error/
  );
  assert.equal(calls, 3); // 1 initial + 2 retries
});

test('does NOT retry a 4xx (auth/validation stays visible immediately)', async () => {
  let calls = 0;
  await assert.rejects(
    getWithTransientRetry(async () => { calls += 1; throw httpError(403); }, { sleep: noSleep }),
    /status 403/
  );
  assert.equal(calls, 1);
});

test('does NOT retry a 500 (programming error is not masked)', async () => {
  let calls = 0;
  await assert.rejects(
    getWithTransientRetry(async () => { calls += 1; throw httpError(500); }, { sleep: noSleep }),
    /status 500/
  );
  assert.equal(calls, 1);
});
