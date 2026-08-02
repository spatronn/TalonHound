import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createConfirmActionController } from './confirmActionController.js';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('first click opens the modal without running the action', () => {
  let ran = 0;
  const c = createConfirmActionController();
  c.request({ payload: { providerKey: 'virustotal' }, onConfirm: async () => { ran += 1; } });
  assert.equal(ran, 0);
  assert.equal(c.getState().open, true);
  assert.equal(c.getState().payload.providerKey, 'virustotal');
});

test('Cancel / ESC / backdrop close without running the action', async () => {
  let ran = 0;
  const c = createConfirmActionController();
  c.request({ payload: {}, onConfirm: async () => { ran += 1; } });
  c.cancel();
  assert.equal(ran, 0);
  assert.equal(c.getState().open, false);
  const res = await c.confirm();
  assert.equal(res.ignored, true);
  assert.equal(ran, 0);
});

test('confirm runs the action once for the right payload and closes on success', async () => {
  const seen = [];
  const c = createConfirmActionController();
  c.request({ payload: { providerKey: 'abuseipdb' }, onConfirm: async (p) => { seen.push(p.providerKey); } });
  const res = await c.confirm();
  assert.equal(res.ok, true);
  assert.deepEqual(seen, ['abuseipdb']);
  assert.equal(c.getState().open, false);
});

test('double confirm while in flight does not duplicate the request', async () => {
  let ran = 0;
  const d = deferred();
  const c = createConfirmActionController();
  c.request({ payload: {}, onConfirm: async () => { ran += 1; return d.promise; } });
  const first = c.confirm();
  const second = c.confirm();
  assert.equal((await second).ignored, true);
  assert.equal(ran, 1);
  d.resolve();
  await first;
  assert.equal(ran, 1);
});

test('cancel is blocked while submitting (modal stays open until the request settles)', async () => {
  const d = deferred();
  const c = createConfirmActionController();
  c.request({ payload: {}, onConfirm: async () => d.promise });
  const confirming = c.confirm();
  assert.equal(c.getState().submitting, true);
  c.cancel();
  assert.equal(c.getState().open, true);
  d.resolve();
  await confirming;
  assert.equal(c.getState().open, false);
});

test('on error the modal stays open with the error surfaced', async () => {
  const c = createConfirmActionController();
  c.request({ payload: {}, onConfirm: async () => { throw new Error('Disable failed: boom'); } });
  const res = await c.confirm();
  assert.equal(res.ok, false);
  assert.equal(c.getState().open, true);
  assert.equal(c.getState().submitting, false);
  assert.equal(c.getState().error, 'Disable failed: boom');
});

test('the same controller drives multiple providers independently', async () => {
  const seen = [];
  const c = createConfirmActionController();
  const onConfirm = async (p) => { seen.push(p.providerKey); };
  c.request({ payload: { providerKey: 'virustotal' }, onConfirm });
  await c.confirm();
  c.request({ payload: { providerKey: 'spamhaus_drop' }, onConfirm });
  await c.confirm();
  assert.deepEqual(seen, ['virustotal', 'spamhaus_drop']);
});
