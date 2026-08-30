import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRemoveKeyConfirmController } from './removeKeyConfirm.js';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('first "Remove key" click opens the modal without calling the remove API', () => {
  let calls = 0;
  const c = createRemoveKeyConfirmController();
  c.request({
    providerKey: 'virustotal',
    providerName: 'VirusTotal',
    onConfirm: async () => { calls += 1; }
  });

  const s = c.getState();
  assert.equal(calls, 0, 'onConfirm (API) must not run on the first click');
  assert.equal(s.open, true);
  assert.equal(s.providerKey, 'virustotal');
  assert.equal(s.providerName, 'VirusTotal');
  assert.equal(s.submitting, false);
});

test('the provider name is exposed for display in the modal', () => {
  const c = createRemoveKeyConfirmController();
  c.request({ providerKey: 'abuseipdb', providerName: 'AbuseIPDB', onConfirm: async () => {} });
  assert.equal(c.getState().providerName, 'AbuseIPDB');
});

test('Cancel closes the modal and never runs the remove action', async () => {
  let calls = 0;
  const c = createRemoveKeyConfirmController();
  c.request({ providerKey: 'virustotal', providerName: 'VirusTotal', onConfirm: async () => { calls += 1; } });
  c.cancel();

  assert.equal(calls, 0);
  assert.equal(c.getState().open, false);
  assert.equal(c.getState().providerKey, null);

  // A confirm after cancel is a no-op (ESC / backdrop route through cancel too).
  const res = await c.confirm();
  assert.equal(res.ignored, true);
  assert.equal(calls, 0);
});

test('ESC / backdrop paths (cancel) do not delete once the request is in flight', async () => {
  let calls = 0;
  const d = deferred();
  const c = createRemoveKeyConfirmController();
  c.request({ providerKey: 'virustotal', providerName: 'VirusTotal', onConfirm: async () => { calls += 1; return d.promise; } });

  const confirming = c.confirm();
  assert.equal(c.getState().submitting, true);

  // cancel() is what ESC and backdrop clicks call — must be blocked mid-flight.
  c.cancel();
  assert.equal(c.getState().open, true, 'modal must stay open while submitting');

  d.resolve();
  await confirming;
  assert.equal(calls, 1);
  assert.equal(c.getState().open, false);
});

test('confirming sends exactly one remove request for the correct provider', async () => {
  const seen = [];
  const c = createRemoveKeyConfirmController();
  c.request({
    providerKey: 'abuseipdb',
    providerName: 'AbuseIPDB',
    onConfirm: async ({ providerKey }) => { seen.push(providerKey); }
  });

  const res = await c.confirm();
  assert.equal(res.ok, true);
  assert.deepEqual(seen, ['abuseipdb'], 'one request, right provider');
  assert.equal(c.getState().open, false, 'modal closes on success');
});

test('double-clicking confirm while a request is in flight does not duplicate it', async () => {
  let calls = 0;
  const d = deferred();
  const c = createRemoveKeyConfirmController();
  c.request({ providerKey: 'virustotal', providerName: 'VirusTotal', onConfirm: async () => { calls += 1; return d.promise; } });

  const first = c.confirm();
  const second = c.confirm(); // second click while submitting
  assert.equal((await second).ignored, true);
  assert.equal(calls, 1, 'no duplicate request');

  d.resolve();
  await first;
  assert.equal(calls, 1);
});

test('on error the modal stays open with the error surfaced', async () => {
  const c = createRemoveKeyConfirmController();
  c.request({
    providerKey: 'virustotal',
    providerName: 'VirusTotal',
    onConfirm: async () => { throw new Error('Remove failed: boom'); }
  });

  const res = await c.confirm();
  assert.equal(res.ok, false);
  const s = c.getState();
  assert.equal(s.open, true, 'modal remains open on failure');
  assert.equal(s.submitting, false, 'not stuck in loading');
  assert.equal(s.error, 'Remove failed: boom');
});

test('the user can retry after an error and then succeed', async () => {
  let calls = 0;
  const c = createRemoveKeyConfirmController();
  c.request({
    providerKey: 'virustotal',
    providerName: 'VirusTotal',
    onConfirm: async () => {
      calls += 1;
      if (calls === 1) throw new Error('transient');
    }
  });

  assert.equal((await c.confirm()).ok, false);
  assert.equal(c.getState().open, true);

  const retry = await c.confirm();
  assert.equal(retry.ok, true);
  assert.equal(calls, 2);
  assert.equal(c.getState().open, false);
});

test('the same controller drives multiple providers with independent confirmations', async () => {
  const seen = [];
  const c = createRemoveKeyConfirmController();
  const onConfirm = async ({ providerKey }) => { seen.push(providerKey); };

  // Provider 1
  c.request({ providerKey: 'virustotal', providerName: 'VirusTotal', keyNoun: 'API key', onConfirm });
  assert.equal(c.getState().keyNoun, 'API key');
  await c.confirm();

  // Provider 2 (different wording — token vs API key)
  c.request({ providerKey: 'ipinfo_lite', providerName: 'IPinfo Lite', keyNoun: 'token', confirmLabel: 'Remove token', onConfirm });
  assert.equal(c.getState().keyNoun, 'token');
  assert.equal(c.getState().confirmLabel, 'Remove token');
  await c.confirm();

  assert.deepEqual(seen, ['virustotal', 'ipinfo_lite']);
});

test('notify subscriber receives every state transition', async () => {
  const states = [];
  const c = createRemoveKeyConfirmController((s) => states.push({ open: s.open, submitting: s.submitting }));
  c.request({ providerKey: 'virustotal', providerName: 'VirusTotal', onConfirm: async () => {} });
  await c.confirm();

  // open -> submitting -> closed
  assert.deepEqual(states, [
    { open: true, submitting: false },
    { open: true, submitting: true },
    { open: false, submitting: false }
  ]);
});
