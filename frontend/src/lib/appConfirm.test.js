import test from 'node:test';
import assert from 'node:assert/strict';
import { APP_CONFIRM_INITIAL, createAppConfirmController } from './appConfirm.js';

test('request resolves true on confirm without onConfirm', async () => {
  let state = { ...APP_CONFIRM_INITIAL };
  const c = createAppConfirmController((s) => { state = s; });
  const p = c.request({ title: 'Delete?', variant: 'danger', confirmLabel: 'Delete' });
  assert.equal(state.open, true);
  assert.equal(state.variant, 'danger');
  assert.equal(state.confirmLabel, 'Delete');
  await c.confirm();
  assert.equal(await p, true);
  assert.equal(c.getState().open, false);
});

test('request resolves false on cancel', async () => {
  const c = createAppConfirmController(() => {});
  const p = c.request({ title: 'Run?' });
  c.cancel();
  assert.equal(await p, false);
});

test('cancel is blocked while submitting', async () => {
  let resolveAction;
  const c = createAppConfirmController(() => {});
  const p = c.request({
    title: 'Delete',
    onConfirm: () => new Promise((r) => { resolveAction = r; })
  });
  const confirmPromise = c.confirm();
  assert.equal(c.getState().submitting, true);
  c.cancel();
  assert.equal(c.getState().open, true);
  resolveAction();
  assert.equal(await p, true);
  await confirmPromise;
});

test('onConfirm failure keeps modal open with error', async () => {
  const c = createAppConfirmController(() => {});
  const p = c.request({
    title: 'Delete',
    onConfirm: async () => { throw new Error('nope'); }
  });
  const result = await c.confirm();
  assert.equal(result.ok, false);
  assert.equal(c.getState().open, true);
  assert.equal(c.getState().error, 'nope');
  assert.equal(c.getState().submitting, false);
  c.cancel();
  assert.equal(await p, false);
});

test('double confirm while in flight is ignored', async () => {
  let calls = 0;
  let resolveAction;
  const c = createAppConfirmController(() => {});
  c.request({
    title: 'X',
    onConfirm: () => {
      calls += 1;
      return new Promise((r) => { resolveAction = r; });
    }
  });
  const first = c.confirm();
  const second = await c.confirm();
  assert.equal(second.ignored, true);
  assert.equal(calls, 1);
  resolveAction();
  await first;
});

test('requireReason resolves to the trimmed corroboration and rejects a short one', async () => {
  let state = { ...APP_CONFIRM_INITIAL };
  const c = createAppConfirmController((s) => { state = s; });
  const pending = c.request({ title: 'Promote?', requireReason: true, reasonMin: 12 });
  assert.equal(state.requireReason, true);
  const rejected = await c.confirm({ reason: 'too short' });
  assert.equal(rejected.ok, false);
  assert.equal(state.open, true);
  await c.confirm({ reason: '  Named as the payload host in this report.  ' });
  assert.equal(await pending, 'Named as the payload host in this report.');
});

test('initial focus contract for danger is prefer cancel', () => {
  // Documented contract consumed by AppConfirmHost (initialFocus="cancel").
  assert.equal(APP_CONFIRM_INITIAL.variant, 'primary');
});

test('informational request has no confirm action: confirm() is ignored, Close resolves false', async () => {
  let state = { ...APP_CONFIRM_INITIAL };
  let ran = 0;
  const c = createAppConfirmController((s) => { state = s; });
  const p = c.request({ title: 'No new IOC records', informational: true, cancelLabel: 'Close', onConfirm: () => { ran += 1; } });
  assert.equal(state.open, true);
  assert.equal(state.informational, true);
  assert.equal(state.cancelLabel, 'Close');
  const r = await c.confirm();
  assert.equal(r.ignored, true);
  assert.equal(c.getState().open, true);
  c.cancel();
  assert.equal(await p, false);
  assert.equal(ran, 0);
  assert.equal(c.getState().informational, false, 'reset for the next request');
});
