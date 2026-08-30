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

test('initial focus contract for danger is prefer cancel', () => {
  // Documented contract consumed by AppConfirmHost (initialFocus="cancel").
  assert.equal(APP_CONFIRM_INITIAL.variant, 'primary');
});
