import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IOC_STATS_RECALCULATE_LABEL,
  IOC_STATS_RECALCULATING_LABEL,
  IOC_STATS_RECALCULATION_IN_PROGRESS,
  iocStatsRecalculateConfirmOptions,
  iocStatsRecalculateButtonLabel,
  shouldDisableIocStatsRecalculateButton,
  isIocStatsRecalculationInProgressError,
  runIocStatsRecalculateRequest
} from './iocStatsRecalculate.js';
import { createAppConfirmController } from './appConfirm.js';

test('confirm options use informational primary variant and Recalculate label', () => {
  const opts = iocStatsRecalculateConfirmOptions();
  assert.equal(opts.title, 'Recalculate IOC statistics?');
  assert.match(opts.description, /background/i);
  assert.equal(opts.confirmLabel, 'Recalculate');
  assert.equal(opts.cancelLabel, 'Cancel');
  assert.equal(opts.variant, 'primary');
});

test('button label reflects running state', () => {
  assert.equal(iocStatsRecalculateButtonLabel({}), IOC_STATS_RECALCULATE_LABEL);
  assert.equal(iocStatsRecalculateButtonLabel({ busy: true }), IOC_STATS_RECALCULATING_LABEL);
  assert.equal(
    iocStatsRecalculateButtonLabel({ refreshInProgress: true }),
    IOC_STATS_RECALCULATING_LABEL
  );
});

test('button disabled when readonly, busy, or refresh in progress', () => {
  assert.equal(shouldDisableIocStatsRecalculateButton({ canWrite: true }), false);
  assert.equal(shouldDisableIocStatsRecalculateButton({ canWrite: false }), true);
  assert.equal(shouldDisableIocStatsRecalculateButton({ canWrite: true, busy: true }), true);
  assert.equal(
    shouldDisableIocStatsRecalculateButton({ canWrite: true, refreshInProgress: true }),
    true
  );
});

test('409 ioc_stats_recalculation_in_progress is detected', () => {
  assert.equal(
    isIocStatsRecalculationInProgressError({
      response: {
        status: 409,
        data: { error: IOC_STATS_RECALCULATION_IN_PROGRESS }
      }
    }),
    true
  );
  assert.equal(
    isIocStatsRecalculationInProgressError({
      response: { status: 409, data: { code: IOC_STATS_RECALCULATION_IN_PROGRESS } }
    }),
    true
  );
  assert.equal(
    isIocStatsRecalculationInProgressError({
      response: { status: 500, data: { error: IOC_STATS_RECALCULATION_IN_PROGRESS } }
    }),
    false
  );
});

test('cancel does not call API', async () => {
  let posts = 0;
  const controller = createAppConfirmController(() => {});
  const pending = runIocStatsRecalculateRequest({
    canWrite: true,
    isBlocked: () => false,
    requestConfirm: (opts) => controller.request(opts),
    postRefresh: async () => {
      posts += 1;
      return { data: {} };
    },
    setBusy: () => {}
  });
  controller.cancel();
  const result = await pending;
  assert.equal(result.reason, 'cancelled');
  assert.equal(posts, 0);
});

test('confirm calls API once; AppConfirm submitting blocks double confirm', async () => {
  let posts = 0;
  let busy = false;
  let resolvePost;
  const postGate = new Promise((r) => { resolvePost = r; });
  const controller = createAppConfirmController(() => {});

  const pending = runIocStatsRecalculateRequest({
    canWrite: true,
    isBlocked: () => busy,
    requestConfirm: (opts) => controller.request(opts),
    postRefresh: async () => {
      posts += 1;
      await postGate;
      return { data: { queued: true } };
    },
    setBusy: (v) => { busy = v; }
  });

  const firstConfirm = controller.confirm();
  assert.equal(controller.getState().submitting, true);
  const second = await controller.confirm();
  assert.equal(second.ignored, true);
  assert.equal(posts, 1);

  resolvePost();
  await firstConfirm;
  const result = await pending;
  assert.equal(result.started, true);
  assert.equal(posts, 1);
  assert.equal(busy, true);
});

test('409 already-running keeps busy and closes confirm successfully', async () => {
  let busy = false;
  const outcomes = [];
  const controller = createAppConfirmController(() => {});
  const pending = runIocStatsRecalculateRequest({
    canWrite: true,
    isBlocked: () => busy,
    requestConfirm: (opts) => controller.request(opts),
    postRefresh: async () => {
      throw {
        response: {
          status: 409,
          data: { error: IOC_STATS_RECALCULATION_IN_PROGRESS }
        }
      };
    },
    setBusy: (v) => { busy = v; },
    onOutcome: (kind) => outcomes.push(kind)
  });
  await controller.confirm();
  const result = await pending;
  assert.equal(result.reason, 'already_running');
  assert.equal(busy, true);
  assert.deepEqual(outcomes, ['already_running']);
  assert.equal(controller.getState().open, false);
});

test('hard failure restores busy=false and keeps modal open with error', async () => {
  let busy = false;
  const outcomes = [];
  const controller = createAppConfirmController(() => {});
  const pending = runIocStatsRecalculateRequest({
    canWrite: true,
    isBlocked: () => busy,
    requestConfirm: (opts) => controller.request(opts),
    postRefresh: async () => {
      throw { response: { status: 500, data: { message: 'boom' } }, message: 'boom' };
    },
    setBusy: (v) => { busy = v; },
    onOutcome: (kind) => outcomes.push(kind)
  });
  const confirmResult = await controller.confirm();
  assert.equal(confirmResult.ok, false);
  assert.equal(busy, false);
  assert.deepEqual(outcomes, ['error']);
  assert.equal(controller.getState().open, true);
  assert.match(controller.getState().error, /boom/);
  controller.cancel();
  const result = await pending;
  assert.equal(result.reason, 'error');
});
