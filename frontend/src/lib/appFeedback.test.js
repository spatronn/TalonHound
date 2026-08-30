import test from 'node:test';
import assert from 'node:assert/strict';
import { createAppFeedbackController, feedbackRoleForTone } from './appFeedback.js';

test('push adds success with default auto-dismiss', () => {
  let items = [];
  const fb = createAppFeedbackController((x) => { items = x; });
  fb.success('Saved');
  assert.equal(items.length, 1);
  assert.equal(items[0].tone, 'success');
  assert.equal(items[0].autoDismissMs, 5000);
  assert.equal(feedbackRoleForTone('success'), 'status');
});

test('errors persist until dismissed', () => {
  const fb = createAppFeedbackController(() => {});
  fb.error('Boom');
  assert.equal(fb.getItems()[0].autoDismissMs, null);
  assert.equal(feedbackRoleForTone('error'), 'alert');
});

test('duplicate tone+message is not stacked', () => {
  const fb = createAppFeedbackController(() => {});
  fb.info('Queued');
  fb.info('Queued');
  assert.equal(fb.getItems().length, 1);
});

test('dismiss removes by id', () => {
  const fb = createAppFeedbackController(() => {});
  fb.success('A');
  const id = fb.getItems()[0].id;
  fb.dismiss(id);
  assert.equal(fb.getItems().length, 0);
});

test('clear empties queue', () => {
  const fb = createAppFeedbackController(() => {});
  fb.success('A');
  fb.error('B');
  fb.clear();
  assert.equal(fb.getItems().length, 0);
});
