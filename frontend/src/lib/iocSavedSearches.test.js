import test from 'node:test';
import assert from 'node:assert/strict';
import {
  savedSearchCreatePayload,
  savedSearchErrorMessage,
  SAVED_SEARCH_DELETE_CONFIRM_PREFER_CANCEL,
  captureSavedSearchDeleteTarget,
  savedSearchDeleteConfirmCopy,
  savedSelectedIdAfterDelete,
  savedSearchesAfterDelete,
  createSavedSearchDeleteConfirmController
} from './iocSavedSearches.js';
import { canCloseModal, resolveModalInitialFocus } from './modalOverlay.js';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const LIST = [
  { id: 'ss-a', name: 'Mirai weekly' },
  { id: 'ss-b', name: 'USOM IPs' }
];

test('savedSearchCreatePayload requires name and query', () => {
  assert.equal(savedSearchCreatePayload({ name: '', query: 'type equals "ip"' }).ok, false);
  assert.equal(savedSearchCreatePayload({ name: 'x', query: '  ' }).ok, false);
  const ok = savedSearchCreatePayload({ name: ' Mirai ', query: 'type equals "domain"', description: ' weekly ' });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.body, { name: 'Mirai', query: 'type equals "domain"', description: 'weekly' });
});

test('savedSearchErrorMessage maps duplicate code', () => {
  assert.equal(
    savedSearchErrorMessage({ code: 'SAVED_SEARCH_NAME_DUPLICATE', message: 'x' }),
    'A saved search with this name already exists.'
  );
  assert.equal(savedSearchErrorMessage({ message: 'nope' }), 'nope');
});

test('delete copy names the saved search and uses the destructive labels', () => {
  const c = savedSearchDeleteConfirmCopy('Mirai weekly');
  assert.equal(c.title, 'Delete saved search?');
  assert.equal(c.description, 'Delete “Mirai weekly”? This action cannot be undone.');
  assert.equal(c.cancelLabel, 'Cancel');
  assert.equal(c.confirmLabel, 'Delete saved search');
});

test('delete copy falls back when the name is empty', () => {
  const c = savedSearchDeleteConfirmCopy('  ');
  assert.match(c.description, /this saved search/);
});

test('captureSavedSearchDeleteTarget snapshots id and name at click time', () => {
  assert.equal(captureSavedSearchDeleteTarget(LIST, ''), null);
  assert.deepEqual(captureSavedSearchDeleteTarget(LIST, 'ss-a'), { id: 'ss-a', name: 'Mirai weekly' });
  assert.deepEqual(captureSavedSearchDeleteTarget(LIST, 'missing'), { id: 'missing', name: '' });
});

test('clicking Delete opens confirmation and does not call delete immediately', async () => {
  let calls = 0;
  const c = createSavedSearchDeleteConfirmController();
  const target = captureSavedSearchDeleteTarget(LIST, 'ss-a');
  c.request(target);
  assert.equal(c.getState().open, true);
  assert.deepEqual(c.getState().target, { id: 'ss-a', name: 'Mirai weekly' });
  assert.equal(calls, 0);
  const ignored = await c.confirm(async () => { calls += 1; });
  assert.equal(ignored.ok, true);
  assert.equal(calls, 1);
});

test('opening Delete does not invoke the delete API until confirm', () => {
  let calls = 0;
  const c = createSavedSearchDeleteConfirmController();
  c.request(captureSavedSearchDeleteTarget(LIST, 'ss-a'));
  assert.equal(c.getState().open, true);
  assert.equal(calls, 0);
});

test('Cancel closes the dialog and does not delete', async () => {
  let calls = 0;
  const c = createSavedSearchDeleteConfirmController();
  c.request(captureSavedSearchDeleteTarget(LIST, 'ss-a'));
  c.cancel();
  assert.equal(c.getState().open, false);
  const res = await c.confirm(async () => { calls += 1; });
  assert.equal(res.ignored, true);
  assert.equal(calls, 0);
});

test('confirming calls delete exactly once for the captured saved-search id', async () => {
  const seen = [];
  const c = createSavedSearchDeleteConfirmController();
  c.request(captureSavedSearchDeleteTarget(LIST, 'ss-b'));
  const res = await c.confirm(async (id) => { seen.push(id); });
  assert.equal(res.ok, true);
  assert.deepEqual(seen, ['ss-b']);
  assert.equal(res.deletedId, 'ss-b');
});

test('successful deletion closes the dialog and updates the saved-search UI', async () => {
  const c = createSavedSearchDeleteConfirmController();
  c.request(captureSavedSearchDeleteTarget(LIST, 'ss-a'));
  const res = await c.confirm(async () => {});
  assert.equal(res.ok, true);
  assert.equal(c.getState().open, false);
  assert.equal(c.getState().submitting, false);
  assert.deepEqual(savedSearchesAfterDelete(LIST, res.deletedId).map((s) => s.id), ['ss-b']);
  assert.equal(savedSelectedIdAfterDelete('ss-a', res.deletedId), '');
});

test('failed deletion does not pretend the item was deleted', async () => {
  const c = createSavedSearchDeleteConfirmController();
  c.request(captureSavedSearchDeleteTarget(LIST, 'ss-a'));
  const res = await c.confirm(async () => {
    throw Object.assign(new Error('boom'), { response: { data: { message: 'Failed to delete saved search' } } });
  });
  assert.equal(res.ok, false);
  assert.equal(res.deletedId, null);
  assert.equal(c.getState().open, true);
  assert.equal(c.getState().submitting, false);
  assert.equal(c.getState().error, 'Failed to delete saved search');
  assert.deepEqual(savedSearchesAfterDelete(LIST, res.deletedId).map((s) => s.id), ['ss-a', 'ss-b']);
  assert.equal(savedSelectedIdAfterDelete('ss-a', res.deletedId), 'ss-a');
});

test('stale selection changes cannot delete a different saved search', async () => {
  const seen = [];
  const c = createSavedSearchDeleteConfirmController();
  const target = captureSavedSearchDeleteTarget(LIST, 'ss-a');
  c.request(target);
  let selectedId = 'ss-b';
  const res = await c.confirm(async (id) => { seen.push(id); });
  assert.deepEqual(seen, ['ss-a']);
  assert.equal(res.deletedId, 'ss-a');
  assert.equal(savedSelectedIdAfterDelete(selectedId, res.deletedId), 'ss-b');
});

test('duplicate confirmation clicks cannot issue duplicate delete requests', async () => {
  let calls = 0;
  const d = deferred();
  const c = createSavedSearchDeleteConfirmController();
  c.request(captureSavedSearchDeleteTarget(LIST, 'ss-a'));
  const first = c.confirm(async () => { calls += 1; return d.promise; });
  const second = await c.confirm(async () => { calls += 1; });
  assert.equal(second.ignored, true);
  assert.equal(calls, 1);
  d.resolve();
  await first;
  assert.equal(calls, 1);
});

test('Cancel is blocked while delete is in flight and request cannot retarget', async () => {
  const d = deferred();
  const c = createSavedSearchDeleteConfirmController();
  c.request(captureSavedSearchDeleteTarget(LIST, 'ss-a'));
  const confirming = c.confirm(async () => d.promise);
  assert.equal(c.getState().submitting, true);
  c.cancel();
  assert.equal(c.getState().open, true);
  c.request(captureSavedSearchDeleteTarget(LIST, 'ss-b'));
  assert.equal(c.getState().target.id, 'ss-a');
  d.resolve();
  await confirming;
  assert.equal(c.getState().open, false);
});

test('Escape/backdrop stay locked while delete is in flight', () => {
  assert.equal(canCloseModal({ onClose: undefined }), false);
  assert.equal(canCloseModal({ onClose: () => {} }), true);
  assert.equal(SAVED_SEARCH_DELETE_CONFIRM_PREFER_CANCEL, true);
});

test('delete confirm initial focus prefers Cancel', () => {
  const cancel = { id: 'cancel' };
  const container = {
    contains: () => false,
    querySelector(sel) {
      if (sel === '[data-modal-cancel]') return cancel;
      return null;
    },
    querySelectorAll: () => []
  };
  assert.equal(
    resolveModalInitialFocus(container, { preferCancel: SAVED_SEARCH_DELETE_CONFIRM_PREFER_CANCEL }),
    cancel
  );
});
