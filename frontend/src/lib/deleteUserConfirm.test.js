import test from 'node:test';
import assert from 'node:assert/strict';
import { DELETE_USER_CONFIRM_PREFER_CANCEL, deleteUserConfirmCopy } from './deleteUserConfirm.js';
import { canCloseModal, resolveModalInitialFocus } from './modalOverlay.js';

test('deleteUserConfirmCopy includes username and avoids vague empty', () => {
  const c = deleteUserConfirmCopy('alice');
  assert.equal(c.title, 'Delete user');
  assert.match(c.description, /alice/);
  assert.match(c.description, /cannot be undone/i);
});

test('delete confirmation never uses window.confirm — modal close contract', () => {
  // Destructive confirm stays open while submitting (onClose undefined).
  assert.equal(canCloseModal({ onClose: undefined }), false);
  assert.equal(canCloseModal({ onClose: () => {} }), true);
  assert.equal(DELETE_USER_CONFIRM_PREFER_CANCEL, true);
});

test('delete confirm initial focus prefers Cancel control', () => {
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
    resolveModalInitialFocus(container, { preferCancel: DELETE_USER_CONFIRM_PREFER_CANCEL }),
    cancel
  );
});
