import test from 'node:test';
import assert from 'node:assert/strict';
import { canDismissFormModal, formModalOnClose } from './formModalClose.js';
import { canCloseModal } from './modalOverlay.js';

test('form modal dismisses when idle (Escape/backdrop/Cancel eligible)', () => {
  assert.equal(canDismissFormModal({ busy: false }), true);
  assert.equal(canDismissFormModal({}), true);
});

test('form modal does not dismiss while busy/saving', () => {
  assert.equal(canDismissFormModal({ busy: true }), false);
});

test('formModalOnClose returns handler only when idle', () => {
  const close = () => {};
  assert.equal(formModalOnClose({ busy: false, onClose: close }), close);
  assert.equal(formModalOnClose({ busy: true, onClose: close }), undefined);
  assert.equal(formModalOnClose({ busy: false, onClose: null }), undefined);
});

test('formModalOnClose stays aligned with ModalOverlay canCloseModal', () => {
  const idle = formModalOnClose({ busy: false, onClose: () => {} });
  assert.equal(canCloseModal({ onClose: idle }), true);
  assert.equal(canCloseModal({ onClose: formModalOnClose({ busy: true, onClose: () => {} }) }), false);
});

test('re-resolving idle onClose keeps stable handler identity (no duplicate semantics)', () => {
  const close = () => {};
  assert.equal(formModalOnClose({ busy: false, onClose: close }), close);
  assert.equal(formModalOnClose({ busy: false, onClose: close }), close);
});

test('Custom Threat Feeds Edit/Delete use the same busy lock contract', () => {
  const close = () => {};
  assert.equal(formModalOnClose({ busy: false, onClose: close }), close);
  assert.equal(formModalOnClose({ busy: true, onClose: close }), undefined); // saving | deleteLoading
});

test('Feeds settings busy aggregate locks Escape', () => {
  const close = () => {};
  const settingsBusy = true; // any of schedule|expiration|confidence|credentials|testing|color
  assert.equal(formModalOnClose({ busy: settingsBusy, onClose: close }), undefined);
  assert.equal(formModalOnClose({ busy: false, onClose: close }), close);
});
