import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canDismissIocSourceFormModal,
  iocSourceConfirmModalOnClose,
  iocSourceFormModalOnClose
} from './iocSourceFormModal.js';
import { canCloseModal } from './modalOverlay.js';

test('Edit form dismisses when idle (Escape/backdrop/Cancel eligible)', () => {
  assert.equal(canDismissIocSourceFormModal({ saving: false }), true);
  assert.equal(canDismissIocSourceFormModal({}), true);
});

test('Edit form does not dismiss while saving', () => {
  assert.equal(canDismissIocSourceFormModal({ saving: true }), false);
});

test('iocSourceFormModalOnClose returns handler only when idle', () => {
  const close = () => {};
  assert.equal(iocSourceFormModalOnClose({ saving: false, onClose: close }), close);
  assert.equal(iocSourceFormModalOnClose({ saving: true, onClose: close }), undefined);
  assert.equal(iocSourceFormModalOnClose({ saving: false, onClose: null }), undefined);
});

test('Cancel/Escape stay aligned with shared ModalOverlay canCloseModal contract', () => {
  const idle = iocSourceFormModalOnClose({ saving: false, onClose: () => {} });
  assert.equal(canCloseModal({ onClose: idle }), true);
  assert.equal(canCloseModal({ onClose: iocSourceFormModalOnClose({ saving: true, onClose: () => {} }) }), false);
});

test('confirm overlays (Disable/Archive/Delete/Move) lock Escape while busy', () => {
  const close = () => {};
  assert.equal(iocSourceConfirmModalOnClose({ busy: false, onClose: close }), close);
  assert.equal(iocSourceConfirmModalOnClose({ busy: true, onClose: close }), undefined);
  assert.equal(
    canCloseModal({ onClose: iocSourceConfirmModalOnClose({ busy: true, onClose: close }) }),
    false
  );
});

test('re-resolving onClose while idle does not imply duplicate listeners (handler identity)', () => {
  const close = () => {};
  const a = iocSourceFormModalOnClose({ saving: false, onClose: close });
  const b = iocSourceFormModalOnClose({ saving: false, onClose: close });
  assert.equal(a, b);
  assert.equal(a, close);
});
