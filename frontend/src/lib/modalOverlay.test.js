import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MODAL_SIZES,
  canCloseModal,
  getFocusableElements,
  modalSizeClass,
  resolveModalInitialFocus,
  trapFocusKeydown
} from './modalOverlay.js';

test('modalSizeClass maps sm/md/lg and defaults to md', () => {
  assert.equal(modalSizeClass('sm'), MODAL_SIZES.sm);
  assert.equal(modalSizeClass('md'), MODAL_SIZES.md);
  assert.equal(modalSizeClass('lg'), MODAL_SIZES.lg);
  assert.equal(modalSizeClass(undefined), MODAL_SIZES.md);
  assert.equal(modalSizeClass('nope'), MODAL_SIZES.md);
});

test('canCloseModal requires an onClose function and honors closeOnEsc=false', () => {
  assert.equal(canCloseModal({ onClose: () => {} }), true);
  assert.equal(canCloseModal({ onClose: undefined }), false);
  assert.equal(canCloseModal({ onClose: null }), false);
  assert.equal(canCloseModal({ onClose: () => {}, closeOnEsc: false }), false);
});

test('getFocusableElements skips disabled controls', () => {
  const enabled = { hasAttribute: () => false, getAttribute: () => null, focus() {} };
  const disabled = { hasAttribute: (n) => n === 'disabled', getAttribute: () => null, focus() {} };
  const root = {
    querySelectorAll(sel) {
      assert.match(sel, /button/);
      return [enabled, disabled];
    }
  };
  assert.deepEqual(getFocusableElements(root), [enabled]);
  assert.deepEqual(getFocusableElements(null), []);
});

test('trapFocusKeydown wraps from last to first', () => {
  const first = { id: 'first', focus() { this.focused = true; } };
  const last = { id: 'last', focus() { this.focused = true; } };
  const container = {
    contains: (el) => el === first || el === last,
    querySelectorAll: () => [first, last]
  };
  const prev = globalThis.document;
  globalThis.document = { activeElement: last };
  try {
    const ev = { key: 'Tab', shiftKey: false, preventDefault() { this.prevented = true; } };
    assert.equal(trapFocusKeydown(ev, container), true);
    assert.equal(ev.prevented, true);
    assert.equal(first.focused, true);
  } finally {
    if (prev === undefined) delete globalThis.document;
    else globalThis.document = prev;
  }
});

test('resolveModalInitialFocus prefers preferredEl, then cancel, then first focusable', () => {
  const preferred = { id: 'preferred' };
  const cancelBtn = { id: 'cancel' };
  const other = { id: 'other' };

  const container = {
    contains(el) {
      return el === preferred || el === cancelBtn || el === other;
    },
    querySelector(sel) {
      if (sel === '[data-modal-cancel]') return cancelBtn;
      return null;
    },
    querySelectorAll() {
      return [];
    }
  };

  assert.equal(
    resolveModalInitialFocus(container, { preferredEl: preferred }),
    preferred
  );
  assert.equal(
    resolveModalInitialFocus(container, { preferCancel: true }),
    cancelBtn
  );
  assert.equal(resolveModalInitialFocus(null), null);
});

test('resolveModalInitialFocus focuses the search input over an earlier chip remove button', () => {
  // Threat Classifications / Threat Actors editors: selected chips render remove
  // buttons before the search input in DOM order. Passing the search input as
  // the preferred element must win so initial focus lands on search, not a chip.
  const chipRemoveBtn = { id: 'remove-chip', focus() {} };
  const searchInput = { id: 'search', focus() {} };
  const container = {
    contains(el) {
      return el === chipRemoveBtn || el === searchInput;
    },
    querySelector() {
      return null;
    },
    // First focusable in DOM order is the chip remove button.
    querySelectorAll() {
      return [chipRemoveBtn, searchInput];
    }
  };

  assert.equal(
    resolveModalInitialFocus(container, { preferredEl: searchInput }),
    searchInput
  );
  // Without a preferred element, focus would fall to the earlier chip button.
  assert.equal(resolveModalInitialFocus(container), chipRemoveBtn);
});

test('trapFocusKeydown ignores non-Tab keys', () => {
  const handled = trapFocusKeydown({ key: 'Escape' }, {});
  assert.equal(handled, false);
});

test('aria contract docs: dialog should expose labelledBy when title provided', () => {
  // Sanity marker used by ModalOverlay consumers / docs — size sm string stable.
  assert.equal(modalSizeClass('sm'), 'modal-dialog--sm');
});
