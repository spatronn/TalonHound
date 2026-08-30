/**
 * Shared dismiss rules for admin Edit/Create form modals that render via ModalOverlay.
 * Keeps busy-state close contracts unit-testable without mounting React.
 */

import { canCloseModal } from './modalOverlay.js';

/**
 * @param {{ busy?: boolean }} [opts]
 * @returns {boolean}
 */
export function canDismissFormModal({ busy = false } = {}) {
  return canCloseModal({
    onClose: busy ? null : () => {},
    closeOnEsc: true
  });
}

/**
 * Resolve ModalOverlay onClose — Escape/backdrop only when not busy.
 * @param {{ busy?: boolean, onClose: Function }} opts
 * @returns {Function | undefined}
 */
export function formModalOnClose({ busy = false, onClose } = {}) {
  if (typeof onClose !== 'function') return undefined;
  return canDismissFormModal({ busy }) ? onClose : undefined;
}
