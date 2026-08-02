/**
 * Close / dismiss rules for IOC Sources Edit/Add (and related page modals).
 * Visual dismissal goes through ModalOverlay; these helpers keep busy-state
 * contracts unit-testable without mounting React.
 */

import { canCloseModal } from './modalOverlay.js';

/**
 * Edit/Add form may dismiss via Escape, backdrop, or Cancel only when not saving.
 * @param {{ saving?: boolean }} [opts]
 * @returns {boolean}
 */
export function canDismissIocSourceFormModal({ saving = false } = {}) {
  return canCloseModal({
    onClose: saving ? null : () => {},
    closeOnEsc: true
  });
}

/**
 * Resolve ModalOverlay onClose for the Edit/Add form.
 * @param {{ saving?: boolean, onClose: Function }} opts
 * @returns {Function | undefined}
 */
export function iocSourceFormModalOnClose({ saving = false, onClose } = {}) {
  if (typeof onClose !== 'function') return undefined;
  return canDismissIocSourceFormModal({ saving }) ? onClose : undefined;
}

/**
 * Confirm-style overlays (Disable / Archive / Delete / Move) share the same
 * busy lock: Escape + backdrop close only when not busy.
 * @param {{ busy?: boolean, onClose: Function }} opts
 * @returns {Function | undefined}
 */
export function iocSourceConfirmModalOnClose({ busy = false, onClose } = {}) {
  if (typeof onClose !== 'function') return undefined;
  return busy ? undefined : onClose;
}
