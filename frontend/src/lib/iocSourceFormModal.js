/**
 * Close / dismiss rules for IOC Sources Edit/Add (and related page modals).
 * Thin wrappers over shared formModalClose helpers (ModalOverlay contract).
 */

import { canDismissFormModal, formModalOnClose } from './formModalClose.js';

/**
 * Edit/Add form may dismiss via Escape, backdrop, or Cancel only when not saving.
 * @param {{ saving?: boolean }} [opts]
 * @returns {boolean}
 */
export function canDismissIocSourceFormModal({ saving = false } = {}) {
  return canDismissFormModal({ busy: saving });
}

/**
 * Resolve ModalOverlay onClose for the Edit/Add form.
 * @param {{ saving?: boolean, onClose: Function }} opts
 * @returns {Function | undefined}
 */
export function iocSourceFormModalOnClose({ saving = false, onClose } = {}) {
  return formModalOnClose({ busy: saving, onClose });
}

/**
 * Confirm-style overlays (Disable / Archive / Delete / Move) share the same
 * busy lock: Escape + backdrop close only when not busy.
 * @param {{ busy?: boolean, onClose: Function }} opts
 * @returns {Function | undefined}
 */
export function iocSourceConfirmModalOnClose({ busy = false, onClose } = {}) {
  return formModalOnClose({ busy, onClose });
}
