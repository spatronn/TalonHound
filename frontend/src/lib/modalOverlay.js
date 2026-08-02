/**
 * Framework-agnostic helpers for ModalOverlay focus / size / close rules.
 * Unit-testable without mounting React.
 */

export const MODAL_SIZES = Object.freeze({
  sm: 'modal-dialog--sm',
  md: 'modal-dialog--md',
  lg: 'modal-dialog--lg'
});

/** Default size when callers pass title/footer (structured chrome). */
export const MODAL_DEFAULT_SIZE = 'md';

export const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'textarea:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  '[tabindex]:not([tabindex="-1"])'
].join(',');

/**
 * @param {ParentNode | null | undefined} container
 * @returns {HTMLElement[]}
 */
export function getFocusableElements(container) {
  if (!container || typeof container.querySelectorAll !== 'function') return [];
  return Array.from(container.querySelectorAll(FOCUSABLE_SELECTOR)).filter((el) => {
    if (!el) return false;
    if (typeof el.hasAttribute === 'function' && el.hasAttribute('disabled')) return false;
    if (typeof el.getAttribute === 'function' && el.getAttribute('aria-hidden') === 'true') return false;
    // Hidden via CSS / not rendered (browsers that support checkVisibility)
    if (typeof el.checkVisibility === 'function') {
      try {
        if (!el.checkVisibility()) return false;
      } catch {
        /* ignore */
      }
    }
    return true;
  });
}

/**
 * @param {'sm'|'md'|'lg'|string|null|undefined} size
 * @returns {string}
 */
export function modalSizeClass(size) {
  if (size && MODAL_SIZES[size]) return MODAL_SIZES[size];
  return MODAL_SIZES[MODAL_DEFAULT_SIZE];
}

/**
 * Backdrop / ESC may close only when onClose is a function.
 * @param {{ onClose?: Function | null, closeOnEsc?: boolean }} opts
 */
export function canCloseModal({ onClose, closeOnEsc = true } = {}) {
  return typeof onClose === 'function' && closeOnEsc !== false;
}

/**
 * Pick the element that should receive focus when the modal opens.
 * Destructive confirms should pass preferCancel so focus lands on Cancel.
 *
 * @param {ParentNode | null | undefined} container
 * @param {{ preferredEl?: HTMLElement | null, preferCancel?: boolean }} [opts]
 * @returns {HTMLElement | null}
 */
export function resolveModalInitialFocus(container, { preferredEl = null, preferCancel = false } = {}) {
  if (preferredEl && container?.contains?.(preferredEl)) return preferredEl;
  if (!container) return null;

  if (preferCancel) {
    const cancel =
      container.querySelector('[data-modal-cancel]') ||
      container.querySelector('button.th-btn--secondary') ||
      container.querySelector('button[type="button"]');
    if (cancel) return cancel;
  }

  const focusables = getFocusableElements(container);
  if (focusables[0]) return focusables[0];
  return typeof container.focus === 'function' ? container : null;
}

/**
 * Cycle Tab within the dialog. Returns whether the event was handled.
 * @param {KeyboardEvent} event
 * @param {ParentNode | null | undefined} container
 */
export function trapFocusKeydown(event, container) {
  if (!event || event.key !== 'Tab' || !container) return false;
  const focusables = getFocusableElements(container);
  if (focusables.length === 0) {
    event.preventDefault?.();
    return true;
  }
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  const active = typeof document !== 'undefined' ? document.activeElement : null;

  if (event.shiftKey) {
    if (active === first || !container.contains?.(active)) {
      event.preventDefault?.();
      last.focus?.();
      return true;
    }
  } else if (active === last || !container.contains?.(active)) {
    event.preventDefault?.();
    first.focus?.();
    return true;
  }
  return false;
}
