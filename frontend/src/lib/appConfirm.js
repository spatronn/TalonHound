/**
 * Promise-based confirmation controller. Replaces window.confirm with a styled
 * modal while keeping the familiar await-true/false call site shape.
 *
 * Mode A — boolean confirm (migrate window.confirm):
 *   const ok = await controller.request({ title, description, variant: 'danger' });
 *
 * Mode B — async action (modal stays open on error):
 *   await controller.request({ title, onConfirm: async () => api.delete(...) });
 */

export const APP_CONFIRM_INITIAL = Object.freeze({
  open: false,
  title: '',
  description: '',
  detail: '',
  confirmLabel: 'Confirm',
  cancelLabel: 'Cancel',
  variant: 'primary', // primary | warning | danger
  submitting: false,
  error: ''
});

/**
 * @param {(state: object) => void} notify
 */
export function createAppConfirmController(notify) {
  let state = { ...APP_CONFIRM_INITIAL };
  let resolver = null;
  let action = null;

  function set(patch) {
    state = { ...state, ...patch };
    if (typeof notify === 'function') notify({ ...state });
    return state;
  }

  function settle(value) {
    const resolve = resolver;
    resolver = null;
    action = null;
    set({ ...APP_CONFIRM_INITIAL });
    if (resolve) resolve(value);
  }

  return {
    getState() {
      return state;
    },

    /**
     * Open the confirm dialog. Resolves to boolean when no onConfirm is given.
     * When onConfirm is provided, resolves to true on success / false on cancel;
     * failures keep the modal open and set error (promise stays pending until
     * success or cancel).
     * @param {object} options
     * @returns {Promise<boolean>}
     */
    request(options = {}) {
      if (state.open && state.submitting) {
        return Promise.resolve(false);
      }
      // Cancel any unfinished waiter without running its action.
      if (resolver) {
        const prev = resolver;
        resolver = null;
        prev(false);
      }
      action = typeof options.onConfirm === 'function' ? options.onConfirm : null;
      const variant = ['primary', 'warning', 'danger'].includes(options.variant)
        ? options.variant
        : 'primary';
      set({
        open: true,
        title: String(options.title || 'Confirm'),
        description: String(options.description || ''),
        detail: String(options.detail || ''),
        confirmLabel: String(options.confirmLabel || 'Confirm'),
        cancelLabel: String(options.cancelLabel || 'Cancel'),
        variant,
        submitting: false,
        error: ''
      });
      return new Promise((resolve) => {
        resolver = resolve;
      });
    },

    cancel() {
      if (!state.open || state.submitting) return state;
      settle(false);
      return state;
    },

    async confirm() {
      if (!state.open || state.submitting) return { ok: false, ignored: true };
      if (!action) {
        settle(true);
        return { ok: true };
      }
      set({ submitting: true, error: '' });
      try {
        await action();
        settle(true);
        return { ok: true };
      } catch (err) {
        const message = err?.response?.data?.message || err?.message || 'Action failed';
        set({ submitting: false, error: String(message) });
        return { ok: false, error: err };
      }
    }
  };
}
