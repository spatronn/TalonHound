// Framework-agnostic controller for a reusable "confirm then run" action.
//
// One instance backs a single ConfirmActionModal that any provider can drive:
// the first click only opens the modal (no side effect), the confirmed action
// runs exactly once (double-clicks are ignored while in flight), the modal stays
// open with the error surfaced on failure, and closes on success. Logic lives
// here so it is unit-testable without a DOM.

export const CONFIRM_ACTION_INITIAL_STATE = Object.freeze({
  open: false,
  payload: null,
  submitting: false,
  error: ''
});

export function createConfirmActionController(notify) {
  let state = { ...CONFIRM_ACTION_INITIAL_STATE };
  let confirmHandler = null;

  function set(patch) {
    state = { ...state, ...patch };
    if (typeof notify === 'function') notify(state);
    return state;
  }

  return {
    getState() {
      return state;
    },

    // Open the modal. Never runs the action. `payload` carries whatever the modal
    // needs to render (title, description, confirmLabel, providerKey, …).
    request({ payload = null, onConfirm } = {}) {
      if (state.submitting) return state;
      confirmHandler = typeof onConfirm === 'function' ? onConfirm : null;
      return set({ open: true, payload, submitting: false, error: '' });
    },

    // Cancel / ESC / backdrop. Never runs the action; blocked while submitting.
    cancel() {
      if (state.submitting) return state;
      confirmHandler = null;
      return set({ ...CONFIRM_ACTION_INITIAL_STATE });
    },

    // Run the confirmed action exactly once. Concurrent calls are no-ops while
    // the first is in flight. Success closes the modal; failure keeps it open.
    async confirm() {
      if (!state.open || state.submitting || !confirmHandler) {
        return { ok: false, ignored: true };
      }
      const handler = confirmHandler;
      const payload = state.payload;
      set({ submitting: true, error: '' });
      try {
        await handler(payload);
        confirmHandler = null;
        set({ ...CONFIRM_ACTION_INITIAL_STATE });
        return { ok: true };
      } catch (err) {
        set({ submitting: false, error: (err && err.message) || 'Action failed' });
        return { ok: false, error: err };
      }
    }
  };
}
