// Framework-agnostic confirmation state machine for the shared "Remove key" flow.
//
// A single controller instance is reused by every enrichment provider that
// supports key/token removal. It guarantees the destructive API request only
// fires after an explicit second confirmation and never fires twice for one
// confirmation. The React layer (useRemoveKeyConfirm + ConfirmRemoveKeyModal)
// is a thin wrapper around this; the logic lives here so it can be unit tested
// with `node --test` without a DOM.

export const REMOVE_KEY_INITIAL_STATE = Object.freeze({
  open: false,
  providerKey: null,
  providerName: '',
  keyNoun: 'API key',
  confirmLabel: 'Remove key',
  submitting: false,
  error: ''
});

export function createRemoveKeyConfirmController(notify) {
  let state = { ...REMOVE_KEY_INITIAL_STATE };
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

    // First "Remove key" click: only opens the modal. It must NOT run the
    // destructive action. Ignored if a request is already in flight.
    request({ providerKey, providerName, keyNoun, confirmLabel, onConfirm } = {}) {
      if (state.submitting) return state;
      confirmHandler = typeof onConfirm === 'function' ? onConfirm : null;
      return set({
        open: true,
        providerKey: providerKey ?? null,
        providerName: providerName || '',
        keyNoun: keyNoun || 'API key',
        confirmLabel: confirmLabel || 'Remove key',
        submitting: false,
        error: ''
      });
    },

    // Cancel / ESC / backdrop click all route here. Never runs the action.
    // Blocked while submitting so the request cannot be abandoned mid-flight.
    cancel() {
      if (state.submitting) return state;
      confirmHandler = null;
      return set({ ...REMOVE_KEY_INITIAL_STATE });
    },

    // Second confirmation: runs the destructive action exactly once. Concurrent
    // calls (double click) are no-ops while the first is in flight. On success
    // the modal closes; on failure it stays open with the error surfaced.
    async confirm() {
      if (!state.open || state.submitting || !confirmHandler) {
        return { ok: false, ignored: true };
      }
      const handler = confirmHandler;
      const providerKey = state.providerKey;
      set({ submitting: true, error: '' });
      try {
        await handler({ providerKey });
        confirmHandler = null;
        set({ ...REMOVE_KEY_INITIAL_STATE });
        return { ok: true };
      } catch (err) {
        set({
          submitting: false,
          error: (err && err.message) || 'Remove failed'
        });
        return { ok: false, error: err };
      }
    }
  };
}
