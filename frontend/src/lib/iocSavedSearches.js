/**
 * Helpers for IOC List saved-search UI.
 */

export function savedSearchCreatePayload({ name, query, description } = {}) {
  const n = String(name || '').trim();
  const q = String(query || '').trim();
  const errors = [];
  if (!n) errors.push('name');
  if (!q) errors.push('query');
  if (errors.length) return { ok: false, errors };
  const body = { name: n, query: q };
  const d = description == null ? '' : String(description).trim();
  if (d) body.description = d;
  return { ok: true, body };
}

export function savedSearchErrorMessage(payload, fallback = 'Failed to save search') {
  if (payload?.code === 'SAVED_SEARCH_NAME_DUPLICATE') {
    return 'A saved search with this name already exists.';
  }
  return payload?.message || payload?.error?.message || fallback;
}

/** Initial focus for the destructive confirm — Cancel, never Delete. */
export const SAVED_SEARCH_DELETE_CONFIRM_PREFER_CANCEL = true;

export const SAVED_SEARCH_DELETE_CONFIRM_INITIAL = Object.freeze({
  open: false,
  target: null,
  submitting: false,
  error: ''
});

export function savedSearchDeleteConfirmCopy(name) {
  const display = String(name || '').trim() || 'this saved search';
  return {
    title: 'Delete saved search?',
    description: `Delete “${display}”? This action cannot be undone.`,
    cancelLabel: 'Cancel',
    confirmLabel: 'Delete saved search'
  };
}

/**
 * Snapshot the selected saved search at Delete-click time.
 * Later dropdown changes must not retarget a pending confirmation.
 */
export function captureSavedSearchDeleteTarget(savedSearches, selectedId) {
  const id = String(selectedId || '').trim();
  if (!id) return null;
  const found = Array.isArray(savedSearches)
    ? savedSearches.find((s) => String(s?.id) === id)
    : null;
  return { id, name: found?.name != null ? String(found.name) : '' };
}

export function savedSelectedIdAfterDelete(selectedId, deletedId) {
  return String(selectedId || '') === String(deletedId || '') ? '' : selectedId;
}

export function savedSearchesAfterDelete(savedSearches, deletedId) {
  const id = String(deletedId || '');
  return (Array.isArray(savedSearches) ? savedSearches : []).filter((s) => String(s?.id) !== id);
}

function deleteErrorMessage(err) {
  return savedSearchErrorMessage(
    err?.response?.data,
    err?.message || 'Failed to delete saved search'
  );
}

/**
 * Framework-agnostic delete-confirm controller.
 * Opening never calls the API; confirm uses the id captured at request().
 */
export function createSavedSearchDeleteConfirmController(notify) {
  let state = { ...SAVED_SEARCH_DELETE_CONFIRM_INITIAL };

  function set(patch) {
    state = { ...state, ...patch };
    if (typeof notify === 'function') notify({ ...state });
    return state;
  }

  return {
    getState() {
      return state;
    },

    request(target) {
      if (state.submitting) return state;
      if (!target?.id) return state;
      return set({
        open: true,
        target: { id: String(target.id), name: String(target.name || '') },
        submitting: false,
        error: ''
      });
    },

    cancel() {
      if (!state.open || state.submitting) return state;
      return set({ ...SAVED_SEARCH_DELETE_CONFIRM_INITIAL });
    },

    async confirm(deleteSavedSearch) {
      if (!state.open || state.submitting || !state.target?.id) {
        return { ok: false, ignored: true };
      }
      if (typeof deleteSavedSearch !== 'function') {
        return { ok: false, ignored: true };
      }
      const capturedId = state.target.id;
      set({ submitting: true, error: '' });
      try {
        await deleteSavedSearch(capturedId);
        set({ ...SAVED_SEARCH_DELETE_CONFIRM_INITIAL });
        return { ok: true, deletedId: capturedId };
      } catch (err) {
        set({ submitting: false, error: deleteErrorMessage(err) });
        return { ok: false, error: err, deletedId: null };
      }
    }
  };
}
