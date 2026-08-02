/**
 * Minimal page feedback queue (toast/banner). No dependencies.
 * Success/info auto-dismiss; errors persist until dismissed or cleared.
 */

let seq = 0;

export const FEEDBACK_TONES = Object.freeze(['success', 'error', 'warning', 'info']);

/**
 * @param {(items: object[]) => void} notify
 */
export function createAppFeedbackController(notify) {
  let items = [];

  function publish() {
    if (typeof notify === 'function') notify(items.slice());
    return items;
  }

  return {
    getItems() {
      return items.slice();
    },

    /**
     * @param {{ tone?: string, message: string, autoDismissMs?: number|null, id?: string }} opts
     */
    push({ tone = 'info', message, autoDismissMs, id } = {}) {
      const text = String(message || '').trim();
      if (!text) return items;
      const safeTone = FEEDBACK_TONES.includes(tone) ? tone : 'info';
      // Dedupe: same tone+message already visible → refresh id/timer conceptually by skipping.
      if (items.some((it) => it.tone === safeTone && it.message === text)) {
        return publish();
      }
      const itemId = id || `fb-${Date.now()}-${++seq}`;
      let dismissMs = autoDismissMs;
      if (dismissMs === undefined) {
        dismissMs = safeTone === 'error' ? null : 5000;
      }
      items = [...items, { id: itemId, tone: safeTone, message: text, autoDismissMs: dismissMs }];
      return publish();
    },

    dismiss(id) {
      items = items.filter((it) => it.id !== id);
      return publish();
    },

    clear() {
      items = [];
      return publish();
    },

    /** Convenience helpers */
    success(message, autoDismissMs) {
      return this.push({ tone: 'success', message, autoDismissMs });
    },
    error(message) {
      return this.push({ tone: 'error', message, autoDismissMs: null });
    },
    warning(message, autoDismissMs) {
      return this.push({ tone: 'warning', message, autoDismissMs });
    },
    info(message, autoDismissMs) {
      return this.push({ tone: 'info', message, autoDismissMs });
    }
  };
}

export function feedbackRoleForTone(tone) {
  return tone === 'error' ? 'alert' : 'status';
}
