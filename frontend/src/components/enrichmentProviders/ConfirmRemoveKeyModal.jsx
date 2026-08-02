import React, { useEffect, useRef } from 'react';

// Shared confirmation modal for removing an enrichment provider's API key.
// Reused by every provider — the provider-specific wording comes from props.
export default function ConfirmRemoveKeyModal({
  open,
  providerName,
  keyNoun = 'API key',
  confirmLabel = 'Remove key',
  submitting = false,
  error = '',
  onCancel,
  onConfirm
}) {
  const cancelRef = useRef(null);

  // Default focus lands on the safe option (Cancel) when the modal opens.
  useEffect(() => {
    if (open && cancelRef.current) cancelRef.current.focus();
  }, [open]);

  // ESC closes the modal (unless a request is in flight).
  useEffect(() => {
    if (!open) return undefined;
    function onKeyDown(e) {
      if (e.key === 'Escape') {
        e.stopPropagation();
        if (!submitting) onCancel?.();
      }
    }
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [open, submitting, onCancel]);

  if (!open) return null;

  const titleId = 'ep-remove-key-title';
  const descId = 'ep-remove-key-desc';

  return (
    <div
      className="ep-modal-backdrop"
      role="presentation"
      onClick={() => { if (!submitting) onCancel?.(); }}
    >
      <div
        className="ep-modal"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id={titleId} className="ep-modal-title">
          Remove {providerName} {keyNoun}?
        </h2>
        <p id={descId} className="ep-modal-text">
          This action will permanently remove the configured {keyNoun}. The provider
          may stop working until a new {keyNoun} is added.
        </p>

        {error ? (
          <div className="ep-banner ep-banner--error ep-modal-error" role="alert">
            {error}
          </div>
        ) : null}

        <div className="ep-modal-actions">
          <button
            type="button"
            ref={cancelRef}
            className="ep-btn ep-btn-secondary"
            onClick={() => onCancel?.()}
            disabled={submitting}
          >
            Cancel
          </button>
          <button
            type="button"
            className="ep-btn ep-btn-danger"
            onClick={() => onConfirm?.()}
            disabled={submitting}
          >
            {submitting ? 'Removing...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
