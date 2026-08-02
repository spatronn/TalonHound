import React, { useEffect, useRef } from 'react';

// Generic, reusable confirmation modal for provider actions (disable, remove key,
// …). Behaviour is shared across every provider: default focus on the safe
// option, ESC / backdrop / Cancel close (blocked while a request is in flight),
// destructive styling for the confirm button, and a loading state.
export default function ConfirmActionModal({
  open,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive = false,
  submitting = false,
  submittingLabel,
  error = '',
  onCancel,
  onConfirm
}) {
  const cancelRef = useRef(null);

  // Default focus lands on the safe option (Cancel) when the modal opens.
  useEffect(() => {
    if (open && cancelRef.current) cancelRef.current.focus();
  }, [open]);

  // ESC closes the modal unless a request is in flight.
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

  const titleId = 'ep-confirm-title';
  const descId = 'ep-confirm-desc';
  const confirmClass = destructive ? 'ep-btn ep-btn-danger' : 'ep-btn ep-btn-primary';

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
        <h2 id={titleId} className="ep-modal-title">{title}</h2>
        {description ? <p id={descId} className="ep-modal-text">{description}</p> : null}

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
            {cancelLabel}
          </button>
          <button
            type="button"
            className={confirmClass}
            onClick={() => onConfirm?.()}
            disabled={submitting}
          >
            {submitting ? (submittingLabel || 'Working...') : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
