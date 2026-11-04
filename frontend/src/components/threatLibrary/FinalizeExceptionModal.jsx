import React, { useEffect, useState } from 'react';
import ThreatLibraryModal, { ModalCancelButton } from './ThreatLibraryModal.jsx';
import { ui } from './styles.js';
import { canSubmitFinalizeException, FINALIZE_EXCEPTION_REASON_MIN_CHARS, obligationLabel } from './extractionQualityUi.js';

/**
 * Administrator's reasoned exception to the finalize obligations of a new report.
 * The server re-checks everything; this states what is being set aside.
 */
export default function FinalizeExceptionModal({ open, obligations = [], submitting = false, error = '', onClose, onSubmit }) {
  const [reason, setReason] = useState('');
  useEffect(() => { if (open) setReason(''); }, [open]);
  const ready = canSubmitFinalizeException(reason) && !submitting;
  return (
    <ThreatLibraryModal
      open={open}
      title="Finalize with an exception"
      description="This report has unmet obligations. Your reason is stored with the report and in the audit log."
      onClose={onClose}
      closeDisabled={submitting}
      footer={(
        <>
          <ModalCancelButton onClick={onClose} disabled={submitting} />
          <button type="button" style={ui.btnDanger} disabled={!ready} onClick={() => onSubmit(reason.trim())}>
            {submitting ? 'Finalizing…' : 'Finalize with exception'}
          </button>
        </>
      )}
    >
      <ul data-testid="finalize-obligations">
        {obligations.map((o) => (
          <li key={o.code}>
            <strong>{obligationLabel(o.code)}</strong>
            {' '}
            {o.message}
          </li>
        ))}
      </ul>
      <label htmlFor="finalize-exception-reason">Reason</label>
      <textarea
        id="finalize-exception-reason"
        style={{ ...ui.input, width: '100%', minHeight: 88 }}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        aria-describedby="finalize-exception-hint"
      />
      <p id="finalize-exception-hint">At least {FINALIZE_EXCEPTION_REASON_MIN_CHARS} characters.</p>
      {error ? <p role="alert">{error}</p> : null}
    </ThreatLibraryModal>
  );
}
