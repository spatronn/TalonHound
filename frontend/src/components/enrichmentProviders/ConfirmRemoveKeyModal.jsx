import React from 'react';
import ConfirmActionModal from './ConfirmActionModal.jsx';

// Remove-key confirmation, expressed through the shared ConfirmActionModal so the
// modal behaviour stays identical across every provider action.
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
  return (
    <ConfirmActionModal
      open={open}
      title={`Remove ${providerName} ${keyNoun}?`}
      description={`This action will permanently remove the configured ${keyNoun}. The provider may stop working until a new ${keyNoun} is added.`}
      confirmLabel={confirmLabel}
      submittingLabel="Removing..."
      destructive
      submitting={submitting}
      error={error}
      onCancel={onCancel}
      onConfirm={onConfirm}
    />
  );
}
