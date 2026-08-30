import React from 'react';

export default function ProviderActionBar({
  onSave,
  onTest,
  onRemove,
  onSync,
  saveLabel = 'Save Changes',
  testLabel = 'Test Connection',
  removeLabel,
  syncLabel = 'Run sync now',
  busy = {},
  disabled = false,
  saveDisabled = false,
  testDisabled = false,
  removeDisabled = false,
  syncDisabled = false
}) {
  return (
    <div className="ep-actions">
      {onTest ? (
        <button
          type="button"
          className="ep-btn ep-btn-primary"
          onClick={onTest}
          disabled={disabled || testDisabled || busy.test}
        >
          {busy.test ? 'Testing...' : testLabel}
        </button>
      ) : null}
      {onSave ? (
        <button
          type="button"
          className="ep-btn ep-btn-secondary"
          onClick={onSave}
          disabled={disabled || saveDisabled || busy.save}
        >
          {busy.save ? 'Saving...' : saveLabel}
        </button>
      ) : null}
      {onSync ? (
        <button
          type="button"
          className="ep-btn ep-btn-secondary"
          onClick={onSync}
          disabled={disabled || syncDisabled || busy.sync}
        >
          {busy.sync ? 'Queuing...' : syncLabel}
        </button>
      ) : null}
      {onRemove ? (
        <button
          type="button"
          className="ep-btn ep-btn-danger"
          onClick={onRemove}
          disabled={disabled || removeDisabled || busy.remove}
        >
          {busy.remove ? 'Removing...' : removeLabel || 'Remove key'}
        </button>
      ) : null}
    </div>
  );
}
