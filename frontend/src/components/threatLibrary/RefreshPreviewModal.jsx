import React, { useEffect, useState } from 'react';
import ThreatLibraryModal, { ModalCancelButton } from './ThreatLibraryModal.jsx';
import { ToneBadge } from './reportPageParts.jsx';
import { ui } from './styles.js';
import {
  ACCEPTANCE_REASON_MIN_CHARS,
  buildRefreshRequestBody,
  canSubmitAcceptance,
  describeRefreshPreview
} from './refreshPreviewUi.js';
import { REFRESH_EXTRACTION_CONFIRM } from './reportRetryUi.js';

const LIST_LIMIT = 50;

function ValueRow({ item, children }) {
  return (
    <li className="tl-refresh__row">
      <span className="tl-quality__type">{item.typeLabel}</span>
      <code className="tl-quality__value">{item.value}</code>
      {children}
    </li>
  );
}

function ChangeGroup({ title, count, testId, children }) {
  if (!count) return null;
  return (
    <section className="tl-refresh__group" data-testid={testId}>
      <h4 className="tl-refresh__group-title">
        {title} <span className="tl-heading__count">{count}</span>
      </h4>
      {children}
    </section>
  );
}

/**
 * Refresh extraction with a read-only preview first. Unprotected changes run
 * on a plain confirmation; protected ones need an explicit acceptance with a
 * reason, bound to this preview (the server re-checks when the job runs).
 */
export default function RefreshPreviewModal({ open, loading, error, preview, busy, isAdmin = false, onClose, onSubmit }) {
  const [reason, setReason] = useState('');
  const [submitError, setSubmitError] = useState('');

  useEffect(() => {
    if (open) {
      setReason('');
      setSubmitError('');
    }
  }, [open, preview]);

  const model = describeRefreshPreview(preview, { isAdmin });
  const body = model.available ? buildRefreshRequestBody(model, reason) : null;
  const submitting = busy === 'refresh_extraction';

  async function submit() {
    if (!body) return;
    setSubmitError('');
    try {
      await onSubmit(body);
    } catch (err) {
      setSubmitError(err?.response?.data?.message || err?.message || 'Refresh extraction failed to start');
    }
  }

  const primaryLabel = model.blocked ? 'Accept changes and refresh' : REFRESH_EXTRACTION_CONFIRM.confirmLabel;
  const reasonValid = canSubmitAcceptance(reason);

  return (
    <ThreatLibraryModal
      open={open}
      title={REFRESH_EXTRACTION_CONFIRM.title}
      description={REFRESH_EXTRACTION_CONFIRM.description}
      onClose={onClose}
      width={720}
      closeDisabled={submitting}
      footer={(
        <>
          <ModalCancelButton onClick={onClose} disabled={submitting} />
          {model.available && !(model.blocked && !model.needsAcceptance) ? (
            <button
              type="button"
              style={model.blocked ? ui.btnDanger : ui.btnPrimary}
              disabled={submitting || loading || !body}
              onClick={() => submit().catch(() => {})}
              data-testid="refresh-preview-submit"
            >
              {submitting ? 'Starting…' : primaryLabel}
            </button>
          ) : null}
        </>
      )}
    >
      <div data-testid="refresh-preview">
        {loading ? <div style={ui.muted}>Computing the preview (deterministic, no AI)…</div> : null}
        {!loading && error ? <div style={ui.error} role="alert">{error}</div> : null}
        {!loading && !error && model.available ? (
          <>
            <div className="tl-refresh__summary">
              <ToneBadge tone={model.blocked ? 'danger' : 'success'}>
                {model.blocked ? 'Needs your acceptance' : 'Safe to apply'}
              </ToneBadge>
              {model.indicatorsLine ? <strong data-testid="refresh-preview-indicators">{model.indicatorsLine}</strong> : null}
              <span className="tl-refresh__counts">
                +{model.counts.added} added · −{model.counts.removed} removed · {model.counts.changed} reclassified
              </span>
            </div>
            <p className="tl-refresh__headline">{model.headline}</p>
            <p style={ui.helper}>{REFRESH_EXTRACTION_CONFIRM.detail}</p>

            {model.blockingReasons.length ? (
              <div style={ui.warnBanner} data-testid="refresh-preview-blocking">
                <strong style={{ display: 'block', marginBottom: 4 }}>Why this refresh is protected</strong>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {model.blockingReasons.map((r) => (
                    <li key={r.code}>
                      <strong>{r.title}</strong>{r.count ? ` (${r.count})` : ''}. {r.detail}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            {model.advisoryReasons.length ? (
              <div className="tl-refresh__advisory" data-testid="refresh-preview-advisory">
                <span className="tl-refresh__advisory-label">Also noted (does not block)</span>
                <ul>
                  {model.advisoryReasons.map((r) => (
                    <li key={r.code}>{r.title}. {r.detail}</li>
                  ))}
                </ul>
              </div>
            ) : null}

            <ChangeGroup title="Removed from Indicators" count={model.removed.length} testId="refresh-preview-removed">
              <ul className="tl-refresh__list">
                {model.removed.slice(0, LIST_LIMIT).map((item) => (
                  <ValueRow key={item.identity} item={item}>
                    <span className="tl-refresh__reason">{item.reason}</span>
                    {item.badges.map((b) => <ToneBadge key={b.label} tone={b.tone}>{b.label}</ToneBadge>)}
                  </ValueRow>
                ))}
              </ul>
            </ChangeGroup>
            <ChangeGroup title="Analyst decisions that would be deleted" count={model.deletedReviewed.length} testId="refresh-preview-deleted">
              <ul className="tl-refresh__list">
                {model.deletedReviewed.slice(0, LIST_LIMIT).map((item) => (
                  <ValueRow key={item.identity} item={item}>
                    <span className="tl-refresh__reason">{item.reason}</span>
                    {item.badges.map((b) => <ToneBadge key={b.label} tone={b.tone}>{b.label}</ToneBadge>)}
                  </ValueRow>
                ))}
              </ul>
            </ChangeGroup>
            <ChangeGroup title="Added to Indicators" count={model.added.length} testId="refresh-preview-added">
              <ul className="tl-refresh__list">
                {model.added.slice(0, LIST_LIMIT).map((item) => <ValueRow key={item.identity} item={item} />)}
              </ul>
            </ChangeGroup>
            <ChangeGroup title="Reclassified" count={model.changed.length} testId="refresh-preview-changed">
              <ul className="tl-refresh__list">
                {model.changed.slice(0, LIST_LIMIT).map((item) => (
                  <ValueRow key={item.identity} item={item}>
                    <span className="tl-refresh__reason">{item.from} → {item.to}</span>
                  </ValueRow>
                ))}
              </ul>
            </ChangeGroup>

            {model.adminNotice ? (
              <div style={ui.error} role="alert" data-testid="refresh-preview-admin-required">{model.adminNotice}</div>
            ) : null}
            {model.blocked && model.needsAcceptance && model.canAccept ? (
              <div className="tl-refresh__accept">
                <label htmlFor="tl-refresh-reason" style={ui.label}>Reason for accepting these changes</label>
                <textarea
                  id="tl-refresh-reason"
                  data-testid="refresh-preview-reason"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  rows={3}
                  maxLength={2000}
                  disabled={submitting}
                  style={{ ...ui.input, width: '100%', resize: 'vertical', fontFamily: 'inherit' }}
                  placeholder="For example: verified against the publisher appendix; the removed rows were an analysis table."
                />
                <span style={ui.helper}>
                  {reasonValid
                    ? 'Recorded in the audit log with your name. Applies only to the changes shown here.'
                    : `At least ${ACCEPTANCE_REASON_MIN_CHARS} characters. Recorded in the audit log.`}
                </span>
              </div>
            ) : null}
            {model.blocked && !model.needsAcceptance ? (
              <div style={ui.error} role="alert">This preview cannot be accepted. Close it and open Refresh extraction again.</div>
            ) : null}
            {submitError ? <div style={{ ...ui.error, marginTop: 10 }} role="alert">{submitError}</div> : null}
          </>
        ) : null}
      </div>
    </ThreatLibraryModal>
  );
}
