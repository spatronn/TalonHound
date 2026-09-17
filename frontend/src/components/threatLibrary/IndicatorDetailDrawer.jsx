import React, { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { describeCandidateDetail } from './candidateDetail.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import {
  assessmentTone,
  matchStateTone,
  promotionOutcomeTone,
  reviewStatusTone
} from './reportDisplayLabels.js';
import { CopyValueButton, ToneBadge } from './reportPageParts.jsx';
import { ui } from './styles.js';

const compactBtn = { ...ui.btn, minHeight: 30, padding: '4px 10px', fontSize: 12 };

function Field({ label, children, mono }) {
  return (
    <>
      <dt>{label}</dt>
      <dd className={mono ? 'is-mono' : undefined}>{children}</dd>
    </>
  );
}

/**
 * Right-side detail panel for one indicator row: an inspection surface only.
 * It reads the same candidate object the table renders, shows the current
 * review / IOC state read-only, copies the value and walks the current
 * filtered result set via Previous / Next (`position`). Review-state
 * mutations live exclusively in the Indicators table toolbar; this component
 * has no review handler at all.
 */
export default function IndicatorDetailDrawer({
  candidate,
  onClose,
  position = null,
  onNavigate
}) {
  const panelRef = useRef(null);
  const open = Boolean(candidate);

  useEffect(() => {
    if (!open) return undefined;
    function onKey(e) {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose?.();
      } else if (e.altKey && e.key === 'ArrowLeft' && position?.prevId != null) {
        e.preventDefault();
        onNavigate?.(position.prevId);
      } else if (e.altKey && e.key === 'ArrowRight' && position?.nextId != null) {
        e.preventDefault();
        onNavigate?.(position.nextId);
      }
    }
    document.addEventListener('keydown', onKey, true);
    return () => document.removeEventListener('keydown', onKey, true);
  }, [open, onClose, onNavigate, position?.prevId, position?.nextId]);

  useEffect(() => {
    if (open && panelRef.current) {
      try { panelRef.current.focus({ preventScroll: true }); } catch { /* ignore */ }
    }
  }, [open, candidate?.id]);

  if (!open || typeof document === 'undefined') return null;

  const d = describeCandidateDetail(candidate, { formatDateTime: formatUserDateTime });
  const fields = Object.fromEntries(d.fields.map((f) => [f.key, f]));
  const title = `${d.typeLabel || 'Indicator'} ${d.value}`;
  const hasNav = position && position.total > 0 && position.index > 0;

  return createPortal(
    <>
      <div className="tl-drawer-backdrop" role="presentation" onClick={() => onClose?.()} />
      <aside
        ref={panelRef}
        className="tl-drawer"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        data-testid="indicator-drawer"
      >
        <div className="tl-drawer__head">
          <div className="tl-drawer__headrow">
            <span className="tl-drawer__type">{d.typeLabel || 'Indicator'}</span>
            <span className="tl-drawer__headright">
              {hasNav ? <span className="tl-drawer__counter" data-testid="drawer-position">{position.index} / {position.total}</span> : null}
              <button
                type="button"
                className="tl-icon-btn tl-drawer__close"
                onClick={() => onClose?.()}
                aria-label="Close details"
                title="Close (Esc)"
              >
                ×
              </button>
            </span>
          </div>
          <div className="tl-drawer__valuerow">
            {/* Inert text by design: never an anchor, even for URLs. */}
            <span className="tl-value tl-drawer__value" data-testid="drawer-value">{d.value || '—'}</span>
            {d.value ? <CopyValueButton value={d.value} label="Copy indicator" /> : null}
          </div>
        </div>

        <div className="tl-drawer__body">
          <section className="tl-drawer__section" aria-labelledby="tl-drawer-assessment">
            <h3 className="tl-section-title" id="tl-drawer-assessment">Assessment</h3>
            <div style={{ marginBottom: 8 }}>
              <ToneBadge tone={assessmentTone(fields.assessment?.raw)}>{fields.assessment?.value}</ToneBadge>
            </div>
            <dl className="tl-dl tl-dl--tight">
              <Field label="Role">{fields.role?.value}</Field>
              <Field label="Confidence">{fields.confidence?.value}</Field>
              <Field label="Review"><ToneBadge tone={reviewStatusTone(fields.review_status?.raw)}>{fields.review_status?.value}</ToneBadge></Field>
              <Field label="Existing match">
                <ToneBadge tone={candidate.matched_ioc_id ? 'neutral' : matchStateTone(fields.match?.raw)}>{fields.match?.value}</ToneBadge>
              </Field>
              <Field label="IOC result"><ToneBadge tone={promotionOutcomeTone(fields.ioc_result?.raw)}>{fields.ioc_result?.value}</ToneBadge></Field>
              {fields.promoted_at ? <Field label="Promoted">{fields.promoted_at.value}</Field> : null}
              {fields.original_value ? <Field label="As written" mono>{fields.original_value.value}</Field> : null}
            </dl>
          </section>

          <section className="tl-drawer__section" aria-labelledby="tl-drawer-evidence">
            <h3 className="tl-section-title" id="tl-drawer-evidence">Evidence</h3>
            <div style={{ fontSize: 13, color: '#e2e8f0' }}>
              {d.evidence.assertion}
              {d.evidence.declaredType ? <span style={{ color: '#94a3b8' }}> · {d.evidence.declaredType}</span> : null}
              {!d.evidence.direct ? <span style={{ color: '#fbbf24' }}> · derived</span> : null}
            </div>
            {d.evidence.decision ? <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 2 }}>{d.evidence.decision}</div> : null}
            {d.evidence.description ? <div style={{ fontSize: 13, color: '#cbd5e1', marginTop: 4 }}>{d.evidence.description}</div> : null}
            {d.evidence.resolution ? (
              <div style={{ fontSize: 12, color: '#fbbf24', marginTop: 4 }}>
                {d.evidence.resolution.label}
                {d.evidence.resolution.detail ? <span style={{ color: '#94a3b8' }}> · {d.evidence.resolution.detail}</span> : null}
              </div>
            ) : null}
            {d.evidence.ports || d.evidence.urlHost ? (
              <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
                {d.evidence.ports ? `port ${d.evidence.ports}` : ''}
                {d.evidence.ports && d.evidence.urlHost ? ' · ' : ''}
                {d.evidence.urlHost ? `host ${d.evidence.urlHost} (URL metadata)` : ''}
              </div>
            ) : null}
            {d.evidence.text ? <blockquote className="tl-quote">{d.evidence.text}</blockquote> : null}
          </section>

          {d.tableRows.length ? (
            <section className="tl-drawer__section" aria-labelledby="tl-drawer-tables">
              <h3 className="tl-section-title" id="tl-drawer-tables">Table references · {d.tableRows.length}</h3>
              {d.tableRows.map((r) => (
                <div key={r.key} style={{ fontSize: 12, marginBottom: 6 }}>
                  <div style={{ color: '#e2e8f0' }}>{r.label}</div>
                  {r.description ? <div style={{ color: '#94a3b8' }}>{r.description}</div> : null}
                </div>
              ))}
            </section>
          ) : null}

          <section className="tl-drawer__section" aria-labelledby="tl-drawer-occurrences">
            <h3 className="tl-section-title" id="tl-drawer-occurrences">Occurrences · {d.evidence.occurrenceCount}</h3>
            {d.occurrences.length ? d.occurrences.map((o) => (
              <div key={o.key} className="tl-occurrence">
                <div className="tl-occurrence__where">{o.label}</div>
                {/* Occurrence text is quoted source content: inert, never linkified. */}
                {o.text ? <blockquote className="tl-quote">{o.text}</blockquote> : null}
              </div>
            )) : (
              <div style={{ fontSize: 12, color: '#64748b' }}>No occurrence context recorded.</div>
            )}
          </section>
        </div>

        {hasNav ? (
          <div className="tl-drawer__foot">
            <div className="tl-drawer__nav" role="group" aria-label="Navigate indicators">
              <button
                type="button"
                style={compactBtn}
                disabled={position.prevId == null}
                onClick={() => onNavigate?.(position.prevId)}
                aria-label="Previous indicator"
              >
                ‹ Previous
              </button>
              <span className="tl-drawer__counter" aria-live="polite">{position.index} / {position.total}</span>
              <button
                type="button"
                style={compactBtn}
                disabled={position.nextId == null}
                onClick={() => onNavigate?.(position.nextId)}
                aria-label="Next indicator"
              >
                Next ›
              </button>
            </div>
          </div>
        ) : null}
      </aside>
    </>,
    document.body
  );
}
