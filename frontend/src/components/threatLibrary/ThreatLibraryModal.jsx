import React, { useEffect, useRef } from 'react';
import { ui } from './styles.js';

/**
 * Lightweight modal matching AppShell dark panels (no dependency on main.jsx ModalOverlay).
 */
export default function ThreatLibraryModal({
  open,
  title,
  description,
  onClose,
  children,
  footer,
  width = 640,
  closeDisabled = false
}) {
  const panelRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    function onKeyDown(e) {
      if (e.key === 'Escape' && !closeDisabled) {
        e.stopPropagation();
        onClose?.();
      }
    }
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [open, closeDisabled, onClose]);

  useEffect(() => {
    if (open && panelRef.current) {
      try { panelRef.current.focus({ preventScroll: true }); } catch { /* ignore */ }
    }
  }, [open]);

  if (!open) return null;

  return (
    <div
      role="presentation"
      onClick={() => { if (!closeDisabled) onClose?.(); }}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1100,
        background: 'rgba(2, 6, 23, 0.72)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={{
          width,
          maxWidth: '96vw',
          maxHeight: '90vh',
          overflowY: 'auto',
          background: 'linear-gradient(180deg, #111827 0%, #0f172a 100%)',
          borderRadius: 12,
          padding: 20,
          border: '1px solid #334155',
          color: '#e2e8f0',
          boxShadow: '0 24px 60px rgba(2,6,23,0.55)',
          outline: 'none'
        }}
      >
        {title ? <h3 style={{ margin: '0 0 6px', fontSize: 18, fontWeight: 700, color: '#f1f5f9' }}>{title}</h3> : null}
        {description ? <p style={{ margin: '0 0 14px', fontSize: 13, color: '#94a3b8', lineHeight: 1.45 }}>{description}</p> : null}
        <div>{children}</div>
        {footer ? (
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16, flexWrap: 'wrap' }}>
            {footer}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function ModalCancelButton({ onClick, disabled, label = 'Cancel' }) {
  return (
    <button type="button" style={ui.btn} onClick={onClick} disabled={disabled}>
      {label}
    </button>
  );
}
