import React, { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { IocDetailIcons } from '../iocDetails/IocDetailIcons.jsx';
import { computeOverflowMenuPosition } from '../../lib/backupMenuPosition.js';
import { IOC_COPY_FEEDBACK_MS, copyTextToClipboard } from '../../lib/iocCopyFeedback.js';
import { badgeStyle } from './styles.js';

const TONE_COLORS = Object.freeze({
  danger: { border: '#7f1d1d', bg: 'rgba(220,38,38,0.14)', color: '#fca5a5' },
  warning: { border: '#92400e', bg: 'rgba(217,119,6,0.14)', color: '#fcd34d' },
  success: { border: '#166534', bg: 'rgba(22,163,74,0.14)', color: '#86efac' },
  info: { border: '#1d4ed8', bg: 'rgba(37,99,235,0.14)', color: '#93c5fd' },
  neutral: { border: '#334155', bg: '#1e293b', color: '#cbd5e1' },
  muted: { border: '#1e293b', bg: 'transparent', color: '#64748b' }
});

/** Subtle status chip. `tone: 'none'` renders the text plain (no chip). */
export function ToneBadge({ tone = 'neutral', children, title }) {
  if (tone === 'none' || children == null || children === '' || children === '—') {
    return <span style={{ color: '#64748b' }} title={title}>{children == null || children === '' ? '—' : children}</span>;
  }
  const colors = TONE_COLORS[tone] || TONE_COLORS.neutral;
  return <span style={{ ...badgeStyle(colors), fontWeight: 600, padding: '2px 7px' }} title={title}>{children}</span>;
}

/**
 * Copy-to-clipboard icon button (same clipboard helper as the IOC Details
 * header). Feedback only on a confirmed write.
 */
export function CopyValueButton({ value, label = 'Copy value', size = 13, className = '' }) {
  const [copied, setCopied] = useState(false);
  const [epoch, setEpoch] = useState(0);

  useEffect(() => {
    if (!copied) return undefined;
    const id = globalThis.setTimeout(() => setCopied(false), IOC_COPY_FEEDBACK_MS);
    return () => globalThis.clearTimeout(id);
  }, [copied, epoch]);

  async function onCopy(e) {
    e.stopPropagation();
    const result = await copyTextToClipboard(value);
    if (!result.ok) {
      setCopied(false);
      return;
    }
    setCopied(true);
    setEpoch((n) => n + 1);
  }

  return (
    <button
      type="button"
      className={`tl-icon-btn${copied ? ' is-copied' : ''}${className ? ` ${className}` : ''}`}
      onClick={onCopy}
      aria-label={copied ? 'Copied' : label}
      title={copied ? 'Copied' : label}
    >
      {copied ? <IocDetailIcons.check size={size} /> : <IocDetailIcons.copy size={size} />}
    </button>
  );
}

/** Text variant of the copy control ("Copy URL" / "Copied"), same helper. */
export function CopyUrlButton({ value, label = 'Copy URL' }) {
  const [copied, setCopied] = useState(false);
  const [epoch, setEpoch] = useState(0);

  useEffect(() => {
    if (!copied) return undefined;
    const id = globalThis.setTimeout(() => setCopied(false), IOC_COPY_FEEDBACK_MS);
    return () => globalThis.clearTimeout(id);
  }, [copied, epoch]);

  async function onCopy() {
    const result = await copyTextToClipboard(value);
    if (!result.ok) {
      setCopied(false);
      return;
    }
    setCopied(true);
    setEpoch((n) => n + 1);
  }

  return (
    <button
      type="button"
      className={`tl-ghost-btn${copied ? ' is-copied' : ''}`}
      onClick={onCopy}
      aria-label={copied ? 'Copied' : label}
      title={copied ? 'Copied' : label}
    >
      {copied ? <IocDetailIcons.check size={13} /> : <IocDetailIcons.copy size={13} />}
      {copied ? 'Copied' : label}
    </button>
  );
}

/** Underline tab bar (same visual as the IOC Details section tabs). */
export function ReportTabBar({ tabs, active, onChange, ariaLabel = 'Report sections' }) {
  return (
    <div className="tl-tabbar" role="tablist" aria-label={ariaLabel}>
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          id={`tl-tab-${t.id}`}
          aria-selected={active === t.id}
          aria-controls={`tl-panel-${t.id}`}
          className="tl-tabbar__tab"
          onClick={() => onChange(t.id)}
        >
          {t.label}
          {t.count != null ? <span className="tl-tabbar__count" data-testid={`tab-count-${t.id}`}>{t.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

/**
 * Overflow ("...") menu for secondary / destructive report actions. Mirrors
 * the IOC Details source-actions menu: portal, viewport-aware placement,
 * Escape / outside click to close, shared .br-menu-item styling.
 */
export function ReportActionsMenu({ items, disabled, label = 'More report actions' }) {
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState({ top: 0, left: 0, width: 200 });
  const triggerRef = useRef(null);
  const menuRef = useRef(null);
  const menuId = useId();

  const updatePosition = useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const menuRect = menuRef.current?.getBoundingClientRect();
    const pos = computeOverflowMenuPosition({
      trigger: rect,
      menuWidth: menuRect?.width || 200,
      menuHeight: menuRect?.height || 120,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight
    });
    setCoords({ top: pos.top, left: pos.left, width: pos.width });
  }, []);

  useLayoutEffect(() => {
    if (!open) return undefined;
    updatePosition();
    const onReposition = () => updatePosition();
    window.addEventListener('resize', onReposition);
    window.addEventListener('scroll', onReposition, true);
    return () => {
      window.removeEventListener('resize', onReposition);
      window.removeEventListener('scroll', onReposition, true);
    };
  }, [open, updatePosition]);

  useEffect(() => {
    if (!open) return undefined;
    function onDoc(e) {
      if (triggerRef.current?.contains(e.target)) return;
      if (menuRef.current?.contains(e.target)) return;
      setOpen(false);
    }
    function onKey(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const id = requestAnimationFrame(() => {
      menuRef.current?.querySelector('[role="menuitem"]:not([disabled])')?.focus();
    });
    return () => cancelAnimationFrame(id);
  }, [open]);

  const visible = (items || []).filter(Boolean);
  if (!visible.length) return null;

  return (
    <div style={{ position: 'relative', display: 'inline-flex' }}>
      <button
        type="button"
        ref={triggerRef}
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
        style={{
          width: 36,
          height: 36,
          minHeight: 36,
          padding: 0,
          borderRadius: 8,
          border: '1px solid #475569',
          background: '#1f2937',
          color: '#cbd5e1',
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}
      >
        <IocDetailIcons.more size={16} />
      </button>
      {open && typeof document !== 'undefined'
        ? createPortal(
          <div
            id={menuId}
            ref={menuRef}
            role="menu"
            style={{
              position: 'fixed',
              fontFamily: 'sans-serif',
              top: coords.top,
              left: coords.left,
              minWidth: coords.width,
              zIndex: 1050,
              border: '1px solid #334155',
              borderRadius: 8,
              background: '#0b1220',
              color: '#e2e8f0',
              padding: 4,
              boxShadow: '0 12px 28px rgba(0,0,0,0.45)'
            }}
          >
            {visible.map((item) => (
              <button
                key={item.id}
                type="button"
                role="menuitem"
                className={`br-menu-item${item.danger ? ' ioc-source-menu-item--danger' : ''}`}
                disabled={Boolean(item.disabled)}
                onClick={() => {
                  setOpen(false);
                  triggerRef.current?.focus();
                  item.onSelect?.();
                }}
              >
                {item.label}
              </button>
            ))}
          </div>,
          document.body
        )
        : null}
    </div>
  );
}

/** Uppercase section label used across Overview / Source / drawer. */
export function SectionTitle({ children, right }) {
  if (!right) return <h3 className="tl-section-title">{children}</h3>;
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, marginBottom: 8 }}>
      <h3 className="tl-section-title" style={{ margin: 0 }}>{children}</h3>
      {right}
    </div>
  );
}

/** Compact label/value list; callers pass only present values. */
export function DetailList({ items, testId, className = '' }) {
  if (!items?.length) return null;
  return (
    <dl className={`tl-dl${className ? ` ${className}` : ''}`} data-testid={testId}>
      {items.map((it) => (
        <React.Fragment key={it.key}>
          <dt>{it.label}</dt>
          <dd className={it.mono ? 'is-mono' : undefined} title={it.title || undefined}>{it.value}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}
