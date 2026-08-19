import React, { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { IocDetailIcons } from './IocDetailIcons.jsx';
import { formatIocDetailDateTime, listSourceMembershipActions } from '../../lib/iocDetailTimestamps.js';
import { ACTIVE_SOURCES_COLUMNS, buildIocSummaryStripItems } from '../../lib/iocOverviewLayout.js';
import { computeOverflowMenuPosition } from '../../lib/backupMenuPosition.js';
import './activeSourcesMenu.css';

const SOURCE_MENU_EVENT = 'ioc-source-actions-menu';

function SourceActionsMenu({
  src,
  isAdmin,
  actionLoading,
  onAction
}) {
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState({ top: 0, left: 0, width: 180 });
  const triggerRef = useRef(null);
  const menuRef = useRef(null);
  const rootRef = useRef(null);
  const menuId = useId();
  const actions = listSourceMembershipActions(src);
  const canShow = isAdmin && src.source_type === 'feed' && src.actions_enabled;
  const menuKey = String(src.membership_id || src.id || '');

  const updatePosition = useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const menuRect = menuRef.current?.getBoundingClientRect();
    const pos = computeOverflowMenuPosition({
      trigger: rect,
      menuWidth: menuRect?.width || 180,
      menuHeight: menuRect?.height || 168,
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
      const t = e.target;
      if (triggerRef.current?.contains(t)) return;
      if (menuRef.current?.contains(t)) return;
      setOpen(false);
    }

    function onKey(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
        triggerRef.current?.focus();
      }
    }

    function onOtherMenu(e) {
      if (String(e.detail) !== menuKey) setOpen(false);
    }

    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    window.addEventListener(SOURCE_MENU_EVENT, onOtherMenu);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener(SOURCE_MENU_EVENT, onOtherMenu);
    };
  }, [open, menuKey]);

  useEffect(() => {
    if (!open) return undefined;
    const id = requestAnimationFrame(() => {
      const first = menuRef.current?.querySelector('[role="menuitem"]:not([disabled])')
        || menuRef.current?.querySelector('[role="menuitem"]');
      first?.focus();
    });
    return () => cancelAnimationFrame(id);
  }, [open]);

  if (!canShow) return '—';

  function toggleMenu() {
    setOpen((wasOpen) => {
      const next = !wasOpen;
      if (next) {
        window.dispatchEvent(new CustomEvent(SOURCE_MENU_EVENT, { detail: menuKey }));
      }
      return next;
    });
  }

  function pick(actionType) {
    setOpen(false);
    triggerRef.current?.focus();
    onAction(actionType, src.membership_id);
  }

  return (
    <div ref={rootRef} style={{ position: 'relative', display: 'inline-flex' }}>
      <button
        type="button"
        ref={triggerRef}
        aria-label={`Actions for ${src.name || 'source'}`}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        disabled={actionLoading}
        onClick={toggleMenu}
        style={{
          width: 30,
          height: 30,
          borderRadius: 8,
          border: '1px solid #475569',
          background: '#0f172a',
          color: '#cbd5e1',
          cursor: actionLoading ? 'wait' : 'pointer',
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}
      >
        <IocDetailIcons.more size={14} />
      </button>
      {open && typeof document !== 'undefined'
        ? createPortal(
          <div
            id={menuId}
            ref={menuRef}
            role="menu"
            style={{
              position: 'fixed',
              top: coords.top,
              left: coords.left,
              minWidth: coords.width,
              zIndex: 10050,
              border: '1px solid #334155',
              borderRadius: 8,
              background: '#0b1220',
              color: '#e2e8f0',
              padding: 4,
              boxShadow: '0 12px 28px rgba(0,0,0,0.45)'
            }}
          >
            {actions.map((action) => (
              <button
                key={action.type}
                type="button"
                role="menuitem"
                className={`br-menu-item${action.danger ? ' ioc-source-menu-item--danger' : ''}`}
                disabled={!action.enabled || actionLoading}
                onClick={() => {
                  if (!action.enabled) return;
                  pick(action.type);
                }}
              >
                {action.label}
              </button>
            ))}
          </div>,
          document.body
        )
        : null}
    </div>
  );
}

export function ActiveSourcesTable({
  activeSources,
  sourceColorIndex,
  SourceBadge,
  iocSourceTypeLabel,
  iocSourceStatusBadge,
  isAdmin,
  actionLoading,
  onMembershipAction
}) {
  return (
    <div style={{ padding: 14, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
      <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>Active Sources</div>
      {activeSources.length ? (
        <div style={{ overflowX: 'auto' }}>
          <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 12, color: '#e2e8f0', minWidth: 640 }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                {ACTIVE_SOURCES_COLUMNS.map((label) => (
                  <th key={label}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {activeSources.map((src) => (
                <tr key={src.id} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td><SourceBadge index={sourceColorIndex} label={src.name} /></td>
                  <td>{iocSourceTypeLabel(src)}</td>
                  <td>{iocSourceStatusBadge(src)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{src.source_type === 'feed' ? formatIocDetailDateTime(src.policy_expires_at) : '—'}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatIocDetailDateTime(src.expires_at)}</td>
                  <td>{src.source_type === 'feed' ? (src.override_enabled ? 'Yes' : 'No') : '—'}</td>
                  <td>
                    <SourceActionsMenu
                      src={src}
                      isAdmin={isAdmin}
                      actionLoading={actionLoading}
                      onAction={onMembershipAction}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ fontSize: 13, color: '#94a3b8' }}>No active sources.</div>
      )}
    </div>
  );
}

export function IocSummaryStrip({ summary }) {
  const items = buildIocSummaryStripItems(summary);
  if (!items.length) return null;

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
      gap: 10,
      padding: '10px 12px',
      border: '1px solid #334155',
      borderRadius: 8,
      background: '#0f172a'
    }}>
      {items.map((item) => (
        <div key={item.label} style={{ minWidth: 0 }}>
          <div style={{ fontSize: 11, color: '#64748b', marginBottom: 3 }}>{item.label}</div>
          <div style={{ fontSize: 13, fontWeight: 600, color: '#cbd5e1', overflowWrap: 'anywhere' }}>{item.value}</div>
        </div>
      ))}
    </div>
  );
}
