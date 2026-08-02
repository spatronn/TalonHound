import React, { useMemo, useState } from 'react';
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors
} from '@dnd-kit/core';
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import {
  applyThreatClassificationReorder,
  isThreatClassificationRowLocked,
  sortThreatClassificationsForDisplay
} from '../../lib/threatClassificationOrder.js';

function DragHandle({ attributes, listeners, disabled, setActivatorNodeRef }) {
  return (
    <button
      type="button"
      ref={setActivatorNodeRef}
      className="tc-drag-handle"
      aria-label={disabled ? 'Row order locked' : 'Drag to reorder'}
      title={disabled ? 'Unknown is always first' : 'Drag to reorder'}
      disabled={disabled}
      {...(disabled ? {} : { ...attributes, ...listeners })}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: 28,
        height: 28,
        padding: 0,
        border: '1px solid #334155',
        borderRadius: 6,
        background: disabled ? 'transparent' : '#0f172a',
        color: disabled ? '#475569' : '#94a3b8',
        cursor: disabled ? 'not-allowed' : 'grab',
        opacity: disabled ? 0.45 : 1
      }}
    >
      <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
        <circle cx="5" cy="4" r="1.3" fill="currentColor" />
        <circle cx="11" cy="4" r="1.3" fill="currentColor" />
        <circle cx="5" cy="8" r="1.3" fill="currentColor" />
        <circle cx="11" cy="8" r="1.3" fill="currentColor" />
        <circle cx="5" cy="12" r="1.3" fill="currentColor" />
        <circle cx="11" cy="12" r="1.3" fill="currentColor" />
      </svg>
    </button>
  );
}

function SortableClassificationRow({
  item,
  ui,
  disabled,
  onEdit,
  onDisable,
  onEnable
}) {
  const locked = isThreatClassificationRowLocked(item);
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging
  } = useSortable({
    id: String(item.id),
    disabled: disabled || locked
  });

  const style = {
    opacity: item.active ? (isDragging ? 0.92 : 1) : 0.62,
    transform: CSS.Transform.toString(transform),
    transition,
    background: isDragging ? 'rgba(30, 41, 59, 0.95)' : undefined,
    position: 'relative',
    zIndex: isDragging ? 2 : undefined
  };

  return (
    <tr ref={setNodeRef} style={style} data-classification-id={item.id} data-locked={locked ? 'true' : 'false'}>
      <td className="tc-col-handle" style={ui.td}>
        <DragHandle
          attributes={attributes}
          listeners={listeners}
          disabled={disabled || locked}
          setActivatorNodeRef={setActivatorNodeRef}
        />
      </td>
      <td className="tc-col-classification" style={ui.td}>
        <div style={{ fontWeight: 600 }}>{item.name}</div>
        <code style={{ fontSize: 11, color: '#64748b' }}>{item.slug}</code>
      </td>
      <td className="tc-col-description tc-description-cell" style={ui.td} title={item.description || undefined}>
        {item.description || '—'}
      </td>
      <td className="tc-col-status" style={ui.td}>
        <span
          style={{
            display: 'inline-block',
            padding: '2px 8px',
            borderRadius: 999,
            fontSize: 11,
            fontWeight: 600,
            background: item.active ? 'rgba(22, 101, 52, 0.35)' : 'rgba(71, 85, 105, 0.35)',
            color: item.active ? '#86efac' : '#94a3b8',
            border: `1px solid ${item.active ? '#166534' : '#475569'}`
          }}
        >
          {item.active ? 'Active' : 'Inactive'}
        </span>
      </td>
      <td className="tc-col-builtin" style={ui.td}>{item.system_default ? 'Yes' : '—'}</td>
      <td className="tc-col-actions tc-actions-cell" style={ui.td}>
        <div className="tc-action-buttons">
          <button type="button" style={ui.btn} onClick={() => onEdit(item)} disabled={disabled}>Edit</button>
          {item.slug === 'unknown' ? null : item.active ? (
            <button
              type="button"
              style={{ ...ui.btnDanger }}
              onClick={() => onDisable(item)}
              disabled={disabled}
            >
              Disable
            </button>
          ) : (
            <button type="button" style={ui.btn} onClick={() => onEnable(item)} disabled={disabled}>
              Enable
            </button>
          )}
        </div>
      </td>
    </tr>
  );
}

/**
 * @param {{
 *   items: Array<object>,
 *   ui: object,
 *   loading?: boolean,
 *   reordering?: boolean,
 *   onReorder: (nextItems: Array<object>, activeId: string, overId: string) => void | Promise<void>,
 *   onEdit: (item: object) => void,
 *   onDisable: (item: object) => void | Promise<void>,
 *   onEnable: (item: object) => void | Promise<void>,
 *   emptyState?: React.ReactNode
 * }} props
 */
export function ThreatClassificationSortableTable({
  items,
  ui,
  loading = false,
  reordering = false,
  onReorder,
  onEdit,
  onDisable,
  onEnable,
  emptyState = null
}) {
  const [activeId, setActiveId] = useState(null);
  const sortedItems = useMemo(() => sortThreatClassificationsForDisplay(items), [items]);
  const sortableIds = useMemo(
    () => sortedItems.map((item) => String(item.id)),
    [sortedItems]
  );

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  );

  const disabled = Boolean(loading || reordering);

  function handleDragStart(event) {
    setActiveId(String(event.active.id));
  }

  async function handleDragEnd(event) {
    const { active, over } = event;
    setActiveId(null);
    if (!over || String(active.id) === String(over.id) || disabled) return;
    const next = applyThreatClassificationReorder(sortedItems, String(active.id), String(over.id));
    const changed = next.map((x) => x.id).join('|') !== sortedItems.map((x) => x.id).join('|');
    if (!changed) return;
    await onReorder(next, String(active.id), String(over.id));
  }

  function handleDragCancel() {
    setActiveId(null);
  }

  return (
    <div style={{ marginTop: 16, overflowX: 'auto', maxWidth: '100%' }}>
      <DndContext
        sensors={sensors}
        collisionDetection={closestCenter}
        onDragStart={handleDragStart}
        onDragEnd={(event) => { handleDragEnd(event).catch(() => {}); }}
        onDragCancel={handleDragCancel}
      >
        <table className="ioc-table threat-classifications-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th className="tc-col-handle" style={ui.th} aria-label="Reorder">
                <span className="sr-only">Reorder</span>
              </th>
              <th className="tc-col-classification" style={ui.th}>Classification</th>
              <th className="tc-col-description" style={ui.th}>Description</th>
              <th className="tc-col-status" style={ui.th}>Status</th>
              <th className="tc-col-builtin" style={ui.th} title="Platform-managed classification">Built-in</th>
              <th className="tc-col-actions" style={ui.th}>Actions</th>
            </tr>
          </thead>
          <tbody>
            <SortableContext items={sortableIds} strategy={verticalListSortingStrategy}>
              {loading ? (
                <tr><td colSpan={6} style={ui.td}>Loading…</td></tr>
              ) : !sortedItems.length ? (
                <tr><td colSpan={6} style={{ ...ui.td, padding: 0 }}>{emptyState || 'No classifications found.'}</td></tr>
              ) : sortedItems.map((item) => (
                <SortableClassificationRow
                  key={item.id}
                  item={item}
                  ui={ui}
                  disabled={disabled}
                  onEdit={onEdit}
                  onDisable={onDisable}
                  onEnable={onEnable}
                />
              ))}
            </SortableContext>
          </tbody>
        </table>
      </DndContext>
      {reordering ? (
        <div style={{ marginTop: 8, color: '#94a3b8', fontSize: 13 }} aria-live="polite">
          Saving order…
        </div>
      ) : null}
      {activeId ? <span className="sr-only" aria-live="polite">Reordering classification</span> : null}
    </div>
  );
}
