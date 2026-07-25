/**
 * Position an overflow menu relative to a trigger, keeping it in the viewport.
 * Used by Backup History row actions (portal menu).
 */
export function computeOverflowMenuPosition({
  trigger,
  menuWidth = 168,
  menuHeight = 132,
  viewportWidth,
  viewportHeight,
  gap = 4,
  pad = 8
}) {
  const vw = Number(viewportWidth);
  const vh = Number(viewportHeight);
  const tw = Number(menuWidth);
  const th = Number(menuHeight);

  let placement = 'bottom';
  let top = trigger.bottom + gap;
  // Prefer right-aligning the menu to the trigger's right edge.
  let left = trigger.right - tw;

  if (top + th > vh - pad) {
    const above = trigger.top - gap - th;
    if (above >= pad) {
      top = above;
      placement = 'top';
    } else {
      top = Math.max(pad, Math.min(top, vh - pad - th));
    }
  }

  if (left < pad) left = pad;
  if (left + tw > vw - pad) left = Math.max(pad, vw - pad - tw);

  return { top, left, placement, width: tw };
}
