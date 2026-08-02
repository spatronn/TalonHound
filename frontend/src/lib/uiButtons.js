/**
 * Shared button class helpers for the TalonHound console.
 *
 * Visual language (dark, corporate):
 * - secondary / warning / success → neutral family (same look)
 * - primary → blue accent for the single main CTA only
 * - danger → subtle (text/border); use dangerSolid only in destructive modal footers
 */

export const BTN_BASE = 'th-btn';

export const BTN_VARIANTS = Object.freeze({
  primary: 'th-btn--primary',
  secondary: 'th-btn--secondary',
  danger: 'th-btn--danger',
  dangerSolid: 'th-btn--danger-solid',
  ghost: 'th-btn--ghost',
  icon: 'th-btn--icon',
  // Aliases kept for call-site compatibility; CSS maps them onto the neutral family.
  warning: 'th-btn--warning',
  success: 'th-btn--success'
});

export const BTN_SIZES = Object.freeze({
  sm: 'th-btn--sm',
  md: 'th-btn--md'
});

/**
 * @param {{
 *   variant?: keyof typeof BTN_VARIANTS,
 *   size?: keyof typeof BTN_SIZES,
 *   className?: string
 * }} [opts]
 * @returns {string}
 */
export function buttonClassName({ variant = 'secondary', size, className = '' } = {}) {
  const parts = [BTN_BASE];
  const variantClass = BTN_VARIANTS[variant];
  if (variantClass) parts.push(variantClass);
  const sizeClass = size ? BTN_SIZES[size] : null;
  if (sizeClass) parts.push(sizeClass);
  const extra = String(className || '').trim();
  if (extra) parts.push(extra);
  return parts.join(' ');
}

/** Resolve modal confirm button variant from AppConfirm tone. */
export function confirmButtonVariant(tone) {
  if (tone === 'danger') return 'dangerSolid';
  if (tone === 'warning') return 'secondary';
  return 'primary';
}
