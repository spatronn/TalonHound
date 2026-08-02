/**
 * Shared button class helpers for the TalonHound console.
 *
 * Universal visual language: every text button shares one shell.
 * Variant class names remain for call-site compatibility but must
 * resolve to the same CSS appearance (see injected `.th-btn--*` rules).
 * Size is the only visual knob: default vs compact (sm alias) vs icon.
 */

export const BTN_BASE = 'th-btn';

export const BTN_VARIANTS = Object.freeze({
  primary: 'th-btn--primary',
  secondary: 'th-btn--secondary',
  danger: 'th-btn--danger',
  dangerSolid: 'th-btn--danger-solid',
  ghost: 'th-btn--ghost',
  icon: 'th-btn--icon',
  warning: 'th-btn--warning',
  success: 'th-btn--success'
});

export const BTN_SIZES = Object.freeze({
  /** Compact — table row / dense toolbars */
  compact: 'th-btn--compact',
  /** Alias kept for existing call sites */
  sm: 'th-btn--compact',
  /** Explicit default (optional; same as omitting size) */
  md: 'th-btn--md'
});

/**
 * @param {{
 *   variant?: keyof typeof BTN_VARIANTS,
 *   size?: keyof typeof BTN_SIZES,
 *   className?: string,
 *   loading?: boolean
 * }} [opts]
 * @returns {string}
 */
export function buttonClassName({ variant = 'secondary', size, className = '', loading = false } = {}) {
  const parts = [BTN_BASE];
  const variantClass = BTN_VARIANTS[variant];
  if (variantClass) parts.push(variantClass);
  const sizeClass = size ? BTN_SIZES[size] : null;
  if (sizeClass) parts.push(sizeClass);
  if (loading) parts.push('is-loading');
  const extra = String(className || '').trim();
  if (extra) parts.push(extra);
  return parts.join(' ');
}

/**
 * Modal confirm button class mapping — visual variants are neutralized;
 * always returns the default (secondary) shell so labels carry meaning.
 */
export function confirmButtonVariant(_tone) {
  return 'secondary';
}
