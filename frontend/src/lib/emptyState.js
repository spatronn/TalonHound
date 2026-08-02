/**
 * Permission-aware empty state helpers.
 */

/**
 * @param {{ title: string, description?: string, ctaLabel?: string, canWrite?: boolean }} opts
 */
export function buildEmptyStateModel({
  title,
  description = '',
  ctaLabel = '',
  canWrite = false
} = {}) {
  return {
    title: String(title || 'Nothing here yet'),
    description: String(description || ''),
    showCta: Boolean(canWrite && ctaLabel),
    ctaLabel: String(ctaLabel || '')
  };
}
