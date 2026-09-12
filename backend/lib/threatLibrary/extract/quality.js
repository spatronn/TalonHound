/**
 * Canonical document quality gates (CJK-aware).
 * Character counts ignore whitespace — Chinese text without spaces is valid.
 */

const NAV_BOILERPLATE_RE =
  /cookie|privacy policy|accept all|sign in|log in|subscribe|newsletter|all rights reserved|导航|登录|注册|隐私政策|版权所有/i;

/**
 * Meaningful character count (no whitespace). Works for CJK.
 * @param {import('../canonicalDocument.js').CanonicalDocument} doc
 */
export function meaningfulCharCount(doc) {
  return (doc?.blocks || [])
    .map((b) => String(b.text || ''))
    .join('')
    .replace(/\s+/g, '').length;
}

/**
 * @param {import('../canonicalDocument.js').CanonicalDocument} doc
 * @param {{ minChars?: number, minBlocks?: number }} [opts]
 */
export function assessDocumentQuality(doc, opts = {}) {
  const minChars = opts.minChars ?? 40;
  const minBlocks = opts.minBlocks ?? 1;
  const blocks = doc?.blocks || [];
  const chars = meaningfulCharCount(doc);
  const reasons = [];

  if (blocks.length < minBlocks) reasons.push('too_few_blocks');
  if (chars < minChars) reasons.push('below_char_threshold');

  const joined = blocks.map((b) => b.text || '').join(' ');
  const navHits = (joined.match(NAV_BOILERPLATE_RE) || []).length;
  if (chars > 0 && chars < 120 && navHits >= 2 && blocks.length <= 3) {
    reasons.push('navigation_boilerplate');
  }

  if (reasons.includes('navigation_boilerplate')) {
    return {
      ok: false,
      code: 'document_below_quality_threshold',
      message: 'Extracted content looks like navigation/boilerplate, not an article body.',
      chars,
      blocks: blocks.length,
      reasons
    };
  }
  if (reasons.includes('below_char_threshold') || reasons.includes('too_few_blocks')) {
    return {
      ok: false,
      code: 'document_empty_after_extraction',
      message: 'Fetched page had no extractable article content.',
      chars,
      blocks: blocks.length,
      reasons
    };
  }
  return { ok: true, code: null, message: null, chars, blocks: blocks.length, reasons: [] };
}
