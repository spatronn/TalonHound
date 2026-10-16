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

const AUTHOR_BYLINE_RE =
  /^(?:by\b|view all posts|min read|\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b|january|february|march|april|may|june|july|august|september|october|november|december|\d{1,2}\s+min)/i;

/**
 * Header/byline chrome with no long body paragraphs, tables, or section
 * headings — typical when a card/teaser `<article>` is mistaken for the post.
 * @param {import('../canonicalDocument.js').CanonicalDocument} doc
 * @param {number} chars
 */
function looksLikeBylineChromeOnly(doc, chars) {
  const blocks = doc?.blocks || [];
  if (blocks.length === 0 || chars >= 800) return false;
  if (blocks.some((b) => b.type === 'table')) return false;
  if (blocks.some((b) => b.type === 'heading' && Number(b.level || 0) >= 2)) return false;
  const longBody = blocks.filter((b) => String(b.text || '').replace(/\s+/g, '').length >= 80);
  if (longBody.length >= 2) return false;
  if (longBody.length === 1 && chars >= 400) return false;
  const texts = blocks.map((b) => String(b.text || '').trim()).filter(Boolean);
  const bylineHits = texts.filter((t) => AUTHOR_BYLINE_RE.test(t) || /view all posts/i.test(t)).length;
  // Require repeated byline/read-time chrome so short legitimate advisories are kept.
  if (bylineHits < 2) return false;
  const short = texts.filter((t) => t.length < 80 || AUTHOR_BYLINE_RE.test(t) || /view all posts/i.test(t));
  return short.length >= Math.max(3, Math.ceil(texts.length * 0.7));
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
  if (looksLikeBylineChromeOnly(doc, chars)) {
    reasons.push('byline_chrome_only');
  }

  if (reasons.includes('navigation_boilerplate') || reasons.includes('byline_chrome_only')) {
    return {
      ok: false,
      code: 'document_below_quality_threshold',
      message: reasons.includes('byline_chrome_only')
        ? 'Extracted content looks like page header/byline chrome, not an article body.'
        : 'Extracted content looks like navigation/boilerplate, not an article body.',
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
