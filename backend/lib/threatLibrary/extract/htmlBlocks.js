/**
 * Shared HTML → ordered text blocks (headings, paragraphs, lists, tables).
 */

export function stripTags(s) {
  return String(s || '').replace(/<[^>]+>/g, ' ');
}

export function decodeEntities(s) {
  return String(s || '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

export function cleanNoiseHtml(html) {
  return String(html || '')
    .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<svg\b[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<nav\b[\s\S]*?<\/nav>/gi, ' ')
    .replace(/<footer\b[\s\S]*?<\/footer>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');
}

/**
 * Extract ordered blocks from an HTML fragment.
 * @param {string} fragmentHtml
 * @param {{ blockId: (prefix: string, index: number) => string }} ids
 */
export function extractBlocksFromHtmlFragment(fragmentHtml, ids) {
  const body = cleanNoiseHtml(fragmentHtml);
  const blocks = [];
  let idx = 1;
  const push = (type, text, section = null) => {
    const t = decodeEntities(text).replace(/\s+/g, ' ').trim();
    if (!t) return;
    // Drop ultra-short UI crumbs
    if (t.length < 2) return;
    blocks.push({
      id: ids.blockId('b', idx++),
      type,
      text: t,
      page: null,
      section
    });
  };

  const headingRe = /<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi;
  const paragraphRe = /<(p|li|pre|code|td|th|caption|blockquote|section)\b[^>]*>([\s\S]*?)<\/\1>/gi;
  /** @type {{ pos: number, type: string, text: string }[]} */
  const found = [];
  let m;
  while ((m = headingRe.exec(body)) !== null) {
    found.push({ pos: m.index, type: 'heading', text: stripTags(m[2]) });
  }
  while ((m = paragraphRe.exec(body)) !== null) {
    const tag = m[1].toLowerCase();
    let type = 'paragraph';
    if (tag === 'li') type = 'list';
    else if (tag === 'pre' || tag === 'code') type = 'code';
    else if (tag === 'td' || tag === 'th') type = 'table';
    else if (tag === 'caption') type = 'caption';
    else if (tag === 'section') type = 'paragraph';
    found.push({ pos: m.index, type, text: stripTags(m[2]) });
  }
  found.sort((a, b) => a.pos - b.pos);

  let currentSection = null;
  for (const item of found) {
    if (item.type === 'heading') currentSection = item.text.slice(0, 200);
    push(item.type, item.text, currentSection);
  }

  if (blocks.length === 0) {
    const fallback = decodeEntities(stripTags(body)).replace(/\s+/g, ' ').trim();
    if (fallback) {
      for (let i = 0; i < fallback.length; i += 800) {
        push('paragraph', fallback.slice(i, i + 800));
      }
    }
  }

  return blocks;
}

/**
 * Pick best title from HTML meta / tags.
 * @param {string} html
 * @param {string} [hint]
 */
export function extractHtmlTitle(html, hint = '') {
  const raw = String(html || '');
  if (hint) return decodeEntities(stripTags(hint)).trim();
  const og =
    raw.match(/property=["']og:title["'][^>]*content=["']([^"']+)["']/i)
    || raw.match(/content=["']([^"']+)["'][^>]*property=["']og:title["']/i);
  if (og?.[1]) return decodeEntities(og[1]).trim();
  const tw =
    raw.match(/name=["']twitter:title["'][^>]*content=["']([^"']+)["']/i)
    || raw.match(/content=["']([^"']+)["'][^>]*name=["']twitter:title["']/i);
  if (tw?.[1]) return decodeEntities(tw[1]).trim();
  const titleMatch = raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (titleMatch) return decodeEntities(stripTags(titleMatch[1])).trim();
  return '';
}

/**
 * @param {string} html
 */
export function extractHtmlLanguage(html) {
  const raw = String(html || '');
  const htmlLang = raw.match(/<html[^>]*\slang=["']?([a-zA-Z-]{2,10})/i);
  if (htmlLang) return htmlLang[1].toLowerCase().slice(0, 16);
  const ogLocale = raw.match(/property=["']og:locale["'][^>]*content=["']([^"']+)["']/i);
  if (ogLocale?.[1]) return String(ogLocale[1]).toLowerCase().replace('_', '-').slice(0, 16);
  return null;
}
