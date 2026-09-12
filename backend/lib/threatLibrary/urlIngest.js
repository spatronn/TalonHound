/**
 * SSRF-safe URL fetch + HTML → canonical document for Threat Library.
 * Reuses custom threat feed SSRF policy and DNS pinning.
 */

import { fetchFeedUrl } from '../customThreatFeedFetch.js';
import { validateFeedUrlPolicy } from '../customThreatFeedSsrf.js';
import {
  URL_FETCH_MAX_BYTES,
  URL_FETCH_TIMEOUT_MS,
  URL_ALLOWED_CONTENT_TYPES
} from './constants.js';
import {
  createCanonicalDocument,
  blockId,
  isEffectivelyEmptyDocument
} from './canonicalDocument.js';

/**
 * @param {string} url
 */
export function validateThreatLibraryUrl(url) {
  const sync = validateFeedUrlPolicy(url);
  if (!sync.ok) return sync;
  if (sync.parsed.username || sync.parsed.password) {
    return { ok: false, error: 'URLs with embedded credentials are not allowed' };
  }
  return sync;
}

/**
 * @param {string} contentTypeHeader
 */
export function isAllowedUrlContentType(contentTypeHeader) {
  const ct = String(contentTypeHeader || '').split(';')[0].trim().toLowerCase();
  if (!ct) return false;
  return URL_ALLOWED_CONTENT_TYPES.some((allowed) => ct === allowed || ct.endsWith(`+${allowed.split('/')[1]}`));
}

/**
 * Strip scripts/styles and extract readable blocks from HTML.
 * Intentionally vendor-agnostic (not tied to a specific blog layout).
 * @param {string} html
 * @param {{ url?: string, titleHint?: string }} [meta]
 */
export function htmlToCanonicalDocument(html, meta = {}) {
  const raw = String(html || '');
  let title = meta.titleHint || '';
  const titleMatch = raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!title && titleMatch) {
    title = decodeEntities(stripTags(titleMatch[1])).trim();
  }

  // Prefer <article> / <main> when present
  let body = raw;
  const articleMatch = raw.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i);
  const mainMatch = raw.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i);
  if (articleMatch) body = articleMatch[1];
  else if (mainMatch) body = mainMatch[1];
  else {
    const bodyMatch = raw.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i);
    if (bodyMatch) body = bodyMatch[1];
  }

  body = body
    .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<nav\b[\s\S]*?<\/nav>/gi, ' ')
    .replace(/<footer\b[\s\S]*?<\/footer>/gi, ' ')
    .replace(/<header\b[\s\S]*?<\/header>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');

  const blocks = [];
  let idx = 1;
  const push = (type, text, section = null) => {
    const t = decodeEntities(text).replace(/\s+/g, ' ').trim();
    if (!t) return;
    blocks.push({
      id: blockId('b', idx++),
      type,
      text: t,
      page: null,
      section
    });
  };

  // Headings
  const headingRe = /<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi;
  const paragraphRe = /<(p|li|pre|code|td|th|caption|blockquote)\b[^>]*>([\s\S]*?)<\/\1>/gi;

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
      // Split into ~800-char paragraphs
      for (let i = 0; i < fallback.length; i += 800) {
        push('paragraph', fallback.slice(i, i + 800));
      }
    }
  }

  const langMatch = raw.match(/<html[^>]*\slang=["']?([a-zA-Z-]{2,10})/i);
  const doc = createCanonicalDocument({
    title: title || 'Untitled',
    language: langMatch ? langMatch[1].toLowerCase().slice(0, 8) : null,
    blocks,
    meta: { source_url: meta.url || null, extractor: 'threat_library_html_v1' }
  });
  return doc;
}

function stripTags(s) {
  return String(s || '').replace(/<[^>]+>/g, ' ');
}

function decodeEntities(s) {
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

/**
 * Fetch URL with SSRF protections and convert to canonical document.
 * @param {string} url
 * @param {{ timeoutMs?: number, maxBytes?: number }} [opts]
 */
export async function ingestUrlToCanonicalDocument(url, opts = {}) {
  const policy = validateThreatLibraryUrl(url);
  if (!policy.ok) {
    const err = new Error(policy.error);
    err.code = 'invalid_url';
    throw err;
  }

  const result = await fetchFeedUrl(policy.url, {
    timeoutMs: opts.timeoutMs || URL_FETCH_TIMEOUT_MS,
    maxBytes: opts.maxBytes || URL_FETCH_MAX_BYTES,
    credentials: null
  });

  const contentType = result.contentType || '';
  // fetchFeedUrl returns bodyText + contentType; reject non-text when present
  if (contentType && !isAllowedUrlContentType(contentType) && !String(contentType).includes('text/')) {
    const err = new Error(`Unsupported content type: ${String(contentType).split(';')[0]}`);
    err.code = 'unsupported_content_type';
    throw err;
  }

  const bodyText = result.bodyText || '';
  const ct = String(contentType).toLowerCase();
  let document;
  if (ct.includes('application/pdf') || bodyText.startsWith('%PDF')) {
    const err = new Error('URL resolved to a PDF; upload the PDF via the PDF import tab instead');
    err.code = 'pdf_via_url_unsupported';
    throw err;
  }
  if (ct.includes('text/plain') && !ct.includes('html')) {
    document = createCanonicalDocument({
      title: policy.parsed.hostname,
      language: null,
      blocks: bodyText.split(/\n{2,}/).filter(Boolean).map((t, i) => ({
        id: blockId('b', i + 1),
        type: 'paragraph',
        text: t.trim(),
        page: null
      })),
      meta: { source_url: policy.url, extractor: 'threat_library_text_v1' }
    });
  } else {
    document = htmlToCanonicalDocument(bodyText, { url: policy.url });
  }

  if (isEffectivelyEmptyDocument(document)) {
    const err = new Error('Fetched page had no extractable article content');
    err.code = 'empty_document';
    throw err;
  }

  if (result.ok === false) {
    const err = new Error(`Upstream fetch returned HTTP ${result.httpStatus || 'error'}`);
    err.code = 'fetch_http_error';
    throw err;
  }

  return {
    url: policy.url,
    finalUrl: result.finalUrl || policy.url,
    fetchedBytes: result.fetchedBytes ?? bodyText.length,
    contentType: contentType || 'text/html',
    document
  };
}
