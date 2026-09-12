/**
 * SSRF-safe URL fetch + layered HTML → canonical document for Threat Library.
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
import { extractCanonicalDocumentFromHtml, extractGenericArticleDocument } from './extract/extractHtml.js';
import { assessDocumentQuality } from './extract/quality.js';

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
 * HTML → canonical document (layered extraction).
 * Kept as a named export for unit tests / callers.
 * @param {string} html
 * @param {{ url?: string, titleHint?: string, finalUrl?: string, httpStatus?: number }} [meta]
 */
export function htmlToCanonicalDocument(html, meta = {}) {
  const extracted = extractCanonicalDocumentFromHtml(html, {
    url: meta.url,
    finalUrl: meta.finalUrl || meta.url,
    titleHint: meta.titleHint,
    httpStatus: meta.httpStatus
  });
  if (extracted.ok && extracted.document) return extracted.document;
  // For callers that only want a best-effort document object (tests may check empty),
  // return the partial document or a generic pass.
  if (extracted.document) return extracted.document;
  return extractGenericArticleDocument(html, meta);
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
  const bodyText = result.bodyText || '';
  const finalUrl = result.finalUrl || policy.url;
  const fetchMeta = {
    url: policy.url,
    final_url: finalUrl,
    http_status: result.httpStatus ?? null,
    content_type: contentType || null,
    fetched_bytes: result.fetchedBytes ?? bodyText.length,
    fetch_ok: result.ok !== false
  };

  if (contentType && !isAllowedUrlContentType(contentType) && !String(contentType).includes('text/')) {
    const err = new Error(`Unsupported content type: ${String(contentType).split(';')[0]}`);
    err.code = 'unsupported_content_type';
    err.fetchMeta = fetchMeta;
    throw err;
  }

  const ct = String(contentType).toLowerCase();
  if (ct.includes('application/pdf') || bodyText.startsWith('%PDF')) {
    const err = new Error('URL resolved to a PDF; upload the PDF via the PDF import tab instead');
    err.code = 'pdf_via_url_unsupported';
    err.fetchMeta = fetchMeta;
    throw err;
  }

  // Prefer classifying HTTP failures after we can inspect body (captcha pages are often 200).
  if (result.ok === false && (result.httpStatus === 401 || result.httpStatus === 403)) {
    const err = new Error(`Source returned HTTP ${result.httpStatus}; article content is not accessible.`);
    err.code = 'source_access_denied';
    err.fetchMeta = fetchMeta;
    throw err;
  }

  let document;
  /** @type {string[]} */
  let extractionPath = [];
  let extractionAdapter = null;

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
      meta: { source_url: policy.url, extractor: 'threat_library_text_v1', adapter: 'text_plain' }
    });
    extractionPath = ['text_plain'];
    extractionAdapter = 'text_plain';
    const quality = assessDocumentQuality(document);
    if (!quality.ok) {
      const err = new Error(quality.message);
      err.code = quality.code || 'document_empty_after_extraction';
      err.fetchMeta = fetchMeta;
      err.extraction = { path: extractionPath, adapter: extractionAdapter, quality };
      throw err;
    }
  } else {
    const extracted = extractCanonicalDocumentFromHtml(bodyText, {
      url: policy.url,
      finalUrl,
      httpStatus: result.httpStatus
    });
    extractionPath = extracted.path || [];
    extractionAdapter = extracted.document?.meta?.adapter || null;

    if (!extracted.ok) {
      const err = new Error(extracted.message || 'Document extraction failed');
      // Map classic empty extraction to legacy empty_document for existing UI/filters.
      err.code = extracted.code === 'document_empty_after_extraction'
        ? 'empty_document'
        : (extracted.code || 'empty_document');
      err.fetchMeta = fetchMeta;
      err.extraction = {
        path: extractionPath,
        adapter: extractionAdapter,
        classification: extracted.classification || null,
        quality: extracted.quality || null
      };
      throw err;
    }
    document = extracted.document;
  }

  if (isEffectivelyEmptyDocument(document)) {
    const err = new Error('Fetched page had no extractable article content');
    err.code = 'empty_document';
    err.fetchMeta = fetchMeta;
    err.extraction = { path: extractionPath, adapter: extractionAdapter };
    throw err;
  }

  if (result.ok === false) {
    const err = new Error(`Upstream fetch returned HTTP ${result.httpStatus || 'error'}`);
    err.code = 'fetch_http_error';
    err.fetchMeta = fetchMeta;
    throw err;
  }

  return {
    url: policy.url,
    finalUrl,
    fetchedBytes: result.fetchedBytes ?? bodyText.length,
    contentType: contentType || 'text/html',
    httpStatus: result.httpStatus ?? null,
    document,
    extraction: {
      path: extractionPath,
      adapter: document.meta?.adapter || extractionAdapter,
      block_count: document.blocks?.length || 0,
      meaningful_chars: assessDocumentQuality(document).chars
    }
  };
}
