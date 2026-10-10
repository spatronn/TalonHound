/**
 * Bounded inspection of an Additional IOC Source (preview only — no candidate writes).
 */

import { pdfToCanonicalDocument } from '../pdfIngest.js';
import { enumerateGitHubIocSource, parseGitHubUrl } from './github.js';
import { fetchIocSourceUrl, publicFetchError, validateIocSourceUrl } from './fetchSafe.js';
import { buildPreviewFromParses, parseIocSourceContent } from './parseContent.js';
import {
  loadOriginalIndicatorKeys,
  loadOtherLinkedKeys,
  replaceSourceFiles,
  transitionSource
} from './store.js';
import { guessTypeFromUrl } from './discover.js';
import { IOC_SOURCE_FETCH } from './constants.js';

/**
 * @param {import('pg').Pool} pool
 * @param {object} source threat_report_ioc_sources row
 * @param {{ fetchImpl?: Function }} [deps]
 */
export async function inspectIocSource(pool, source, deps = {}) {
  await transitionSource(pool, source, 'start_inspect');

  const policy = validateIocSourceUrl(source.canonical_url || source.original_url);
  if (!policy.ok) {
    await transitionSource(pool, source, 'block', {
      error_code: 'blocked_url',
      error_detail: policy.error || 'URL blocked by security policy'
    });
    return { ok: false, code: 'blocked_url' };
  }

  const gh = parseGitHubUrl(source.canonical_url || source.original_url);
  const originalKeys = await loadOriginalIndicatorKeys(pool, source.report_id);
  const otherKeys = await loadOtherLinkedKeys(pool, source.report_id, source.id);

  try {
    if (gh) {
      const listing = await enumerateGitHubIocSource(source.canonical_url || source.original_url, deps);
      if (!listing.ok) {
        const action = listing.code === 'blocked_url' ? 'block' : listing.code?.includes('unsupported') ? 'unsupported' : 'fail_inspect';
        await transitionSource(pool, source, action, {
          error_code: listing.code,
          error_detail: listing.message
        });
        return { ok: false, code: listing.code };
      }

      const parseResults = [];
      const fileRows = [];
      for (const file of listing.files) {
        try {
          const fetched = await fetchIocSourceUrl(file.download_url, {
            fetchImpl: deps.fetchImpl,
            maxBytes: IOC_SOURCE_FETCH.GITHUB_MAX_FILE_BYTES
          });
          const parsed = await parseIocSourceContent({
            body: fetched.body,
            buffer: fetched.buffer,
            contentType: fetched.contentType,
            url: file.download_url,
            path: file.path,
            sourcePublicId: source.public_id,
            pdfToDocument: pdfToCanonicalDocument
          });
          parseResults.push({ ...parsed, path: file.path });
          fileRows.push({
            ...file,
            content_type: fetched.contentType || null,
            parse_status: parsed.ok ? 'ok' : parsed.code === 'unsupported_json_schema' || parsed.code === 'unsupported_format' ? 'unsupported' : 'failed',
            estimated_raw_count: parsed.raw_count ?? 0,
            estimated_unique_count: parsed.unique_count ?? 0,
            type_breakdown: parsed.type_breakdown || {},
            error_detail: parsed.ok ? null : parsed.message || parsed.code
          });
        } catch (err) {
          const pub = publicFetchError(err);
          parseResults.push({ ok: false, code: pub.code, message: pub.message, path: file.path });
          fileRows.push({
            ...file,
            parse_status: 'failed',
            error_detail: pub.message
          });
        }
      }

      await replaceSourceFiles(pool, source.id, fileRows);
      const preview = buildPreviewFromParses(parseResults, {
        originalKeys,
        otherLinkedKeys: otherKeys
      });

      if (!fileRows.some((f) => f.parse_status === 'ok')) {
        await transitionSource(pool, source, 'unsupported', {
          preview,
          source_type: listing.source_type,
          content_hash: listing.content_hash || null,
          repo_revision: listing.repo_revision || null,
          error_code: 'no_parsable_files',
          error_detail: 'No eligible files could be parsed for IOC preview'
        });
        return { ok: false, code: 'no_parsable_files', preview };
      }

      const updated = await transitionSource(pool, source, 'finish_inspect', {
        preview,
        source_type: listing.source_type,
        content_hash: listing.content_hash || null,
        repo_revision: listing.repo_revision || null,
        last_fetched_at: new Date().toISOString()
      });
      return { ok: true, source: updated, preview, files: fileRows };
    }

    // Single URL document
    const fetched = await fetchIocSourceUrl(source.canonical_url || source.original_url, {
      fetchImpl: deps.fetchImpl
    });
    const format = guessTypeFromUrl(fetched.finalUrl) === 'unknown'
      ? null
      : guessTypeFromUrl(fetched.finalUrl);
    const parsed = await parseIocSourceContent({
      body: fetched.body,
      buffer: fetched.buffer,
      contentType: fetched.contentType,
      url: fetched.finalUrl,
      path: null,
      sourcePublicId: source.public_id,
      pdfToDocument: pdfToCanonicalDocument
    });

    if (!parsed.ok) {
      const action = parsed.code?.includes('unsupported') ? 'unsupported' : 'fail_inspect';
      await transitionSource(pool, source, action, {
        error_code: parsed.code,
        error_detail: parsed.message,
        source_type: parsed.format || format || source.source_type
      });
      return { ok: false, code: parsed.code };
    }

    const preview = buildPreviewFromParses([{ ...parsed, path: null }], {
      originalKeys,
      otherLinkedKeys: otherKeys
    });
    const updated = await transitionSource(pool, source, 'finish_inspect', {
      preview,
      source_type: parsed.format || format || source.source_type,
      content_hash: fetched.contentHash,
      last_fetched_at: fetched.fetchedAt
    });
    await replaceSourceFiles(pool, source.id, [
      {
        path: fetched.finalUrl,
        download_url: fetched.finalUrl,
        size_bytes: fetched.bytes,
        content_sha: fetched.contentHash,
        content_type: fetched.contentType,
        selected: true,
        parse_status: 'ok',
        estimated_raw_count: parsed.raw_count,
        estimated_unique_count: parsed.unique_count,
        type_breakdown: parsed.type_breakdown
      }
    ]);
    return { ok: true, source: updated, preview };
  } catch (err) {
    const pub = publicFetchError(err);
    const action = pub.code === 'blocked_url' || pub.code === 'redirect_blocked' ? 'block' : 'fail_inspect';
    await transitionSource(pool, source, action, {
      error_code: pub.code,
      error_detail: pub.message
    });
    return { ok: false, code: pub.code };
  }
}
