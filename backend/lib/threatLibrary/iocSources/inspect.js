/**
 * Bounded inspection of an Additional IOC Source (preview only — no candidate writes).
 */

import { pdfToCanonicalDocument } from '../pdfIngest.js';
import { enumerateGitHubIocSource, gitHubFolderUrl, gitHubScopeIo, parseGitHubUrl } from './github.js';
import {
  IOC_SOURCE_SCOPE_VERSION,
  inventoryBacklinkScope,
  isFolderHashListPath,
  isReadmePath,
  resolveGitHubCampaignFolder
} from './campaignScope.js';
import { BLOCKING_FETCH_CODES, fetchIocSourceUrl, publicFetchError, validateIocSourceUrl } from './fetchSafe.js';
import { buildPreviewFromParses, parseIocSourceContent } from './parseContent.js';
import {
  loadOriginalIndicatorKeys,
  loadOtherLinkedKeys,
  replaceSourceFiles,
  transitionSource
} from './store.js';
import { guessTypeFromUrl } from './sourceType.js';
import { IOC_SOURCE_FETCH } from './constants.js';

/**
 * The submitted source URL itself must clear the destination guard before
 * anything is fetched: GitHub sources are read through api.github.com /
 * raw.githubusercontent.com, so the per-request guard alone would never see
 * the URL the analyst entered.
 * @param {object} source
 * @param {{ destinationGuard?: Function }} deps
 */
export async function guardSourceUrl(source, deps) {
  if (typeof deps?.destinationGuard !== 'function') return { ok: true };
  const verdict = await deps.destinationGuard(source.canonical_url || source.original_url);
  return verdict && verdict.ok === false ? verdict : { ok: true };
}

/**
 * Report context a linked pack is scoped against: the report URL, its title
 * and its section headings (distinctive campaign names). Reads only.
 * @param {import('pg').Pool} pool
 * @param {number} reportId
 */
export async function loadReportScopeContext(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT title, source_url, published_at, canonical_document FROM threat_reports WHERE id = $1`,
    [reportId]
  );
  const r = rows[0] || {};
  const blocks = Array.isArray(r.canonical_document?.blocks) ? r.canonical_document.blocks : [];
  return {
    reportUrl: r.source_url || null,
    reportTitle: r.title || null,
    // STIX validity is judged at publication (parseContent.stixValidityReference).
    publishedAt: r.published_at || null,
    headings: blocks.filter((b) => b?.type === 'heading').map((b) => String(b.text || '')).slice(0, 200)
  };
}

/**
 * Folder files to ingest under campaign scope (kept listed with the reason
 * when deselected):
 * - when the folder README is a multi-campaign index, folder-wide hash lists
 *   cannot be attributed to this report;
 * - an inventory whose own metadata row names a DIFFERENT article
 *   (`description,https://publisher/blog/other-post`) belongs to another
 *   campaign of a shared folder, such as a month directory
 *   (tl-ioc-source-scope-v3).
 * @param {object[]} fileRows
 * @param {object[]} parseResults
 */
export function applyCampaignFileSelection(fileRows, parseResults) {
  const multi = parseResults.some((r) => isReadmePath(r.path || '') && r.scope?.multi_campaign === true);
  const backlinkByPath = new Map(parseResults.filter((r) => r.backlink_scope).map((r) => [r.path, r.backlink_scope]));
  const deselected = [];
  const otherReport = [];
  const rows = fileRows.map((f) => {
    const scope = backlinkByPath.get(f.path);
    if (scope?.verdict === 'other_report') {
      deselected.push(f.path);
      otherReport.push({ path: f.path, backlink: scope.backlink });
      return { ...f, selected: false, parse_status: 'skipped', error_detail: `campaign_backlink_other_report: the file names ${scope.backlink}` };
    }
    if (multi && isFolderHashListPath(f.path)) {
      deselected.push(f.path);
      return { ...f, selected: false, parse_status: 'skipped', error_detail: 'multi_campaign_folder_hash_list: not attributable to this report' };
    }
    return f;
  });
  if (!deselected.length) return { fileRows, parseResults, deselected, otherReport };
  const results = parseResults.filter((r) => !deselected.includes(r.path));
  return { fileRows: rows, parseResults: results, deselected, otherReport };
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} source threat_report_ioc_sources row
 * @param {{ fetchImpl?: Function, destinationGuard?: Function }} [deps]
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

  const verdict = await guardSourceUrl(source, deps);
  if (!verdict.ok) {
    await transitionSource(pool, source, 'block', {
      error_code: verdict.code,
      error_detail: verdict.reason
    });
    return { ok: false, code: verdict.code };
  }

  const gh = parseGitHubUrl(source.canonical_url || source.original_url);
  const originalKeys = await loadOriginalIndicatorKeys(pool, source.report_id);
  const otherKeys = await loadOtherLinkedKeys(pool, source.report_id, source.id);

  const reportScope = await loadReportScopeContext(pool, source.report_id);

  try {
    if (gh) {
      // A repository root is never an IOC pack: resolve the campaign folder
      // from the report's own names, corroborated by a README that links the
      // report; otherwise nothing is ingested (tl-ioc-source-scope-v1).
      let packUrl = source.canonical_url || source.original_url;
      let resolvedScope = null;
      if (gh.kind === 'dir' && !String(gh.path || '').replace(/^\/+|\/+$/g, '')) {
        const resolution = await resolveGitHubCampaignFolder(gh, reportScope, gitHubScopeIo(gh, deps));
        if (!resolution.ok) {
          await transitionSource(pool, source, 'unsupported', {
            error_code: 'campaign_scope_unresolved',
            error_detail: `Repository root: no campaign folder corroborated for this report (${resolution.reason})`,
            preview: { scope: { version: IOC_SOURCE_SCOPE_VERSION, repository_root: true, ...resolution } }
          });
          return { ok: false, code: 'campaign_scope_unresolved' };
        }
        packUrl = gitHubFolderUrl(gh, resolution.path);
        resolvedScope = {
          repository_root: true,
          resolved_path: resolution.path,
          reason: resolution.reason,
          candidates_checked: resolution.candidates_checked
        };
      }
      const listing = await enumerateGitHubIocSource(packUrl, deps);
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
            destinationGuard: deps.destinationGuard,
            maxBytes: IOC_SOURCE_FETCH.GITHUB_MAX_FILE_BYTES
          });
          const parsed = await parseIocSourceContent({
            body: fetched.body,
            buffer: fetched.buffer,
            contentType: fetched.contentType,
            url: file.download_url,
            path: file.path,
            sourcePublicId: source.public_id,
            pdfToDocument: pdfToCanonicalDocument,
            reportScope
          });
          // The inventory's own metadata row says which article it belongs to.
          const backlinkScope = gh.kind === 'dir' ? inventoryBacklinkScope(fetched.body, file.path, reportScope) : null;
          parseResults.push({ ...parsed, path: file.path, ...(backlinkScope ? { backlink_scope: backlinkScope } : {}) });
          fileRows.push({
            ...file,
            // Persist sha256 of fetched bytes for extract-time drift detection.
            content_sha: fetched.contentHash || file.content_sha || null,
            content_type: fetched.contentType || null,
            parse_status: parsed.ok
              ? 'ok'
              : parsed.code === 'unsupported_json_schema'
                || parsed.code === 'unsupported_format'
                || parsed.code === 'unsupported_stix_version'
                || parsed.code === 'not_stix_json'
                || parsed.code === 'not_stix_xml'
                || parsed.code === 'campaign_scope_unresolved'
                ? 'unsupported'
                : 'failed',
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

      const scoped = applyCampaignFileSelection(fileRows, parseResults);
      await replaceSourceFiles(pool, source.id, scoped.fileRows);
      const readme = parseResults.find((r) => isReadmePath(r.path || '') && r.scope);
      const preview = {
        ...buildPreviewFromParses(scoped.parseResults, {
          originalKeys,
          otherLinkedKeys: otherKeys
        }),
        scope: {
          version: IOC_SOURCE_SCOPE_VERSION,
          ...(resolvedScope || {}),
          ...(readme?.scope ? { readme: readme.scope } : {}),
          ...(scoped.deselected.length ? { deselected_files: scoped.deselected } : {}),
          ...(scoped.otherReport?.length ? { other_report_files: scoped.otherReport } : {})
        },
        // Keep original branch/tag alongside resolved commit SHA in repo_revision.
        ...(listing.repo_ref ? { repo_ref: listing.repo_ref } : {})
      };

      if (!scoped.fileRows.some((f) => f.parse_status === 'ok' && f.selected !== false)) {
        // Every parsable file declares another article: the folder holds no
        // inventory of this report (wrong / shared folder link).
        const onlyOtherReports = (scoped.otherReport?.length || 0) > 0 &&
          !scoped.fileRows.some((f) => f.parse_status === 'ok' && f.selected !== false);
        const code = onlyOtherReports ? 'campaign_scope_unresolved' : 'no_parsable_files';
        await transitionSource(pool, source, 'unsupported', {
          preview,
          source_type: listing.source_type,
          content_hash: listing.content_hash || null,
          repo_revision: listing.repo_revision || null,
          error_code: code,
          error_detail: onlyOtherReports
            ? 'Folder inventories belong to other reports (their metadata rows link other articles); none is attributable to this report'
            : 'No eligible files could be parsed for IOC preview'
        });
        return { ok: false, code, preview };
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
      fetchImpl: deps.fetchImpl,
      destinationGuard: deps.destinationGuard
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
      pdfToDocument: pdfToCanonicalDocument,
      reportScope
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
    const action = BLOCKING_FETCH_CODES.has(pub.code) ? 'block' : 'fail_inspect';
    await transitionSource(pool, source, action, {
      error_code: pub.code,
      error_detail: pub.message
    });
    return { ok: false, code: pub.code };
  }
}
