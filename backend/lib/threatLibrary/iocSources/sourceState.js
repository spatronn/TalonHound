/**
 * Additional IOC Sources — lifecycle transitions (idempotent guards).
 */

import { IOC_SOURCE_LIFECYCLE } from './constants.js';

const L = IOC_SOURCE_LIFECYCLE;

const CAN_INSPECT = new Set([
  L.DISCOVERED,
  L.INSPECTED,
  L.FAILED,
  L.UNSUPPORTED,
  L.BLOCKED,
  L.ATTACHED,
  L.EXTRACTED,
  L.STALE
]);

const CAN_APPROVE = new Set([L.INSPECTED, L.ATTACHED, L.EXTRACTED, L.FAILED, L.STALE]);

const CAN_DISMISS = new Set([
  L.DISCOVERED,
  L.INSPECTED,
  L.FAILED,
  L.UNSUPPORTED,
  L.BLOCKED,
  L.STALE
]);

const CAN_EXTRACT = new Set([L.ATTACHED, L.EXTRACTED, L.FAILED, L.STALE]);

/**
 * @param {string|null|undefined} status
 */
export function normalizeLifecycle(status) {
  return String(status || '').toLowerCase();
}

export function canStartInspection(status) {
  return CAN_INSPECT.has(normalizeLifecycle(status));
}

export function canApproveAttach(status) {
  return CAN_APPROVE.has(normalizeLifecycle(status));
}

export function canDismiss(status) {
  return CAN_DISMISS.has(normalizeLifecycle(status));
}

export function canStartExtraction(status) {
  return CAN_EXTRACT.has(normalizeLifecycle(status));
}

/**
 * Apply a lifecycle transition patch. Returns null when the transition is a no-op
 * that callers may treat as success (idempotent approve/extract), or throws when illegal.
 * @param {object} source
 * @param {'start_inspect'|'finish_inspect'|'fail_inspect'|'block'|'unsupported'|'approve'|'start_extract'|'finish_extract'|'fail_extract'|'dismiss'} action
 * @param {object} [extra]
 */
export function transitionPatch(source, action, extra = {}) {
  const status = normalizeLifecycle(source?.lifecycle_status);
  const nowIso = new Date().toISOString();

  switch (action) {
    case 'start_inspect': {
      if (status === L.DISMISSED) {
        const err = new Error('Dismissed sources cannot be inspected');
        err.code = 'source_dismissed';
        throw err;
      }
      if (!canStartInspection(status) && status !== L.INSPECTING) {
        const err = new Error(`Cannot inspect source in status ${status}`);
        err.code = 'invalid_source_transition';
        throw err;
      }
      return {
        lifecycle_status: L.INSPECTING,
        inspection_status: 'running',
        error_code: null,
        error_detail: null,
        updated_at: nowIso
      };
    }
    case 'finish_inspect': {
      return {
        lifecycle_status: L.INSPECTED,
        inspection_status: 'succeeded',
        preview: extra.preview || {},
        source_type: extra.source_type || source.source_type,
        content_hash: extra.content_hash ?? source.content_hash,
        repo_revision: extra.repo_revision ?? source.repo_revision,
        last_fetched_at: extra.last_fetched_at || nowIso,
        error_code: null,
        error_detail: null,
        updated_at: nowIso
      };
    }
    case 'fail_inspect': {
      return {
        lifecycle_status: L.FAILED,
        inspection_status: 'failed',
        error_code: extra.error_code || 'inspect_failed',
        error_detail: extra.error_detail || 'Inspection failed',
        updated_at: nowIso
      };
    }
    case 'block': {
      return {
        lifecycle_status: L.BLOCKED,
        inspection_status: 'failed',
        error_code: extra.error_code || 'blocked_url',
        error_detail: extra.error_detail || 'URL blocked by security policy',
        updated_at: nowIso
      };
    }
    case 'unsupported': {
      return {
        lifecycle_status: L.UNSUPPORTED,
        inspection_status: 'succeeded',
        preview: extra.preview || source.preview || {},
        error_code: extra.error_code || 'unsupported_format',
        error_detail: extra.error_detail || 'Source format is not supported',
        updated_at: nowIso
      };
    }
    case 'approve': {
      if (status === L.ATTACHED || status === L.EXTRACTED || status === L.EXTRACTING) {
        return { idempotent: true, lifecycle_status: status };
      }
      if (!canApproveAttach(status)) {
        const err = new Error(`Cannot approve source in status ${status}`);
        err.code = 'invalid_source_transition';
        throw err;
      }
      return {
        lifecycle_status: L.ATTACHED,
        approved_by: extra.approved_by || null,
        approved_at: nowIso,
        dismissed_by: null,
        dismissed_at: null,
        error_code: null,
        error_detail: null,
        updated_at: nowIso
      };
    }
    case 'start_extract': {
      if (!canStartExtraction(status) && status !== L.EXTRACTING) {
        const err = new Error(`Cannot extract source in status ${status}`);
        err.code = 'invalid_source_transition';
        throw err;
      }
      return {
        lifecycle_status: L.EXTRACTING,
        extraction_status: 'running',
        error_code: null,
        error_detail: null,
        updated_at: nowIso
      };
    }
    case 'finish_extract': {
      return {
        lifecycle_status: L.EXTRACTED,
        extraction_status: 'succeeded',
        preview: extra.preview ? { ...(source.preview || {}), ...extra.preview } : source.preview,
        content_hash: extra.content_hash ?? source.content_hash,
        last_fetched_at: extra.last_fetched_at || nowIso,
        error_code: null,
        error_detail: null,
        updated_at: nowIso
      };
    }
    case 'fail_extract': {
      return {
        lifecycle_status: L.FAILED,
        extraction_status: 'failed',
        error_code: extra.error_code || 'extract_failed',
        error_detail: extra.error_detail || 'Extraction failed',
        updated_at: nowIso
      };
    }
    case 'dismiss': {
      if (status === L.DISMISSED) return { idempotent: true, lifecycle_status: L.DISMISSED };
      if (!canDismiss(status)) {
        const err = new Error(`Cannot dismiss source in status ${status}`);
        err.code = 'invalid_source_transition';
        throw err;
      }
      return {
        lifecycle_status: L.DISMISSED,
        dismissed_by: extra.dismissed_by || null,
        dismissed_at: nowIso,
        updated_at: nowIso
      };
    }
    default: {
      const err = new Error(`Unknown source transition: ${action}`);
      err.code = 'invalid_source_transition';
      throw err;
    }
  }
}
