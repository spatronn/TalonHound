import { throwIfAborted } from './job-cancellation.js';
import {
  createUsomImportStage,
  dropUsomImportStage,
  finalizeUsomImport,
  loadUsomImportContext,
  loadUsomLookupCache,
  saveUsomLookupCache,
  stageUsomEntries
} from './usomImportStore.js';
import {
  buildUsomCanonicalSnapshotHash,
  USOM_PERSISTED_IOC_TYPES
} from './usomNormalizer.js';

const DEFAULT_STORE = Object.freeze({
  createStage: createUsomImportStage,
  stageEntries: stageUsomEntries,
  finalize: finalizeUsomImport,
  dropStage: dropUsomImportStage,
  loadContext: loadUsomImportContext,
  loadLookupCache: loadUsomLookupCache,
  saveLookupCache: saveUsomLookupCache
});

/**
 * Fetches and stages a complete snapshot before allowing the store to mutate
 * production IOC tables. The store is injectable for contract/integration tests.
 */
export async function executeUsomImportPipeline({
  client,
  api,
  stats,
  signal,
  seenAt = new Date(),
  mode = 'incremental',
  runId = null,
  runDetails = {},
  statementTimeoutMs,
  idleInTxTimeoutMs,
  store = DEFAULT_STORE
}) {
  let inRunDuplicates = 0;
  let pipelineError = null;
  const context = store.loadContext
    ? await store.loadContext(client)
    : { cursors: {}, state: null };
  const hasCompleteCursorSet = USOM_PERSISTED_IOC_TYPES.every((type) => context.cursors?.[type]);
  if (mode === 'incremental' && !hasCompleteCursorSet) {
    const error = new Error('USOM incremental cursor bootstrap requires a successful full reconciliation');
    error.code = 'bootstrap_required';
    throw error;
  }
  const effectiveMode = mode;
  if (!['incremental', 'full_reconciliation'].includes(effectiveMode)) {
    throw new TypeError(`Unsupported persistent USOM mode: ${effectiveMode}`);
  }
  const lookupCache = store.loadLookupCache
    ? await store.loadLookupCache(client)
    : {};
  const canonicalIdentities = effectiveMode === 'full_reconciliation' ? [] : null;
  await store.createStage(client);
  try {
    const collection = await api.collect({
      signal,
      stats,
      mode: effectiveMode,
      cursors: context.cursors,
      runStartedAt: seenAt,
      lookupCache,
      persistLookup: store.saveLookupCache
        ? (group, value) => store.saveLookupCache(client, group, value)
        : null,
      onEntries: async (entries, page) => {
        throwIfAborted(signal);
        if (canonicalIdentities) {
          for (const entry of entries) {
            canonicalIdentities.push(`${entry.observableType}|${entry.observable}`);
          }
        }
        const staged = await store.stageEntries(client, entries, page);
        inRunDuplicates += Number(staged?.duplicate || 0);
      }
    });
    throwIfAborted(signal);
    const snapshotHash = canonicalIdentities
      ? buildUsomCanonicalSnapshotHash(canonicalIdentities)
      : null;
    const cursorBefore = context.cursors || {};
    const cursorAfter = { ...cursorBefore, ...(collection.highwaters || {}) };
    const persistence = await store.finalize(client, {
      stats,
      seenAt,
      mode: effectiveMode,
      highwaters: collection.highwaters,
      snapshotHash,
      snapshotStable: collection.paginationStable !== false,
      priorSnapshotHash: context.state?.full_snapshot_hash || null,
      runId,
      inRunDuplicates,
      runDetails: {
        ...runDetails,
        requested_mode: mode,
        effective_mode: effectiveMode,
        cursor_bootstrap_full: false,
        cursor_before: cursorBefore,
        cursor_after: cursorAfter,
        query_windows: collection.queryWindows,
        pagination_stable: collection.paginationStable !== false
      },
      statementTimeoutMs,
      idleInTxTimeoutMs
    });
    return {
      persistence,
      inRunDuplicates,
      requestedMode: mode,
      effectiveMode,
      cursorBefore,
      cursorAfter,
      snapshotHash
    };
  } catch (err) {
    pipelineError = err;
    throw err;
  } finally {
    try {
      await store.dropStage(client);
    } catch (dropError) {
      if (!pipelineError) throw dropError;
    }
  }
}
