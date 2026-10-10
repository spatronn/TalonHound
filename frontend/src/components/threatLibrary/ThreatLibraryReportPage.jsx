import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import { useAppConfirm } from '../../lib/appChromeContext.jsx';
import {
  buildProgressChecklist,
  isProcessingStatus,
  statusLabel
} from './stages.js';
import {
  applyRetryAcceptedState,
  canShowRetryButton,
  canShowRefreshExtraction,
  canShowRerunAi,
  describeMaintenanceAccepted,
  describeMaintenanceOutcome,
  isRefreshExtractionInProgress,
  MAINTENANCE_MODES,
  processingSectionTitle,
  REFRESH_EXTRACTION_CONFIRM,
  RERUN_AI_CONFIRM,
  shouldIgnoreStaleFailedPoll,
  shouldShowFailedPanel,
  shouldShowProcessingPanel
} from './reportRetryUi.js';
import {
  PRIMARY_REVIEW_VIEWS,
  SOURCE_FILTERS,
  MATCH_FILTERS,
  DEFAULT_REVIEW_FILTER,
  DEFAULT_SOURCE_FILTER,
  DEFAULT_MATCH_FILTER,
  TYPE_FILTERS,
  RESULT_FILTERS,
  PAGE_SIZES,
  DEFAULT_PAGE_SIZE,
  isReviewIndicator,
  withInferredPublisherIocScope,
  describeAnalysisFailureDetail,
  confidenceLabel,
  filterReviewCandidates,
  paginateRows,
  parseReviewTableUrlState,
  serializeReviewTableUrlState,
  normalizeReviewFilterState,
  describeIndicatorInventorySummary,
  reviewFiltersAreDefault,
  iocResultLabel,
  iocResultLink,
  iocResultOutcome,
  describeNoCreatableIocs,
  applyPromotionResults,
  formatCreateIocSummary,
  describeReviewFeedback,
  describeCreateIocFeedback,
  describeCreateIocOperationPanel,
  formatCreateIocCountLine,
  describePromoteFeedback,
  describeReviewToolbar,
  isContextOnlyCandidate,
  selectionForAction,
  describeSelectionBanner,
  describeBulkActionConfirm,
  describeAcrossPagesOutcome,
  buildAllMatchingReviewBody,
  headerCheckState,
  toggleExplicitSelection,
  togglePageExplicit,
  toggleExcludedId,
  togglePageExcluded,
  reviewFiltersEqual,
  selectionScopeLabel,
  writeCreateIocSession,
  readCreateIocSession,
  clearCreateIocSession,
  isCreateIocAmbiguousFailure
} from './candidateReview.js';
import {
  REPORT_PHASES,
  REVIEW_NOT_READY_CODE,
  resolveReportPhase,
  canShowReviewTable,
  canFinalize,
  indicatorSectionTitle,
  describeIndicatorCount,
  describePreliminaryState,
  shouldIgnoreStalePoll,
  shouldRefetchDetail,
  createLatestOnly
} from './reportPhase.js';
import { TlpBadge, isElevatedTlp, normalizeTlp, tlpDisplay } from './tlp.jsx';
import ThreatLibraryModal, { ModalCancelButton } from './ThreatLibraryModal.jsx';
import ReportTagsEditor from './ReportTagsEditor.jsx';
import { mergeReportPayload } from './reportTags.js';
import {
  TLP_OPTIONS,
  canEditTlp,
  describeTlpChangeConfirm,
  describeTlpSavedFeedback,
  tlpSourceLabel,
  tlpSourceShortLabel
} from './tlpEdit.js';
import { ui, badgeStyle } from './styles.js';
import {
  REPORT_VIEWS,
  buildReportTabs,
  parseReportView,
  withReportView
} from './reportTabs.js';
import IocSourcesPanel from './IocSourcesPanel.jsx';
import {
  buildOverviewMetrics,
  buildReportDetails,
  buildReviewFilterCounts,
  buildSourceDetails,
  describeArtifact,
  describeOverviewPhaseNote,
  entityConfidenceLabel,
  groupEntitiesByType,
  isOpenableSourceUrl
} from './reportOverview.js';
import {
  assessmentLabel,
  assessmentTone,
  candidateTypeLabel,
  humanizeEnum,
  matchCellLabel,
  matchStateTone,
  promotionOutcomeTone,
  reviewStatusLabel,
  reviewStatusTone,
  roleLabel,
  sourceTypeLabel
} from './reportDisplayLabels.js';
import { candidateDisplayValue, describeDrawerPosition, describeEvidencePreview } from './candidateDetail.js';
import {
  CopyUrlButton,
  CopyValueButton,
  DetailList,
  ReportActionsMenu,
  ReportTabBar,
  ToneBadge
} from './reportPageParts.jsx';
import IndicatorDetailDrawer from './IndicatorDetailDrawer.jsx';
import './reportPage.css';

function CreateIocOperationPanel({ model, onDismiss }) {
  if (!model) return null;
  return (
    <div
      className="tl-create-op"
      data-phase={model.phase}
      data-testid="create-ioc-operation"
      role={model.phase === 'failed' || model.phase === 'ambiguous' ? 'alert' : 'status'}
      aria-live="polite"
    >
      <div className="tl-create-op__header">
        <h3 className="tl-create-op__title">{model.title}</h3>
        {model.elapsedLabel ? (
          <span className="tl-create-op__elapsed" data-testid="create-ioc-elapsed">
            Elapsed {model.elapsedLabel}
          </span>
        ) : null}
      </div>
      <p className="tl-create-op__body">{model.body}</p>
      {model.detail ? <p className="tl-create-op__detail">{model.detail}</p> : null}
      {model.phase === 'completed' && model.counts ? (
        <p className="tl-create-op__counts">{formatCreateIocCountLine(model.counts)}</p>
      ) : null}
      {model.phase === 'processing' ? (
        <div className="tl-create-op__track" aria-hidden="true">
          <span className={`tl-create-op__bar${model.indeterminate ? ' tl-create-op__bar--indeterminate' : ''}`} />
        </div>
      ) : null}
      {model.dismissible ? (
        <button type="button" className="tl-create-op__dismiss" onClick={onDismiss}>
          Dismiss
        </button>
      ) : null}
    </div>
  );
}

function EvidencePreview({ candidate }) {
  const p = describeEvidencePreview(candidate);
  return (
    <div className="tl-evidence">
      <div style={{ color: '#e2e8f0' }}>{p.primary}</div>
      {p.secondary ? <div className="tl-evidence__secondary" title={p.secondary}>{p.secondary}</div> : null}
      {p.warning ? <div style={{ color: '#fbbf24' }}>{p.warning}</div> : null}
      <div className="tl-evidence__tertiary">{p.tertiary}</div>
    </div>
  );
}

function ProgressChecklist({ report, job }) {
  const items = buildProgressChecklist(report, job);
  const progress = report?.analysis_progress || job?.progress || {};
  const analyzing = String(report?.analysis_status || job?.stage || '').toLowerCase() === 'analyzing';
  let activityNote = null;
  if (analyzing) {
    const total = progress.analysis_chunks_total;
    const done = progress.analysis_chunks_completed;
    const current = progress.current_chunk_index;
    const parts = [];
    if (total && current) parts.push(`Chunk ${current} of ${total}`);
    else if (total != null && done != null) parts.push(`${done} / ${total} sections complete`);
    if (progress.last_provider_activity_at) {
      const ago = Math.max(0, Math.round((Date.now() - new Date(progress.last_provider_activity_at).getTime()) / 1000));
      parts.push(`Last provider activity: ${ago}s ago`);
    }
    if (progress.synthesizing) parts.push('Synthesizing final summary');
    if (progress.repairing) parts.push('Repairing model output');
    if (Number.isFinite(Number(progress.ai_calls)) && Number(progress.ai_calls) > 0) parts.push(`AI calls: ${Number(progress.ai_calls)}`);
    if (Number.isFinite(Number(progress.ai_needed_candidates))) parts.push(`Candidates for AI: ${Number(progress.ai_needed_candidates)}`);
    if (parts.length) activityNote = parts.join(' · ');
  }
  return (
    <div>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
        {items.map((item) => {
          const color = item.state === 'done' ? '#86efac'
            : item.state === 'active' ? '#5eead4'
              : item.state === 'failed' ? '#fca5a5'
                : '#64748b';
          const mark = item.state === 'done' ? '✓'
            : item.state === 'active' ? '●'
              : item.state === 'failed' ? '✕'
                : '○';
          return (
            <li key={item.key} style={{ display: 'flex', alignItems: 'center', gap: 10, color, fontSize: 13 }}>
              <span style={{ width: 18, textAlign: 'center', fontWeight: 700 }}>{mark}</span>
              <span style={{ fontWeight: item.state === 'active' ? 700 : 500 }}>{item.label}</span>
            </li>
          );
        })}
      </ul>
      {activityNote ? (
        <div style={{ marginTop: 10, fontSize: 12, color: '#94a3b8' }}>{activityNote}</div>
      ) : null}
    </div>
  );
}

function compactBtn(base, disabled) {
  return {
    ...base,
    ...(disabled ? { opacity: 0.5, cursor: 'not-allowed' } : null)
  };
}

const compactInput = { ...ui.input, padding: '6px 10px', fontSize: 13, minHeight: 32 };
const compactSelect = { ...ui.select, width: 'auto', minWidth: 130, padding: '6px 10px', fontSize: 13, minHeight: 32 };
const compactAction = { ...ui.btn, minHeight: 30, padding: '4px 10px', fontSize: 12 };
const compactPrimary = { ...ui.btnPrimary, minHeight: 30, padding: '4px 10px', fontSize: 12 };

/**
 * Source URL: displayed as inert text with an explicit "Open source" action
 * (http/https only) and the existing edit flow. The report source is
 * legitimate navigation; indicator values elsewhere on the page never are.
 */
function SourceUrlEditor({ value, canWrite, busy, onSave }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value || '');
  const [localError, setLocalError] = useState('');

  useEffect(() => {
    if (!editing) setDraft(value || '');
  }, [value, editing]);

  if (!editing) {
    const url = value ? String(value) : '';
    return (
      <div data-testid="source-url" className="tl-source-card__url">
        {url ? (
          <div className="tl-value tl-source-card__urltext" title={url}>{url}</div>
        ) : (
          <div style={{ color: '#64748b', fontSize: 13 }}>No source URL recorded.</div>
        )}
        <div className="tl-source-card__actions">
          {url && isOpenableSourceUrl(url) ? (
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              style={{ ...compactAction, textDecoration: 'none' }}
            >
              Open source
            </a>
          ) : null}
          {url ? <CopyUrlButton value={url} /> : null}
          {canWrite ? (
            <button
              type="button"
              className="tl-ghost-btn"
              disabled={Boolean(busy)}
              onClick={() => { setLocalError(''); setDraft(value || ''); setEditing(true); }}
            >
              {value ? 'Edit' : 'Add source URL'}
            </button>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <div className="tl-source-card__url">
      <label htmlFor="tl-source-url" style={{ color: '#94a3b8', fontSize: 12, marginBottom: 4, display: 'block' }}>
        Source URL
      </label>
      <input
        id="tl-source-url"
        type="url"
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder="https://"
        style={{ ...compactInput, maxWidth: 560, marginBottom: 8 }}
        autoFocus
      />
      {localError ? <div style={{ ...ui.error, marginBottom: 8 }} role="alert">{localError}</div> : null}
      <div style={{ display: 'flex', gap: 8 }}>
        <button
          type="button"
          style={ui.btnPrimary}
          disabled={Boolean(busy)}
          onClick={async () => {
            setLocalError('');
            try {
              await onSave(draft);
              setEditing(false);
            } catch (err) {
              setLocalError(err?.response?.data?.message || err?.message || 'Could not save source URL');
            }
          }}
        >
          Save
        </button>
        <button
          type="button"
          style={ui.btn}
          disabled={Boolean(busy)}
          onClick={() => { setEditing(false); setDraft(value || ''); setLocalError(''); }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

/**
 * Deliberate TLP change: a select over the canonical set, an explicit Save,
 * and a confirmation only when the sharing restriction is being reduced.
 */
function TlpEditModal({ open, current, source, busy, onClose, onSave }) {
  const [draft, setDraft] = useState(normalizeTlp(current));
  const [localError, setLocalError] = useState('');

  useEffect(() => {
    if (open) {
      setDraft(normalizeTlp(current));
      setLocalError('');
    }
  }, [open, current]);

  const unchanged = normalizeTlp(current) === draft;
  return (
    <ThreatLibraryModal
      open={open}
      title="TLP classification"
      description="TLP is a sharing restriction, not a severity. Set it to what the publisher marked or what your organisation is allowed to share."
      onClose={onClose}
      width={460}
      closeDisabled={Boolean(busy)}
      footer={(
        <>
          <ModalCancelButton onClick={onClose} disabled={Boolean(busy)} />
          <button
            type="button"
            style={ui.btnPrimary}
            disabled={Boolean(busy) || unchanged}
            onClick={async () => {
              setLocalError('');
              try {
                await onSave(draft);
              } catch (err) {
                setLocalError(err?.response?.data?.message || err?.message || 'Could not update TLP');
              }
            }}
          >
            {busy === 'tlp' ? 'Saving…' : 'Save'}
          </button>
        </>
      )}
    >
      <label htmlFor="tl-tlp-select" style={ui.label}>TLP Classification</label>
      <select
        id="tl-tlp-select"
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        style={ui.select}
        disabled={Boolean(busy)}
      >
        {TLP_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
      <span style={ui.helper}>
        Current: {tlpDisplay(current)} · {tlpSourceLabel(source)}
      </span>
      {localError ? <div style={{ ...ui.error, marginTop: 10 }} role="alert">{localError}</div> : null}
    </ThreatLibraryModal>
  );
}

function SectionCard({ title, children, actions }) {
  return (
    <div style={{ ...ui.formPanel, marginBottom: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', marginBottom: 10, flexWrap: 'wrap' }}>
        <h2 style={{ ...ui.formTitle, margin: 0 }}>{title}</h2>
        {actions || null}
      </div>
      {children}
    </div>
  );
}

/**
 * Indicator area while the candidate set is still moving (preparing) or
 * after a failure: progress copy, the preliminary count and an explicitly
 * labelled, collapsed diagnostic list. No review actions, never "Review".
 */
function PreliminaryIndicatorsCard({ report, job, candidates, onRetry, retryEnabled, busy }) {
  const state = describePreliminaryState(report, job, { rawCount: candidates.length || report?.raw_candidate_count || null });
  const failed = state.phase === REPORT_PHASES.FAILED;
  return (
    <SectionCard
      title={indicatorSectionTitle(report)}
      actions={(
        <span
          style={badgeStyle(failed
            ? { border: '#7f1d1d', bg: '#450a0a', color: '#fecaca' }
            : { border: '#0f766e', bg: '#134e4a', color: '#99f6e4' })}
          role="status"
          aria-live="polite"
        >
          {failed ? '✕ Analysis failed' : '● Analysis in progress'}
        </span>
      )}
    >
      <div aria-busy={!failed} data-phase={state.phase}>
        <div style={{ fontWeight: 600, color: '#e2e8f0', marginBottom: 6 }}>{state.title}</div>
        {state.lines.map((line) => (
          <div key={line} style={{ fontSize: 13, color: line === state.countText ? '#e2e8f0' : '#94a3b8', marginBottom: 4 }}>
            {line}
          </div>
        ))}
        {failed && retryEnabled ? (
          <button type="button" style={{ ...ui.btn, marginTop: 8 }} disabled={Boolean(busy)} onClick={onRetry}>
            {busy === 'retry' ? 'Starting…' : 'Retry analysis'}
          </button>
        ) : null}
        {candidates.length > 0 ? (
          <details style={{ marginTop: 12 }}>
            <summary style={{ cursor: 'pointer', color: '#94a3b8', fontSize: 12 }}>
              Show preliminary observables ({candidates.length})
            </summary>
            <div style={{ fontSize: 12, color: '#fbbf24', margin: '8px 0 6px' }}>
              These values are not final and may be removed, retyped or reclassified during analysis.
            </div>
            <ul style={{ margin: 0, paddingLeft: 18, color: '#cbd5e1', fontSize: 13 }}>
              {candidates.slice(0, 60).map((c) => (
                <li key={c.id || c.public_id} style={{ marginBottom: 4, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', wordBreak: 'break-all' }}>
                  [{candidateTypeLabel(c.candidate_type) || c.candidate_type}] {c.normalized_value || c.original_value}
                </li>
              ))}
              {candidates.length > 60 ? <li style={{ color: '#64748b' }}>… {candidates.length - 60} more</li> : null}
            </ul>
          </details>
        ) : null}
      </div>
    </SectionCard>
  );
}

function Stat({ label, value, testId, children }) {
  return (
    <span className="tl-stat" data-testid={testId}>
      <span className="tl-stat__value">{value}</span>
      <span className="tl-stat__label">{label}</span>
      {children}
    </span>
  );
}

function isInteractiveTarget(target) {
  if (!target || typeof target.closest !== 'function') return false;
  return Boolean(target.closest('button, a, input, select, textarea, label, [role="menu"]'));
}

function PageSelectCheckbox({ state, label, onChange }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = state === 'indeterminate';
  }, [state]);
  return (
    <input
      ref={ref}
      type="checkbox"
      checked={state === 'checked'}
      onChange={onChange}
      aria-label={label}
      aria-checked={state === 'indeterminate' ? 'mixed' : state === 'checked'}
      data-testid="page-select-checkbox"
    />
  );
}

export default function ThreatLibraryReportPage({ AppShell, useSession }) {
  const { reportId } = useParams();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestConfirm = useAppConfirm();
  const { isAdmin, canWrite } = useSession();
  const urlState = useMemo(() => parseReviewTableUrlState(searchParams), [searchParams]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [feedback, setFeedback] = useState('');
  const [report, setReport] = useState(null);
  const [candidates, setCandidates] = useState([]);
  const [entities, setEntities] = useState([]);
  const [artifacts, setArtifacts] = useState([]);
  const [documentMeta, setDocumentMeta] = useState(null);
  const [job, setJob] = useState(null);
  const [view, setView] = useState(() => parseReportView(searchParams));
  const [filter, setFilter] = useState(urlState.tab || DEFAULT_REVIEW_FILTER);
  const [sourceFilter, setSourceFilter] = useState(urlState.source || DEFAULT_SOURCE_FILTER);
  const [matchFilter, setMatchFilter] = useState(urlState.match || DEFAULT_MATCH_FILTER);
  const [search, setSearch] = useState(urlState.q || '');
  const [typeFilter, setTypeFilter] = useState(urlState.type || 'all');
  const [resultFilter, setResultFilter] = useState(urlState.result || 'all');
  const [page, setPage] = useState(urlState.page || 1);
  const [pageSize, setPageSize] = useState(urlState.pageSize || DEFAULT_PAGE_SIZE);
  const [selected, setSelected] = useState(() => new Set());
  const [acrossPages, setAcrossPages] = useState(null);
  const busyRef = useRef('');
  const [openCandidateId, setOpenCandidateId] = useState(null);
  const [tlpEditOpen, setTlpEditOpen] = useState(false);
  const [busy, setBusy] = useState('');
  /** Create IOCs UX: processing / completed / failed / ambiguous (not a fake %). */
  const [createOp, setCreateOp] = useState(null);
  const [createElapsedMs, setCreateElapsedMs] = useState(0);
  const [retryAcceptedAt, setRetryAcceptedAt] = useState(0);
  const [retryAcceptedUpdatedAt, setRetryAcceptedUpdatedAt] = useState(null);
  // Maintenance job (refresh_extraction / rerun_ai) whose outcome is still to be reported.
  const [pendingMaintenance, setPendingMaintenance] = useState('');
  const [stickyOffset, setStickyOffset] = useState(0);
  const bulkBarRef = useRef(null);
  // Overlapping detail fetches: only the most recently issued response may land.
  const latestDetail = useRef(createLatestOnly());

  const loadDetail = useCallback(async () => {
    const token = latestDetail.current.next();
    const { data } = await api.get(`/threat-library/reports/${reportId}`);
    if (!latestDetail.current.isLatest(token)) return data;
    setReport((prev) => (shouldIgnoreStalePoll(prev, data?.report) ? prev : (data?.report || null)));
    setCandidates(data?.candidates || []);
    setEntities(data?.entities || []);
    setArtifacts(data?.artifacts || []);
    setDocumentMeta(data?.document_meta || null);
    const jobs = data?.jobs || [];
    setJob(jobs[0] || null);
    return data;
  }, [reportId]);

  const loadStatus = useCallback(async () => {
    const { data } = await api.get(`/threat-library/reports/${reportId}/status`);
    const polled = data?.report || null;
    let ignored = false;
    let previous = null;
    setReport((prev) => {
      previous = prev;
      if (shouldIgnoreStaleFailedPoll(prev, polled, {
        retryAcceptedAt,
        acceptedUpdatedAt: retryAcceptedUpdatedAt
      }) || shouldIgnoreStalePoll(prev, polled)) {
        ignored = true;
        return prev;
      }
      return polled || prev;
    });
    if (!ignored) {
      setJob(data?.job || null);
    }
    return { ...data, _ignoredStaleFailure: ignored, _previous: previous };
  }, [reportId, retryAcceptedAt, retryAcceptedUpdatedAt]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    loadDetail()
      .then(() => {
        if (cancelled) return;
        // Refresh during a sync Create IOCs: never auto-retry; reconcile results.
        const sess = readCreateIocSession(reportId);
        if (!sess) return;
        const age = Date.now() - Number(sess.startedAt || 0);
        clearCreateIocSession();
        if (!Number.isFinite(age) || age < 0 || age > 30 * 60 * 1000) return;
        setCreateOp({
          phase: 'ambiguous',
          eligible: Number(sess.eligible) || 0,
          selected: Number(sess.selected) || 0,
          startedAt: Number(sess.startedAt) || Date.now(),
          summary: null,
          error: null
        });
      })
      .catch((err) => {
        if (!cancelled) setError(err?.response?.data?.message || 'Failed to load report');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [loadDetail, reportId]);

  useEffect(() => {
    if (createOp?.phase !== 'processing' || !createOp.startedAt) {
      setCreateElapsedMs(0);
      return undefined;
    }
    const tick = () => setCreateElapsedMs(Date.now() - createOp.startedAt);
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [createOp?.phase, createOp?.startedAt]);

  useEffect(() => {
    if (createOp?.phase !== 'processing') return undefined;
    const onBeforeUnload = (e) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [createOp?.phase]);

  const processing = isProcessingStatus(report);

  useEffect(() => {
    if (!processing || !reportId) return undefined;
    const timer = window.setInterval(() => {
      loadStatus()
        .then((data) => {
          if (data?._ignoredStaleFailure) return null;
          // Phase change (analyzing → matching → review_required) swaps the
          // preliminary card for the committed review set without a reload.
          if (shouldRefetchDetail(data?._previous, data?.report)) {
            return loadDetail();
          }
          return null;
        })
        .catch(() => {});
    }, 2000);
    return () => window.clearInterval(timer);
  }, [processing, reportId, loadStatus, loadDetail]);

  useEffect(() => {
    if (!pendingMaintenance || processing || !job) return;
    if (job.job_type && job.job_type !== pendingMaintenance) return;
    const outcome = describeMaintenanceOutcome(job);
    if (outcome?.error) setError(outcome.error);
    else if (outcome?.message) setFeedback(outcome.message);
    if (['completed', 'failed', 'cancelled'].includes(String(job.status || ''))) setPendingMaintenance('');
  }, [pendingMaintenance, processing, job]);

  const filtered = useMemo(
    () => filterReviewCandidates(candidates, {
      tab: filter,
      source: sourceFilter,
      match: matchFilter,
      q: search,
      type: typeFilter,
      result: resultFilter
    }),
    [candidates, filter, sourceFilter, matchFilter, search, typeFilter, resultFilter]
  );
  const paged = useMemo(
    () => paginateRows(filtered, page, pageSize),
    [filtered, page, pageSize]
  );
  const pageRows = paged.rows;
  const filterCounts = useMemo(() => buildReviewFilterCounts(candidates), [candidates]);
  const inventorySummary = useMemo(() => describeIndicatorInventorySummary({
    original: filterCounts.indicators || 0,
    totalUnique: filterCounts.total_unique || 0,
    linkedOnly: filterCounts.linked_only || 0,
    needsReview: filterCounts.needs_review || 0
  }), [filterCounts]);
  const filtersDefault = reviewFiltersAreDefault({
    tab: filter,
    source: sourceFilter,
    match: matchFilter,
    type: typeFilter,
    result: resultFilter,
    search
  });

  useEffect(() => {
    const next = withReportView(serializeReviewTableUrlState({
      tab: filter,
      source: sourceFilter,
      match: matchFilter,
      q: search,
      type: typeFilter,
      result: resultFilter,
      page: paged.page,
      pageSize: paged.pageSize
    }), view);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [view, filter, sourceFilter, matchFilter, search, typeFilter, resultFilter, paged.page, paged.pageSize, searchParams, setSearchParams]);

  useEffect(() => {
    if (paged.page !== page) setPage(paged.page);
  }, [paged.page, page]);

  // Sticky table header sits directly under the sticky bulk-action bar.
  useLayoutEffect(() => {
    const el = bulkBarRef.current;
    if (!el) {
      setStickyOffset(0);
      return undefined;
    }
    const measure = () => setStickyOffset(el.offsetHeight || 0);
    measure();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', measure);
      return () => window.removeEventListener('resize', measure);
    }
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [canWrite, view, report?.review_phase]);

  function clearIndicatorSelection() {
    setSelected(() => new Set());
    setAcrossPages(null);
  }

  useEffect(() => {
    setSelected(() => new Set());
    setAcrossPages(null);
  }, [reportId]);

  function changeFilter(next) {
    const dims = normalizeReviewFilterState({ tab: next, source: sourceFilter, match: matchFilter });
    setFilter(dims.tab);
    setSourceFilter(dims.source);
    setMatchFilter(dims.match);
    setPage(1);
    clearIndicatorSelection();
  }

  function changeSource(next) {
    setSourceFilter(next || DEFAULT_SOURCE_FILTER);
    setPage(1);
    clearIndicatorSelection();
  }

  function changeMatch(next) {
    setMatchFilter(next || DEFAULT_MATCH_FILTER);
    setPage(1);
    clearIndicatorSelection();
  }

  function changeSearch(next) {
    setSearch(next);
    setPage(1);
    clearIndicatorSelection();
  }

  function changeType(next) {
    setTypeFilter(next);
    setPage(1);
    clearIndicatorSelection();
  }

  function changeResult(next) {
    setResultFilter(next);
    setPage(1);
    clearIndicatorSelection();
  }

  function resetIndicatorFilters() {
    setFilter(DEFAULT_REVIEW_FILTER);
    setSourceFilter(DEFAULT_SOURCE_FILTER);
    setMatchFilter(DEFAULT_MATCH_FILTER);
    setSearch('');
    setTypeFilter('all');
    setResultFilter('all');
    setPage(1);
    clearIndicatorSelection();
  }

  function changePageSize(next) {
    setPageSize(Number(next) || DEFAULT_PAGE_SIZE);
    setPage(1);
  }

  function goToPage(next) {
    setPage(next);
  }

  function currentFilters() {
    return {
      tab: filter,
      source: sourceFilter,
      match: matchFilter,
      type: typeFilter,
      result: resultFilter,
      search
    };
  }

  function toggleOne(id) {
    if (acrossPages && reviewFiltersEqual(acrossPages.filters, currentFilters())) {
      setAcrossPages((prev) => (prev ? { ...prev, excluded: toggleExcludedId(prev.excluded, id) } : prev));
      return;
    }
    setSelected((prev) => toggleExplicitSelection(prev, id));
  }

  function toggleAllOnPage() {
    const ids = pageRows.map((c) => c.id);
    if (acrossPages && reviewFiltersEqual(acrossPages.filters, currentFilters())) {
      setAcrossPages((prev) => (prev ? { ...prev, excluded: togglePageExcluded(prev.excluded, ids) } : prev));
      return;
    }
    setSelected((prev) => togglePageExplicit(prev, ids));
  }

  function selectAllMatching() {
    setSelected(() => new Set());
    setAcrossPages({
      filters: currentFilters(),
      excluded: new Set()
    });
  }

  /**
   * Review action for the current table selection (the only mutation entry
   * point). Context Only rows are never sent to Approve / Context only /
   * Create IOCs: item-level eligibility is applied here and enforced again by
   * the backend.
   */
  async function runReview(action) {
    if (!canWrite) return;
    if (busyRef.current) return;
    if (createOp?.phase === 'processing') return;
    busyRef.current = action;
    try {
      const acrossActive = acrossPages && reviewFiltersEqual(acrossPages.filters, currentFilters());
      if (acrossActive) {
        if (action === 'promote_to_ioc') {
          await promoteToIoc();
          return;
        }
        await reviewAcrossPages(action);
        return;
      }
      if (action === 'create_iocs') {
        await createIocs();
        return;
      }
      if (action === 'promote_to_ioc') {
        await promoteToIoc();
        return;
      }
      const { ids, excluded } = selectionForAction(action, selectedRows);
      if (action !== 'approve_high_confidence_malicious' && !ids.length) return;
      setBusy(action);
      setFeedback('');
      setError('');
      try {
        if (ids.length > 1 && action !== 'approve_high_confidence_malicious') {
          const dialog = describeBulkActionConfirm({
            action,
            eligible: ids.length,
            matching: selectedRows.length,
            tabLabel: selectionScopeLabel(currentFilters()),
            acrossPages: false,
            excluded
          });
          const ok = await requestConfirm(dialog);
          if (!ok) return;
        }
        const body = { action };
        if (action !== 'approve_high_confidence_malicious') {
          body.candidate_ids = ids;
        }
        const { data } = await api.post(`/threat-library/reports/${reportId}/review`, body);
        const updated = Number.isFinite(Number(data?.updated)) ? Number(data.updated) : null;
        setFeedback(describeReviewFeedback(action, {
          count: updated ?? (action === 'approve_high_confidence_malicious' ? null : ids.length),
          errors: Array.isArray(data?.errors) ? data.errors.length : 0,
          excluded: excluded + (Number(data?.skipped_context_only) || 0)
        }));
        clearIndicatorSelection();
        await loadDetail();
      } catch (err) {
        if (!applyNotReadyRejection(err)) setError(err?.response?.data?.message || 'Review action failed');
      } finally {
        setBusy('');
      }
    } finally {
      busyRef.current = '';
    }
  }

  async function reviewAcrossPages(action) {
    if (!acrossPages) return;
    const filters = acrossPages.filters;
    if (!reviewFiltersEqual(filters, currentFilters())) {
      clearIndicatorSelection();
      setError('Selection was cleared because the filters changed.');
      return;
    }
    const excludedIds = [...acrossPages.excluded];
    const label = selectionScopeLabel(filters);
    let createStartedAt = null;
    let createEligible = 0;
    let createSelected = 0;
    setBusy(action);
    setFeedback('');
    setError('');
    try {
      const { data: preview } = await api.post(`/threat-library/reports/${reportId}/review`, buildAllMatchingReviewBody({
        action,
        filters,
        excludedIds,
        preview: action !== 'create_iocs',
        confirm: action === 'create_iocs' ? false : null
      }));
      let scopeToken = preview?.scope_token;
      if (action === 'create_iocs') {
        const summary = preview?.summary || {};
        const noop = describeNoCreatableIocs(summary);
        if (noop) {
          await requestConfirm({
            ...noop,
            detail: formatCreateIocSummary(summary),
            informational: true,
            cancelLabel: 'Close'
          });
          return;
        }
        const eligible = Number(summary.eligible || 0);
        const ok = await requestConfirm({
          title: `Create ${eligible} IOC${eligible === 1 ? '' : 's'}?`,
          description: `This will create ${eligible} IOC record${eligible === 1 ? '' : 's'} from eligible indicators matching the current ${label} filters across all pages.`,
          detail: formatCreateIocSummary(summary),
          confirmLabel: `Create ${eligible} IOC${eligible === 1 ? '' : 's'}`,
          cancelLabel: 'Cancel'
        });
        if (!ok) return;
      } else {
        const eligible = Number(preview?.eligible || 0);
        const matching = Number(preview?.matching || 0);
        if (eligible <= 0) {
          await requestConfirm({
            title: 'Nothing to update',
            description: matching > 0
              ? `${matching} indicators match this selection, but none are eligible for this action.`
              : 'No indicators match this selection.',
            informational: true,
            cancelLabel: 'Close'
          });
          return;
        }
        const ok = await requestConfirm(describeBulkActionConfirm({
          action,
          eligible,
          matching,
          tabLabel: label,
          acrossPages: true,
          excluded: excludedIds.length
        }));
        if (!ok) return;
      }
      const postCommit = async (token) => {
        const { data } = await api.post(`/threat-library/reports/${reportId}/review`, buildAllMatchingReviewBody({
          action,
          filters,
          excludedIds,
          scopeToken: token,
          confirm: action === 'create_iocs' ? true : null
        }));
        return data;
      };

      if (action === 'create_iocs') {
        createEligible = Number(preview?.summary?.eligible || 0);
        createSelected = Number(preview?.summary?.selected || preview?.matching || 0);
        createStartedAt = Date.now();
        writeCreateIocSession({
          reportId,
          startedAt: createStartedAt,
          eligible: createEligible,
          selected: createSelected,
          acrossPages: true
        });
        setCreateOp({
          phase: 'processing',
          eligible: createEligible,
          selected: createSelected,
          startedAt: createStartedAt,
          summary: null,
          error: null
        });
        setCreateElapsedMs(0);
      }

      let data;
      try {
        data = await postCommit(scopeToken);
      } catch (err) {
        const conflict = err?.response?.data;
        if (conflict?.code !== 'selection_conflict') throw err;
        if (action === 'create_iocs') {
          clearCreateIocSession();
          setCreateOp(null);
        }
        const again = await requestConfirm({
          title: 'Selection changed',
          description: conflict.message || 'The selected indicators changed before this action ran.',
          detail: `${Number(conflict.eligible) || 0} eligible indicators match the current filters now (${Number(conflict.matching) || 0} matching). Confirm again to continue with that set only.`,
          confirmLabel: `Continue with ${Number(conflict.eligible) || 0}`,
          cancelLabel: 'Cancel'
        });
        if (!again) return;
        if (action === 'create_iocs') {
          createEligible = Number(conflict.eligible) || createEligible;
          createSelected = Number(conflict.matching) || createSelected;
          createStartedAt = Date.now();
          writeCreateIocSession({
            reportId,
            startedAt: createStartedAt,
            eligible: createEligible,
            selected: createSelected,
            acrossPages: true
          });
          setCreateOp({
            phase: 'processing',
            eligible: createEligible,
            selected: createSelected,
            startedAt: createStartedAt,
            summary: null,
            error: null
          });
        }
        try {
          data = await postCommit(conflict.scope_token);
        } catch (err2) {
          if (err2?.response?.data?.code === 'selection_conflict') {
            clearCreateIocSession();
            setCreateOp(null);
            setError(err2.response.data.message || 'The selection changed again. Refresh the indicators and select them again.');
            clearIndicatorSelection();
            return;
          }
          throw err2;
        }
      }
      if (action === 'create_iocs') {
        await finishCreateIocsSuccess(data, {
          eligible: createEligible,
          selectedCount: createSelected,
          startedAt: createStartedAt || Date.now()
        });
      } else {
        setFeedback(describeAcrossPagesOutcome(action, data));
        clearIndicatorSelection();
        await loadDetail();
      }
    } catch (err) {
      if (action === 'create_iocs') {
        await finishCreateIocsFailure(err, {
          eligible: createEligible,
          selectedCount: createSelected,
          startedAt: createStartedAt || Date.now()
        });
        return;
      }
      if (!applyNotReadyRejection(err)) setError(err?.response?.data?.message || 'Review action failed');
    } finally {
      setBusy('');
    }
  }

  async function finishCreateIocsSuccess(data, { eligible, selectedCount, startedAt }) {
    if (data?.results) setCandidates((prev) => applyPromotionResults(prev, data.results));
    const created = data?.summary?.created ?? data?.created?.length ?? 0;
    const existing = data?.summary?.already_existing ?? 0;
    const failed = Array.isArray(data?.errors) ? data.errors.length : Number(data?.summary?.failed || 0);
    const elapsedMs = Date.now() - startedAt;
    clearCreateIocSession();
    setCreateOp({
      phase: 'completed',
      eligible,
      selected: selectedCount,
      startedAt,
      summary: data?.summary || { created, already_existing: existing, failed },
      error: null,
      elapsedMs
    });
    setFeedback(describeCreateIocFeedback({ created, existing, errors: failed }));
    clearIndicatorSelection();
    await loadDetail();
  }

  async function finishCreateIocsFailure(err, { eligible, selectedCount, startedAt }) {
    const elapsedMs = Date.now() - startedAt;
    if (err?.response?.data?.code === 'create_iocs_none_eligible') {
      clearCreateIocSession();
      setCreateOp(null);
      await requestConfirm({
        title: 'Approve indicators first',
        description: err.response.data.message
          || 'Only approved indicators can be created as IOCs. Review and approve the selected indicators before creating IOC records.',
        detail: err.response.data.summary ? formatCreateIocSummary(err.response.data.summary) : '',
        informational: true,
        cancelLabel: 'Close'
      });
      return;
    }
    if (err?.response?.data?.code === 'create_iocs_in_progress') {
      clearCreateIocSession();
      setCreateOp({
        phase: 'failed',
        eligible,
        selected: selectedCount,
        startedAt,
        summary: null,
        error: err.response.data.message || 'IOC creation is already in progress for this report.',
        elapsedMs
      });
      return;
    }
    if (isCreateIocAmbiguousFailure(err)) {
      clearCreateIocSession();
      setCreateOp({
        phase: 'ambiguous',
        eligible,
        selected: selectedCount,
        startedAt,
        summary: null,
        error: null,
        elapsedMs
      });
      setError('');
      try {
        await loadDetail();
      } catch {
        /* panel already explains refresh may be needed */
      }
      return;
    }
    clearCreateIocSession();
    if (!applyNotReadyRejection(err)) {
      setCreateOp({
        phase: 'failed',
        eligible,
        selected: selectedCount,
        startedAt,
        summary: null,
        error: err?.response?.data?.message || 'Review action failed',
        elapsedMs
      });
      setError(err?.response?.data?.message || 'Review action failed');
    } else {
      setCreateOp(null);
    }
  }

  async function createIocs() {
    if (!canWrite || !selected.size) return;
    if (createOp?.phase === 'processing' || busyRef.current === 'create_iocs') return;
    const { ids, excluded } = selectionForAction('create_iocs', selectedRows);
    if (!ids.length) return;
    setBusy('create_iocs');
    setFeedback('');
    setError('');
    const excludedNote = excluded > 0
      ? `\n${excluded} Context Only row${excluded === 1 ? ' is' : 's are'} not an IOC candidate and ${excluded === 1 ? 'was' : 'were'} left out.`
      : '';
    try {
      const { data: preview } = await api.post(`/threat-library/reports/${reportId}/review`, {
        action: 'create_iocs',
        candidate_ids: ids,
        confirm: false
      });
      const summary = preview?.summary || {};
      const eligible = Number(summary.eligible || 0);
      // Nothing to create: informational only, no mutation and no OK action.
      // Existing rows already read as "Already exists" from their IOC link.
      const noop = describeNoCreatableIocs(summary);
      if (noop) {
        await requestConfirm({
          ...noop,
          detail: formatCreateIocSummary(summary) + excludedNote,
          informational: true,
          cancelLabel: 'Close'
        });
        return;
      }
      const ok = await requestConfirm({
        title: eligible < (summary.selected || 0) ? 'Create approved IOCs?' : 'Create IOC records?',
        description: eligible < (summary.selected || 0)
          ? `Only the ${eligible} eligible approved indicators will be created.`
          : `${eligible} new IOC record${eligible === 1 ? '' : 's'} will be created.`,
        detail: formatCreateIocSummary(summary) + excludedNote,
        confirmLabel: `Create ${eligible} IOC${eligible === 1 ? '' : 's'}`,
        cancelLabel: 'Cancel'
      });
      if (!ok) return;

      const startedAt = Date.now();
      const selectedCount = Number(summary.selected) || ids.length;
      writeCreateIocSession({
        reportId,
        startedAt,
        eligible,
        selected: selectedCount,
        acrossPages: false
      });
      setCreateOp({
        phase: 'processing',
        eligible,
        selected: selectedCount,
        startedAt,
        summary: null,
        error: null
      });
      setCreateElapsedMs(0);

      try {
        const { data } = await api.post(`/threat-library/reports/${reportId}/review`, {
          action: 'create_iocs',
          candidate_ids: ids,
          confirm: true
        });
        await finishCreateIocsSuccess(data, { eligible, selectedCount, startedAt });
      } catch (err) {
        await finishCreateIocsFailure(err, { eligible, selectedCount, startedAt });
      }
    } catch (err) {
      if (err?.response?.data?.code === 'create_iocs_none_eligible') {
        await requestConfirm({
          title: 'Approve indicators first',
          description: err.response.data.message
            || 'Only approved indicators can be created as IOCs. Review and approve the selected indicators before creating IOC records.',
          detail: err.response.data.summary ? formatCreateIocSummary(err.response.data.summary) : '',
          informational: true,
          cancelLabel: 'Close'
        });
        return;
      }
      if (!applyNotReadyRejection(err)) setError(err?.response?.data?.message || 'Review action failed');
    } finally {
      setBusy('');
    }
  }

  /**
   * Row-level Context Only override. Exactly one selected Context Only row is
   * re-classified as an approved IOC candidate and created (or linked) through
   * the normal Create IOCs path, after an explicit confirmation that names the
   * transition. Never a bulk path.
   */
  async function promoteToIoc() {
    if (!canWrite || selectedRows.length !== 1) return;
    const row = selectedRows[0];
    if (!isContextOnlyCandidate(row)) return;
    const value = candidateDisplayValue(row) || String(row.id);
    const ok = await requestConfirm({
      title: 'Promote to IOC?',
      description: `${value} is classified as Context Only. Promote it to an IOC?`,
      detail: [
        'This is an analyst override of the report evidence.',
        'The indicator will be re-classified as an approved IOC candidate and an IOC record will be created, or linked if one already exists.',
        'Context Only indicators are never created as IOCs in bulk.'
      ].join('\n'),
      confirmLabel: 'Promote to IOC',
      cancelLabel: 'Cancel',
      variant: 'warning'
    });
    if (!ok) return;
    setBusy('promote_to_ioc');
    setFeedback('');
    setError('');
    try {
      const { data } = await api.post(`/threat-library/reports/${reportId}/review`, {
        action: 'promote_to_ioc',
        candidate_ids: [row.id]
      });
      if (data?.results) setCandidates((prev) => applyPromotionResults(prev, data.results));
      setFeedback(describePromoteFeedback(data, value));
      clearIndicatorSelection();
      await loadDetail();
    } catch (err) {
      if (!applyNotReadyRejection(err)) setError(err?.response?.data?.message || 'Promote to IOC failed');
    } finally {
      setBusy('');
    }
  }

  /**
   * Backend refused because the candidate set is still moving: adopt the
   * authoritative report state (polling resumes) instead of a generic error.
   */
  function applyNotReadyRejection(err) {
    const data = err?.response?.data;
    if (data?.code !== REVIEW_NOT_READY_CODE) return false;
    if (data.report) {
      setReport((prev) => (shouldIgnoreStalePoll(prev, data.report) ? prev : data.report));
      setCandidates([]);
    }
    clearIndicatorSelection();
    setOpenCandidateId(null);
    setError(data.message || 'The indicator set is still being refined. Review actions are available once analysis completes.');
    return true;
  }

  async function finalize() {
    if (!canWrite) return;
    setBusy('finalize');
    setError('');
    try {
      await api.post(`/threat-library/reports/${reportId}/finalize`);
      setFeedback('Report finalized.');
      await loadDetail();
    } catch (err) {
      if (err?.response?.data?.code === 'pending_review_remaining') {
        const count = err.response.data.pending_count;
        const ok = await requestConfirm({
          title: `${count} indicator${count === 1 ? '' : 's'} still need review.`,
          description: err.response.data.message || 'Review remaining indicators before finalizing.',
          confirmLabel: 'Show Needs Review',
          cancelLabel: 'Close',
          variant: 'warning'
        });
        if (ok) {
          setView(REPORT_VIEWS.INDICATORS);
          changeFilter('needs_review');
        }
        return;
      }
      if (!applyNotReadyRejection(err)) setError(err?.response?.data?.message || 'Finalize failed');
    } finally {
      setBusy('');
    }
  }

  async function saveSourceUrl(nextUrl) {
    const { data } = await api.patch(`/threat-library/reports/${reportId}`, { source_url: nextUrl });
    if (data?.report) {
      setReport((prev) => ({ ...prev, ...data.report }));
    }
    setFeedback('Source URL saved.');
  }

  /**
   * Manual TLP override (analyst / admin). The backend marks it `manual` so
   * re-analysis keeps it; reducing the restriction asks for confirmation.
   */
  async function saveTlp(nextTlp) {
    if (!canEditTlp({ canWrite, report })) return;
    const confirm = describeTlpChangeConfirm(report?.tlp, nextTlp);
    if (confirm) {
      const ok = await requestConfirm(confirm);
      if (!ok) return;
    }
    setBusy('tlp');
    setError('');
    try {
      const { data } = await api.patch(`/threat-library/reports/${reportId}`, { tlp: nextTlp });
      if (data?.report) {
        setReport((prev) => ({ ...prev, ...data.report }));
      }
      setFeedback(describeTlpSavedFeedback(data?.report?.tlp || nextTlp));
      setTlpEditOpen(false);
    } finally {
      setBusy('');
    }
  }

  async function retry() {
    if (!canWrite || busy || isProcessingStatus(report)) return;
    setBusy('retry');
    setError('');
    try {
      const { data } = await api.post(`/threat-library/reports/${reportId}/retry`);
      const applied = applyRetryAcceptedState(data);
      if (applied.report) setReport((prev) => mergeReportPayload(prev, applied.report));
      if (applied.job) setJob(applied.job);
      // The review set is being rebuilt: previous rows are no longer current.
      setCandidates([]);
      clearIndicatorSelection();
      setOpenCandidateId(null);
      setRetryAcceptedAt(Date.now());
      setRetryAcceptedUpdatedAt(applied.report?.updated_at || null);
      setFeedback(
        applied.alreadyRunning
          ? 'Analysis is already running. Showing live progress.'
          : 'Analysis resumed from saved document and candidates (AI stage only).'
      );
      // Authoritative state already applied from 202; poll continues via processing effect.
      await loadStatus().catch(() => {});
    } catch (err) {
      const code = err?.response?.data?.code;
      if (code === 'analysis_already_running' && err?.response?.data?.report) {
        const applied = applyRetryAcceptedState(err.response.data);
        if (applied.report) setReport((prev) => mergeReportPayload(prev, applied.report));
        if (applied.job) setJob(applied.job);
        setCandidates([]);
        clearIndicatorSelection();
        setOpenCandidateId(null);
        setRetryAcceptedAt(Date.now());
        setRetryAcceptedUpdatedAt(applied.report?.updated_at || null);
        setFeedback('Analysis is already running. Showing live progress.');
      } else {
        setError(err?.response?.data?.message || 'Retry failed');
      }
    } finally {
      setBusy('');
    }
  }

  /**
   * Refresh extraction (deterministic, no AI) / Re-run AI analysis. Each asks
   * for confirmation with text that states whether AI runs.
   */
  async function runMaintenance(mode) {
    if (!canWrite || busy || isProcessingStatus(report)) return;
    const refresh = mode === MAINTENANCE_MODES.REFRESH_EXTRACTION;
    const ok = await requestConfirm(refresh ? REFRESH_EXTRACTION_CONFIRM : RERUN_AI_CONFIRM);
    if (!ok) return;
    setBusy(mode);
    setError('');
    try {
      const path = refresh ? 'refresh-extraction' : 'rerun-ai';
      const { data } = await api.post(`/threat-library/reports/${reportId}/${path}`);
      if (data?.report) setReport((prev) => mergeReportPayload(prev, data.report));
      if (data?.job) setJob(data.job);
      // The candidate set is being rebuilt: previous rows are no longer current.
      setCandidates([]);
      clearIndicatorSelection();
      setOpenCandidateId(null);
      setPendingMaintenance(mode);
      setFeedback(describeMaintenanceAccepted(mode));
      await loadStatus().catch(() => {});
    } catch (err) {
      const data = err?.response?.data;
      if (data?.code === 'analysis_already_running' && data?.report) {
        setReport((prev) => mergeReportPayload(prev, data.report));
        setFeedback('Analysis is already running. Showing live progress.');
      } else {
        setError(data?.message || (refresh ? 'Refresh extraction failed' : 'Re-run AI analysis failed'));
      }
    } finally {
      setBusy('');
    }
  }

  async function cancelAnalysis() {
    if (!canWrite) return;
    setBusy('cancel');
    setError('');
    try {
      await api.post(`/threat-library/reports/${reportId}/cancel`);
      setFeedback('Cancel requested. The worker will stop at the next checkpoint.');
      await loadStatus();
    } catch (err) {
      setError(err?.response?.data?.message || 'Cancel failed');
    } finally {
      setBusy('');
    }
  }

  async function exportThib() {
    if (!canWrite) return;
    setBusy('export');
    setError('');
    try {
      const tlp = normalizeTlp(report?.tlp);
      let confirmRed = '';
      if (tlp === 'red') {
        if (!isAdmin) {
          setError('TLP:RED export requires admin.');
          return;
        }
        const ok = window.confirm('This report is TLP:RED. Export deliberately?');
        if (!ok) return;
        confirmRed = '?confirm_red=1';
      }
      const res = await api.get(`/threat-library/reports/${reportId}/export/thib${confirmRed}`, {
        responseType: 'blob'
      });
      const blob = new Blob([res.data], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${String(report?.title || 'report').replace(/[^\w.\-]+/g, '_').slice(0, 80)}.thib.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setFeedback('Bundle downloaded.');
    } catch (err) {
      let message = 'Export failed';
      const data = err?.response?.data;
      if (data instanceof Blob) {
        try {
          const text = await data.text();
          const parsed = JSON.parse(text);
          message = parsed.message || message;
        } catch { /* ignore */ }
      } else if (data?.message) {
        message = data.message;
      }
      setError(message);
    } finally {
      setBusy('');
    }
  }

  async function removeReport() {
    if (!isAdmin) return;
    const ok = window.confirm('Delete this Threat Library report permanently?');
    if (!ok) return;
    setBusy('delete');
    try {
      await api.delete(`/threat-library/reports/${reportId}`);
      navigate('/threat-intelligence/threat-library');
    } catch (err) {
      setError(err?.response?.data?.message || 'Delete failed');
      setBusy('');
    }
  }

  const phase = resolveReportPhase(report);
  const showReview = Boolean(report) && canShowReviewTable(report);
  const showPreliminary = Boolean(report) && !loading && (phase === REPORT_PHASES.PREPARING || phase === REPORT_PHASES.FAILED);
  const scopedCandidates = useMemo(() => withInferredPublisherIocScope(candidates), [candidates]);
  const reviewCount = useMemo(
    () => scopedCandidates.filter((c) => isReviewIndicator(c)).length,
    [scopedCandidates]
  );
  const indicatorCount = describeIndicatorCount(report, showReview ? { reviewCount } : { rawCount: candidates.length || null });
  const metrics = useMemo(() => buildOverviewMetrics(candidates, report), [candidates, report]);
  const tabs = useMemo(() => buildReportTabs({
    indicatorCount: indicatorCount.value,
    indicatorCountStable: showReview,
    entityCount: entities.length,
    iocSourceCount: report?.ioc_source_summary?.total ?? null
  }), [indicatorCount.value, showReview, entities.length, report?.ioc_source_summary?.total]);
  const reportDetails = useMemo(() => buildReportDetails(report, {
    documentMeta,
    artifacts,
    entityCount: entities.length,
    indicatorCount: showReview ? indicatorCount : null,
    formatDateTime: formatUserDateTime,
    tlpLabel: report ? `${tlpDisplay(report.tlp, report.tlp_display)} · ${tlpSourceShortLabel(report.tlp_source)}` : null
  }), [report, documentMeta, artifacts, entities.length, showReview, indicatorCount]);
  const sourceDetails = useMemo(() => {
    const items = buildSourceDetails(report, { documentMeta, artifacts, formatDateTime: formatUserDateTime });
    // The file name is already the card's identity when there is no source name.
    return report && !report.source_name && report.source_file_name ? items.filter((i) => i.key !== 'file_name') : items;
  }, [report, documentMeta, artifacts]);
  const entityGroups = useMemo(() => groupEntitiesByType(entities), [entities]);
  const openCandidate = useMemo(
    () => (openCandidateId == null ? null : candidates.find((c) => c.id === openCandidateId) || null),
    [candidates, openCandidateId]
  );
  // Previous / Next walk the whole filtered set (every page), not just the visible page.
  const drawerPosition = useMemo(
    () => describeDrawerPosition(filtered, openCandidateId, paged.pageSize),
    [filtered, openCandidateId, paged.pageSize]
  );
  const acrossActive = Boolean(acrossPages && reviewFiltersEqual(acrossPages.filters, currentFilters()));
  const selectedRows = useMemo(() => {
    if (acrossActive) return filtered.filter((c) => !acrossPages.excluded.has(c.id));
    return candidates.filter((c) => selected.has(c.id));
  }, [acrossActive, acrossPages, filtered, candidates, selected]);
  const selectedOnPage = useMemo(() => pageRows.filter((c) => (
    acrossActive ? !acrossPages.excluded.has(c.id) : selected.has(c.id)
  )).length, [pageRows, acrossActive, acrossPages, selected]);
  const pageCheck = headerCheckState({
    mode: acrossActive ? 'all_matching' : 'explicit',
    selectedIds: selected,
    excludedIds: acrossPages?.excluded,
    pageIds: pageRows.map((c) => c.id)
  });
  const selectionBanner = describeSelectionBanner({
    mode: acrossActive ? 'all_matching' : 'explicit',
    selectedCount: acrossActive ? selectedRows.length : selected.size,
    pageIds: pageRows.map((c) => c.id),
    pageSelectedCount: selectedOnPage,
    matchingCount: filtered.length,
    excludedCount: acrossActive ? Math.max(0, filtered.length - selectedRows.length) : 0,
    scopeLabel: selectionScopeLabel(currentFilters())
  });
  // Which review actions exist for this filter and whether the selection can drive them.
  const toolbar = useMemo(
    () => describeReviewToolbar({
      filter,
      selectedRows,
      busy: Boolean(busy) || createOp?.phase === 'processing'
    }),
    [filter, selectedRows, busy, createOp?.phase]
  );

  const createOpModel = useMemo(() => {
    if (!createOp?.phase) return null;
    return describeCreateIocOperationPanel({
      phase: createOp.phase,
      eligible: createOp.eligible,
      selected: createOp.selected,
      summary: createOp.summary,
      elapsedMs: createOp.phase === 'processing'
        ? createElapsedMs
        : (createOp.elapsedMs || createElapsedMs),
      error: createOp.error
    });
  }, [createOp, createElapsedMs]);
  const overflowItems = [
    canShowRefreshExtraction(report, { busy: Boolean(busy), canWrite })
      ? { id: 'refresh-extraction', label: 'Refresh extraction', disabled: Boolean(busy), onSelect: () => runMaintenance(MAINTENANCE_MODES.REFRESH_EXTRACTION).catch(() => {}) }
      : null,
    canShowRerunAi(report, { busy: Boolean(busy), canWrite })
      ? { id: 'rerun-ai', label: 'Re-run AI analysis', disabled: Boolean(busy), onSelect: () => runMaintenance(MAINTENANCE_MODES.RERUN_AI).catch(() => {}) }
      : null,
    isAdmin ? { id: 'delete', label: 'Delete report', danger: true, disabled: Boolean(busy), onSelect: () => removeReport().catch(() => {}) } : null
  ];
  const canCancel = canWrite && processing && ['analyzing', 'matching', 'fetching', 'extracting', 'candidates', 'pending'].includes(String(report?.analysis_status || ''));

  function openRow(c) {
    setOpenCandidateId(c.id);
  }

  /** Drawer navigation: follow the row onto its page without touching the selection. */
  function navigateDrawer(nextId) {
    if (nextId == null) return;
    const target = describeDrawerPosition(filtered, nextId, paged.pageSize);
    if (target.index > 0 && target.page !== paged.page) setPage(target.page);
    setOpenCandidateId(nextId);
  }

  function onRowClick(e, c) {
    if (isInteractiveTarget(e.target)) return;
    const selection = typeof window !== 'undefined' && window.getSelection ? String(window.getSelection() || '') : '';
    if (selection) return;
    openRow(c);
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div className="tl-report-header">
          <div className="tl-report-header__title">
            <Link to="/threat-intelligence/threat-library" style={{ color: '#94a3b8', fontSize: 12, textDecoration: 'none' }}>
              ← Threat Library
            </Link>
            <h1 style={{ ...ui.pageTitle, marginTop: 6, overflowWrap: 'anywhere' }}>
              {loading ? 'Loading…' : (report?.title || 'Report')}
            </h1>
            {report ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', marginTop: 8 }}>
                <span
                  data-testid="report-tlp"
                  data-tlp={normalizeTlp(report.tlp)}
                  data-tlp-source={report.tlp_source || 'default'}
                  title={`TLP: ${tlpSourceLabel(report.tlp_source)}`}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  <TlpBadge tlp={report.tlp} display={report.tlp_display} />
                  {canEditTlp({ canWrite, report }) ? (
                    <button
                      type="button"
                      className="tl-ghost-btn"
                      style={{ minHeight: 24, padding: '2px 8px', fontSize: 11 }}
                      disabled={Boolean(busy)}
                      onClick={() => setTlpEditOpen(true)}
                      aria-label="Edit TLP classification"
                    >
                      Edit TLP
                    </button>
                  ) : null}
                </span>
                <span style={badgeStyle({ border: '#334155', bg: '#1e293b', color: '#cbd5e1' })} data-testid="report-status">
                  {statusLabel(report)}
                </span>
                {report.report_type ? (
                  <span style={{ fontSize: 12, color: '#94a3b8' }}>{humanizeEnum(report.report_type)}</span>
                ) : null}
                <ReportTagsEditor
                  reportId={reportId}
                  tags={report.tags}
                  canWrite={canWrite}
                  disabled={Boolean(busy)}
                  onChange={(nextTags) => setReport((prev) => (prev ? { ...prev, tags: nextTags } : prev))}
                  onError={(message) => setError(message)}
                />
              </div>
            ) : null}
          </div>
          {report ? (
            <div className="tl-report-header__actions">
              {canCancel ? (
                <button type="button" style={ui.btn} disabled={Boolean(busy)} onClick={() => cancelAnalysis().catch(() => {})}>
                  Cancel analysis
                </button>
              ) : null}
              {canShowRetryButton(report, { busy: Boolean(busy), canWrite }) ? (
                <button type="button" style={ui.btn} disabled={Boolean(busy)} onClick={() => retry().catch(() => {})}>
                  {busy === 'retry' ? 'Starting…' : 'Retry analysis'}
                </button>
              ) : null}
              {canWrite ? (
                <button type="button" style={ui.btn} disabled={Boolean(busy)} onClick={() => exportThib().catch(() => {})}>
                  Export THIB
                </button>
              ) : null}
              <ReportActionsMenu items={overflowItems} disabled={Boolean(busy)} />
              {canWrite && canFinalize(report) ? (
                <button type="button" style={ui.btnPrimary} disabled={Boolean(busy)} onClick={() => finalize().catch(() => {})}>
                  {busy === 'finalize' ? 'Finalizing…' : 'Finalize report'}
                </button>
              ) : null}
            </div>
          ) : null}
        </div>

        {isElevatedTlp(report?.tlp) ? (
          <div style={ui.warnBanner}>
            This report is marked {report?.tlp_display || 'with an elevated TLP'}. Limit redistribution and export carefully.
          </div>
        ) : null}

        {error ? <div style={{ ...ui.error, marginBottom: 10 }} role="alert">{error}</div> : null}
        {feedback ? <div style={{ ...ui.infoBanner }}>{feedback}</div> : null}

        {loading ? <div style={ui.muted}>Loading report…</div> : null}
        {!loading && !report ? <div style={ui.muted}>Report not found.</div> : null}

        {report && shouldShowProcessingPanel(report) ? (
          <SectionCard title={processingSectionTitle(report)}>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: '#94a3b8' }}>
              {isRefreshExtractionInProgress(report, job)
                ? 'Re-running deterministic extraction and IOC matching. AI analysis does not run.'
                : 'Analysis is running. Progress updates every few seconds from the worker — not a fake timer.'}
            </p>
            <ProgressChecklist report={report} job={job} />
          </SectionCard>
        ) : null}

        {report && shouldShowFailedPanel(report) ? (
          <SectionCard title={processingSectionTitle(report)}>
            <ProgressChecklist report={report} job={job} />
            <div style={{ ...ui.error, marginTop: 12 }}>
              {report.failure_code ? <strong style={{ display: 'block', marginBottom: 4 }}>{report.failure_code}</strong> : null}
              {report.failure_reason || job?.error_message || 'Analysis failed'}
              {report.failure_stage ? ` (stage: ${report.failure_stage})` : ''}
              {describeAnalysisFailureDetail(report).length ? (
                <ul style={{ margin: '8px 0 0', paddingLeft: 18, fontSize: 12 }}>
                  {describeAnalysisFailureDetail(report).map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              ) : null}
              {Array.isArray(report.failure_details?.issues) && report.failure_details.issues.length ? (
                <ul style={{ margin: '8px 0 0', paddingLeft: 18, fontSize: 12 }}>
                  {report.failure_details.issues.slice(0, 8).map((issue, idx) => (
                    <li key={`${issue.path || 'p'}-${idx}`}>
                      <code>{issue.path || '(root)'}</code>: {issue.message}
                      {issue.received ? ` (received ${issue.received})` : ''}
                    </li>
                  ))}
                </ul>
              ) : null}
              {['source_verification_required', 'source_blocked', 'source_access_denied', 'article_not_found'].includes(
                String(report.failure_code || '')
              ) ? (
                <p style={{ margin: '10px 0 0', fontSize: 12, color: '#fecaca' }}>
                  Tip: if the publisher blocks automated fetch, import a PDF export or a THIB bundle instead of Retrying the same URL.
                </p>
              ) : null}
            </div>
          </SectionCard>
        ) : null}

        {report ? <ReportTabBar tabs={tabs} active={view} onChange={setView} /> : null}

        {report && view === REPORT_VIEWS.OVERVIEW ? (
          <div role="tabpanel" id="tl-panel-overview" aria-labelledby="tl-tab-overview">
            {metrics.available ? (
              <div className="tl-statstrip" data-testid="overview-metrics">
                <Stat label="Candidates" value={metrics.candidates} testId="metric-candidates" />
                <Stat label="New" value={metrics.new} testId="metric-new" />
                <Stat label="Existing" value={metrics.existing} testId="metric-existing" />
                <Stat label="Needs review" value={metrics.needsReview} testId="metric-needs-review" />
                <Stat label="Reviewed" value={`${metrics.reviewed}/${metrics.total}`} testId="metric-progress">
                  <span
                    className="tl-progress tl-progress--inline"
                    role="progressbar"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={metrics.progressPct}
                    aria-label="Review progress"
                    title={`${metrics.progressPct}% reviewed`}
                  >
                    <span className="tl-progress__bar" style={{ width: `${metrics.progressPct}%` }} />
                  </span>
                </Stat>
              </div>
            ) : (
              describeOverviewPhaseNote(report) ? (
                <div style={{ ...ui.muted, marginBottom: 14 }}>{describeOverviewPhaseNote(report)}</div>
              ) : null
            )}

            <div className="tl-overview">
              <div className="tl-overview__summary">
                <h2 className="tl-heading">Summary</h2>
                <div className="tl-summary" data-testid="report-summary">
                  {report.summary || <span style={{ color: '#64748b' }}>No summary available yet.</span>}
                </div>
              </div>
              <div className="tl-overview__info">
                <h2 className="tl-heading">Report information</h2>
                <DetailList items={reportDetails} testId="report-details" className="tl-dl--info" />
              </div>
            </div>
            {(Array.isArray(report.tags) && report.tags.length) || canWrite ? (
              <section className="tl-intel" data-testid="overview-tags">
                <h2 className="tl-heading">Tags</h2>
                <ReportTagsEditor
                  reportId={reportId}
                  tags={report.tags}
                  canWrite={canWrite}
                  disabled={Boolean(busy)}
                  onChange={(nextTags) => setReport((prev) => (prev ? { ...prev, tags: nextTags } : prev))}
                  onError={(message) => setError(message)}
                />
              </section>
            ) : null}
          </div>
        ) : null}

        {report && view === REPORT_VIEWS.INDICATORS ? (
          <div role="tabpanel" id="tl-panel-indicators" aria-labelledby="tl-tab-indicators">
            {showPreliminary ? (
              <PreliminaryIndicatorsCard
                report={report}
                job={job}
                candidates={candidates}
                onRetry={() => retry().catch(() => {})}
                retryEnabled={canShowRetryButton(report, { busy: Boolean(busy), canWrite })}
                busy={busy}
              />
            ) : null}

            {showReview ? (
              <div>
                <div className="tl-inventory-summary" data-testid="indicator-inventory-summary" aria-label="Indicator inventory summary">
                  <p className="tl-inventory-summary__headline">{inventorySummary.headline}</p>
                  <p className="tl-inventory-summary__detail">{inventorySummary.detail}</p>
                </div>
                <div className="tl-filterbar" data-testid="indicator-filterbar">
                  <div className="tl-filterbar__tabs" role="tablist" aria-label="Indicator view">
                    {PRIMARY_REVIEW_VIEWS.map((f) => (
                      <button
                        key={f.id}
                        type="button"
                        role="tab"
                        aria-selected={filter === f.id}
                        className={`tl-filter-tab${f.id === 'all' ? ' tl-filter-tab--advanced' : ''}`}
                        data-testid={`filter-tab-${f.id}`}
                        onClick={() => changeFilter(f.id)}
                        title={f.id === 'all'
                          ? 'Include every extracted candidate, including narrative-only and contextual rows'
                          : undefined}
                      >
                        {f.label}
                        <span className="tl-filter-tab__count" data-testid={`filter-count-${f.id}`}>
                          {filterCounts[f.id] ?? 0}
                        </span>
                      </button>
                    ))}
                  </div>
                  <div className="tl-filterbar__controls">
                    <div className="tl-filter-field">
                      <label htmlFor="tl-source-filter">Source</label>
                      <select
                        id="tl-source-filter"
                        data-testid="source-filter"
                        value={sourceFilter}
                        onChange={(e) => changeSource(e.target.value)}
                        style={compactSelect}
                        title="Original report vs linked-source provenance. Linked sources may overlap the original report; Linked only is exclusive."
                      >
                        {SOURCE_FILTERS.map((t) => (
                          <option key={t.id} value={t.id}>{t.label}</option>
                        ))}
                      </select>
                    </div>
                    <div className="tl-filter-field">
                      <label htmlFor="tl-match-filter">IOC match</label>
                      <select
                        id="tl-match-filter"
                        data-testid="match-filter"
                        value={matchFilter}
                        onChange={(e) => changeMatch(e.target.value)}
                        style={compactSelect}
                        title="Relationship to the global IOC inventory. Independent of review status and Create IOCs outcome."
                      >
                        {MATCH_FILTERS.map((t) => (
                          <option key={t.id} value={t.id}>{t.label}</option>
                        ))}
                      </select>
                    </div>
                    <div className="tl-filter-field">
                      <label htmlFor="tl-type-filter">Type</label>
                      <select
                        id="tl-type-filter"
                        data-testid="type-filter"
                        value={typeFilter}
                        onChange={(e) => changeType(e.target.value)}
                        style={compactSelect}
                      >
                        {TYPE_FILTERS.map((t) => (
                          <option key={t.id} value={t.id}>{t.label}</option>
                        ))}
                      </select>
                    </div>
                    <div className="tl-filter-field">
                      <label htmlFor="tl-result-filter">Creation result</label>
                      <select
                        id="tl-result-filter"
                        data-testid="result-filter"
                        value={resultFilter}
                        onChange={(e) => changeResult(e.target.value)}
                        style={compactSelect}
                        title="Outcome of Create IOCs for this candidate, not global inventory match."
                      >
                        {RESULT_FILTERS.map((t) => (
                          <option key={t.id} value={t.id}>{t.label}</option>
                        ))}
                      </select>
                    </div>
                    <div className="tl-filter-field tl-filter-field--search">
                      <label htmlFor="tl-indicator-search">Search</label>
                      <input
                        id="tl-indicator-search"
                        type="search"
                        value={search}
                        onChange={(e) => changeSearch(e.target.value)}
                        placeholder="Search indicators…"
                        style={{ ...compactInput, width: 200, maxWidth: '100%' }}
                      />
                    </div>
                    {!filtersDefault ? (
                      <button
                        type="button"
                        className="tl-ghost-btn"
                        data-testid="reset-filters"
                        onClick={resetIndicatorFilters}
                      >
                        Reset filters
                      </button>
                    ) : null}
                  </div>
                </div>

                {canWrite ? (
                  <div className="tl-bulkbar" ref={bulkBarRef} data-testid="bulk-actions" data-review-filter={filter}>
                    {/* Context Only != IOC candidate: the toolbar descriptor renders only the actions valid for this filter. */}
                    {toolbar.actions.map((a) => (
                      <button
                        key={a.id}
                        type="button"
                        data-review-action={a.id}
                        style={compactBtn(a.primary ? compactPrimary : compactAction, !a.enabled)}
                        disabled={!a.enabled}
                        title={!a.enabled && a.hint ? a.hint : undefined}
                        onClick={() => runReview(a.id).catch(() => {})}
                      >
                        {busy === 'create_iocs' && a.id === 'create_iocs' ? 'Creating…' : a.label}
                      </button>
                    ))}
                    <span style={{ fontSize: 12, color: '#94a3b8', marginLeft: 'auto' }} aria-live="polite">
                      {acrossActive
                        ? `${selectedRows.length} selected across all pages`
                        : selectedOnPage === selected.size
                          ? `${selected.size} selected on this page`
                          : `${selected.size} selected (${selectedOnPage} on this page)`}
                    </span>
                  </div>
                ) : null}

                {createOpModel ? (
                  <CreateIocOperationPanel
                    model={createOpModel}
                    onDismiss={() => setCreateOp(null)}
                  />
                ) : null}

                {canWrite && selectionBanner ? (
                  <div className="tl-select-banner" role="status" data-testid="selection-banner">
                    <span>{selectionBanner.message}</span>
                    {selectionBanner.action ? (
                      <button
                        type="button"
                        className="tl-select-banner__action"
                        data-testid={selectionBanner.action.id === 'clear' ? 'clear-selection' : 'select-all-matching'}
                        onClick={() => {
                          if (selectionBanner.action.id === 'clear') clearIndicatorSelection();
                          else selectAllMatching();
                        }}
                      >
                        {selectionBanner.action.label}
                      </button>
                    ) : null}
                  </div>
                ) : null}

                <div className="tl-table-container">
                <div className="tl-table-wrap" style={{ '--tl-sticky-offset': `${stickyOffset}px` }}>
                  <table className="tl-table" data-testid="indicator-table">
                    <colgroup>
                      {canWrite ? <col style={{ width: '3%' }} /> : null}
                      <col style={{ width: '6%' }} />
                      <col style={{ width: '17%' }} />
                      <col style={{ width: '10%' }} />
                      <col style={{ width: '10%' }} />
                      <col style={{ width: '9%' }} />
                      <col style={{ width: '15%' }} />
                      <col style={{ width: '11%' }} />
                      <col style={{ width: '9%' }} />
                      <col style={{ width: '10%' }} />
                      <col style={{ width: 34 }} />
                    </colgroup>
                    <thead>
                      <tr>
                        {canWrite ? (
                          <th>
                            <PageSelectCheckbox
                              state={pageCheck}
                              label={pageCheck === 'checked' ? 'Deselect all on this page' : 'Select all on this page'}
                              onChange={toggleAllOnPage}
                            />
                          </th>
                        ) : null}
                        <th>Type</th>
                        <th>Value</th>
                        <th>Assessment</th>
                        <th>Role</th>
                        <th>Confidence</th>
                        <th>Evidence</th>
                        <th>Match</th>
                        <th>Review</th>
                        <th>IOC Result</th>
                        <th aria-label="Details" />
                      </tr>
                    </thead>
                    <tbody>
                      {pageRows.length === 0 ? (
                        <tr>
                          <td colSpan={canWrite ? 11 : 10} className="tl-table-empty" data-testid="indicator-empty">
                            <p>No indicators match these filters.</p>
                            {!filtersDefault ? (
                              <button type="button" className="tl-ghost-btn" onClick={resetIndicatorFilters}>
                                Reset filters
                              </button>
                            ) : null}
                          </td>
                        </tr>
                      ) : pageRows.map((c) => {
                        const value = candidateDisplayValue(c);
                        const resultTone = promotionOutcomeTone(iocResultOutcome(c));
                        const resultHref = iocResultLink(c);
                        const isOpen = openCandidateId != null && c.id === openCandidateId;
                        return (
                          <tr
                            key={c.id || c.public_id}
                            className={`is-clickable${isOpen ? ' is-open' : ''}`}
                            onClick={(e) => onRowClick(e, c)}
                            data-candidate-id={c.id}
                          >
                            {canWrite ? (
                              <td>
                                <input
                                  type="checkbox"
                                  checked={acrossActive ? !acrossPages.excluded.has(c.id) : selected.has(c.id)}
                                  onChange={() => toggleOne(c.id)}
                                  aria-label={`Select ${candidateTypeLabel(c.candidate_type) || c.candidate_type} ${value || c.id}`}
                                />
                              </td>
                            ) : null}
                            <td>{candidateTypeLabel(c.candidate_type) || '—'}</td>
                            <td>
                              <div className="tl-value-cell">
                                {/* Intentionally plain text — never an anchor, even for URL values */}
                                <span className="tl-value" data-testid="indicator-value">{value || '—'}</span>
                                {value ? <CopyValueButton value={value} label="Copy indicator" /> : null}
                              </div>
                            </td>
                            <td><ToneBadge tone={assessmentTone(c.assessment)}>{assessmentLabel(c.assessment) || '—'}</ToneBadge></td>
                            <td>{roleLabel(c.role) || '—'}</td>
                            <td>{confidenceLabel(c)}</td>
                            <td><EvidencePreview candidate={c} /></td>
                            <td>
                              <ToneBadge tone={c.matched_ioc_id ? 'neutral' : matchStateTone(c.match_state)}>{matchCellLabel(c) || '—'}</ToneBadge>
                            </td>
                            <td><ToneBadge tone={reviewStatusTone(c.review_status)}>{reviewStatusLabel(c.review_status) || '—'}</ToneBadge></td>
                            <td title={c.promotion_detail || undefined}>
                              <ToneBadge tone={resultTone}>{iocResultLabel(c)}</ToneBadge>
                              {resultHref ? (
                                <Link to={resultHref} className="tl-ioc-result-link" data-testid="ioc-result-link">View IOC</Link>
                              ) : null}
                              {c.candidate_type === 'cidr' && (!c.promotion_outcome || c.promotion_outcome === 'unsupported') ? (
                                <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 2 }}>
                                  {c.promotion_detail || 'Preserved in Threat Library; not an IOC record.'}
                                </div>
                              ) : c.promotion_detail && c.promotion_outcome === 'unsupported' ? (
                                <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 2 }}>{c.promotion_detail}</div>
                              ) : null}
                            </td>
                            <td>
                              <button
                                type="button"
                                className="tl-row-open"
                                onClick={() => openRow(c)}
                                aria-label={`View details for ${value || c.id}`}
                                aria-haspopup="dialog"
                                aria-expanded={isOpen}
                                title="View details"
                              >
                                ›
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                </div>

                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', marginTop: 10, fontSize: 13, color: '#94a3b8' }}>
                  <span>
                    Page {paged.page} of {paged.totalPages} · {paged.total} total
                  </span>
                  <button
                    type="button"
                    style={compactBtn(compactAction, paged.page <= 1)}
                    disabled={paged.page <= 1}
                    aria-label="Previous page"
                    onClick={() => goToPage(paged.page - 1)}
                  >
                    Previous
                  </button>
                  <button
                    type="button"
                    style={compactBtn(compactAction, paged.page >= paged.totalPages)}
                    disabled={paged.page >= paged.totalPages}
                    aria-label="Next page"
                    onClick={() => goToPage(paged.page + 1)}
                  >
                    Next
                  </button>
                  <label htmlFor="tl-page-size" style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                    Page size
                    <select
                      id="tl-page-size"
                      value={paged.pageSize}
                      onChange={(e) => changePageSize(e.target.value)}
                      style={{ ...compactSelect, minWidth: 72 }}
                    >
                      {PAGE_SIZES.map((n) => (
                        <option key={n} value={n}>{n}</option>
                      ))}
                    </select>
                  </label>
                </div>
              </div>
            ) : null}
          </div>
        ) : null}

        {report && view === REPORT_VIEWS.IOC_SOURCES ? (
          <div role="tabpanel" id="tl-panel-ioc-sources" aria-labelledby="tl-tab-ioc_sources">
            <IocSourcesPanel
              reportId={reportId}
              canWrite={canWrite}
              summary={report.ioc_source_summary}
              onChanged={() => {
                // Refresh report detail so indicator provenance/counts stay current.
                api.get(`/threat-library/reports/${reportId}`).then((res) => {
                  if (res.data?.report) setReport(res.data.report);
                  if (Array.isArray(res.data?.candidates)) setCandidates(res.data.candidates);
                }).catch(() => {});
              }}
            />
          </div>
        ) : null}

        {report && view === REPORT_VIEWS.ENTITIES ? (
          <div role="tabpanel" id="tl-panel-entities" aria-labelledby="tl-tab-entities" data-testid="entities-panel" className="tl-entities">
            {entityGroups.length === 0 ? (
              <div style={ui.muted}>No entities extracted.</div>
            ) : entityGroups.map((group) => (
              <section key={group.type} className="tl-entity-group" data-entity-type={group.type} aria-label={`${group.label} (${group.items.length})`}>
                <h2 className="tl-heading">
                  {group.label} <span className="tl-heading__count">{'\u00b7'} {group.items.length}</span>
                </h2>
                <div className="tl-entity-grid">
                  {group.items.map((e) => {
                    const conf = entityConfidenceLabel(e);
                    return (
                      <div key={e.id} className="tl-entity-card" data-entity-id={e.id}>
                        <div className="tl-entity-card__head">
                          <span className="tl-entity-card__name">{e.name}</span>
                          {conf ? <span className="tl-entity-card__conf" title="Entity link confidence as reported by analysis">Confidence {conf}</span> : null}
                        </div>
                        {e.description ? <div className="tl-entity-card__desc">{e.description}</div> : null}
                        {e.evidence_text ? <blockquote className="tl-quote">{e.evidence_text}</blockquote> : null}
                      </div>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>
        ) : null}

        {report && view === REPORT_VIEWS.SOURCE ? (
          <div role="tabpanel" id="tl-panel-source" aria-labelledby="tl-tab-source" data-testid="source-panel">
            <div className="tl-source-card">
              <div className="tl-source-card__identity">
                <div className="tl-source-card__name" data-testid="source-identity">
                  {report.source_name || report.source_file_name || sourceTypeLabel(report.source_type) || 'Unknown source'}
                </div>
                {report.source_name && report.source_file_name && report.source_file_name !== report.source_name ? (
                  <div className="tl-source-card__sub tl-value">{report.source_file_name}</div>
                ) : null}
              </div>
              <SourceUrlEditor
                value={report.source_url}
                canWrite={canWrite}
                busy={busy}
                onSave={saveSourceUrl}
              />
              <DetailList items={sourceDetails} testId="source-details" className="tl-dl--grid" />
              {artifacts?.length ? (
                <details className="tl-artifacts" data-testid="artifacts">
                  <summary>Artifacts ({artifacts.length})</summary>
                  <div style={{ marginTop: 4 }}>
                    {artifacts.map((a) => {
                      const d = describeArtifact(a, { formatDateTime: formatUserDateTime });
                      return (
                        <div key={d.key} className="tl-artifact">
                          <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
                            <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{d.typeLabel}</span>
                            {d.name ? <span className="tl-value" style={{ fontSize: 12 }}>{d.name}</span> : null}
                          </div>
                          {d.facts.length ? <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 2 }}>{d.facts.join(' \u00b7 ')}</div> : null}
                          {d.sha256 ? <div className="tl-value" style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>sha256 {d.sha256}</div> : null}
                        </div>
                      );
                    })}
                  </div>
                </details>
              ) : null}
            </div>
          </div>
        ) : null}
      </section>

      <IndicatorDetailDrawer
        candidate={openCandidate}
        onClose={() => setOpenCandidateId(null)}
        position={drawerPosition}
        onNavigate={navigateDrawer}
      />

      {report && canEditTlp({ canWrite, report }) ? (
        <TlpEditModal
          open={tlpEditOpen}
          current={report.tlp}
          source={report.tlp_source}
          busy={busy}
          onClose={() => { if (busy !== 'tlp') setTlpEditOpen(false); }}
          onSave={saveTlp}
        />
      ) : null}
    </AppShell>
  );
}
