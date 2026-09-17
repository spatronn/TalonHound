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
  processingSectionTitle,
  shouldIgnoreStaleFailedPoll,
  shouldShowFailedPanel,
  shouldShowProcessingPanel
} from './reportRetryUi.js';
import {
  REVIEW_FILTERS,
  DEFAULT_REVIEW_FILTER,
  TYPE_FILTERS,
  RESULT_FILTERS,
  PAGE_SIZES,
  DEFAULT_PAGE_SIZE,
  isReviewIndicator,
  describeAnalysisFailureDetail,
  confidenceLabel,
  filterReviewCandidates,
  paginateRows,
  parseReviewTableUrlState,
  serializeReviewTableUrlState,
  iocResultLabel,
  applyPromotionResults,
  formatCreateIocSummary,
  describeReviewFeedback,
  describeCreateIocFeedback
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
import { TlpBadge, isElevatedTlp, normalizeTlp } from './tlp.jsx';
import { ui, badgeStyle } from './styles.js';
import {
  REPORT_VIEWS,
  buildReportTabs,
  parseReportView,
  withReportView
} from './reportTabs.js';
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
  const [search, setSearch] = useState(urlState.q || '');
  const [typeFilter, setTypeFilter] = useState(urlState.type || 'all');
  const [resultFilter, setResultFilter] = useState(urlState.result || 'all');
  const [page, setPage] = useState(urlState.page || 1);
  const [pageSize, setPageSize] = useState(urlState.pageSize || DEFAULT_PAGE_SIZE);
  const [selected, setSelected] = useState(() => new Set());
  const [openCandidateId, setOpenCandidateId] = useState(null);
  const [busy, setBusy] = useState('');
  const [retryAcceptedAt, setRetryAcceptedAt] = useState(0);
  const [retryAcceptedUpdatedAt, setRetryAcceptedUpdatedAt] = useState(null);
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
      .catch((err) => {
        if (!cancelled) setError(err?.response?.data?.message || 'Failed to load report');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [loadDetail]);

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

  const filtered = useMemo(
    () => filterReviewCandidates(candidates, { tab: filter, q: search, type: typeFilter, result: resultFilter }),
    [candidates, filter, search, typeFilter, resultFilter]
  );
  const paged = useMemo(
    () => paginateRows(filtered, page, pageSize),
    [filtered, page, pageSize]
  );
  const pageRows = paged.rows;
  const filterCounts = useMemo(() => buildReviewFilterCounts(candidates), [candidates]);

  useEffect(() => {
    const next = withReportView(serializeReviewTableUrlState({
      tab: filter,
      q: search,
      type: typeFilter,
      result: resultFilter,
      page: paged.page,
      pageSize: paged.pageSize
    }), view);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [view, filter, search, typeFilter, resultFilter, paged.page, paged.pageSize, searchParams, setSearchParams]);

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

  function changeFilter(next) {
    setFilter(next);
    setPage(1);
    setSelected(new Set());
  }

  function changeSearch(next) {
    setSearch(next);
    setPage(1);
    setSelected(new Set());
  }

  function changeType(next) {
    setTypeFilter(next);
    setPage(1);
    setSelected(new Set());
  }

  function changeResult(next) {
    setResultFilter(next);
    setPage(1);
    setSelected(new Set());
  }

  function changePageSize(next) {
    setPageSize(Number(next) || DEFAULT_PAGE_SIZE);
    setPage(1);
    setSelected(new Set());
  }

  function goToPage(next) {
    setPage(next);
    setSelected(new Set());
  }

  function toggleOne(id) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAllOnPage() {
    setSelected((prev) => {
      const ids = pageRows.map((c) => c.id);
      const allOn = ids.length > 0 && ids.every((id) => prev.has(id));
      const next = new Set();
      if (!allOn) ids.forEach((id) => next.add(id));
      return next;
    });
  }

  /** Review action for the current table selection (the only mutation entry point). */
  async function runReview(action) {
    if (!canWrite) return;
    if (action === 'create_iocs') {
      await createIocs();
      return;
    }
    setBusy(action);
    setFeedback('');
    setError('');
    try {
      const body = { action };
      if (action !== 'approve_high_confidence_malicious') {
        body.candidate_ids = [...selected];
      }
      const { data } = await api.post(`/threat-library/reports/${reportId}/review`, body);
      const updated = Number.isFinite(Number(data?.updated)) ? Number(data.updated) : null;
      setFeedback(describeReviewFeedback(action, {
        count: updated ?? (action === 'approve_high_confidence_malicious' ? null : selected.size),
        errors: Array.isArray(data?.errors) ? data.errors.length : 0
      }));
      setSelected(new Set());
      await loadDetail();
    } catch (err) {
      if (!applyNotReadyRejection(err)) setError(err?.response?.data?.message || 'Review action failed');
    } finally {
      setBusy('');
    }
  }

  async function createIocs() {
    if (!canWrite || !selected.size) return;
    setBusy('create_iocs');
    setFeedback('');
    setError('');
    const ids = [...selected];
    try {
      const { data: preview } = await api.post(`/threat-library/reports/${reportId}/review`, {
        action: 'create_iocs',
        candidate_ids: ids,
        confirm: false
      });
      const summary = preview?.summary || {};
      const eligible = Number(summary.eligible || 0);
      if (eligible <= 0 && Number(summary.not_approved || 0) === Number(summary.selected || 0)) {
        await requestConfirm({
          title: 'Approve indicators first',
          description: 'Only approved indicators can be created as IOCs. Review and approve the selected indicators before creating IOC records.',
          confirmLabel: 'OK',
          cancelLabel: 'Close',
          variant: 'warning'
        });
        return;
      }
      if (eligible <= 0) {
        await requestConfirm({
          title: 'Create approved IOCs?',
          description: 'None of the selected indicators can be created as IOC records.',
          detail: formatCreateIocSummary(summary),
          confirmLabel: 'OK',
          cancelLabel: 'Close',
          variant: 'warning'
        });
        return;
      }
      const ok = await requestConfirm({
        title: eligible < (summary.selected || 0) ? 'Create approved IOCs?' : 'Create IOC records?',
        description: eligible < (summary.selected || 0)
          ? `Only the ${eligible} eligible approved indicators will be created.`
          : `${eligible} new IOC record${eligible === 1 ? '' : 's'} will be created.`,
        detail: formatCreateIocSummary(summary),
        confirmLabel: `Create ${eligible} IOC${eligible === 1 ? '' : 's'}`,
        cancelLabel: 'Cancel'
      });
      if (!ok) return;
      const { data } = await api.post(`/threat-library/reports/${reportId}/review`, {
        action: 'create_iocs',
        candidate_ids: ids,
        confirm: true
      });
      if (data?.results) setCandidates((prev) => applyPromotionResults(prev, data.results));
      const created = data?.summary?.created ?? data?.created?.length ?? 0;
      const existing = data?.summary?.already_existing ?? 0;
      setFeedback(describeCreateIocFeedback({
        created,
        existing,
        errors: Array.isArray(data?.errors) ? data.errors.length : 0
      }));
      setSelected(new Set());
      await loadDetail();
    } catch (err) {
      if (err?.response?.data?.code === 'create_iocs_none_eligible') {
        await requestConfirm({
          title: 'Approve indicators first',
          description: err.response.data.message
            || 'Only approved indicators can be created as IOCs. Review and approve the selected indicators before creating IOC records.',
          detail: err.response.data.summary ? formatCreateIocSummary(err.response.data.summary) : '',
          confirmLabel: 'OK',
          cancelLabel: 'Close',
          variant: 'warning'
        });
        return;
      }
      if (!applyNotReadyRejection(err)) setError(err?.response?.data?.message || 'Review action failed');
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
    setSelected(new Set());
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

  async function retry() {
    if (!canWrite || busy || isProcessingStatus(report)) return;
    setBusy('retry');
    setError('');
    try {
      const { data } = await api.post(`/threat-library/reports/${reportId}/retry`);
      const applied = applyRetryAcceptedState(data);
      if (applied.report) setReport(applied.report);
      if (applied.job) setJob(applied.job);
      // The review set is being rebuilt: previous rows are no longer current.
      setCandidates([]);
      setSelected(new Set());
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
        if (applied.report) setReport(applied.report);
        if (applied.job) setJob(applied.job);
        setCandidates([]);
        setSelected(new Set());
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
  const reviewCount = useMemo(() => candidates.filter((c) => isReviewIndicator(c)).length, [candidates]);
  const indicatorCount = describeIndicatorCount(report, showReview ? { reviewCount } : { rawCount: candidates.length || null });
  const metrics = useMemo(() => buildOverviewMetrics(candidates, report), [candidates, report]);
  const tabs = useMemo(() => buildReportTabs({
    indicatorCount: indicatorCount.value,
    indicatorCountStable: showReview,
    entityCount: entities.length
  }), [indicatorCount.value, showReview, entities.length]);
  const reportDetails = useMemo(() => buildReportDetails(report, {
    documentMeta,
    artifacts,
    entityCount: entities.length,
    indicatorCount: showReview ? indicatorCount : null,
    formatDateTime: formatUserDateTime
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
  const selectedOnPage = useMemo(() => pageRows.filter((c) => selected.has(c.id)).length, [pageRows, selected]);
  const overflowItems = [
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
                <TlpBadge tlp={report.tlp} display={report.tlp_display} />
                <span style={badgeStyle({ border: '#334155', bg: '#1e293b', color: '#cbd5e1' })} data-testid="report-status">
                  {statusLabel(report)}
                </span>
                {report.report_type ? (
                  <span style={{ fontSize: 12, color: '#94a3b8' }}>{humanizeEnum(report.report_type)}</span>
                ) : null}
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
              Analysis is running. Progress updates every few seconds from the worker — not a fake timer.
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
                <div className="tl-filterbar">
                  <div className="tl-filterbar__tabs" role="tablist" aria-label="Indicator filters">
                    {REVIEW_FILTERS.map((f) => (
                      <button
                        key={f.id}
                        type="button"
                        role="tab"
                        aria-selected={filter === f.id}
                        className="tl-filter-tab"
                        onClick={() => changeFilter(f.id)}
                      >
                        {f.label}
                        <span className="tl-filter-tab__count" data-testid={`filter-count-${f.id}`}>{filterCounts[f.id] ?? 0}</span>
                      </button>
                    ))}
                  </div>
                  <div className="tl-filterbar__controls">
                    <label htmlFor="tl-indicator-search" style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>
                      Search indicators
                    </label>
                    <input
                      id="tl-indicator-search"
                      type="search"
                      value={search}
                      onChange={(e) => changeSearch(e.target.value)}
                      placeholder="Search indicators…"
                      style={{ ...compactInput, width: 220 }}
                    />
                    <label htmlFor="tl-type-filter" style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>
                      Type
                    </label>
                    <select
                      id="tl-type-filter"
                      value={typeFilter}
                      onChange={(e) => changeType(e.target.value)}
                      style={compactSelect}
                    >
                      {TYPE_FILTERS.map((t) => (
                        <option key={t.id} value={t.id}>{t.label}</option>
                      ))}
                    </select>
                    <label htmlFor="tl-result-filter" style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>
                      IOC Result
                    </label>
                    <select
                      id="tl-result-filter"
                      value={resultFilter}
                      onChange={(e) => changeResult(e.target.value)}
                      style={compactSelect}
                    >
                      {RESULT_FILTERS.map((t) => (
                        <option key={t.id} value={t.id}>{t.label}</option>
                      ))}
                    </select>
                  </div>
                </div>

                {canWrite ? (
                  <div className="tl-bulkbar" ref={bulkBarRef} data-testid="bulk-actions">
                    <button type="button" style={compactBtn(compactAction, !selected.size || Boolean(busy))} disabled={!selected.size || Boolean(busy)} onClick={() => runReview('approve').catch(() => {})}>
                      Approve
                    </button>
                    <button type="button" style={compactBtn(compactAction, !selected.size || Boolean(busy))} disabled={!selected.size || Boolean(busy)} onClick={() => runReview('context_only').catch(() => {})}>
                      Context only
                    </button>
                    <button type="button" style={compactBtn(compactAction, !selected.size || Boolean(busy))} disabled={!selected.size || Boolean(busy)} onClick={() => runReview('ignore').catch(() => {})}>
                      Ignore
                    </button>
                    <button type="button" style={compactBtn(compactPrimary, !selected.size || Boolean(busy))} disabled={!selected.size || Boolean(busy)} onClick={() => runReview('create_iocs').catch(() => {})}>
                      Create IOCs
                    </button>
                    <button type="button" style={compactBtn(compactAction, Boolean(busy))} disabled={Boolean(busy)} onClick={() => runReview('approve_high_confidence_malicious').catch(() => {})}>
                      Approve high-confidence malicious
                    </button>
                    <span style={{ fontSize: 12, color: '#94a3b8', marginLeft: 'auto' }} aria-live="polite">
                      {selectedOnPage === selected.size
                        ? `${selected.size} selected on this page`
                        : `${selected.size} selected (${selectedOnPage} on this page)`}
                    </span>
                  </div>
                ) : null}

                <div className="tl-table-container">
                <div className="tl-table-wrap" style={{ '--tl-sticky-offset': `${stickyOffset}px` }}>
                  <table className="tl-table" data-testid="indicator-table">
                    <colgroup>
                      {canWrite ? <col style={{ width: '3%' }} /> : null}
                      <col style={{ width: '6%' }} />
                      <col style={{ width: '17%' }} />
                      <col style={{ width: '9%' }} />
                      <col style={{ width: '11%' }} />
                      <col style={{ width: '9%' }} />
                      <col style={{ width: '16%' }} />
                      <col style={{ width: '11%' }} />
                      <col style={{ width: '8%' }} />
                      <col style={{ width: '10%' }} />
                      <col style={{ width: 34 }} />
                    </colgroup>
                    <thead>
                      <tr>
                        {canWrite ? (
                          <th>
                            <input
                              type="checkbox"
                              checked={pageRows.length > 0 && pageRows.every((c) => selected.has(c.id))}
                              onChange={toggleAllOnPage}
                              aria-label="Select all on this page"
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
                        <tr><td colSpan={canWrite ? 11 : 10} style={{ color: '#94a3b8' }}>No candidates in this filter.</td></tr>
                      ) : pageRows.map((c) => {
                        const value = candidateDisplayValue(c);
                        const resultTone = promotionOutcomeTone(c.promotion_outcome);
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
                                  checked={selected.has(c.id)}
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
    </AppShell>
  );
}
