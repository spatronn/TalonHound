import React, { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api } from './lib/api.js';
import {
  SEARCH_FIELDS,
  FIELD_BY_NAME,
  EXPORT_COLUMN_OPTIONS,
  DEFAULT_EXPORT_COLUMNS,
  OPERATOR_LABELS,
  buildDslFromConditions,
  defaultOperatorFor,
  newCondition,
  chipLabel
} from './lib/iocSearchDslClient.js';
import { getIocStatusCardPresentation } from './lib/iocStatusCard.js';
import {
  CONFIDENCE_OPTIONS,
  getIocConfidencePresentation,
  formatConfidenceAuditMetadata,
  confidenceBadgeStyle,
  confidenceLabel
} from './lib/iocConfidenceCard.js';
import { getIpEnrichmentEligibility, getAbuseIpdbEligibility } from './lib/ipEnrichmentTarget.js';
import { isRdapEligibleObservable } from './lib/iocProviderApplicability.js';
import { normalizeVisibleClassifications } from './lib/classificationSummary.js';
import { getDnsmaniaPresentation } from './lib/dnsmaniaPresentation.js';
import {
  compactAssociatedIpViewModel,
  indexAssociatedIpResults,
  isAssociatedIpEnrichmentCandidate
} from './lib/associatedIpEnrichment.js';
import { IOC_SOURCE_TIMESTAMP_PRESENTATION } from './lib/iocSourceTimestampPresentation.js';
import { IOC_LIST_TIMESTAMP_PRESENTATION, resolveIocListTimestamp } from './lib/iocListTimestampPresentation.js';
import { formatIocDetailDateTime } from './lib/iocDetailTimestamps.js';
import { resolveCanonicalDetailRedirect } from './lib/fileArtifactDetailRedirect.js';
import { buildIntegrationRunNowPayload } from './lib/integrationRunNowPayload.js';
import { computeJobDurationMs, formatJobDuration } from './lib/integrationJobDuration.js';
import {
  presentQueueJobResult,
  presentQueueJobReason,
  buildQueueJobDetailMetrics,
  formatQueueTrigger,
  formatQueueRunMode
} from './lib/jobQueueResult.js';
import { buildIocTagBadges, formatTagSourcesCell } from './lib/iocTagBadges.js';
import {
  DEFAULT_SOURCE_COLOR,
  isValidHexColor,
  normalizeHexColor,
  sourceBadgeStyle as sourceColorBadgeStyle,
  buildSourceColorIndex,
  resolveSourceBadgeStyle
} from './lib/sourceBadge.js';
import EnrichmentProvidersPageView from './components/EnrichmentProvidersPage.jsx';
import BackupRestorePageView from './components/BackupRestorePage.jsx';
import InitialSetupPage from './components/InitialSetupPage.jsx';
import { NavIcons } from './components/NavIcons.jsx';
import { IocHeader } from './components/iocDetails/IocHeader.jsx';
import { IocStatusSummary } from './components/iocDetails/IocStatusSummary.jsx';
import { ActiveSourcesTable, IocSummaryStrip } from './components/iocDetails/ActiveSourcesTable.jsx';
import { IocTimestampCards } from './components/iocDetails/IocTimestampCards.jsx';
import { IocMetadataCards } from './components/iocDetails/IocMetadataCards.jsx';
import talonHoundLogo from './assets/talonhound-logo.png';
import { formatSidebarRoleLabel, userInitialsFromEmail } from './lib/sidebarAccount.js';
import {
  formatUserDateTime,
  notifyTimezoneChanged,
  getSystemTimezone,
  setSystemTimezoneCache,
  systemLocalInputToUtcIso,
  TIMEZONE_CHANGED_EVENT
} from './lib/formatDate.js';
import {
  presentFeedLastResult,
  resolveFeedLastResult,
  FEED_RESULT_TONE_COLORS,
  FEED_RESULT_METRIC_TOOLTIPS
} from './lib/feedLastResult.js';
import './AppShell.css';
import './components/LoginPage.css';
import './components/enrichmentProviders/enrichmentProviders.css';
import {
  TAG_MANAGER_PAGE_SIZE,
  TAG_MANAGER_SEARCH_DEBOUNCE_MS,
  buildTagManagerQueryParams,
  buildTagManagerUrlSearchParams,
  clampTagManagerPage,
  formatTagManagerShowingLabel,
  parseTagManagerUrlState
} from './lib/tagManagerList.js';
import {
  ACTION_CENTER_FILTERS,
  ACTION_CENTER_PAGE_SIZE,
  actionCenterPollIntervalMs,
  actionCenterStatusBadgeStyle,
  buildActionCenterListParams,
  formatActionCenterStatus,
  formatExpiresIn,
  formatFileSize,
  taskTypeLabel,
  truncateQuery
} from './lib/actionCenter.js';
import { IntelligenceTabPanel } from './intelligenceTab.jsx';

// Shared, process-wide cache for the source-color catalog so the many screens
// that render source badges resolve identical colors without each refetching.
let sourceColorCatalogCache = null;
let sourceColorCatalogPromise = null;

async function fetchSourceColorCatalog(force = false) {
  if (!force && Array.isArray(sourceColorCatalogCache)) return sourceColorCatalogCache;
  if (!force && sourceColorCatalogPromise) return sourceColorCatalogPromise;
  sourceColorCatalogPromise = api.get('/source-colors')
    .then((res) => {
      sourceColorCatalogCache = Array.isArray(res.data?.colors) ? res.data.colors : [];
      return sourceColorCatalogCache;
    })
    .catch(() => {
      sourceColorCatalogCache = sourceColorCatalogCache || [];
      return sourceColorCatalogCache;
    })
    .finally(() => { sourceColorCatalogPromise = null; });
  return sourceColorCatalogPromise;
}

/** Invalidate the cached catalog after a color edit so badges refresh. */
function invalidateSourceColorCatalog() {
  sourceColorCatalogCache = null;
  sourceColorCatalogPromise = null;
}

/** React hook returning a name->color index for source badges. */
function useSourceColorIndex() {
  const [entries, setEntries] = useState(sourceColorCatalogCache || []);
  useEffect(() => {
    let alive = true;
    fetchSourceColorCatalog().then((list) => { if (alive) setEntries(list); });
    return () => { alive = false; };
  }, []);
  return useMemo(() => buildSourceColorIndex(entries), [entries]);
}

/**
 * Shared color picker used by every source/feed edit form: native color input +
 * editable hex text field + live badge preview. Empty means "use fallback".
 * Reports validity so callers can block invalid saves.
 *
 * @param {{ value: string, onChange: (next: string) => void, previewLabel?: string,
 *   disabled?: boolean, label?: string, helper?: string, ui?: object }} props
 */
function SourceColorField({ value, onChange, previewLabel = 'Source', disabled = false, label = 'Badge color', helper }) {
  const raw = value == null ? '' : String(value);
  const trimmed = raw.trim();
  const isEmpty = trimmed === '';
  const valid = isEmpty || isValidHexColor(trimmed);
  const effectiveColor = valid && !isEmpty ? normalizeHexColor(trimmed) : DEFAULT_SOURCE_COLOR;
  const previewStyle = sourceColorBadgeStyle(effectiveColor);
  const colorInputValue = isValidHexColor(trimmed) ? normalizeHexColor(trimmed) : DEFAULT_SOURCE_COLOR;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {label ? <span style={{ fontSize: 12, color: '#94a3b8' }}>{label}</span> : null}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <input
          type="color"
          aria-label={`${label} color picker`}
          value={colorInputValue}
          disabled={disabled}
          onChange={(e) => onChange(String(e.target.value || '').toLowerCase())}
          style={{ width: 42, height: 32, padding: 0, border: '1px solid #334155', borderRadius: 6, background: 'transparent', cursor: disabled ? 'not-allowed' : 'pointer' }}
        />
        <input
          type="text"
          value={raw}
          disabled={disabled}
          placeholder={DEFAULT_SOURCE_COLOR}
          spellCheck={false}
          onChange={(e) => onChange(e.target.value)}
          style={{
            width: 120,
            padding: '6px 8px',
            borderRadius: 6,
            border: `1px solid ${valid ? '#334155' : '#b91c1c'}`,
            background: '#0b1220',
            color: '#e2e8f0',
            fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace",
            fontSize: 13
          }}
        />
        <span style={{ display: 'inline-flex', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700, ...previewStyle }}>
          {previewLabel || 'Source'}
        </span>
        {isEmpty ? <span style={{ fontSize: 11, color: '#64748b' }}>Default</span> : null}
      </div>
      {!valid ? (
        <span style={{ fontSize: 11, color: '#fca5a5' }}>Enter a hex color like #7c3aed, or leave blank for the default.</span>
      ) : (helper ? <span style={{ fontSize: 11, color: '#64748b' }}>{helper}</span> : null)}
    </div>
  );
}

/** True when a color value is acceptable to save (empty or valid hex). */
function isSavableColor(value) {
  const t = value == null ? '' : String(value).trim();
  return t === '' || isValidHexColor(t);
}

/**
 * Rounded source badge whose color comes from the managed catalog (falling back
 * to the neutral default). Used wherever a single source/feed name is shown.
 */
function SourceBadge({ index, label, style }) {
  const text = label == null ? '' : String(label);
  const badge = resolveSourceBadgeStyle(index, text);
  return (
    <span style={{ display: 'inline-flex', borderRadius: 999, padding: '2px 9px', fontSize: 12, fontWeight: 700, whiteSpace: 'nowrap', ...badge, ...style }}>
      {text || '-'}
    </span>
  );
}

const SessionContext = React.createContext({
  authState: 'loading',
  userEmail: '',
  userId: null,
  role: 'admin',
  canWrite: true,
  isAdmin: true,
  refreshSession: async () => {}
});

function SessionProvider({ children }) {
  const [authState, setAuthState] = useState('loading');
  const [userEmail, setUserEmail] = useState('');
  const [userId, setUserId] = useState(null);
  const [role, setRole] = useState('admin');

  const refreshSession = useCallback(async () => {
    try {
      const { data } = await api.get('/auth/me');
      const u = data?.user || {};
      const em = String(u.email || '');
      if (em) {
        setUserEmail(em);
        setUserId(u.id != null ? String(u.id) : null);
        setRole(String(u.role || 'admin'));
        setAuthState('authed');
      } else {
        setAuthState('anon');
      }
    } catch {
      setAuthState('anon');
      setUserEmail('');
      setUserId(null);
      setRole('admin');
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  const canWrite = role !== 'readonly';
  const isAdmin = role === 'admin';
  const value = useMemo(
    () => ({ authState, userEmail, userId, role, canWrite, isAdmin, refreshSession }),
    [authState, userEmail, userId, role, canWrite, isAdmin, refreshSession]
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

function useSession() {
  return useContext(SessionContext);
}

const COMMON_TIMEZONES = [
  'UTC',
  'Europe/Istanbul',
  'Europe/Berlin',
  'Europe/London',
  'America/New_York',
  'Asia/Dubai'
];

const FILE_HASH_TYPES = new Set(['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);

function formatDurationMs(ms) {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return '-';
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function formatDurationSeconds(totalSec) {
  if (totalSec == null || !Number.isFinite(totalSec) || totalSec < 0) return '-';
  return formatDurationMs(totalSec * 1000);
}


function formatIntegrationJobDisplayName(jobName, integrationKey = null) {
  const byKey = {
    'et-blockrules': 'Blockrules IP import',
    'usom-trcert': 'Siber Güvenlik Başkanlığı / USOM API import',
    'urlhaus-abusech': 'Recent malicious URLs import',
    'threatfox-abusech': 'Recent IOCs import',
    'malwarebazaar-abusech': 'Recent malware samples import',
    'phishtank-opendnsrr': 'Online-valid phishing import'
  };
  const byName = {
    'hourly-import': 'Blockrules IP import',
    'usom-import': 'Siber Güvenlik Başkanlığı / USOM API import',
    'urlhaus-import': 'Recent malicious URLs import',
    'threatfox-import': 'Recent IOCs import',
    'malwarebazaar-import': 'Recent malware samples import',
    'phishtank-import': 'Online-valid phishing import',
    'feed_data_purge': 'Feed data purge'
  };
  const key = String(integrationKey || '').trim();
  if (key && byKey[key]) return byKey[key];
  const name = String(jobName || '').trim();
  if (name && byName[name]) return byName[name];
  return name || '-';
}

function integrationJobDisplayName(job) {
  return job?.display_name || formatIntegrationJobDisplayName(job?.name || job?.job_name, job?.integration_key);
}

function integrationRunModeLabel(mode) {
  if (mode === 'full_reconciliation') return 'Full reconciliation';
  if (mode === 'incremental') return 'Incremental';
  return '-';
}

function usomRunDiagnostics(run) {
  if (!run) return 'No run recorded';
  const details = run.run_details || {};
  const parts = [
    integrationRunModeLabel(run.run_mode || details.run_mode),
    String(run.status || '').toLowerCase() || 'unknown'
  ];
  const records = details.provider_records ?? run.records_processed;
  const pages = details.pages_fetched ?? details.page_count;
  if (records != null) parts.push(`${Number(records).toLocaleString()} records`);
  if (pages != null) parts.push(`${Number(pages).toLocaleString()} pages`);
  return parts.filter(Boolean).join(' · ');
}

function integrationJobReasonLabel(job) {
  return presentQueueJobReason(job, {
    formatDurationMs: (ms) => formatJobDuration(ms),
    formatUserDateTime
  });
}

function queueHealthColor(health) {
  const key = String(health || '').toLowerCase();
  if (key === 'healthy') return '#86efac';
  if (key === 'degraded') return '#fcd34d';
  if (key === 'blocked') return '#fca5a5';
  return '#94a3b8';
}

function queueHealthPanelClass(health) {
  const key = String(health || '').toLowerCase();
  if (key === 'blocked') return 'queue-health-panel queue-health-panel--blocked';
  if (key === 'degraded') return 'queue-health-panel queue-health-panel--degraded';
  if (key === 'healthy') return 'queue-health-panel queue-health-panel--healthy';
  return 'queue-health-panel';
}

const queuePageInputStyle = {
  padding: '8px 10px',
  borderRadius: 8,
  border: '1px solid #334155',
  background: '#0f172a',
  color: '#e2e8f0'
};

function queueJobStateColor(state) {
  const s = String(state || '').toLowerCase();
  if (s === 'success') return '#86efac';
  if (s === 'failed' || s === 'fail') return '#fca5a5';
  if (s === 'running') return '#fcd34d';
  if (s === 'queued') return '#93c5fd';
  return '#94a3b8';
}

function suppressionKey(iocValue, iocType) {
  return `${String(iocType || '').trim().toLowerCase()}\t${String(iocValue || '').trim().toLowerCase()}`;
}

const SUPPRESSION_IOC_TYPES = ['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'];

// Client-side best-effort detection for the manual "Add Suppression" form.
// The backend re-detects/validates; this is only a UX hint. Kept in sync with
// backend/lib/suppressionInput.js detectSuppressionType.
function detectSuppressionTypeUI(rawValue) {
  const v = String(rawValue || '').trim();
  if (!v) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return 'url';
  const core = v.split('/')[0].trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(core) && core.split('.').every((o) => Number(o) <= 255)) return 'ip';
  if (core.includes(':') && /^[0-9a-f:]+$/i.test(core)) return 'ipv6';
  if (/^[a-f0-9]{32}$/i.test(v)) return 'md5';
  if (/^[a-f0-9]{40}$/i.test(v)) return 'sha1';
  if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256';
  if (v.includes('/')) return 'url';
  if (/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/i.test(v)) return 'domain';
  return null;
}

function isSuppressionActiveRow(row) {
  if (!row?.active) return false;
  if (!row?.expires_at) return true;
  const exp = Date.parse(row.expires_at);
  return Number.isFinite(exp) && exp > Date.now();
}

function expiresAtFromPreset(preset, customDate) {
  if (preset === 'never') return null;
  const now = new Date();
  if (preset === '7d') {
    const d = new Date(now);
    d.setUTCDate(d.getUTCDate() + 7);
    return d.toISOString();
  }
  if (preset === '30d') {
    const d = new Date(now);
    d.setUTCDate(d.getUTCDate() + 30);
    return d.toISOString();
  }
  if (preset === 'custom' && customDate) {
    const d = new Date(customDate);
    if (Number.isNaN(d.getTime())) return null;
    return d.toISOString();
  }
  return null;
}

function suppressionBadgeStyle(kind = 'suppressed') {
  const base = {
    display: 'inline-block',
    borderRadius: 999,
    padding: '3px 9px',
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: '0.02em',
    marginLeft: 8,
    verticalAlign: 'middle',
    whiteSpace: 'nowrap'
  };
  if (kind === 'fp') {
    return { ...base, background: 'rgba(34,197,94,0.15)', color: '#86efac', border: '1px solid #166534' };
  }
  return { ...base, background: 'rgba(148,163,184,0.18)', color: '#cbd5e1', border: '1px solid #475569' };
}

function suppressionStatusBadgeStyle(status) {
  const s = String(status || '').toLowerCase();
  const base = {
    display: 'inline-block',
    borderRadius: 999,
    padding: '4px 10px',
    fontSize: 11,
    fontWeight: 700,
    textTransform: 'capitalize'
  };
  if (s === 'active') return { ...base, background: 'rgba(34,197,94,0.15)', color: '#86efac', border: '1px solid #166534' };
  if (s === 'expired') return { ...base, background: 'rgba(251,191,36,0.15)', color: '#fcd34d', border: '1px solid #854d0e' };
  if (s === 'disabled' || s === 'inactive') return { ...base, background: 'rgba(148,163,184,0.15)', color: '#94a3b8', border: '1px solid #475569' };
  return { ...base, background: 'rgba(148,163,184,0.15)', color: '#94a3b8', border: '1px solid #475569' };
}

function formatSuppressionStatusLabel(status) {
  const s = String(status || '').toLowerCase();
  if (s === 'disabled' || s === 'inactive') return 'Disabled';
  if (s === 'active') return 'Active';
  if (s === 'expired') return 'Expired';
  return status || 'unknown';
}

function apiErrorMessage(err, fallback = 'Request failed') {
  const d = err?.response?.data;
  if (d?.error && d?.message) return String(d.message);
  if (d?.error) return String(d.error);
  if (Array.isArray(d?.errors) && d.errors.length) return d.errors.join('; ');
  if (d?.message && d?.detail) return `${d.message}: ${d.detail}`;
  return String(d?.message || err?.message || fallback);
}

function parseIocSourceDeleteError(err) {
  const status = err?.response?.status;
  const data = err?.response?.data || {};
  const message = String(data.message || '').trim();
  const errorCode = String(data.error || '').trim();
  if (status === 409) {
    if (errorCode === 'source_used_by_published_feeds') {
      return {
        blocked: true,
        mode: 'published_feeds',
        message: message || 'This source is used by Published Feeds. Remove it from those Published Feed filters before deleting.',
        published_feed_dependencies: Array.isArray(data.published_feed_dependencies) ? data.published_feed_dependencies : []
      };
    }
    return {
      blocked: true,
      mode: 'blocked',
      message: message || 'This source contains IOC records. Move them to another source before deleting.',
      published_feed_dependencies: []
    };
  }
  const raw = String(err?.message || '');
  if (!status || status >= 500 || /^request failed with status code 502/i.test(raw)) {
    return { blocked: false, mode: 'empty', message: 'Delete failed. Please check server logs.', published_feed_dependencies: [] };
  }
  return { blocked: false, mode: 'empty', message: apiErrorMessage(err, 'Delete failed'), published_feed_dependencies: [] };
}

function resolveDeleteModalMode(preview) {
  if (!preview) return 'empty';
  if (Number(preview.ioc_count || 0) > 0 || preview.blocked_reason === 'has_iocs') return 'blocked';
  if (preview.blocked_reason === 'published_feed_dependency' || (preview.published_feed_dependencies || []).length > 0) {
    return 'published_feeds';
  }
  return preview.can_delete === false ? 'empty' : 'empty';
}

function parseFeedPurgeError(err, fallback = 'Failed to start purge job. Please try again or check backend logs.') {
  const d = err?.response?.data;
  const code = String(d?.error || '').trim();
  if (code === 'confirm_name_mismatch') {
    return String(d?.message || 'Feed name confirmation does not match.');
  }
  if (code === 'purge_already_running') {
    return String(d?.message || 'A purge job is already running for this feed.');
  }
  const raw = String(d?.message || err?.message || '');
  if (err?.response?.status === 504 || /status code 504|gateway timeout|timeout of \d+ms exceeded/i.test(raw)) {
    return fallback;
  }
  if (/^request failed with status code \d+/i.test(raw)) {
    return fallback;
  }
  return apiErrorMessage(err, fallback);
}

function isApiMutationSuccess(data) {
  if (data == null) return true;
  if (data.success === false) return false;
  return data.success === true || data.ok === true;
}

const IOC_EXPIRATION_ACTION_PRESETS = {
  expire_ioc: {
    title: 'Expire IOC now',
    description: 'This IOC will be marked as expired. It will not be published/exported. Existing audit history will remain unchanged.',
    requiresReason: true,
    requiresDate: false,
    confirmLabel: 'Expire IOC',
    danger: true,
    successToast: 'IOC marked as expired'
  },
  reactivate_ioc: {
    title: 'Reactivate IOC',
    description: 'This will manually reactivate the IOC and set a new expiration policy. It may become eligible for publish/export again unless disabled or suppressed.',
    requiresReason: true,
    requiresDate: false,
    requiresExpirationPolicy: true,
    confirmLabel: 'Reactivate IOC',
    danger: false,
    successToast: 'IOC reactivated'
  },
  custom_expire_ioc: {
    title: 'Set custom expire date',
    description: 'This will set a manual expiration date for this IOC.',
    requiresReason: true,
    requiresDate: true,
    confirmLabel: 'Save expire date',
    danger: false,
    successToast: 'Custom expire date saved'
  },
  clear_ioc_override: {
    title: 'Clear manual override',
    description: 'This will remove the manual override and return this IOC to feed policy based expiration.',
    requiresReason: false,
    requiresDate: false,
    confirmLabel: 'Clear override',
    danger: false,
    successToast: 'Manual override cleared'
  },
  expire_membership: {
    title: 'Expire feed source now',
    description: 'This feed membership will be marked as expired. If no other active feed source remains, the global IOC may become expired.',
    requiresReason: true,
    requiresDate: false,
    confirmLabel: 'Expire source',
    danger: true,
    successToast: 'Feed source marked as expired'
  },
  reactivate_membership: {
    title: 'Reactivate feed source',
    description: 'This feed membership will be manually reactivated. The global IOC status will be recomputed after the change.',
    requiresReason: true,
    requiresDate: false,
    confirmLabel: 'Reactivate source',
    danger: false,
    successToast: 'Feed source reactivated'
  },
  custom_expire_membership: {
    title: 'Set custom expire date',
    description: 'This will set a manual expiration date for this feed source.',
    requiresReason: true,
    requiresDate: true,
    confirmLabel: 'Save expire date',
    danger: false,
    successToast: 'Custom expire date saved for source'
  },
  clear_membership_override: {
    title: 'Clear source override',
    description: 'This will remove the manual override and return this feed source to feed policy based expiration.',
    requiresReason: false,
    requiresDate: false,
    confirmLabel: 'Clear override',
    danger: false,
    successToast: 'Source override cleared'
  }
};

function IocExpirationActionModal({
  pending,
  reason,
  onReasonChange,
  expireAt,
  onExpireAtChange,
  expirationPolicy,
  onExpirationPolicyChange,
  expireDays,
  onExpireDaysChange,
  loading,
  error,
  onCancel,
  onConfirm,
  ui
}) {
  useEffect(() => {
    if (!pending || loading) return undefined;
    function onKeyDown(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCancel();
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [pending, loading, onCancel]);

  if (!pending) return null;
  const inputStyle = {
    padding: '8px 10px',
    borderRadius: 6,
    border: '1px solid #475569',
    background: '#0f172a',
    color: '#e2e8f0',
    fontSize: 13,
    width: '100%',
    boxSizing: 'border-box'
  };
  const confirmStyle = pending.danger
    ? { ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.25)' }
    : ui.btnPrimary;
  const minDateTimeLocal = new Date(Date.now() - new Date().getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);

  return (
    <ModalOverlay onClose={loading ? undefined : onCancel}>
      <h3 style={{ marginTop: 0, color: '#f1f5f9', fontSize: 18 }}>{pending.title}</h3>
      <p style={{ color: '#cbd5e1', fontSize: 13, lineHeight: 1.55, marginTop: 0, marginBottom: 14 }}>{pending.description}</p>
      <div style={{ display: 'grid', gap: 12 }}>
        {pending.requiresExpirationPolicy ? (
          <>
            <label style={{ display: 'grid', gap: 6 }}>
              <span style={ui.label}>Expiration policy</span>
              <select
                value={expirationPolicy}
                onChange={(e) => onExpirationPolicyChange(e.target.value)}
                disabled={loading}
                style={inputStyle}
              >
                {IOC_EXPIRE_POLICY_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </label>
            {expirationPolicy === 'expire_after_days' ? (
              <label style={{ display: 'grid', gap: 6 }}>
                <span style={ui.label}>Expire after days</span>
                <input
                  type="number"
                  min={1}
                  max={3650}
                  value={expireDays}
                  onChange={(e) => onExpireDaysChange(e.target.value)}
                  disabled={loading}
                  style={inputStyle}
                />
              </label>
            ) : null}
            {expirationPolicy === 'custom_date' ? (
              <label style={{ display: 'grid', gap: 6 }}>
                <span style={ui.label}>Custom expire date</span>
                <input
                  type="datetime-local"
                  min={minDateTimeLocal}
                  value={expireAt}
                  onChange={(e) => onExpireAtChange(e.target.value)}
                  disabled={loading}
                  style={inputStyle}
                />
              </label>
            ) : null}
          </>
        ) : null}
        {pending.requiresDate ? (
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={ui.label}>Expire date/time</span>
            <input
              type="datetime-local"
              value={expireAt}
              onChange={(e) => onExpireAtChange(e.target.value)}
              disabled={loading}
              style={inputStyle}
            />
          </label>
        ) : null}
        <label style={{ display: 'grid', gap: 6 }}>
          <span style={ui.label}>Reason{pending.requiresReason ? '' : ' (optional)'}</span>
          <textarea
            value={reason}
            onChange={(e) => onReasonChange(e.target.value)}
            disabled={loading}
            rows={3}
            placeholder={pending.requiresReason ? 'Enter reason…' : 'Optional reason…'}
            style={{ ...ui.textarea, minHeight: 72 }}
          />
        </label>
        {error ? (
          <div style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
            {error}
          </div>
        ) : null}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 4 }}>
          <button type="button" style={ui.btn} onClick={onCancel} disabled={loading}>Cancel</button>
          <button type="button" style={confirmStyle} onClick={onConfirm} disabled={loading}>
            {loading ? 'Working…' : pending.confirmLabel}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

function buildExpirationPatchPayload(exp) {
  const enabled = Boolean(exp?.enabled);
  const mode = enabled ? String(exp?.expiration_mode || 'never') : 'never';
  const payload = {
    observable_type: 'all',
    enabled,
    expiration_mode: mode,
    ttl_days: null,
    grace_days: null
  };
  if (!enabled) return payload;

  if (['fixed_ttl', 'last_seen_ttl'].includes(mode)) {
    const raw = exp?.ttl_days;
    if (raw !== '' && raw != null) {
      const n = parseInt(String(raw), 10);
      if (Number.isFinite(n) && n > 0) payload.ttl_days = n;
    }
  }
  if (mode === 'missing_from_feed_ttl') {
    const raw = exp?.grace_days !== '' && exp?.grace_days != null ? exp.grace_days : exp?.ttl_days;
    if (raw !== '' && raw != null) {
      const n = parseInt(String(raw), 10);
      if (Number.isFinite(n) && n > 0) payload.grace_days = n;
    }
  }
  return payload;
}

const EXPIRATION_OVERRIDE_IOC_TYPES = ['domain', 'ip', 'url', 'file_hash'];
const EXPIRATION_OVERRIDE_MODES = ['inherit', 'no_expire', 'fixed_ttl'];

function buildExpirationTypePoliciesPayload(overrides) {
  const out = [];
  const src = overrides || {};
  for (const iocType of EXPIRATION_OVERRIDE_IOC_TYPES) {
    const o = src[iocType] || {};
    const mode = EXPIRATION_OVERRIDE_MODES.includes(o.mode) ? o.mode : 'inherit';
    const entry = { ioc_type: iocType, mode, ttl_days: null };
    if (mode === 'fixed_ttl') {
      const raw = o.ttl_days;
      const n = raw === '' || raw == null ? NaN : parseInt(String(raw), 10);
      if (Number.isFinite(n) && n > 0) entry.ttl_days = n;
    }
    out.push(entry);
  }
  return out;
}

function buildExpirationFullPatchPayload(exp) {
  return {
    ...buildExpirationPatchPayload(exp),
    expiration_type_policies: buildExpirationTypePoliciesPayload(exp?.type_overrides)
  };
}

/** Human-readable effective policy preview for one IOC type. */
function formatTypeOverridePreview(label, override, feedExp) {
  const mode = override?.mode || 'inherit';
  if (mode === 'no_expire') return `${label}: No expire`;
  if (mode === 'fixed_ttl') {
    const n = parseInt(String(override?.ttl_days), 10);
    return Number.isFinite(n) && n > 0 ? `${label}: Fixed TTL ${n} days` : `${label}: Fixed TTL (set days)`;
  }
  // inherit
  if (!feedExp?.enabled || feedExp?.expiration_mode === 'never') {
    return `${label}: Inherits default (no expiration)`;
  }
  const days = parseInt(String(feedExp?.ttl_days ?? feedExp?.grace_days), 10);
  return Number.isFinite(days) && days > 0
    ? `${label}: Inherits default ${days} days`
    : `${label}: Inherits default`;
}

function auditSeverityBadgeStyle(severity) {
  const s = String(severity || 'info').toLowerCase();
  const base = { display: 'inline-block', borderRadius: 999, padding: '4px 10px', fontSize: 11, fontWeight: 700, textTransform: 'capitalize' };
  if (s === 'critical') return { ...base, background: 'rgba(239,68,68,0.18)', color: '#fca5a5', border: '1px solid #991b1b' };
  if (s === 'warning') return { ...base, background: 'rgba(251,191,36,0.15)', color: '#fcd34d', border: '1px solid #854d0e' };
  return { ...base, background: 'rgba(148,163,184,0.15)', color: '#94a3b8', border: '1px solid #475569' };
}

function auditStatusBadgeStyle(status) {
  const s = String(status || 'success').toLowerCase();
  const base = { display: 'inline-block', borderRadius: 999, padding: '4px 10px', fontSize: 11, fontWeight: 700, textTransform: 'capitalize' };
  if (s === 'failed') return { ...base, background: 'rgba(239,68,68,0.18)', color: '#fca5a5', border: '1px solid #991b1b' };
  return { ...base, background: 'rgba(34,197,94,0.15)', color: '#86efac', border: '1px solid #166534' };
}

function auditJsonBlock(value) {
  if (value == null) return '—';
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

const IOC_EXPIRATION_AUDIT_ACTIONS = new Set([
  'ioc.expired',
  'ioc.reactivated_by_user',
  'ioc.reactivated_by_match',
  'ioc_feed_membership.expired',
  'ioc_feed_membership.expired_by_user',
  'ioc_feed_membership.reactivated_by_match'
]);

const IOC_TAXONOMY_AUDIT_ACTIONS = new Set([
  'ioc.threat_classification.updated',
  'ioc.threat_classifications.updated',
  'ioc.threat_actor.updated',
  'threat_classification.created',
  'threat_classification.updated',
  'threat_classification.disabled',
  'threat_classification.enabled',
  'threat_actor.created',
  'threat_actor.updated',
  'threat_actor.disabled',
  'threat_actor.enabled',
  'tag.disabled',
  'tag.enabled'
]);

function formatExpirationPolicyLabel(policy) {
  const value = String(policy || '').trim();
  if (!value) return '—';
  if (value === 'never') return 'Never expire';
  if (value === 'expire_after_days') return 'Expire after days';
  if (value === 'custom_date') return 'Custom expire date';
  return value.replace(/_/g, ' ');
}

function auditMetadataValue(metadata, ...keys) {
  if (!metadata || typeof metadata !== 'object') return null;
  for (const key of keys) {
    const value = metadata[key];
    if (value != null && value !== '') return value;
  }
  return null;
}

function auditSnapshotValue(row, ...keys) {
  const metadata = row?.metadata;
  const fromMeta = auditMetadataValue(metadata, ...keys);
  if (fromMeta) return fromMeta;
  const before = row?.before_data;
  const after = row?.after_data;
  if (before && typeof before === 'object') {
    for (const key of keys) {
      const value = before[key];
      if (value != null && value !== '') return value;
    }
  }
  if (after && typeof after === 'object') {
    for (const key of keys) {
      const value = after[key];
      if (value != null && value !== '') return value;
    }
  }
  return null;
}

function truncateAuditText(value, max = 72) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}

function formatAuditEntityPrimary(row) {
  const subjectValue = row?.subject_ioc_value
    || auditSnapshotValue(row, 'subject_ioc_value', 'observable_value', 'original_value', 'ioc_value');
  if (subjectValue) return subjectValue;
  if (row?.entity_display) return row.entity_display;
  const value = auditSnapshotValue(row, 'ioc_value', 'observable');
  if (value) return value;
  const type = auditSnapshotValue(row, 'ioc_observable_type', 'observable_type', 'subject_ioc_type');
  if (type && row?.entity_id) return `${type} · #${row.entity_id}`;
  return row?.entity_id || '—';
}

function formatAuditEntitySubtitle(row) {
  const entityType = String(row?.entity_type || 'ioc').trim();
  const type = row?.subject_ioc_type
    || auditSnapshotValue(row, 'subject_ioc_type', 'ioc_observable_type', 'observable_type');
  const id = row?.subject_ioc_id
    || auditSnapshotValue(row, 'subject_ioc_id', 'ioc_id')
    || row?.entity_id;
  const parts = [entityType];
  if (type) parts.push(type);
  if (id) parts.push(`#${id}`);
  return parts.join(' · ');
}

function formatAuditEntityLabel(row) {
  return formatAuditEntityPrimary(row);
}

function AuditEntityCell({ row }) {
  const primaryFull = formatAuditEntityPrimary(row);
  const primary = truncateAuditText(primaryFull, 72);
  const subtitle = formatAuditEntitySubtitle(row);
  return (
    <div>
      <div title={primaryFull !== primary ? primaryFull : undefined} style={{ overflowWrap: 'anywhere' }}>{primary}</div>
      {subtitle ? <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{subtitle}</div> : null}
    </div>
  );
}

function formatThreatClassificationLabel(value) {
  const slug = String(value || 'unknown').trim() || 'unknown';
  if (slug === 'unknown') return 'Unknown';
  return slug.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatExpirationAuditReasonLabel(reason) {
  const value = String(reason || '').trim();
  if (!value) return '—';
  if (value === 'expires_at_reached') return 'Expires at reached';
  if (value === 'all_feed_memberships_expired') return 'All feed memberships expired';
  if (value === 'manual_override') return 'Manual override';
  if (value === 'correlation_match') return 'Correlation match';
  if (value.startsWith('legacy-migrated')) return value.replace(/-/g, ' ');
  return value.replace(/_/g, ' ');
}

function formatTaxonomyAuditMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object') return null;
  const parts = [];
  const oldClasses = metadata.old_classifications || (metadata.old_classification != null ? [metadata.old_classification] : null);
  const newClasses = metadata.new_classifications || (metadata.new_classification != null ? [metadata.new_classification] : null);
  if (Array.isArray(oldClasses) || Array.isArray(newClasses)) {
    const oldText = Array.isArray(oldClasses) && oldClasses.length
      ? oldClasses.map((x) => formatThreatClassificationLabel(x)).join(', ')
      : 'Unknown';
    const newText = Array.isArray(newClasses) && newClasses.length
      ? newClasses.map((x) => formatThreatClassificationLabel(x)).join(', ')
      : 'Unknown';
    parts.push(`${oldText} ? ${newText}`);
  } else {
    const oldClass = auditMetadataValue(metadata, 'old_classification');
    const newClass = auditMetadataValue(metadata, 'new_classification');
    if (oldClass != null && newClass != null) {
      parts.push(`${formatThreatClassificationLabel(oldClass)} ? ${formatThreatClassificationLabel(newClass)}`);
    }
  }
  const oldActor = auditMetadataValue(metadata, 'old_threat_actor');
  const newActor = auditMetadataValue(metadata, 'new_threat_actor');
  if (oldActor != null || newActor != null) {
    parts.push(`${oldActor || 'Not selected'} ? ${newActor || 'Not selected'}`);
  }
  return parts.length ? parts.join(' · ') : null;
}

function formatAuditStatusTransition(metadata) {
  const oldStatus = auditMetadataValue(metadata, 'old_status');
  const newStatus = auditMetadataValue(metadata, 'new_status');
  if (!oldStatus && !newStatus) return '—';
  if (oldStatus && newStatus) return `${oldStatus} ? ${newStatus}`;
  return oldStatus || newStatus;
}

function AuditExpirationSummary({ item }) {
  if (!item || !IOC_EXPIRATION_AUDIT_ACTIONS.has(String(item.action || ''))) return null;
  const metadata = item?.metadata && typeof item.metadata === 'object' ? item.metadata : {};
  const iocValue = auditSnapshotValue(item, 'ioc_value', 'observable');
  const rows = [
    ['IOC', iocValue],
    ['Type', auditSnapshotValue(item, 'ioc_observable_type', 'observable_type')],
    ['Status', formatAuditStatusTransition(metadata) || formatAuditStatusTransition(item?.before_data && item?.after_data ? { old_status: item.before_data?.status, new_status: item.after_data?.status } : null)],
    ['Reason', formatExpirationAuditReasonLabel(auditSnapshotValue(item, 'reason'))],
    ['Expiration policy', formatExpirationPolicyLabel(auditSnapshotValue(item, 'expiration_policy'))],
    ['Expire days', auditSnapshotValue(item, 'expire_days')],
    ['Policy expires at', formatAuditDate(auditSnapshotValue(item, 'policy_expires_at', 'expires_at') || item?.after_data?.expires_at)],
    ['Old expires at', formatAuditDate(auditSnapshotValue(item, 'old_expires_at') || item?.before_data?.expires_at)],
    ['Expired at', formatAuditDate(auditSnapshotValue(item, 'expired_at') || item?.after_data?.expired_at)],
    ['Feed', auditSnapshotValue(item, 'feed_name')],
    ['Membership ID', auditSnapshotValue(item, 'membership_id')],
    ['Source', auditSnapshotValue(item, 'source') || item?.source]
  ].filter(([, value]) => value && value !== '—');

  if (!rows.length) return null;

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#111827' }}>
      <div style={{ fontWeight: 700, marginBottom: 10, color: '#f8fafc' }}>IOC expiration context</div>
      <div style={{ display: 'grid', gap: 8 }}>
        {rows.map(([label, value]) => (
          <div key={label} style={{ display: 'grid', gridTemplateColumns: '140px 1fr', gap: 10, fontSize: 13 }}>
            <span style={{ color: '#94a3b8' }}>{label}</span>
            <span style={{ color: '#e2e8f0', overflowWrap: 'anywhere' }}>{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AuditTaxonomySummary({ item }) {
  if (!item || !IOC_TAXONOMY_AUDIT_ACTIONS.has(String(item.action || ''))) return null;
  const metadata = item?.metadata && typeof item.metadata === 'object' ? item.metadata : {};
  const oldClass = auditSnapshotValue(item, 'old_classification') || metadata.old_classification;
  const newClass = auditSnapshotValue(item, 'new_classification') || metadata.new_classification;
  const oldActor = auditSnapshotValue(item, 'old_threat_actor') || metadata.old_threat_actor;
  const newActor = auditSnapshotValue(item, 'new_threat_actor') || metadata.new_threat_actor;
  const oldClasses = item?.before_data?.threat_classifications || metadata.old_classifications
    || (oldClass != null ? [oldClass] : null);
  const newClasses = item?.after_data?.threat_classifications || metadata.new_classifications
    || (newClass != null ? [newClass] : null);
  const classSummary = Array.isArray(oldClasses) || Array.isArray(newClasses)
    ? `${(Array.isArray(oldClasses) && oldClasses.length ? oldClasses.map((x) => formatThreatClassificationLabel(x)).join(', ') : 'Unknown')} → ${(Array.isArray(newClasses) && newClasses.length ? newClasses.map((x) => formatThreatClassificationLabel(x)).join(', ') : 'Unknown')}`
    : (oldClass != null && newClass != null ? `${formatThreatClassificationLabel(oldClass)} → ${formatThreatClassificationLabel(newClass)}` : null);
  const rows = [
    ['Classifications', classSummary],
    ['Threat actor', oldActor != null || newActor != null ? `${oldActor || 'Not selected'} → ${newActor || 'Not selected'}` : null],
    ['IOC', auditSnapshotValue(item, 'ioc_value', 'observable')],
    ['Type', auditSnapshotValue(item, 'ioc_observable_type', 'observable_type')]
  ].filter(([, value]) => value && value !== '—');

  if (!rows.length) return null;

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#111827' }}>
      <div style={{ fontWeight: 700, marginBottom: 10, color: '#f8fafc' }}>Threat taxonomy context</div>
      <div style={{ display: 'grid', gap: 8 }}>
        {rows.map(([label, value]) => (
          <div key={label} style={{ display: 'grid', gridTemplateColumns: '140px 1fr', gap: 10, fontSize: 13 }}>
            <span style={{ color: '#94a3b8' }}>{label}</span>
            <span style={{ color: '#e2e8f0', overflowWrap: 'anywhere' }}>{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function formatAuditDate(value) {
  if (!value) return '—';
  const formatted = formatUserDateTime(value);
  return formatted === '-' ? String(value) : formatted;
}

async function fetchActiveSuppressionIndex(maxPages = 20) {
  const index = new Map();
  let page = 1;
  let total = Infinity;
  while ((page - 1) * 100 < total && page <= maxPages) {
    const { data } = await api.get('/ioc-suppressions', {
      params: { page, pageSize: 100, active: 'true', expires: 'active' }
    });
    const items = data?.items || [];
    total = Number(data?.total || 0);
    for (const item of items) {
      index.set(suppressionKey(item.ioc_value, item.ioc_type), item);
    }
    page += 1;
    if (!items.length) break;
  }
  return index;
}

async function resolveIocDetailsPublicId(iocValue, iocType) {
  const type = String(iocType || '').trim().toLowerCase();
  const rawValue = String(iocValue || '').trim();
  if (!rawValue) return null;

  const normalizedValue = (type === 'domain' || type === 'url') ? rawValue.toLowerCase() : rawValue;
  const candidates = [...new Set([rawValue, normalizedValue].filter(Boolean))];

  for (const observable of candidates) {
    try {
      const { data } = await api.get('/ioc/details/resolve', {
        params: { type: type || undefined, observable }
      });
      const publicId = String(data?.public_id || '').trim();
      if (publicId) return publicId;
    } catch (err) {
      console.warn('[ioc-details-resolve] resolve attempt failed', { observable, type, detail: err?.response?.data || err?.message });
    }
  }

  if (type) {
    try {
      const { data } = await api.get('/ioc/details/resolve', {
        params: { observable: normalizedValue }
      });
      const publicId = String(data?.public_id || '').trim();
      if (publicId) return publicId;
    } catch (err) {
      console.warn('[ioc-details-resolve] resolve without type failed', { observable: normalizedValue, detail: err?.response?.data || err?.message });
    }
  }

  if (type) {
    try {
      const q = `${type}:${normalizedValue}`;
      const { data } = await api.get('/ioc/list', { params: { q, page: 1, page_size: 10 } });
      const items = Array.isArray(data?.items) ? data.items : [];
      const match = items.find((row) =>
        suppressionKey(row.observable || row.ip, row.observable_type || 'ip') === suppressionKey(normalizedValue, type)
      ) || items.find((row) => String(row.public_id || '').trim());
      const publicId = String(match?.public_id || '').trim();
      if (publicId) return publicId;
    } catch (err) {
      console.warn('[ioc-details-resolve] list fallback failed', { type, normalizedValue, detail: err?.response?.data || err?.message });
    }
  }

  return null;
}

async function navigateToIocDetailsFromSuppression(item, navigate) {
  const iocValue = String(item?.ioc_value || '').trim();
  const iocType = String(item?.ioc_type || '').trim();
  if (!iocValue) {
    throw new Error('missing IOC value');
  }
  const publicId = await resolveIocDetailsPublicId(iocValue, iocType);
  if (publicId) {
    navigate(`/ioc/details/${encodeURIComponent(publicId)}`);
    return;
  }
  throw new Error(`no public_id for ${iocValue}`);
}

let modalScrollLockCount = 0;

function lockPageScroll() {
  modalScrollLockCount += 1;
  if (modalScrollLockCount === 1) {
    document.documentElement.classList.add('modal-scroll-lock');
    document.body.classList.add('modal-scroll-lock');
  }
}

function unlockPageScroll() {
  modalScrollLockCount = Math.max(0, modalScrollLockCount - 1);
  if (modalScrollLockCount === 0) {
    document.documentElement.classList.remove('modal-scroll-lock');
    document.body.classList.remove('modal-scroll-lock');
  }
}

function useBodyScrollLock(active) {
  useEffect(() => {
    if (!active) return undefined;
    lockPageScroll();
    return () => unlockPageScroll();
  }, [active]);
}

function ModalOverlay({ children, onClose, title, footer, zIndex = 1000 }) {
  useBodyScrollLock(true);

  const modal = (
    <div
      className="modal-overlay"
      role="presentation"
      onClick={onClose}
      style={{ zIndex }}
    >
      <div
        className={`modal-dialog${footer || title ? '' : ' modal-dialog--legacy'}`}
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
      >
        {title ? (
          <div className="modal-header">
            <h3 className="modal-title">{title}</h3>
          </div>
        ) : null}
        {footer || title ? (
          <>
            <div className="modal-body">{children}</div>
            {footer ? <div className="modal-footer">{footer}</div> : null}
          </>
        ) : (
          children
        )}
      </div>
    </div>
  );

  return createPortal(modal, document.body);
}

const ReasonPromptContext = React.createContext(null);

function ReasonPromptProvider({ children }) {
  const [state, setState] = useState(null);
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const resolverRef = useRef(null);

  const requestRequiredReason = useCallback((actionLabel, options = {}) => {
    if (resolverRef.current) return Promise.resolve(null);
    return new Promise((resolve) => {
      resolverRef.current = resolve;
      setReason('');
      setError('');
      setState({
        title: options.title || actionLabel,
        description: options.description || 'Provide a reason for this action (minimum 3 characters).',
        confirmLabel: options.confirmLabel || 'Confirm'
      });
    });
  }, []);

  const close = useCallback((value) => {
    const resolve = resolverRef.current;
    resolverRef.current = null;
    setState(null);
    setReason('');
    setError('');
    if (resolve) resolve(value);
  }, []);

  const handleCancel = useCallback(() => close(null), [close]);

  const handleSubmit = useCallback(() => {
    const trimmed = String(reason || '').trim();
    if (trimmed.length < 3) {
      setError('Reason is required (minimum 3 characters).');
      return;
    }
    close(trimmed.slice(0, 4000));
  }, [reason, close]);

  const value = useMemo(() => requestRequiredReason, [requestRequiredReason]);

  const inputStyle = {
    padding: '8px 10px',
    borderRadius: 6,
    border: '1px solid #475569',
    background: '#0f172a',
    color: '#e2e8f0',
    fontSize: 13,
    width: '100%',
    boxSizing: 'border-box',
    minHeight: 72,
    resize: 'vertical'
  };

  return (
    <ReasonPromptContext.Provider value={value}>
      {children}
      {state ? (
        <ModalOverlay onClose={handleCancel}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9', fontSize: 18 }}>{state.title}</h3>
          <p style={{ color: '#cbd5e1', fontSize: 13, lineHeight: 1.55, marginTop: 0, marginBottom: 14 }}>{state.description}</p>
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={{ color: '#94a3b8', fontSize: 13 }}>Reason</span>
            <textarea
              value={reason}
              onChange={(e) => { setReason(e.target.value); if (error) setError(''); }}
              rows={4}
              placeholder="Enter reason…"
              style={inputStyle}
              autoFocus
            />
          </label>
          {error ? (
            <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
              {error}
            </div>
          ) : null}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 14 }}>
            <button type="button" onClick={handleCancel}>Cancel</button>
            <button type="button" onClick={handleSubmit}>{state.confirmLabel}</button>
          </div>
        </ModalOverlay>
      ) : null}
    </ReasonPromptContext.Provider>
  );
}

function useReasonPrompt() {
  const ctx = useContext(ReasonPromptContext);
  if (!ctx) throw new Error('useReasonPrompt must be used within ReasonPromptProvider');
  return ctx;
}

const SAVED_VIEW_STORAGE = {
  detectionEvents: 'demo.savedViews.detectionEvents',
  incidents: 'demo.savedViews.incidents'
};

const BULK_TRIAGE_MAX = 100;

function loadSavedViews(storageKey) {
  try {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persistSavedViews(storageKey, views) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(views.slice(0, 20)));
  } catch {
    /* ignore quota errors */
  }
}

function BulkActionConfirmModal({
  open,
  title,
  description,
  confirmLabel,
  loading,
  error,
  reason,
  onReasonChange,
  onCancel,
  onConfirm,
  extraContent = null
}) {
  if (!open) return null;
  return (
    <ModalOverlay onClose={loading ? undefined : onCancel}>
      <h3 style={{ marginTop: 0, color: '#f1f5f9', fontSize: 18 }}>{title}</h3>
      <p style={{ color: '#cbd5e1', fontSize: 13, lineHeight: 1.55, marginTop: 0, marginBottom: 14 }}>{description}</p>
      {extraContent}
      <label style={{ display: 'grid', gap: 6 }}>
        <span style={{ color: '#94a3b8', fontSize: 13 }}>Reason (required, min 3 characters)</span>
        <textarea
          value={reason}
          onChange={(e) => onReasonChange(e.target.value)}
          rows={4}
          placeholder="Enter reason…"
          style={{
            padding: '8px 10px',
            borderRadius: 6,
            border: '1px solid #475569',
            background: '#0f172a',
            color: '#e2e8f0',
            fontSize: 13,
            width: '100%',
            boxSizing: 'border-box',
            minHeight: 72,
            resize: 'vertical'
          }}
          autoFocus
        />
      </label>
      {error ? (
        <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
          {error}
        </div>
      ) : null}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 14 }}>
        <button type="button" onClick={onCancel} disabled={loading}>Cancel</button>
        <button type="button" onClick={onConfirm} disabled={loading}>{loading ? 'Working…' : confirmLabel}</button>
      </div>
    </ModalOverlay>
  );
}

function normalizeEventContext(event) {
  const sourceType = String(event?.source_type || '').toLowerCase();
  const parserSource = String(event?.parser_source || '').toLowerCase();
  const match = event?.match_context || {};
  const lab = String(event?.context_label || '');
  const v2famEarly = String(event?.v2_context?.event_family || '').toLowerCase();
  if (lab === 'DNS' && v2famEarly === 'proxy') return 'Proxy';

  if (event?.context_label) return String(event.context_label);
  if (event?.inferred_context) return String(event.inferred_context);

  const labelFromFamily = (fam) => {
    const f = String(fam || '').toLowerCase();
    if (f === 'proxy') return 'Proxy';
    if (f === 'dns') return 'DNS';
    if (f === 'firewall') return 'Firewall';
    if (f === 'waf') return 'WAF';
    if (f === 'endpoint') return 'Endpoint';
    return '';
  };
  const topFam = labelFromFamily(event?.event_family);
  if (topFam) return topFam;
  const v2Fam = labelFromFamily(event?.v2_context?.event_family);
  if (v2Fam) return v2Fam;

  const v2Control = String(event?.control_point || event?.v2_context?.control_point || '').toLowerCase();
  if (v2Control === 'proxy') return 'Proxy';
  if (v2Control === 'dns_resolver' || v2Control === 'dns') return 'DNS';
  if (v2Control === 'firewall') return 'Firewall';

  const norm = event?.normalized_event_json || {};

  const proxySource = /(proxy|web|url)/i.test(sourceType) || /(proxy|squid|web|url|http)/i.test(parserSource);
  const proxyFields = [norm?.url, norm?.http_host, norm?.request_url, norm?.method, norm?.status_code, match?.url, match?.http_host, match?.request_url]
    .some((v) => String(v || '').trim() !== '');
  if (proxySource || proxyFields) return 'Proxy';

  const dnsParser = /(dns|microsoft_dns|bind_dns|dns_debug|microsoft_dns_debug|dns_kv)/i.test(parserSource);
  const dnsSource = sourceType === 'dns';
  const dnsFields = [match?.ioc_query, match?.query_type, match?.response_ip, norm?.query, norm?.dns_query, norm?.domain_query]
    .some((v) => String(v || '').trim() !== '');
  if (dnsParser || dnsSource || dnsFields) return 'DNS';

  const firewallSource = /(firewall|traffic)/i.test(sourceType) || /(fortigate|firewall|traffic|paloalto|pan-os|checkpoint|netflow)/i.test(parserSource);
  const trafficFields = [match?.srcip, match?.dstip, match?.dstport, match?.proto, match?.action, norm?.src_ip, norm?.dst_ip, norm?.destination_port]
    .some((v) => String(v || '').trim() !== '');
  if (firewallSource || trafficFields) return 'Firewall';

  if (sourceType === 'waf' || /(waf|f5|asm|modsecurity|nginx-waf)/i.test(parserSource)) return 'WAF';
  if (sourceType === 'endpoint' || /(endpoint|edr|xdr|sysmon)/i.test(parserSource)) return 'Endpoint';

  const tokens = [
    event?.type,
    event?.log_type,
    event?.parser_type,
    event?.source_type,
    event?.context,
    event?.v2_context?.event_family,
    event?.v2_context?.control_point,
    event?.v2_context?.scenario_type
  ]
    .map((v) => String(v || '').toLowerCase())
    .filter(Boolean)
    .join(' ');

  if (/(proxy|url|http|webproxy|secure web gateway|swg)/i.test(tokens)) return 'Proxy';
  if (/(^|\s)dns(\s|$)|resolver|query_type|resolved_ip/i.test(tokens)) return 'DNS';
  if (/(waf|f5|asm|application firewall|modsecurity|nginx-waf)/i.test(tokens)) return 'WAF';
  if (/(endpoint|edr|xdr|process|file[_\s-]?event|sysmon)/i.test(tokens)) return 'Endpoint';
  if (/(firewall|traffic|fortigate|forti|paloalto|pan-os|checkpoint|netflow|forward)/i.test(tokens)) return 'Firewall';

  if ((sourceType === 'generic' || sourceType === '') && (parserSource === 'unknown' || parserSource === '')) return 'Generic';
  return 'Generic';
}

function LoginPage() {
  const navigate = useNavigate();
  const { refreshSession } = useSession();
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setError('');
    const form = new FormData(e.currentTarget);
    const email = String(form.get('email') || '').trim();
    const password = String(form.get('password') || '');

    if (!email || !password) {
      setError('Enter your username and password to continue.');
      return;
    }

    setSubmitting(true);
    try {
      await api.post('/auth/login', { email, password });
      localStorage.removeItem('demo_timezone');
      await refreshSession();
      navigate('/ioc');
    } catch (err) {
      const msg = err?.response?.data?.message || 'Invalid email or password';
      setError(msg);
      setSubmitting(false);
    }
  }

  return (
    <div className="login-shell">
      <main className="auth">
        <div className="top-brand">
          <img src={talonHoundLogo} alt="TalonHound" draggable={false} />
          <span className="wm">Talon<span className="hound">Hound</span></span>
        </div>

        <div className="card">
          <h1>Sign in</h1>
          <p className="sub">Enter your credentials to access TalonHound.</p>

          <form onSubmit={onSubmit} noValidate>
            <div className="field">
              <label htmlFor="login-user">Username or email</label>
              <input id="login-user" name="email" type="text" autoComplete="username" required />
            </div>

            <div className="field">
              <label htmlFor="login-pass">Password</label>
              <input id="login-pass" name="password" type="password" autoComplete="current-password" required />
            </div>

            <button className={`btn${submitting ? ' loading' : ''}`} type="submit" disabled={submitting}>
              {submitting ? 'Signing in…' : 'Sign in'}
            </button>
            {error ? <div className="msg err" role="alert">{error}</div> : null}
          </form>
        </div>

        <p className="foot">TalonHound Console</p>
      </main>

      <aside className="brand">
        <svg className="texture" viewBox="0 0 1200 900" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
          <circle className="dash" cx="980" cy="180" r="150" />
          <circle className="dash" cx="1060" cy="620" r="230" />
          <circle cx="850" cy="430" r="60" />
          <circle className="dash" cx="220" cy="760" r="180" />
          <rect className="dash" x="640" y="330" width="760" height="140" rx="70" />
          <line className="dash" x1="80" y1="140" x2="420" y2="140" />
          <line className="dash" x1="760" y1="810" x2="1150" y2="810" />
        </svg>

        <div className="brand-inner">
          <img className="wolf" src={talonHoundLogo} alt="" draggable={false} />
          <div className="wordmark">Talon<span className="hound">Hound</span></div>
          <p className="tagline">Track adversaries across your network before they reach what matters.</p>
        </div>
      </aside>
    </div>
  );
}

function AppShell({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { userEmail, role, canWrite, isAdmin, refreshSession } = useSession();
  const [timezone, setTimezone] = useState(getSystemTimezone());
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);

  useEffect(() => {
    setIsMobileNavOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    let mounted = true;
    async function loadSystemTz() {
      try {
        const { data } = await api.get('/system/timezone');
        if (!mounted) return;
        if (data?.system_timezone) {
          setSystemTimezoneCache(data.system_timezone);
          setTimezone(data.system_timezone);
        }
      } catch {
        /* setup gate / auth will redirect as needed */
      }
    }
    loadSystemTz();
    const onTz = () => setTimezone(getSystemTimezone());
    window.addEventListener(TIMEZONE_CHANGED_EVENT, onTz);
    return () => {
      mounted = false;
      window.removeEventListener(TIMEZONE_CHANGED_EVENT, onTz);
    };
  }, []);

  async function logout() {
    try {
      await api.post('/auth/logout');
    } catch {
      /* still leave app */
    }
    await refreshSession();
    navigate('/login');
  }

  const isActive = (path) => location.pathname === path;
  const isAdminSettingsActive = isActive('/administration')
    && !isActive('/administration/users')
    && !isActive('/administration/api-keys')
    && !isActive('/administration/audit-logs')
    && !isActive('/administration/enrichment-providers')
    && !isActive('/administration/backup-restore')
    && !isActive('/administration/tags')
    && !isActive('/administration/threat-classifications')
    && !isActive('/administration/threat-actors')
    && !isActive('/administration/ioc-sources');

  const navLinkClass = (active) => `sidebar-nav-link${active ? ' is-active' : ''}`;
  const roleLabel = formatSidebarRoleLabel(role);
  const initials = userInitialsFromEmail(userEmail);
  const displayName = userEmail || 'demo user';

  return (
    <div className="app-shell" style={{ width: '100%', margin: '16px 0', fontFamily: 'sans-serif', display: 'flex', gap: 16, alignItems: 'flex-start', padding: '0 16px', boxSizing: 'border-box' }}>
      <div className="mobile-topbar">
        <button className="mobile-menu-btn" onClick={() => setIsMobileNavOpen((v) => !v)} aria-label="Toggle navigation menu">?</button>
        <span className="mobile-topbar-title">TalonHound</span>
        <span className="mobile-topbar-user">{userEmail ? userEmail.split('@')[0] : 'user'}</span>
      </div>
      {isMobileNavOpen && <div className="mobile-backdrop" onClick={() => setIsMobileNavOpen(false)} />}
      <aside className={`sidebar${isMobileNavOpen ? ' sidebar--open' : ''}`} style={{ flex: '0 0 260px', border: '1px solid #334155', borderRadius: 10, padding: 0, height: 'fit-content', position: 'sticky', top: 16, background: '#0f172a', overflow: 'hidden' }}>
        <div className="mobile-sidebar-close"><button onClick={() => setIsMobileNavOpen(false)} aria-label="Close menu">?</button></div>

        <div className="sidebar-brand">
          <img
            src={talonHoundLogo}
            alt="TalonHound"
            className="sidebar-brand-logo"
            draggable={false}
          />
        </div>

        <div className="sidebar-user-panel" title={displayName}>
          <div className="sidebar-user-avatar" aria-hidden="true">{initials}</div>
          <div className="sidebar-user-meta">
            <div className="sidebar-user-email">{displayName}</div>
            <div className="sidebar-user-role">{roleLabel}</div>
          </div>
          <span className="sidebar-user-chevron" aria-hidden="true">▾</span>
        </div>

        <nav className="sidebar-nav">
          <div className="sidebar-nav-section">
            <div className="sidebar-nav-section-label">System</div>
            <Link to="/system" className={navLinkClass(isActive('/system'))}>{NavIcons.system}<span>System</span></Link>
          </div>

          <div className="sidebar-nav-section">
            <div className="sidebar-nav-section-label">Operations</div>
            <Link to="/ioc" className={navLinkClass(isActive('/ioc'))}>{NavIcons.iocList}<span>IOC List</span></Link>
            {canWrite ? (
              <Link to="/ioc/new" className={navLinkClass(isActive('/ioc/new'))}>{NavIcons.addIoc}<span>Add IOC</span></Link>
            ) : (
              <span className="sidebar-nav-link is-disabled" title="Read-only role">{NavIcons.addIoc}<span>Add IOC</span></span>
            )}
            <Link to="/operations/ioc-suppressions" className={navLinkClass(location.pathname.startsWith('/operations/ioc-suppressions'))}>{NavIcons.suppressions}<span>IOC Suppressions</span></Link>
            <Link to="/action-center" className={navLinkClass(location.pathname.startsWith('/action-center'))}>{NavIcons.actionCenter}<span>Action Center</span></Link>
          </div>

          <div className="sidebar-nav-section">
            <div className="sidebar-nav-section-label">Threat Intelligence</div>
            <Link to="/threat-intelligence/feeds" className={navLinkClass(isActive('/threat-intelligence/feeds') || isActive('/threat-intelligence'))}>{NavIcons.feeds}<span>Feeds</span></Link>
            <Link to="/threat-intelligence/custom-threat-feeds" className={navLinkClass(isActive('/threat-intelligence/custom-threat-feeds'))}>{NavIcons.customFeeds}<span>Custom Threat Feeds</span></Link>
            <Link to="/threat-intelligence/queue" className={navLinkClass(isActive('/threat-intelligence/queue'))}>{NavIcons.jobQueue}<span>Job Queue Status</span></Link>
            <Link to="/threat-intelligence/published-feeds" className={navLinkClass(isActive('/threat-intelligence/published-feeds'))}>{NavIcons.publishedFeeds}<span>Published Feeds</span></Link>
          </div>

          <div className="sidebar-nav-section">
            <div className="sidebar-nav-section-label">Administration</div>
            <Link to="/administration" className={navLinkClass(isAdminSettingsActive)}>{NavIcons.settings}<span>Settings</span></Link>
            {isAdmin ? <Link to="/administration/users" className={navLinkClass(isActive('/administration/users'))}>{NavIcons.users}<span>Users</span></Link> : null}
            <Link to="/administration/audit-logs" className={navLinkClass(isActive('/administration/audit-logs'))}>{NavIcons.auditLogs}<span>Audit Logs</span></Link>
            <Link to="/administration/tags" className={navLinkClass(isActive('/administration/tags'))}>{NavIcons.tags}<span>Tags</span></Link>
            {isAdmin ? <Link to="/administration/threat-classifications" className={navLinkClass(isActive('/administration/threat-classifications'))}>{NavIcons.classifications}<span>Threat Classifications</span></Link> : null}
            {isAdmin ? <Link to="/administration/threat-actors" className={navLinkClass(isActive('/administration/threat-actors'))}>{NavIcons.threatActors}<span>Threat Actors</span></Link> : null}
            {isAdmin ? <Link to="/administration/ioc-sources" className={navLinkClass(isActive('/administration/ioc-sources'))}>{NavIcons.iocSources}<span>IOC Sources</span></Link> : null}
            <Link to="/administration/api-keys" className={navLinkClass(isActive('/administration/api-keys'))}>{NavIcons.apiKeys}<span>API Keys</span></Link>
            <Link to="/administration/enrichment-providers" className={navLinkClass(isActive('/administration/enrichment-providers'))}>{NavIcons.enrichmentProviders}<span>Enrichment Providers</span></Link>
            {isAdmin ? <Link to="/administration/backup-restore" className={navLinkClass(isActive('/administration/backup-restore'))}>{NavIcons.backupRestore}<span>Backup &amp; Restore</span></Link> : null}
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-timezone">Timezone: <b>{timezone}</b></div>
          <button type="button" className="sidebar-logout-btn" onClick={logout} aria-label="Logout">
            <span aria-hidden="true" style={{ display: 'inline-flex', width: 16, height: 16 }}>
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                <path d="M16 17l5-5-5-5" />
                <path d="M21 12H9" />
              </svg>
            </span>
            Logout
          </button>
        </div>
      </aside>

      <main className="main-content" style={{ flex: 1, minWidth: 0 }}>
        {children}
      </main>
    </div>
  );
}

function SystemStatusPage() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadStatus = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get('/system/status');
      setStatus(data);
    } catch {
      setError('Failed to load system status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStatus().catch(() => {});
  }, [loadStatus]);

  const database = status?.database || {};
  const redisStatus = status?.redis || {};
  const queues = status?.queues || {};
  const queueRows = Object.entries(queues).filter(([key]) => key !== 'error');
  const integrations = status?.integrations || {};
  const telemetry = status?.telemetry || {};

  const statusDot = (ok) => ({
    display: 'inline-flex',
    alignItems: 'center',
    gap: 8,
    fontSize: 13,
    fontWeight: 700,
    color: ok ? '#22c55e' : '#f87171'
  });

  const renderTimestamp = (value) => (value ? formatUserDateTime(value) : '-');

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
          <div>
            <h2 style={{ margin: 0 }}>System Status</h2>
            <div style={{ color: '#94a3b8', fontSize: 13 }}>
              Last refresh: <b>{status?.generated_at ? formatUserDateTime(status.generated_at) : '-'}</b>
            </div>
          </div>
          <button onClick={() => loadStatus().catch(() => {})} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>

        {error && (
          <div style={{ marginTop: 12, padding: 10, borderRadius: 8, border: '1px solid #f87171', background: '#451a1a', color: '#fecaca' }}>
            {error}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12, marginTop: 16 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 700 }}>Database</div>
              <span style={statusDot(database.ok)}>? {database.ok ? 'OK' : 'Down'}</span>
            </div>
            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Name:</b> {database.current_database || '-'}</div>
              <div><b>Version:</b> {database.version ? database.version.split('on')[0].trim() : '-'}</div>
              <div><b>Size:</b> {database.size_mb !== undefined ? `${database.size_mb} MB` : '-'}</div>
              <div><b>Connections:</b> {database.connections ? `${database.connections.total} (active ${database.connections.active}, idle ${database.connections.idle})` : '-'}</div>
              {database.error && <div style={{ color: '#f87171' }}>{database.error}</div>}
            </div>
          </div>

          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 700 }}>Redis</div>
              <span style={statusDot(redisStatus.ok)}>? {redisStatus.ok ? 'OK' : 'Down'}</span>
            </div>
            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Version:</b> {redisStatus.version || '-'}</div>
              <div><b>Mode:</b> {redisStatus.mode || '-'}</div>
              <div><b>Uptime:</b> {redisStatus.uptime_seconds ? `${Math.round(redisStatus.uptime_seconds / 3600)}h` : '-'}</div>
              <div><b>Clients:</b> {redisStatus.connected_clients ?? '-'}</div>
              <div><b>Memory:</b> {redisStatus.memory_used_mb ? `${redisStatus.memory_used_mb} MB` : '-'}</div>
              {redisStatus.error && <div style={{ color: '#f87171' }}>{redisStatus.error}</div>}
            </div>
          </div>

        </div>

        <div style={{ marginTop: 20, border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Queues</div>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 480 }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#111827' }}>
                <th>Queue</th>
                <th>Waiting</th>
                <th>Active</th>
                <th>Completed</th>
                <th>Failed</th>
                <th>Delayed</th>
              </tr>
            </thead>
            <tbody>
              {queueRows.length ? queueRows.map(([name, counts]) => (
                <tr key={name} style={{ borderTop: '1px solid #334155' }}>
                  <td style={{ textTransform: 'capitalize' }}>{name.replace(/_/g, ' ')}</td>
                  <td>{counts?.waiting ?? '-'}</td>
                  <td>{counts?.active ?? '-'}</td>
                  <td>{counts?.completed ?? '-'}</td>
                  <td>{counts?.failed ?? '-'}</td>
                  <td>{counts?.delayed ?? '-'}</td>
                </tr>
              )) : (
                <tr><td colSpan={6} style={{ color: '#94a3b8' }}>{queues.error || 'No queue data available'}</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginTop: 20 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>Integration Pipeline</div>
            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Active feeds:</b> {integrations.active_feeds ?? '-'} / {integrations.total_feeds ?? '-'}</div>
              <div><b>Last queue job:</b> {integrations.last_queue_job ? `${integrations.last_queue_job.status} @ ${renderTimestamp(integrations.last_queue_job.queued_at)}` : '-'}</div>
              <div><b>Last run:</b> {integrations.last_run ? `${integrations.last_run.status} (${integrations.last_run.job_type}) @ ${renderTimestamp(integrations.last_run.started_at)}` : '-'}</div>
              {integrations.error && <div style={{ color: '#f87171' }}>{integrations.error}</div>}
            </div>
          </div>


          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>Telemetry</div>
            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Total IOCs:</b> {telemetry.ioc_total ?? '-'}</div>
              <div><b>IOCs added today:</b> {telemetry.ioc_today ?? '-'}</div>
              {telemetry.error && <div style={{ color: '#f87171' }}>{telemetry.error}</div>}
            </div>
          </div>
        </div>
      </section>
    </AppShell>
  );
}

const FEED_SCHEDULE_OPTIONS = [
  { cron: '*/5 * * * *', label: 'Every 5 min' },
  { cron: '*/15 * * * *', label: 'Every 15 min' },
  { cron: '*/30 * * * *', label: 'Every 30 min' },
  { cron: '0 * * * *', label: 'Every hour' },
  { cron: '0 0 * * *', label: 'Every day' },
  { cron: 'run_once', label: 'Run once' }
];

const RUN_ONCE_SCHEDULE_HELPER = 'Run once feeds are not executed by the recurring scheduler. Use Run now to execute them manually.';

const FEED_METRIC_TOOLTIPS = {
  processed: FEED_RESULT_METRIC_TOOLTIPS.checked,
  inserted: FEED_RESULT_METRIC_TOOLTIPS.new,
  unchanged: FEED_RESULT_METRIC_TOOLTIPS.unchanged,
  reactivated: FEED_RESULT_METRIC_TOOLTIPS.reactivated,
  removed: FEED_RESULT_METRIC_TOOLTIPS.expired,
  duplicate: 'Deprecated alias of Unchanged.',
  updated: FEED_RESULT_METRIC_TOOLTIPS.updated,
  skipped: FEED_RESULT_METRIC_TOOLTIPS.filtered,
  suppressed: FEED_RESULT_METRIC_TOOLTIPS.suppressed,
  failed: FEED_RESULT_METRIC_TOOLTIPS.failed
};

function feedMetricsHintPresentation(hint) {
  const map = {
    legacy_metrics: { label: 'Legacy metrics', color: '#fcd34d', title: 'Import breakdown unavailable until the feed runs again with granular metrics.' },
    no_delta: { label: 'No changes', color: '#94a3b8', title: 'Last run checked records but did not insert or update IOCs — normal when feed content is unchanged.' },
    high_skipped: { label: 'High filtered', color: '#fdba74', title: 'Most records were filtered (unsupported or outside importer scope). Informational only.' },
    high_failed: { label: 'High failed', color: '#fca5a5', title: 'A significant share of records failed to import.' },
    partial_fetch: { label: 'Partial fetch', color: '#fcd34d', title: 'Provider returned a truncated or partial result; some pages may be missing.' }
  };
  return map[hint] || { label: hint, color: '#94a3b8', title: hint };
}

function feedStatePresentation(enabled) {
  if (enabled) {
    return { label: 'Enabled', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534' };
  }
  return { label: 'Disabled', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' };
}

const EXPIRATION_MODE_OPTIONS = [
  { id: 'never', label: 'Never' },
  { id: 'fixed_ttl', label: 'Fixed TTL (from first seen in feed)' },
  { id: 'last_seen_ttl', label: 'Last seen TTL' },
  { id: 'missing_from_feed_ttl', label: 'Missing from feed (snapshot feeds)' }
];

function iocStatusBadge(status) {
  const s = String(status || 'active').toLowerCase();
  const map = {
    active: { label: 'Active', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534' },
    expired: { label: 'Expired', color: '#fcd34d', bg: 'rgba(120,53,15,0.25)', border: '#854d0e' },
    purged: { label: 'Purged', color: '#fca5a5', bg: 'rgba(127,29,29,0.25)', border: '#991b1b' },
    removed: { label: 'Removed', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' },
    disabled: { label: 'Disabled', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' },
    inactive: { label: 'Inactive', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' },
    suppressed: { label: 'Suppressed', color: '#93c5fd', bg: 'rgba(30,58,138,0.25)', border: '#1d4ed8' },
    false_positive: { label: 'False Positive', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534' },
    fp: { label: 'False Positive', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534' }
  };
  const hit = map[s] || map.active;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: hit.color, background: hit.bg, border: `1px solid ${hit.border}`, whiteSpace: 'nowrap' }}>
      <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: 999, background: hit.color, flexShrink: 0 }} />
      {hit.label}
    </span>
  );
}

function iocSourceStatusBadge(source) {
  if (!source) return iocStatusBadge('active');
  const status = source.purged_at ? 'purged' : String(source.status || 'active').toLowerCase();
  return iocStatusBadge(status);
}

function iocSourceTypeLabel(source) {
  if (!source) return 'Source';
  return source.source_type === 'manual' ? 'Manual source' : 'Feed';
}

const EXPIRATION_TYPE_OVERRIDE_TYPES = [
  { id: 'domain', label: 'Domain' },
  { id: 'ip', label: 'IP' },
  { id: 'url', label: 'URL' },
  { id: 'file_hash', label: 'Hash' }
];

const EXPIRATION_TYPE_OVERRIDE_MODES = [
  { id: 'inherit', label: 'Inherit' },
  { id: 'no_expire', label: 'No expire' },
  { id: 'fixed_ttl', label: 'Fixed TTL' }
];

function defaultTypeOverridesDraft(typePolicies) {
  const byType = {};
  for (const entry of Array.isArray(typePolicies) ? typePolicies : []) {
    if (entry?.ioc_type) byType[entry.ioc_type] = entry;
  }
  const draft = {};
  for (const t of EXPIRATION_TYPE_OVERRIDE_TYPES) {
    const p = byType[t.id];
    draft[t.id] = {
      mode: p?.mode || 'inherit',
      ttl_days: p?.ttl_days ?? ''
    };
  }
  return draft;
}

function defaultExpirationDraft(policy, typePolicies) {
  const p = policy || {};
  return {
    enabled: Boolean(p.enabled),
    expiration_mode: p.expiration_mode || 'never',
    ttl_days: p.ttl_days ?? '',
    grace_days: p.grace_days ?? '',
    type_overrides: defaultTypeOverridesDraft(typePolicies)
  };
}

function FeedHealthModal({ title, children, onClose, actions }) {
  return (
    <ModalOverlay onClose={onClose} title={title} footer={actions}>
      {children}
    </ModalOverlay>
  );
}

function FeedActiveConfirmModal({ feed, mode, loading, error, onCancel, onConfirm }) {
  const enable = mode === 'enable';
  return (
    <FeedHealthModal
      title={enable ? 'Enable feed?' : 'Disable feed?'}
      onClose={loading ? undefined : onCancel}
      actions={(
        <>
          <button type="button" onClick={onCancel} disabled={loading}>Cancel</button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={loading}
            style={enable ? undefined : { background: '#991b1b', borderColor: '#7f1d1d' }}
          >
            {loading ? (enable ? 'Enabling...' : 'Disabling...') : (enable ? 'Enable Feed' : 'Disable Feed')}
          </button>
        </>
      )}
    >
      <p style={{ margin: '0 0 12px', color: '#94a3b8', fontSize: 13, lineHeight: 1.55 }}>
        {enable
          ? 'Enabling this feed will allow scheduled imports to run again for this threat feed.'
          : 'Disabling this feed will stop scheduled imports for this threat feed. Existing IOCs, incidents, and historical evidence will not be deleted, but new IOC updates from this source will stop until the feed is enabled again.'}
      </p>
      <div style={{ fontSize: 13, color: '#cbd5e1' }}>
        <span style={{ color: '#94a3b8' }}>Feed: </span>
        <strong>{feed?.name || feed?.key}</strong>
      </div>
      {error ? (
        <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
          {error}
        </div>
      ) : null}
    </FeedHealthModal>
  );
}

const URLHAUS_FEED_KEY = 'urlhaus-abusech';
const MALWAREBAZAAR_FEED_KEY = 'malwarebazaar-abusech';
const THREATFOX_FEED_KEY = 'threatfox-abusech';
const ALIENVAULT_OTX_FEED_KEY = 'alienvault-otx';

const AUTH_KEY_FEED_CONFIG = {
  [URLHAUS_FEED_KEY]: {
    title: 'URLHaus Auth-Key',
    placeholder: 'Enter URLHaus Auth-Key',
    helpText: 'Required for URLHaus file exports. Do not include it in the URL.',
    saveSuccess: 'URLHaus Auth-Key saved.',
    saveError: 'Failed to save URLHaus Auth-Key',
    supportsTest: true
  },
  [MALWAREBAZAAR_FEED_KEY]: {
    title: 'MalwareBazaar Auth-Key',
    placeholder: 'Enter MalwareBazaar Auth-Key',
    helpText: 'Required for MalwareBazaar file exports. Do not include it in the URL.',
    saveSuccess: 'MalwareBazaar Auth-Key saved.',
    saveError: 'Failed to save MalwareBazaar Auth-Key',
    supportsTest: true
  },
  [THREATFOX_FEED_KEY]: {
    title: 'ThreatFox Auth-Key',
    placeholder: 'Enter ThreatFox Auth-Key',
    helpText: 'Required for ThreatFox recent IOC API (get_iocs). Default lookback is 3 days (1–7).',
    saveSuccess: 'ThreatFox Auth-Key saved.',
    saveError: 'Failed to save ThreatFox Auth-Key',
    supportsTest: true,
    supportsRecentDays: true
  },
  [ALIENVAULT_OTX_FEED_KEY]: {
    title: 'AlienVault OTX API Key',
    placeholder: 'Enter OTX API Key',
    helpText: 'Required for the OTX DirectConnect API. Imports IOCs from your subscribed pulses (X-OTX-API-KEY). Find it under your OTX account settings.',
    saveSuccess: 'AlienVault OTX API Key saved.',
    saveError: 'Failed to save AlienVault OTX API Key',
    supportsTest: true
  }
};

function feedSupportsAuthKey(feedKey) {
  return Boolean(AUTH_KEY_FEED_CONFIG[feedKey]);
}

function FeedSettingsModal({
  feed,
  draftCron,
  onDraftChange,
  draftExpiration,
  onExpirationChange,
  draftConfidence,
  onConfidenceChange,
  savingConfidence,
  confidenceError,
  confidenceSuccess,
  onSaveConfidence,
  draftColor,
  onColorChange,
  savingColor,
  colorError,
  colorSuccess,
  onSaveColor,
  draftAuthKey,
  onAuthKeyChange,
  maskedAuthKey,
  authKeyConfigured,
  draftRecentDays,
  onRecentDaysChange,
  testingCredentials,
  credentialsTestMessage,
  credentialsTestOk,
  onTestCredentials,
  savingSchedule,
  savingExpiration,
  savingCredentials,
  credentialsError,
  credentialsSuccess,
  error,
  expirationError,
  expirationSuccess,
  expirationRefreshWarn,
  onClose,
  onRequestActiveChange,
  onSaveSchedule,
  onSaveExpiration,
  onSaveCredentials,
  onOpenPurge,
  onArchive,
  onRestore,
  onRunFullReconciliation,
  runningFullReconciliation,
  purgeActive,
  canWrite
}) {
  const isActive = feed?.active !== false;
  const isArchived = Boolean(feed?.archived_at);
  const isBuiltIn = String(feed?.feed_kind || 'built_in') !== 'custom';
  const state = isArchived
    ? { label: 'Archived', color: '#cbd5e1', bg: 'rgba(100,116,139,0.18)', border: '#64748b' }
    : feedStatePresentation(isActive);
  const currentCron = feed?.schedule || '0 * * * *';
  const scheduleUnchanged = draftCron === currentCron;
  const exp = draftExpiration || defaultExpirationDraft();
  const showTtl = exp.enabled && ['fixed_ttl', 'last_seen_ttl'].includes(exp.expiration_mode);
  const showGrace = exp.enabled && exp.expiration_mode === 'missing_from_feed_ttl';

  return (
    <FeedHealthModal
      title="Feed settings"
      onClose={(savingSchedule || savingExpiration || savingConfidence || savingCredentials || testingCredentials) ? undefined : onClose}
      actions={<button type="button" onClick={onClose} disabled={savingSchedule || savingExpiration || savingConfidence || savingCredentials || testingCredentials}>Close</button>}
    >
      <div style={{ display: 'grid', gap: 16, fontSize: 13 }}>
        <div>
          <div style={{ color: '#94a3b8', marginBottom: 4 }}>Feed</div>
          <strong style={{ color: '#e2e8f0' }}>{feed?.name || feed?.key}</strong>
        </div>

        {feed?.source_url ? (
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={{ color: '#94a3b8' }}>Source endpoint</span>
            <input
              type="url"
              value={feed.source_url}
              readOnly
              aria-label="Source endpoint"
              style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#0f172a', color: '#cbd5e1', fontSize: 12, cursor: 'not-allowed' }}
            />
          </label>
        ) : null}

        <div>
          <div style={{ color: '#94a3b8', marginBottom: 6 }}>Current state</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: state.color, background: state.bg, border: `1px solid ${state.border}` }}>
              {state.label}
            </span>
            {(() => {
              const health = feedHealthPresentation(feed);
              return (
                <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: health.color, background: health.bg, border: `1px solid ${health.border}` }}>
                  {health.label}
                </span>
              );
            })()}
            {canWrite ? (
              <button
                type="button"
                onClick={onRequestActiveChange}
                disabled={isArchived}
                style={{ fontSize: 12, padding: '4px 10px', borderRadius: 6, border: '1px solid #475569', background: 'transparent', color: isActive ? '#fca5a5' : '#86efac', cursor: isArchived ? 'not-allowed' : 'pointer', opacity: isArchived ? 0.5 : 1 }}
              >
                {isActive ? 'Disable feed' : 'Enable feed'}
              </button>
            ) : null}
          </div>
          <div style={{ marginTop: 10, color: '#94a3b8', fontSize: 12, lineHeight: 1.5 }}>
            Schedule: <span style={{ color: '#cbd5e1' }}>{formatFeedScheduleLabel(feed?.schedule)}</span>
            <span style={{ color: '#475569' }}> · </span>
            Confidence: <span style={{ color: '#cbd5e1' }}>{feedConfidencePresentation(feed?.default_confidence).label}</span>
            <span style={{ color: '#475569' }}> · </span>
            Expiration: <span style={{ color: '#cbd5e1' }}>{feed?.expiration_summary ?? 'Disabled'}</span>
          </div>
        </div>

        {(() => {
          const result = resolveFeedLastResult(feed);
          const view = presentFeedLastResult(result, { healthState: feed?.health_state });
          if (result.status === 'never' && !result.checked) return null;
          return (
            <div style={{ borderTop: '1px solid #1e293b', paddingTop: 14 }}>
              <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Last result</div>
              <div style={{ display: 'grid', gap: 6, color: '#cbd5e1', fontSize: 12, lineHeight: 1.5 }}>
                <div style={{ color: FEED_RESULT_TONE_COLORS[view.primaryTone] || '#cbd5e1', fontWeight: 650 }}>{view.primary}</div>
                <div title={FEED_RESULT_METRIC_TOOLTIPS.checked}>Checked: {Number(result.checked || 0).toLocaleString()}</div>
                <div title={FEED_RESULT_METRIC_TOOLTIPS.new}>New: {Number(result.new || 0).toLocaleString()}</div>
                <div title={FEED_RESULT_METRIC_TOOLTIPS.updated}>Updated: {Number(result.updated || 0).toLocaleString()}</div>
                <div title={FEED_RESULT_METRIC_TOOLTIPS.unchanged}>Unchanged: {Number(result.unchanged || 0).toLocaleString()}</div>
                <div title={FEED_RESULT_METRIC_TOOLTIPS.filtered}>Filtered: {Number(result.filtered || 0).toLocaleString()}</div>
                <div title={FEED_RESULT_METRIC_TOOLTIPS.rejected}>Failed/Rejected: {Number(result.failed || result.rejected || 0).toLocaleString()}</div>
                {result.expired > 0 ? <div title={FEED_RESULT_METRIC_TOOLTIPS.expired}>Removed: {Number(result.expired).toLocaleString()}</div> : null}
                {result.suppressed > 0 ? <div title={FEED_RESULT_METRIC_TOOLTIPS.suppressed}>Suppressed: {Number(result.suppressed).toLocaleString()}</div> : null}
                {result.started_at ? <div>Started at: {formatUserDateTime(result.started_at)}</div> : null}
                {result.finished_at ? <div>Finished at: {formatUserDateTime(result.finished_at)}</div> : null}
                {result.message && /legacy skipped/i.test(String(result.message)) ? (
                  <div style={{ color: '#94a3b8' }} title="Older runs stored existing/no-op rows in skipped; shown as Unchanged.">
                    Legacy skipped / unchanged fallback
                  </div>
                ) : null}
                {result.message && result.status === 'failed' ? <div style={{ color: '#fca5a5' }}>{result.message}</div> : null}
              </div>
            </div>
          );
        })()}

        <div style={{ borderTop: '1px solid #1e293b', paddingTop: 14 }}>
          <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Default confidence</div>
          <div style={{ display: 'grid', gap: 10 }}>
            <div style={{ color: '#94a3b8', fontSize: 12, lineHeight: 1.55 }}>
              Changing feed confidence updates the default confidence for this feed. IOC records that inherit confidence from this feed will use the new value automatically. Explicit feed-entry confidence and manual analyst overrides are not changed. No bulk rewrite will be performed.
            </div>
            <label style={{ display: 'grid', gap: 6 }}>
              <span style={{ color: '#94a3b8' }}>Default confidence</span>
              <select
                value={draftConfidence || ''}
                onChange={(e) => onConfidenceChange(e.target.value)}
                disabled={!canWrite || savingConfidence}
                style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#111827', color: '#e2e8f0', fontSize: 13 }}
              >
                <option value="">Unknown / —</option>
                {CONFIDENCE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </label>
            {confidenceError ? <div style={{ color: '#fca5a5', fontSize: 12 }}>{confidenceError}</div> : null}
            {confidenceSuccess ? <div style={{ color: '#86efac', fontSize: 12 }}>{confidenceSuccess}</div> : null}
            {canWrite ? (
              <button type="button" onClick={onSaveConfidence} disabled={savingConfidence || !draftConfidence}>
                {savingConfidence ? 'Saving...' : 'Save Default Confidence'}
              </button>
            ) : null}
          </div>
        </div>

        <div style={{ borderTop: '1px solid #1e293b', paddingTop: 14 }}>
          <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Schedule</div>
          <div style={{ display: 'grid', gap: 10 }}>
            <div>
              <span style={{ color: '#94a3b8' }}>Current schedule: </span>
              <strong style={{ color: '#e2e8f0' }}>{formatFeedScheduleLabel(feed?.schedule)}</strong>
            </div>
            <label style={{ display: 'grid', gap: 6 }}>
              <span style={{ color: '#94a3b8' }}>New schedule</span>
              <select
                value={draftCron}
                onChange={(e) => onDraftChange(e.target.value)}
                disabled={!canWrite || savingSchedule}
                style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#111827', color: '#e2e8f0', fontSize: 13 }}
              >
                {FEED_SCHEDULE_OPTIONS.map((opt) => (
                  <option key={opt.cron} value={opt.cron}>{opt.label}</option>
                ))}
              </select>
            </label>
            <FeedRunOnceScheduleHint cron={draftCron} />
            {canWrite ? (
              <button type="button" onClick={onSaveSchedule} disabled={savingSchedule || scheduleUnchanged}>
                {savingSchedule ? 'Saving...' : 'Save Schedule'}
              </button>
            ) : null}
          </div>
        </div>

        <div style={{ borderTop: '1px solid #1e293b', paddingTop: 14 }}>
          <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Badge Color</div>
          <div style={{ display: 'grid', gap: 8 }}>
            <SourceColorField
              value={draftColor || ''}
              onChange={onColorChange}
              previewLabel={feed?.name || 'Feed'}
              disabled={!canWrite || savingColor}
              label=""
              helper="Leave blank to use the default badge color."
            />
            {colorError ? <span style={{ color: '#fca5a5', fontSize: 12 }}>{colorError}</span> : null}
            {colorSuccess ? <span style={{ color: '#86efac', fontSize: 12 }}>{colorSuccess}</span> : null}
            {canWrite ? (
              <button type="button" onClick={onSaveColor} disabled={savingColor || !isSavableColor(draftColor)} style={{ justifySelf: 'start' }}>
                {savingColor ? 'Saving...' : 'Save Color'}
              </button>
            ) : null}
          </div>
        </div>

        {feed?.key === 'usom-trcert' ? (
          <div style={{ borderTop: '1px solid #1e293b', paddingTop: 14 }}>
            <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.04em' }}>USOM Reconciliation</div>
            <div style={{ display: 'grid', gap: 8, color: '#cbd5e1', fontSize: 12, lineHeight: 1.5 }}>
              <div><b>Incremental:</b> {usomRunDiagnostics(feed.last_incremental_run)}</div>
              <div><b>Last incremental success:</b> {formatUserDateTime(feed.last_incremental_success_at)}</div>
              <div><b>Full:</b> {usomRunDiagnostics(feed.last_full_reconciliation_run)}</div>
              <div><b>Last full sync:</b> {formatUserDateTime(feed.last_full_reconciliation_success_at)}</div>
              <div><b>Next full sync:</b> {formatUserDateTime(feed.next_full_reconciliation_run_at)}</div>
              {feed.reconciliation_warning ? (
                <div style={{ color: feed.reconciliation_health_state === 'degraded' ? '#fca5a5' : '#fcd34d' }}>
                  {feed.reconciliation_warning}
                </div>
              ) : null}
              {canWrite ? (
                <button
                  type="button"
                  onClick={onRunFullReconciliation}
                  disabled={!isActive || isArchived || purgeActive || runningFullReconciliation}
                  style={{ justifySelf: 'start' }}
                >
                  {runningFullReconciliation ? 'Queueing...' : 'Run Full Reconciliation'}
                </button>
              ) : null}
            </div>
          </div>
        ) : null}

        {feedSupportsAuthKey(feed?.key) ? (
          <div style={{ borderTop: '1px solid #1e293b', paddingTop: 14 }}>
            <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              {AUTH_KEY_FEED_CONFIG[feed.key]?.title || 'Auth-Key'}
            </div>
            <div style={{ display: 'grid', gap: 10 }}>
              <label style={{ display: 'grid', gap: 6 }}>
                <span style={{ color: '#94a3b8' }}>Auth Key</span>
                <input
                  type="password"
                  value={draftAuthKey}
                  onChange={(e) => onAuthKeyChange(e.target.value)}
                  disabled={!canWrite || savingCredentials}
                  placeholder={AUTH_KEY_FEED_CONFIG[feed.key]?.placeholder || 'Enter Auth-Key'}
                  autoComplete="off"
                  style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#111827', color: '#e2e8f0', fontSize: 13 }}
                />
              </label>
              <div style={{ color: '#94a3b8', fontSize: 12, lineHeight: 1.5 }}>
                {AUTH_KEY_FEED_CONFIG[feed.key]?.helpText || 'Required for file exports. Do not include it in the URL.'}
              </div>
              {maskedAuthKey ? (
                <div style={{ color: '#94a3b8', fontSize: 12 }}>Current key: {maskedAuthKey}</div>
              ) : authKeyConfigured ? (
                <div style={{ color: '#94a3b8', fontSize: 12 }}>Auth key is configured.</div>
              ) : null}
              {AUTH_KEY_FEED_CONFIG[feed.key]?.supportsRecentDays ? (
                <label style={{ display: 'grid', gap: 6 }}>
                  <span style={{ color: '#94a3b8' }}>Recent days (1–7)</span>
                  <input
                    type="number"
                    min={1}
                    max={7}
                    value={draftRecentDays}
                    onChange={(e) => onRecentDaysChange(e.target.value)}
                    disabled={!canWrite || savingCredentials}
                    style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#111827', color: '#e2e8f0', fontSize: 13, maxWidth: 120 }}
                  />
                </label>
              ) : null}
              {canWrite ? (
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button type="button" onClick={onSaveCredentials} disabled={savingCredentials || !draftAuthKey}>
                    {savingCredentials ? 'Saving...' : 'Save Auth Key'}
                  </button>
                  {AUTH_KEY_FEED_CONFIG[feed.key]?.supportsTest ? (
                    <button
                      type="button"
                      onClick={onTestCredentials}
                      disabled={testingCredentials || savingCredentials || (!draftAuthKey && !authKeyConfigured)}
                      style={{ padding: '6px 12px', borderRadius: 6, border: '1px solid #475569', background: '#1f2937', color: '#e2e8f0' }}
                    >
                      {testingCredentials ? 'Testing...' : 'Test Connection'}
                    </button>
                  ) : null}
                </div>
              ) : null}
              {credentialsTestMessage ? (
                <div style={{
                  marginTop: 4,
                  padding: '8px 10px',
                  borderRadius: 8,
                  border: credentialsTestOk ? '1px solid #166534' : '1px solid #7f1d1d',
                  color: credentialsTestOk ? '#86efac' : '#fca5a5',
                  background: credentialsTestOk ? 'rgba(20,83,45,0.2)' : 'rgba(127,29,29,0.2)',
                  fontSize: 13
                }}>
                  {credentialsTestMessage}
                </div>
              ) : null}
            </div>
            {credentialsSuccess ? (
              <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid #166534', color: '#86efac', background: 'rgba(20,83,45,0.2)', fontSize: 13 }}>
                {credentialsSuccess}
              </div>
            ) : null}
            {credentialsError ? (
              <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
                {credentialsError}
              </div>
            ) : null}
          </div>
        ) : null}

        <div style={{ borderTop: '1px solid #1e293b', paddingTop: 14 }}>
          <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Expiration Policy</div>
          <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 10 }}>
            Expired IOCs are kept in database but excluded from publish/export.
          </div>
          <div style={{ display: 'grid', gap: 10 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input
                type="checkbox"
                checked={exp.enabled}
                disabled={!canWrite || savingExpiration}
                onChange={(e) => onExpirationChange({ ...exp, enabled: e.target.checked })}
              />
              <span style={{ color: '#e2e8f0' }}>Enable expiration</span>
            </label>
            <label style={{ display: 'grid', gap: 6 }}>
              <span style={{ color: '#94a3b8' }}>Mode</span>
              <select
                value={exp.expiration_mode}
                disabled={!canWrite || savingExpiration || !exp.enabled}
                onChange={(e) => onExpirationChange({ ...exp, expiration_mode: e.target.value })}
                style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#111827', color: '#e2e8f0', fontSize: 13 }}
              >
                {EXPIRATION_MODE_OPTIONS.map((opt) => (
                  <option key={opt.id} value={opt.id}>{opt.label}</option>
                ))}
              </select>
            </label>
            {showTtl ? (
              <label style={{ display: 'grid', gap: 6 }}>
                <span style={{ color: '#94a3b8' }}>TTL days</span>
                <input
                  type="number"
                  min={1}
                  value={exp.ttl_days}
                  disabled={!canWrite || savingExpiration}
                  onChange={(e) => onExpirationChange({ ...exp, ttl_days: e.target.value })}
                  style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#111827', color: '#e2e8f0', fontSize: 13 }}
                />
              </label>
            ) : null}
            {showGrace ? (
              <label style={{ display: 'grid', gap: 6 }}>
                <span style={{ color: '#94a3b8' }}>Grace days</span>
                <input
                  type="number"
                  min={1}
                  value={exp.grace_days}
                  disabled={!canWrite || savingExpiration}
                  onChange={(e) => onExpirationChange({ ...exp, grace_days: e.target.value })}
                  style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#111827', color: '#e2e8f0', fontSize: 13 }}
                />
              </label>
            ) : null}
            <div style={{ padding: 10, borderRadius: 8, border: '1px solid #334155', background: '#0b1220', color: '#94a3b8', fontSize: 12, lineHeight: 1.5 }}>
              When IOC expires:
              <ul style={{ margin: '8px 0 0', paddingLeft: 18 }}>
                <li>It will not be published/exported</li>
                <li>It will remain in database with status=expired</li>
              </ul>
            </div>

            <div style={{ borderTop: '1px solid #1e293b', paddingTop: 12, marginTop: 2 }}>
              <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.04em' }}>IOC Type Overrides</div>
              <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 10, lineHeight: 1.5 }}>
                IOC type overrides take precedence over the feed default expiration policy.
              </div>
              <div style={{ display: 'grid', gap: 10 }}>
                {EXPIRATION_TYPE_OVERRIDE_TYPES.map((t) => {
                  const ovr = (exp.type_overrides && exp.type_overrides[t.id]) || { mode: 'inherit', ttl_days: '' };
                  const isFixed = ovr.mode === 'fixed_ttl';
                  const setOverride = (patch) => onExpirationChange({
                    ...exp,
                    type_overrides: {
                      ...(exp.type_overrides || {}),
                      [t.id]: { ...ovr, ...patch }
                    }
                  });
                  return (
                    <div key={t.id} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 110px', gap: 8, alignItems: 'center' }}>
                      <span style={{ color: '#e2e8f0' }}>{t.label}</span>
                      <select
                        value={ovr.mode}
                        disabled={!canWrite || savingExpiration}
                        onChange={(e) => setOverride({ mode: e.target.value })}
                        style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#111827', color: '#e2e8f0', fontSize: 13 }}
                      >
                        {EXPIRATION_TYPE_OVERRIDE_MODES.map((m) => (
                          <option key={m.id} value={m.id}>{m.label}</option>
                        ))}
                      </select>
                      <input
                        type="number"
                        min={1}
                        required={isFixed}
                        placeholder="TTL days"
                        value={isFixed ? ovr.ttl_days : ''}
                        disabled={!canWrite || savingExpiration || !isFixed}
                        onChange={(e) => setOverride({ ttl_days: e.target.value })}
                        style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid #475569', background: '#111827', color: '#e2e8f0', fontSize: 13, opacity: isFixed ? 1 : 0.5 }}
                      />
                    </div>
                  );
                })}
              </div>
              <div style={{ marginTop: 10, padding: 10, borderRadius: 8, border: '1px solid #334155', background: '#0b1220', color: '#cbd5e1', fontSize: 12, lineHeight: 1.6 }}>
                {EXPIRATION_TYPE_OVERRIDE_TYPES.map((t) => (
                  <div key={t.id}>{formatTypeOverridePreview(t.label, (exp.type_overrides || {})[t.id], exp)}</div>
                ))}
              </div>
            </div>

            {canWrite ? (
              <button type="button" onClick={onSaveExpiration} disabled={savingExpiration}>
                {savingExpiration ? 'Saving...' : 'Save Expiration Policy'}
              </button>
            ) : null}
          </div>
        </div>

        {canWrite ? (
          <div style={{ borderTop: '1px solid #7f1d1d', paddingTop: 14 }}>
            <div style={{ color: '#fca5a5', fontSize: 11, fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Feed data actions</div>
            <div style={{ color: '#94a3b8', fontSize: 12, lineHeight: 1.55, marginBottom: 10 }}>
              Remove active IOC memberships imported from this feed.
            </div>
            {!isArchived ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                <button
                  type="button"
                  onClick={onOpenPurge}
                  disabled={purgeActive}
                  title={purgeActive ? 'A purge job is already running for this feed.' : undefined}
                  style={{ fontSize: 12, padding: '6px 10px', borderRadius: 6, border: '1px solid #7f1d1d', background: 'rgba(127,29,29,0.2)', color: '#fca5a5', cursor: purgeActive ? 'not-allowed' : 'pointer', opacity: purgeActive ? 0.55 : 1 }}
                >
                  Purge feed data
                </button>
                {!isBuiltIn ? (
                  <button
                    type="button"
                    onClick={onArchive}
                    disabled={purgeActive}
                    title={purgeActive ? 'Wait for the purge job to finish before archiving.' : undefined}
                    style={{ fontSize: 12, padding: '6px 10px', borderRadius: 6, border: '1px solid #854d0e', background: 'rgba(120,53,15,0.2)', color: '#fcd34d', cursor: purgeActive ? 'not-allowed' : 'pointer', opacity: purgeActive ? 0.55 : 1 }}
                  >
                    Archive feed
                  </button>
                ) : null}
              </div>
            ) : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {!isBuiltIn ? (
                  <button
                    type="button"
                    onClick={onRestore}
                    style={{ fontSize: 12, padding: '6px 10px', borderRadius: 6, border: '1px solid #166534', background: 'rgba(20,83,45,0.2)', color: '#86efac', cursor: 'pointer' }}
                  >
                    Restore feed
                  </button>
                ) : (
                  <span style={{ color: '#94a3b8', fontSize: 12 }}>This archived built-in feed cannot be restored from this screen.</span>
                )}
              </div>
            )}
          </div>
        ) : null}
      </div>
      {error ? (
        <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
          {error}
        </div>
      ) : null}
      {expirationSuccess ? (
        <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #166534', color: '#86efac', background: 'rgba(20,83,45,0.2)', fontSize: 13 }}>
          {expirationSuccess}
        </div>
      ) : null}
      {expirationRefreshWarn ? (
        <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #854d0e', color: '#fcd34d', background: 'rgba(120,53,15,0.2)', fontSize: 13 }}>
          {expirationRefreshWarn}
        </div>
      ) : null}
      {expirationError ? (
        <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
          {expirationError}
        </div>
      ) : null}
    </FeedHealthModal>
  );
}

function feedHealthPresentation(feed) {
  const state = String(feed?.health_state || '').toLowerCase();
  const runtime = String(feed?.runtime_state || '').toLowerCase();
  if (state === 'disabled') return { label: 'Disabled', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' };
  if (state === 'failed') return { label: 'Failed', color: '#fca5a5', bg: 'rgba(127,29,29,0.25)', border: '#7f1d1d' };
  if (state === 'degraded') return { label: 'Degraded', color: '#fca5a5', bg: 'rgba(127,29,29,0.25)', border: '#7f1d1d' };
  if (state === 'warning') return { label: 'Warning', color: '#fcd34d', bg: 'rgba(120,53,15,0.25)', border: '#854d0e' };
  if (state === 'never') return { label: 'Never run', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' };
  if (state === 'success') {
    if (runtime === 'running') return { label: 'Healthy', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534', runtimeLabel: 'Running' };
    if (runtime === 'queued') return { label: 'Healthy', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534', runtimeLabel: 'Queued' };
    return { label: 'Healthy', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534' };
  }
  return { label: 'Unknown', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' };
}

function feedConfidencePresentation(defaultConfidence) {
  const value = String(defaultConfidence || '').trim().toLowerCase();
  if (!value || !['low', 'medium', 'high'].includes(value)) {
    return { label: '—', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' };
  }
  const badge = confidenceBadgeStyle(value);
  return {
    label: confidenceLabel(value),
    color: badge.color,
    bg: badge.bg,
    border: badge.border
  };
}

function formatFeedScheduleLabel(cron) {
  const map = {
    '*/5 * * * *': 'Every 5 min',
    '*/15 * * * *': 'Every 15 min',
    '*/30 * * * *': 'Every 30 min',
    '0 * * * *': 'Every hour',
    '0 0 * * *': 'Every day',
    run_once: 'Run once'
  };
  return map[String(cron || '').trim()] || String(cron || '-');
}

function FeedRunOnceScheduleHint({ cron }) {
  if (String(cron || '').trim() !== 'run_once') return null;
  return (
    <div style={{ color: '#64748b', fontSize: 11, lineHeight: 1.45, marginTop: 4 }}>
      {RUN_ONCE_SCHEDULE_HELPER}
    </div>
  );
}

function truncateFeedError(text, max = 48) {
  const raw = String(text || '').trim();
  if (!raw) return '';
  if (raw.length <= max) return raw;
  return `${raw.slice(0, max - 1)}…`;
}

function formatFeedClock(value) {
  if (!value) return '-';
  const raw = formatUserDateTime(value);
  if (!raw || raw === '-') return '-';
  // en-GB → DD/MM/YYYY, HH:MM:SS — show HH:MM for compact table cells.
  const parts = String(raw).split(',').map((p) => p.trim());
  if (parts.length >= 2) {
    const time = parts[1].slice(0, 5);
    return time || parts[1];
  }
  return raw;
}

function formatFeedLastRunCell(feed) {
  if (feed?.key === 'usom-trcert') {
    const at = feed.last_incremental_success_at || feed.last_success_at || feed.last_finished_at;
    return {
      primary: `Incremental · ${formatFeedClock(at)}`,
      title: [
        `Last incremental: ${formatUserDateTime(feed.last_incremental_success_at)}`,
        `Last full sync: ${formatUserDateTime(feed.last_full_reconciliation_success_at)}`,
        feed.next_full_reconciliation_run_at ? `Next full sync: ${formatUserDateTime(feed.next_full_reconciliation_run_at)}` : null
      ].filter(Boolean).join('\n')
    };
  }
  const at = feed?.last_success_at
    || (['success', 'skipped', 'skipped_unchanged'].includes(String(feed?.last_status || feed?.status || '').toLowerCase())
      ? feed?.last_finished_at
      : null);
  return {
    primary: formatUserDateTime(at),
    title: at ? formatUserDateTime(at) : 'No successful run'
  };
}

function formatFeedNextRunCell(feed, canRunNow) {
  if (!canRunNow) return { primary: '-', title: '' };
  if (feed?.key === 'usom-trcert') {
    const at = feed.next_incremental_run_at || feed.next_run_at;
    return {
      primary: `Incremental · ${formatFeedClock(at)}`,
      title: [
        `Next incremental: ${formatUserDateTime(at)}`,
        `Next full sync: ${formatUserDateTime(feed.next_full_reconciliation_run_at)}`
      ].join('\n')
    };
  }
  return {
    primary: formatUserDateTime(feed?.next_run_at),
    title: formatUserDateTime(feed?.next_run_at)
  };
}

function LastRunMetricsCell({ feed }) {
  const result = resolveFeedLastResult(feed);
  const view = presentFeedLastResult(result, { healthState: feed?.health_state });
  const primaryColor = FEED_RESULT_TONE_COLORS[view.primaryTone] || FEED_RESULT_TONE_COLORS.neutral;

  return (
    <div style={{ maxWidth: 280 }} title={view.title}>
      <div style={{ color: primaryColor, fontSize: 12, fontWeight: 650, lineHeight: 1.35, whiteSpace: 'normal' }}>
        {view.primary}
      </div>
    </div>
  );
}

function FeedPurgePreviewSummary({ preview, loading }) {
  if (loading) {
    return (
      <div style={{ marginTop: 12, padding: 12, borderRadius: 8, border: '1px solid #334155', background: '#0b1220', fontSize: 13, color: '#94a3b8' }}>
        Loading impact summary…
      </div>
    );
  }
  if (!preview) return null;

  const feedState = preview.feed_archived
    ? 'Archived'
    : (preview.feed_enabled ? 'Enabled' : 'Disabled');
  const reimportLabel = preview.reimport_possible ? 'Yes' : 'No';

  return (
    <div style={{ marginTop: 12, padding: 12, borderRadius: 8, border: '1px solid #334155', background: '#0b1220', fontSize: 13, lineHeight: 1.55 }}>
      <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>Before purging, here is what will be affected:</div>
      <div style={{ color: '#cbd5e1' }}>Active memberships to purge: <b>{preview.active_memberships ?? 0}</b></div>
      <div style={{ color: '#cbd5e1' }}>IOCs that will become expired/removed: <b>{preview.iocs_only_from_this_feed ?? 0}</b></div>
      <div style={{ color: '#cbd5e1' }}>IOCs that will stay active because of other sources: <b>{preview.iocs_shared_with_other_sources ?? 0}</b></div>
      <div style={{ color: '#94a3b8', marginTop: 8 }}>Feed state: {feedState}</div>
      <div style={{ color: '#94a3b8' }}>Re-import possible: {reimportLabel}</div>
      {preview.feed_enabled && !preview.feed_archived ? (
        <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid #854d0e', color: '#fcd34d', background: 'rgba(120,53,15,0.2)', fontSize: 12, lineHeight: 1.5 }}>
          Warning: This feed is currently enabled. Future scheduled runs may re-import purged IOCs. Disable the feed first if you want this purge to remain permanent.
        </div>
      ) : null}
    </div>
  );
}

function FeedPurgeModal({ feed, open, onClose, onCompleted }) {
  const [confirmName, setConfirmName] = useState('');
  const [confirmDirty, setConfirmDirty] = useState(false);
  const [attemptedPurge, setAttemptedPurge] = useState(false);
  const [preview, setPreview] = useState(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [purging, setPurging] = useState(false);
  const [error, setError] = useState('');

  useBodyScrollLock(open && Boolean(feed?.key));

  useEffect(() => {
    if (!open || !feed?.key) {
      setConfirmName('');
      setConfirmDirty(false);
      setAttemptedPurge(false);
      setPreview(null);
      setError('');
      setLoadingPreview(false);
      setPurging(false);
      return undefined;
    }

    let cancelled = false;
    setConfirmName('');
    setConfirmDirty(false);
    setAttemptedPurge(false);
    setPreview(null);
    setError('');
    setPurging(false);
    setLoadingPreview(true);

    (async () => {
      try {
        const { data } = await api.get(`/integrations/${encodeURIComponent(feed.key)}/purge-preview`);
        if (!cancelled) setPreview(data);
      } catch (err) {
        if (!cancelled) {
          setError(apiErrorMessage(err, 'Failed to load purge preview'));
          setPreview(null);
        }
      } finally {
        if (!cancelled) setLoadingPreview(false);
      }
    })();

    return () => { cancelled = true; };
  }, [open, feed?.key]);

  useEffect(() => {
    if (!open || purging) return undefined;
    function onKeyDown(e) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open, purging, onClose]);

  if (!open || !feed) return null;

  const trimmedConfirm = String(confirmName || '').trim();
  const expectedName = String(feed.name || '').trim();
  const nameMatches = trimmedConfirm === expectedName;
  const showNameMismatch = (confirmDirty || attemptedPurge) && trimmedConfirm.length > 0 && !nameMatches;
  const busy = purging || loadingPreview;

  async function runPurge() {
    setAttemptedPurge(true);
    if (!nameMatches || purging) return;
    setError('');
    setPurging(true);
    try {
      const response = await api.post(`/integrations/${encodeURIComponent(feed.key)}/purge`, { confirm_name: trimmedConfirm });
      if (response.status === 202 || response.data?.accepted) {
        onCompleted?.(feed.name || feed.key);
        onClose();
        return;
      }
      setError(parseFeedPurgeError({ response }));
    } catch (err) {
      setError(parseFeedPurgeError(err));
    } finally {
      setPurging(false);
    }
  }

  const modal = (
    <div
      className="modal-overlay modal-overlay--purge"
      role="presentation"
      onClick={busy ? undefined : onClose}
    >
      <div
        className="modal-dialog modal-dialog--purge"
        role="dialog"
        aria-modal="true"
        aria-labelledby="feed-purge-modal-title"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-body">
          <div id="feed-purge-modal-title" className="modal-title" style={{ marginBottom: 8 }}>Purge feed data</div>
          <p style={{ margin: '0 0 12px', color: '#cbd5e1', fontSize: 13, lineHeight: 1.5 }}>
            This will remove active IOC memberships imported from this feed.
          </p>
          <FeedPurgePreviewSummary preview={preview} loading={loadingPreview} />
          <p style={{ margin: '12px 0 0', color: '#94a3b8', fontSize: 12, lineHeight: 1.5 }}>
            This operation will run in the background. You can continue using the system.
          </p>
          <label style={{ display: 'grid', gap: 4, marginTop: 12 }}>
            <span style={{ fontSize: 12, color: '#94a3b8' }}>Type feed name to confirm: <b>{feed.name}</b></span>
            <span style={{ fontSize: 11, color: '#64748b' }}>Type the exact feed name to enable purge.</span>
            <input
              value={confirmName}
              onChange={(e) => { setConfirmDirty(true); setConfirmName(e.target.value); }}
              placeholder={feed.name}
              disabled={busy}
              aria-invalid={showNameMismatch ? 'true' : undefined}
            />
            {showNameMismatch ? (
              <span style={{ fontSize: 12, color: '#fca5a5' }}>
                Feed name does not match. Please type: {expectedName}
              </span>
            ) : null}
          </label>
          {error ? <div style={{ color: '#fca5a5', fontSize: 13, marginTop: 10 }}>{error}</div> : null}
        </div>
        <div className="modal-footer">
          <button type="button" onClick={onClose} disabled={purging}>Cancel</button>
          <button
            type="button"
            onClick={() => runPurge().catch(() => {})}
            disabled={!nameMatches || busy || !preview}
            style={(!nameMatches || busy || !preview) ? { opacity: 0.55, cursor: 'not-allowed' } : undefined}
          >
            {purging ? 'Starting purge job…' : 'Purge'}
          </button>
        </div>
      </div>
    </div>
  );

  return createPortal(modal, document.body);
}

function IntegrationsPage({ title = 'Feeds', onlyKeys = null, hideKeys = null, showRunAll = true } = {}) {
  const { canWrite } = useSession();
  const requestRequiredReason = useReasonPrompt();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [integrations, setIntegrations] = useState([]);
  const [healthSummary, setHealthSummary] = useState(null);
  const [runningNowAll, setRunningNowAll] = useState(false);
  const [runningKeys, setRunningKeys] = useState({});
  const [togglingKeys, setTogglingKeys] = useState({});
  const [editingFeed, setEditingFeed] = useState(null);
  const [settingsDraftCron, setSettingsDraftCron] = useState('0 * * * *');
  const [settingsDraftExpiration, setSettingsDraftExpiration] = useState(defaultExpirationDraft());
  const [settingsError, setSettingsError] = useState('');
  const [settingsExpirationError, setSettingsExpirationError] = useState('');
  const [settingsExpirationSuccess, setSettingsExpirationSuccess] = useState('');
  const [settingsExpirationRefreshWarn, setSettingsExpirationRefreshWarn] = useState('');
  const [savingExpirationKey, setSavingExpirationKey] = useState('');
  const [activeConfirm, setActiveConfirm] = useState(null);
  const [activeConfirmError, setActiveConfirmError] = useState('');
  const [savingScheduleKey, setSavingScheduleKey] = useState('');
  const [settingsDraftAuthKey, setSettingsDraftAuthKey] = useState('');
  const [settingsMaskedAuthKey, setSettingsMaskedAuthKey] = useState(null);
  const [settingsAuthKeyConfigured, setSettingsAuthKeyConfigured] = useState(false);
  const [savingCredentialsKey, setSavingCredentialsKey] = useState('');
  const [settingsCredentialsError, setSettingsCredentialsError] = useState('');
  const [settingsCredentialsSuccess, setSettingsCredentialsSuccess] = useState('');
  const [settingsDraftRecentDays, setSettingsDraftRecentDays] = useState('3');
  const [testingCredentialsKey, setTestingCredentialsKey] = useState('');
  const [settingsCredentialsTestMessage, setSettingsCredentialsTestMessage] = useState('');
  const [settingsCredentialsTestOk, setSettingsCredentialsTestOk] = useState(false);
  const [settingsDraftConfidence, setSettingsDraftConfidence] = useState('');
  const [settingsConfidenceError, setSettingsConfidenceError] = useState('');
  const [settingsConfidenceSuccess, setSettingsConfidenceSuccess] = useState('');
  const [savingConfidenceKey, setSavingConfidenceKey] = useState('');
  const [settingsDraftColor, setSettingsDraftColor] = useState('');
  const [settingsColorError, setSettingsColorError] = useState('');
  const [settingsColorSuccess, setSettingsColorSuccess] = useState('');
  const [savingColorKey, setSavingColorKey] = useState('');
  const [purgeFeed, setPurgeFeed] = useState(null);
  const [showPurgeModal, setShowPurgeModal] = useState(false);
  const [feedActionSuccess, setFeedActionSuccess] = useState('');
  const [showArchivedFeeds, setShowArchivedFeeds] = useState(false);

  async function load() {
    setLoading(true);
    setLoadError('');
    try {
      const { data } = await api.get('/integrations');
      const list = data?.integrations || [];
      setIntegrations(list);
      setHealthSummary(data?.health_summary || null);
      return list;
    } catch (err) {
      setIntegrations([]);
      setHealthSummary(null);
      setLoadError(apiErrorMessage(err, 'Failed to load integrations'));
      return [];
    } finally {
      setLoading(false);
    }
  }

  function syncEditingFeed(list) {
    setEditingFeed((prev) => {
      if (!prev) return prev;
      const f = (list || []).find((i) => i.key === prev.key);
      if (!f) return prev;
      return {
        ...prev,
        ...f,
        key: f.key,
        name: f.name,
        schedule: f.schedule || '0 * * * *',
        active: f.active !== false,
        feed_kind: f.feed_kind || 'built_in',
        archived_at: f.archived_at || null,
        purge_active: Boolean(f.purge_active),
        purge_status: f.purge_status || null,
        purge_status_label: f.purge_status_label || null,
        expiration_policy: f.expiration_policy,
        expiration_summary: f.expiration_summary,
        default_confidence: f.default_confidence
      };
    });
  }

  useEffect(() => { load().catch(() => {}); }, []);

  async function runNowAll() {
    if (!canWrite) return;
    const ok = window.confirm('All integrations will be queued now. Do you want to continue?');
    if (!ok || runningNowAll) return;
    setRunningNowAll(true);
    try {
      const { data } = await api.post('/integrations/run-now');
      await load();
      const skipped = Array.isArray(data?.skipped) ? data.skipped.length : 0;
      alert(skipped > 0
        ? `Queued ${data?.count || 0} integration(s); ${skipped} skipped (already running)`
        : 'All integrations queued');
    } catch (err) {
      alert(apiErrorMessage(err, 'Failed to queue integrations'));
    } finally {
      setRunningNowAll(false);
    }
  }

  async function runNowOne(key, name, runMode = 'incremental') {
    if (!canWrite) return;
    const isUsom = key === 'usom-trcert';
    const runningKey = isUsom ? `${key}:${runMode}` : key;
    const isFull = isUsom && runMode === 'full_reconciliation';
    const ok = window.confirm(isFull
      ? `Run a FULL reconciliation for ${name || key}? This scans the complete USOM dataset and may take significantly longer.`
      : isUsom
        ? `Queue incremental run for ${name || key} now?`
        : `Queue ${name || key} now?`);
    if (!ok || runningKeys[runningKey]) return;
    setRunningKeys((prev) => ({ ...prev, [runningKey]: true }));
    try {
      const payload = buildIntegrationRunNowPayload(key, runMode);
      const { data } = await api.post(`/integrations/${encodeURIComponent(key)}/run-now`, payload);
      await load();
      if (isUsom) {
        alert(data?.coalesced
          ? `${integrationRunModeLabel(runMode)} is already queued or running.`
          : `${integrationRunModeLabel(runMode)} queued`);
      } else {
        alert('Run queued');
      }
    } catch (err) {
      alert(apiErrorMessage(err, `Failed to queue ${key}`));
    } finally {
      setRunningKeys((prev) => ({ ...prev, [runningKey]: false }));
    }
  }

  async function openSettingsModal(feed) {
    if (!canWrite) return;
    setShowPurgeModal(false);
    setPurgeFeed(null);
    setSettingsError('');
    setSettingsExpirationError('');
    setSettingsExpirationSuccess('');
    setSettingsExpirationRefreshWarn('');
    setSettingsCredentialsError('');
    setSettingsCredentialsSuccess('');
    setSettingsCredentialsTestMessage('');
    setSettingsCredentialsTestOk(false);
    setSettingsConfidenceError('');
    setSettingsConfidenceSuccess('');
    setSettingsColorError('');
    setSettingsColorSuccess('');
    setSettingsDraftColor(feed.color || '');
    setSettingsDraftAuthKey('');
    setSettingsDraftCron(feed.schedule || '0 * * * *');
    setSettingsDraftConfidence(String(feed.default_confidence || '').trim().toLowerCase());
    setSettingsDraftExpiration(defaultExpirationDraft(feed.expiration_policy));
    const credSummary = feed.credentials_summary || null;
    setSettingsMaskedAuthKey(credSummary?.masked_auth_key || null);
    setSettingsAuthKeyConfigured(Boolean(credSummary?.auth_key_configured));
    setSettingsDraftRecentDays(String(credSummary?.recent_days ?? 3));
    setEditingFeed({
      ...feed,
      key: feed.key,
      name: feed.name,
      schedule: feed.schedule || '0 * * * *',
      active: feed.active !== false,
      feed_kind: feed.feed_kind || 'built_in',
      archived_at: feed.archived_at || null,
      purge_active: Boolean(feed.purge_active),
      purge_status: feed.purge_status || null,
      purge_status_label: feed.purge_status_label || null
    });
    try {
      const { data } = await api.get(`/threat-feeds/${encodeURIComponent(feed.key)}/expiration-policy`);
      setSettingsDraftExpiration(defaultExpirationDraft(data?.policy, data?.expiration_type_policies));
    } catch {
      setSettingsDraftExpiration(defaultExpirationDraft(feed.expiration_policy));
    }
    if (feedSupportsAuthKey(feed.key)) {
      try {
        const { data } = await api.get(`/integrations/${encodeURIComponent(feed.key)}/credentials`);
        setSettingsMaskedAuthKey(data?.masked_auth_key || null);
        setSettingsAuthKeyConfigured(Boolean(data?.auth_key_configured));
        if (data?.recent_days != null) {
          setSettingsDraftRecentDays(String(data.recent_days));
        }
      } catch {
        // keep list summary if credentials endpoint unavailable
      }
    }
  }

  function closeSettingsModal() {
    if (savingScheduleKey || savingCredentialsKey || savingConfidenceKey || testingCredentialsKey) return;
    setEditingFeed(null);
    setSettingsError('');
  }

  async function saveSettingsConfidence() {
    if (!canWrite || !editingFeed || !settingsDraftConfidence) return;
    const { key } = editingFeed;
    if (savingConfidenceKey) return;

    setSettingsConfidenceError('');
    setSettingsConfidenceSuccess('');
    setSavingConfidenceKey(key);
    try {
      await api.patch(`/integrations/${encodeURIComponent(key)}/default-confidence`, {
        default_confidence: settingsDraftConfidence
      });
      setSettingsConfidenceSuccess('Default confidence updated. Inherited IOC confidence will reflect this at read time.');
      const list = await load();
      syncEditingFeed(list);
    } catch (err) {
      setSettingsConfidenceError(apiErrorMessage(err, 'Failed to update default confidence'));
    } finally {
      setSavingConfidenceKey('');
    }
  }

  async function saveSettingsColor() {
    if (!canWrite || !editingFeed) return;
    const { key } = editingFeed;
    if (savingColorKey) return;
    if (!isSavableColor(settingsDraftColor)) {
      setSettingsColorError('Badge color must be a hex value like #7c3aed, or left blank.');
      return;
    }

    setSettingsColorError('');
    setSettingsColorSuccess('');
    setSavingColorKey(key);
    try {
      await api.put(`/integrations/${encodeURIComponent(key)}/color`, {
        color: String(settingsDraftColor || '').trim() || null
      });
      setSettingsColorSuccess('Badge color updated.');
      invalidateSourceColorCatalog();
      const list = await load();
      syncEditingFeed(list);
    } catch (err) {
      setSettingsColorError(apiErrorMessage(err, 'Failed to update badge color'));
    } finally {
      setSavingColorKey('');
    }
  }

  function requestActiveChange() {
    if (!canWrite || !editingFeed) return;
    setActiveConfirmError('');
    setActiveConfirm({
      key: editingFeed.key,
      name: editingFeed.name,
      mode: editingFeed.active ? 'disable' : 'enable'
    });
  }

  function closeActiveConfirm() {
    if (togglingKeys[activeConfirm?.key]) return;
    setActiveConfirm(null);
    setActiveConfirmError('');
  }

  async function confirmActiveChange() {
    if (!canWrite || !activeConfirm) return;
    const { key, mode } = activeConfirm;
    const nextActive = mode === 'enable';
    if (togglingKeys[key]) return;

    setActiveConfirmError('');
    setTogglingKeys((prev) => ({ ...prev, [key]: true }));
    try {
      await api.patch(`/integrations/${encodeURIComponent(key)}/active`, { active: nextActive });
      setActiveConfirm(null);
      const list = await load();
      syncEditingFeed(list);
    } catch (err) {
      setActiveConfirmError(apiErrorMessage(err, 'Failed to update feed active state'));
    } finally {
      setTogglingKeys((prev) => ({ ...prev, [key]: false }));
    }
  }

  async function archiveFeedFromSettings() {
    if (!canWrite || !editingFeed) return;
    const feed = editingFeed;
    const ok = window.confirm(`Archive feed "${feed.name}"? It will be hidden from the default list and scheduling will stop.`);
    if (!ok) return;
    try {
      await api.patch(`/integrations/${encodeURIComponent(feed.key)}/archive`);
      const list = await load();
      syncEditingFeed(list);
      setFeedActionSuccess(`Feed "${feed.name}" archived.`);
    } catch (err) {
      alert(apiErrorMessage(err, 'Failed to archive feed'));
    }
  }

  async function restoreFeedFromSettings() {
    if (!canWrite || !editingFeed) return;
    const feed = editingFeed;
    try {
      await api.patch(`/integrations/${encodeURIComponent(feed.key)}/restore`);
      const list = await load();
      syncEditingFeed(list);
      setFeedActionSuccess(`Feed "${feed.name}" restored.`);
    } catch (err) {
      alert(apiErrorMessage(err, 'Failed to restore feed'));
    }
  }

  function openPurgeFromEdit(feed) {
    if (!canWrite || !feed?.key) return;
    setPurgeFeed({ key: feed.key, name: feed.name });
    setShowPurgeModal(true);
    setEditingFeed(null);
  }

  function closePurgeModal() {
    setShowPurgeModal(false);
    setPurgeFeed(null);
  }

  function handlePurgeCompleted(feedName) {
    setFeedActionSuccess(`Purge job started for ${feedName}. This may take a few minutes. You can continue using the system.`);
    load().catch(() => {});
  }

  async function saveSettingsCredentials() {
    if (!canWrite || !editingFeed || !feedSupportsAuthKey(editingFeed.key)) return;
    const { key } = editingFeed;
    if (savingCredentialsKey || !settingsDraftAuthKey.trim()) return;

    setSettingsCredentialsError('');
    setSettingsCredentialsSuccess('');
    const reason = await requestRequiredReason('Update integration credentials');
    if (!reason) return;
    setSavingCredentialsKey(key);
    try {
      const payload = { auth_key: settingsDraftAuthKey.trim(), reason };
      if (AUTH_KEY_FEED_CONFIG[key]?.supportsRecentDays) {
        payload.recent_days = Number(settingsDraftRecentDays);
      }
      const { data } = await api.put(`/integrations/${encodeURIComponent(key)}/credentials`, payload);
      setSettingsMaskedAuthKey(data?.masked_auth_key || null);
      setSettingsAuthKeyConfigured(Boolean(data?.auth_key_configured));
      if (data?.recent_days != null) {
        setSettingsDraftRecentDays(String(data.recent_days));
      }
      setSettingsDraftAuthKey('');
      setSettingsCredentialsSuccess(AUTH_KEY_FEED_CONFIG[key]?.saveSuccess || 'Auth-Key saved.');
      await load();
    } catch (err) {
      setSettingsCredentialsError(apiErrorMessage(err, AUTH_KEY_FEED_CONFIG[key]?.saveError || 'Failed to save Auth-Key'));
    } finally {
      setSavingCredentialsKey('');
    }
  }

  async function testSettingsCredentials() {
    if (!canWrite || !editingFeed || !feedSupportsAuthKey(editingFeed.key)) return;
    const { key } = editingFeed;
    if (testingCredentialsKey || savingCredentialsKey) return;
    if (!settingsDraftAuthKey.trim() && !settingsAuthKeyConfigured) return;

    setSettingsCredentialsTestMessage('');
    setSettingsCredentialsTestOk(false);
    setTestingCredentialsKey(key);
    try {
      const payload = {};
      if (settingsDraftAuthKey.trim()) {
        payload.auth_key = settingsDraftAuthKey.trim();
      }
      if (AUTH_KEY_FEED_CONFIG[key]?.supportsRecentDays) {
        payload.recent_days = Number(settingsDraftRecentDays);
      }
      const { data } = await api.post(`/integrations/${encodeURIComponent(key)}/credentials/test`, payload);
      setSettingsCredentialsTestOk(Boolean(data?.ok));
      setSettingsCredentialsTestMessage(data?.message || (data?.ok ? 'Connection successful' : 'Connection failed'));
    } catch (err) {
      setSettingsCredentialsTestOk(false);
      setSettingsCredentialsTestMessage(apiErrorMessage(err, 'Connection test failed'));
    } finally {
      setTestingCredentialsKey('');
    }
  }

  async function saveSettingsSchedule() {
    if (!canWrite || !editingFeed) return;
    const { key } = editingFeed;
    if (savingScheduleKey) return;

    setSettingsError('');
    setSavingScheduleKey(key);
    try {
      await api.put(`/integrations/${encodeURIComponent(key)}/schedule`, { schedule_cron: settingsDraftCron });
      const list = await load();
      syncEditingFeed(list);
      setSettingsDraftCron(settingsDraftCron);
    } catch (err) {
      setSettingsError(apiErrorMessage(err, 'Failed to update schedule'));
    } finally {
      setSavingScheduleKey('');
    }
  }

  async function saveSettingsExpiration() {
    if (!canWrite || !editingFeed) return;
    const { key } = editingFeed;
    if (savingExpirationKey) return;
    setSettingsExpirationError('');
    setSettingsExpirationSuccess('');
    setSettingsExpirationRefreshWarn('');
    setSavingExpirationKey(key);

    let patchData;
    try {
      const { data } = await api.patch(
        `/threat-feeds/${encodeURIComponent(key)}/expiration-policy`,
        buildExpirationFullPatchPayload(settingsDraftExpiration)
      );
      patchData = data;
    } catch (err) {
      setSettingsExpirationError(apiErrorMessage(err, 'Failed to update expiration policy'));
      return;
    } finally {
      setSavingExpirationKey('');
    }

    if (patchData?.success === false) {
      setSettingsExpirationError(patchData.error || 'Failed to update expiration policy');
      return;
    }

    const policy = patchData?.policy;
    const summary = patchData?.summary;
    if (policy) {
      setSettingsDraftExpiration(defaultExpirationDraft(policy, patchData?.expiration_type_policies));
      setIntegrations((prev) => prev.map((i) => (
        i.key === key
          ? { ...i, expiration_policy: policy, expiration_summary: summary || i.expiration_summary }
          : i
      )));
    }

    setSettingsExpirationSuccess('Expiration policy updated');

    try {
      const list = await load();
      syncEditingFeed(list);
    } catch {
      setSettingsExpirationRefreshWarn('Policy saved, but refreshing the feed list failed. Values in this dialog are up to date.');
    }
  }

  const visibleIntegrations = integrations.filter((i) => {
    if (String(i.feed_kind || 'built_in') === 'custom') return false;
    if (!showArchivedFeeds && i.archived_at) return false;
    if (Array.isArray(onlyKeys) && onlyKeys.length) return onlyKeys.includes(i.key);
    if (Array.isArray(hideKeys) && hideKeys.length) return !hideKeys.includes(i.key);
    return true;
  });

  const hasArchivedFeeds = integrations.some((i) => i.archived_at);

  const metricFromFeed = (feed, key) => {
    const m = feed?.last_run_metrics;
    if (m && m.available === false && key !== 'processed') return 0;
    if (m && m[key] != null) return Number(m[key] || 0);
    const flatKey = {
      processed: 'last_records_processed',
      inserted: 'last_records_inserted',
      updated: 'last_records_updated',
      unchanged: 'last_records_unchanged',
      reactivated: 'last_records_reactivated',
      removed: 'last_records_removed',
      // DEPRECATED: kept only so an old cached API response still resolves. New UI
      // reads 'unchanged'.
      duplicate: 'last_records_duplicate',
      skipped: 'last_records_skipped',
      suppressed: 'last_records_suppressed',
      failed: 'last_records_failed'
    }[key];
    const v = feed?.[flatKey];
    return v === null || v === undefined ? 0 : Number(v || 0);
  };

  const summary = healthSummary || {
    total_feeds: visibleIntegrations.length,
    enabled_feeds: visibleIntegrations.filter((i) => i.active !== false).length,
    active_feeds: visibleIntegrations.filter((i) => i.active !== false).length,
    failing_feeds: visibleIntegrations.filter((i) => {
      return ['failed', 'degraded'].includes(String(i.health_state || '').toLowerCase()) || Number(i.consecutive_failures || 0) > 0;
    }).length,
    last_run_new_total: visibleIntegrations.reduce((acc, i) => acc + metricFromFeed(i, 'inserted'), 0),
    last_run_inserted_total: visibleIntegrations.reduce((acc, i) => acc + metricFromFeed(i, 'inserted'), 0),
    last_run_processed_total: visibleIntegrations.reduce((acc, i) => acc + metricFromFeed(i, 'processed'), 0)
  };

  const showHealthDashboard = showRunAll && !onlyKeys;

  return (
    <AppShell>
      <div className="page-content">
      <section className="integrations-feeds-page" style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ marginTop: 0, marginBottom: 4, color: '#f1f5f9' }}>{title}</h2>
            {showHealthDashboard ? (
              <div style={{ color: '#94a3b8', fontSize: 13 }}>Feed health and last import results at a glance</div>
            ) : null}
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {showRunAll ? <button onClick={runNowAll} disabled={runningNowAll || !canWrite}>{runningNowAll ? 'Queueing...' : 'Run now (all)'}</button> : null}
            {hasArchivedFeeds ? (
              <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: '#94a3b8', fontSize: 12 }}>
                <input type="checkbox" checked={showArchivedFeeds} onChange={(e) => setShowArchivedFeeds(e.target.checked)} />
                Show archived
              </label>
            ) : null}
            {showHealthDashboard ? <Link to="/threat-intelligence/queue" style={{ padding: '6px 10px', borderRadius: 8, border: '1px solid #475569', color: '#cbd5e1', textDecoration: 'none', fontSize: 13 }}>View job queue status</Link> : null}
            <button onClick={() => load().catch(() => {})}>Refresh</button>
          </div>
        </div>

        {loadError ? <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>{loadError}</div> : null}
        {feedActionSuccess ? (
          <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid #166534', color: '#86efac', background: 'rgba(20,83,45,0.2)', fontSize: 13 }}>
            {feedActionSuccess}
          </div>
        ) : null}

        {showHealthDashboard ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10, marginTop: 14, marginBottom: 14 }}>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>Total Feeds</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{summary.total_feeds}</div>
            </div>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>Healthy</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#86efac' }}>{summary.healthy_feeds ?? 0}</div>
            </div>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>Needs Attention</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: (summary.needs_attention_feeds ?? 0) > 0 ? '#fcd34d' : '#e2e8f0' }}>{summary.needs_attention_feeds ?? 0}</div>
            </div>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>Running / Queued</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: (summary.running_queued_feeds ?? 0) > 0 ? '#93c5fd' : '#e2e8f0' }}>{summary.running_queued_feeds ?? 0}</div>
            </div>
            {summary.changes_24h?.available ? (
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
                <div style={{ fontSize: 11, color: '#94a3b8' }}>Last 24h Changes</div>
                <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', marginTop: 6, lineHeight: 1.35 }}>
                  {Number(summary.changes_24h.new || 0).toLocaleString()} new
                  <span style={{ color: '#64748b', fontWeight: 500 }}> · </span>
                  {Number(summary.changes_24h.updated || 0).toLocaleString()} updated
                </div>
              </div>
            ) : null}
          </div>
        ) : null}

        {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
          <div className="integrations-feeds-table-scroll">
            <table className="ioc-table integrations-feeds-table" width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', background: '#0f172a', fontSize: 12, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
              <colgroup>
                <col className="integrations-feeds-col-feed" />
                <col className="integrations-feeds-col-state" />
                <col className="integrations-feeds-col-health" />
                <col className="integrations-feeds-col-last-run" />
                <col className="integrations-feeds-col-metrics" />
                <col className="integrations-feeds-col-next-run" />
                <col className="integrations-feeds-col-action" />
              </colgroup>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', background: '#1f2937', color: '#cbd5e1' }}>
                  <th>Feed</th>
                  <th>State</th>
                  <th>Health</th>
                  <th>Last Run</th>
                  <th>Last Result</th>
                  <th>Next Run</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {visibleIntegrations.length ? visibleIntegrations.map((i) => {
                  const isActive = i.active !== false;
                  const isArchived = Boolean(i.archived_at);
                  const purgeActive = Boolean(i.purge_active);
                  const canRunNow = isActive && !isArchived && !purgeActive;
                  const health = feedHealthPresentation(i);
                  const state = isArchived
                    ? { label: 'Archived', color: '#cbd5e1', bg: 'rgba(100,116,139,0.18)', border: '#64748b' }
                    : feedStatePresentation(isActive);
                  const lastRunCell = formatFeedLastRunCell(i);
                  const nextRunCell = formatFeedNextRunCell(i, canRunNow);
                  return (
                    <tr key={i.key} style={{ borderBottom: '1px solid #1e293b', opacity: isActive && !isArchived ? 1 : 0.78 }}>
                      <td className="integrations-feeds-feed-name" style={{ color: '#e2e8f0', fontWeight: 600 }}>
                        <span style={{ display: 'inline-flex', borderRadius: 999, padding: '2px 9px', fontSize: 12, fontWeight: 700, ...sourceColorBadgeStyle(i.color || DEFAULT_SOURCE_COLOR) }}>{i.name}</span>
                        {i.purge_status_label ? (
                          <div style={{ marginTop: 4 }}>
                            <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 10, fontWeight: 700, color: i.purge_status === 'failed' ? '#fca5a5' : '#fcd34d', background: i.purge_status === 'failed' ? 'rgba(127,29,29,0.25)' : 'rgba(120,53,15,0.25)', border: `1px solid ${i.purge_status === 'failed' ? '#7f1d1d' : '#854d0e'}` }}>
                              {i.purge_status_label}
                            </span>
                          </div>
                        ) : null}
                      </td>
                      <td>
                        <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: state.color, background: state.bg, border: `1px solid ${state.border}`, whiteSpace: 'nowrap' }}>
                          {state.label}
                        </span>
                      </td>
                      <td>
                        <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: health.color, background: health.bg, border: `1px solid ${health.border}` }}>
                          {health.label}
                        </span>
                        {health.runtimeLabel ? (
                          <div style={{ marginTop: 4, color: '#93c5fd', fontSize: 10, fontWeight: 600 }}>{health.runtimeLabel}</div>
                        ) : null}
                        {i.reconciliation_warning ? (
                          <div style={{ marginTop: 4, maxWidth: 160, color: i.reconciliation_health_state === 'degraded' ? '#fca5a5' : '#fcd34d', fontSize: 10, lineHeight: 1.35 }}>
                            {i.reconciliation_warning}
                          </div>
                        ) : null}
                      </td>
                      <td style={{ whiteSpace: 'nowrap', color: '#94a3b8', fontSize: 11 }} title={lastRunCell.title}>
                        {lastRunCell.primary}
                      </td>
                      <td><LastRunMetricsCell feed={i} /></td>
                      <td style={{ whiteSpace: 'nowrap', color: '#94a3b8', fontSize: 11 }} title={nextRunCell.title}>
                        {nextRunCell.primary}
                      </td>
                      <td className="integrations-feeds-action-cell">
                        <div className="integrations-feeds-action-buttons" style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-start' }}>
                          <button type="button" onClick={() => runNowOne(i.key, i.name, 'incremental')} disabled={Boolean(runningKeys[i.key === 'usom-trcert' ? `${i.key}:incremental` : i.key]) || !canWrite || !canRunNow} style={{ fontSize: 11, padding: '4px 8px' }} title={purgeActive ? 'A purge job is running for this feed.' : (!canRunNow ? 'Enable the feed before running manually.' : undefined)}>
                            {runningKeys[i.key === 'usom-trcert' ? `${i.key}:incremental` : i.key] ? 'Queueing...' : (i.key === 'usom-trcert' ? 'Run Incremental' : 'Run now')}
                          </button>
                          {i.key === 'usom-trcert' ? (
                            <button type="button" onClick={() => runNowOne(i.key, i.name, 'full_reconciliation')} disabled={Boolean(runningKeys[`${i.key}:full_reconciliation`]) || !canWrite || !canRunNow} style={{ fontSize: 11, padding: '4px 8px', borderColor: '#b45309', color: '#fcd34d' }}>
                              {runningKeys[`${i.key}:full_reconciliation`] ? 'Queueing...' : 'Full Reconciliation'}
                            </button>
                          ) : null}
                          {canWrite ? (
                            <button type="button" onClick={() => { setFeedActionSuccess(''); openSettingsModal(i); }} style={{ fontSize: 11, padding: '4px 8px', borderRadius: 6, border: '1px solid #475569', background: 'transparent', color: '#93c5fd', cursor: 'pointer' }}>
                              Edit
                            </button>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  );
                }) : (
                  <tr><td colSpan={7} style={{ color: '#94a3b8', padding: 12 }}>No feeds found.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>
      </div>

      {editingFeed ? (
        <FeedSettingsModal
          feed={editingFeed}
          draftCron={settingsDraftCron}
          onDraftChange={setSettingsDraftCron}
          draftExpiration={settingsDraftExpiration}
          onExpirationChange={setSettingsDraftExpiration}
          draftConfidence={settingsDraftConfidence}
          onConfidenceChange={setSettingsDraftConfidence}
          savingConfidence={Boolean(savingConfidenceKey)}
          confidenceError={settingsConfidenceError}
          confidenceSuccess={settingsConfidenceSuccess}
          onSaveConfidence={() => saveSettingsConfidence().catch(() => {})}
          draftColor={settingsDraftColor}
          onColorChange={setSettingsDraftColor}
          savingColor={Boolean(savingColorKey)}
          colorError={settingsColorError}
          colorSuccess={settingsColorSuccess}
          onSaveColor={() => saveSettingsColor().catch(() => {})}
          draftAuthKey={settingsDraftAuthKey}
          onAuthKeyChange={setSettingsDraftAuthKey}
          maskedAuthKey={settingsMaskedAuthKey}
          authKeyConfigured={settingsAuthKeyConfigured}
          draftRecentDays={settingsDraftRecentDays}
          onRecentDaysChange={setSettingsDraftRecentDays}
          testingCredentials={Boolean(testingCredentialsKey)}
          credentialsTestMessage={settingsCredentialsTestMessage}
          credentialsTestOk={settingsCredentialsTestOk}
          onTestCredentials={() => testSettingsCredentials().catch(() => {})}
          savingSchedule={Boolean(savingScheduleKey)}
          savingExpiration={Boolean(savingExpirationKey)}
          savingCredentials={Boolean(savingCredentialsKey)}
          credentialsError={settingsCredentialsError}
          credentialsSuccess={settingsCredentialsSuccess}
          error={settingsError}
          expirationError={settingsExpirationError}
          expirationSuccess={settingsExpirationSuccess}
          expirationRefreshWarn={settingsExpirationRefreshWarn}
          onClose={closeSettingsModal}
          onRequestActiveChange={requestActiveChange}
          onSaveSchedule={() => saveSettingsSchedule().catch(() => {})}
          onSaveExpiration={() => saveSettingsExpiration().catch(() => {})}
          onSaveCredentials={() => saveSettingsCredentials().catch(() => {})}
          onOpenPurge={() => openPurgeFromEdit(editingFeed)}
          onArchive={() => archiveFeedFromSettings().catch(() => {})}
          onRestore={() => restoreFeedFromSettings().catch(() => {})}
          onRunFullReconciliation={() => runNowOne(editingFeed.key, editingFeed.name, 'full_reconciliation').catch(() => {})}
          runningFullReconciliation={Boolean(runningKeys[`${editingFeed.key}:full_reconciliation`])}
          purgeActive={Boolean(editingFeed?.purge_active)}
          canWrite={canWrite}
        />
      ) : null}

      {activeConfirm ? (
        <FeedActiveConfirmModal
          feed={activeConfirm}
          mode={activeConfirm.mode}
          loading={Boolean(togglingKeys[activeConfirm.key])}
          error={activeConfirmError}
          onCancel={closeActiveConfirm}
          onConfirm={() => confirmActiveChange().catch(() => {})}
        />
      ) : null}

      <FeedPurgeModal
        feed={purgeFeed}
        open={showPurgeModal && Boolean(purgeFeed)}
        onClose={closePurgeModal}
        onCompleted={handlePurgeCompleted}
      />
    </AppShell>
  );
}


function IntegrationsQueueStatusPage() {
  const { isAdmin } = useSession();
  const [loading, setLoading] = useState(true);
  const [queue, setQueue] = useState({ counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [], pagination: { page: 1, page_size: 25, total: 0, total_pages: 1 } });
  const [integrations, setIntegrations] = useState([]);
  const [tableWidths, setTableWidths] = useState({
    id: 120, integration: 180, name: 160, state: 100, queued: 160, started: 160, finished: 160, duration: 100, result: 240
  });
  const [resizeState, setResizeState] = useState(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [search, setSearch] = useState('');
  const [windowValue, setWindowValue] = useState('24h');
  const [integrationFilter, setIntegrationFilter] = useState('');
  const [stateFilter, setStateFilter] = useState('');
  const [customFrom, setCustomFrom] = useState('');
  const [customTo, setCustomTo] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [recoverPreview, setRecoverPreview] = useState(null);
  const [recoverLoading, setRecoverLoading] = useState(false);
  const [recoverError, setRecoverError] = useState('');
  const [loadError, setLoadError] = useState('');

  function toIsoOrUndefined(localValue) {
    if (!localValue) return undefined;
    const ms = Date.parse(localValue);
    if (!Number.isFinite(ms)) return undefined;
    return new Date(ms).toISOString();
  }

  async function load(
    targetPage = page,
    targetPageSize = pageSize,
    targetSearch = search,
    targetWindow = windowValue,
    targetIntegration = integrationFilter,
    targetState = stateFilter,
    targetFrom = customFrom,
    targetTo = customTo
  ) {
    setLoading(true);
    setLoadError('');
    try {
      const params = {
        queue_page: targetPage,
        queue_page_size: targetPageSize,
        queue_search: targetSearch || undefined,
        queue_window: targetWindow,
        queue_integration: targetIntegration || undefined,
        queue_state: targetState || undefined
      };
      if (targetWindow === 'custom') {
        params.queue_from = toIsoOrUndefined(targetFrom);
        params.queue_to = toIsoOrUndefined(targetTo);
      }
      const { data } = await api.get('/integrations', { params });
      setQueue(data?.queue || { counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [], pagination: { page: 1, page_size: 25, total: 0, total_pages: 1 } });
      if (Array.isArray(data?.integrations)) setIntegrations(data.integrations);
    } catch (err) {
      setLoadError(err?.response?.data?.message || 'Failed to load queue');
      setQueue({ counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [], pagination: { page: 1, page_size: targetPageSize, total: 0, total_pages: 1 } });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (windowValue === 'custom') return;
    load(page, pageSize, search, windowValue, integrationFilter, stateFilter, customFrom, customTo).catch(() => {});
  }, [page, pageSize, search, windowValue, integrationFilter, stateFilter]);

  useEffect(() => {
    if (!resizeState) return undefined;
    function onMove(e) {
      const delta = e.clientX - resizeState.startX;
      const next = Math.max(80, resizeState.startWidth + delta);
      setTableWidths((prev) => ({ ...prev, [resizeState.col]: next }));
    }
    function onUp() { setResizeState(null); }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [resizeState]);

  function startResize(col, e) {
    e.preventDefault();
    e.stopPropagation();
    setResizeState({ col, startX: e.clientX, startWidth: tableWidths[col] || 120 });
  }

  async function previewRecover() {
    if (!isAdmin) return;
    setRecoverLoading(true);
    setRecoverError('');
    try {
      const { data } = await api.post('/integrations/queue/recover?dry_run=true');
      setRecoverPreview(data);
    } catch (err) {
      setRecoverError(err?.response?.data?.message || 'Failed to preview recovery');
      setRecoverPreview(null);
    } finally {
      setRecoverLoading(false);
    }
  }

  async function applyRecover() {
    if (!isAdmin) return;
    setRecoverLoading(true);
    setRecoverError('');
    try {
      await api.post('/integrations/queue/recover');
      setRecoverPreview(null);
      await load(page, pageSize, search, windowValue, integrationFilter, stateFilter, customFrom, customTo);
    } catch (err) {
      setRecoverError(err?.response?.data?.message || 'Failed to recover queue');
    } finally {
      setRecoverLoading(false);
    }
  }

  function applyCustomRange() {
    setPage(1);
    load(1, pageSize, search, 'custom', integrationFilter, stateFilter, customFrom, customTo).catch(() => {});
  }

  const qh = queue.queue_health || {};
  const colCount = 9;
  const resultToneColor = {
    success: '#86efac',
    danger: '#fca5a5',
    warning: '#fcd34d',
    neutral: '#94a3b8'
  };

  const feedOptions = useMemo(() => {
    const seen = new Set();
    const opts = [];
    for (const feed of integrations || []) {
      const key = String(feed.key || '').trim();
      if (!key || seen.has(key)) continue;
      seen.add(key);
      opts.push({ key, name: feed.name || key });
    }
    return opts.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  }, [integrations]);

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <h2 style={{ marginTop: 0, color: '#f1f5f9' }}>Job Queue Status</h2>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {isAdmin ? (
              <button type="button" onClick={() => previewRecover().catch(() => {})} disabled={recoverLoading}>
                {recoverLoading ? 'Checking...' : 'Recover Queue'}
              </button>
            ) : null}
            <button
              type="button"
              onClick={() => load(page, pageSize, search, windowValue, integrationFilter, stateFilter, customFrom, customTo).catch(() => {})}
            >
              Refresh
            </button>
          </div>
        </div>
        {qh.queue_health ? (
          <div className={queueHealthPanelClass(qh.queue_health)} style={{ marginBottom: 12, padding: 12, borderRadius: 8, fontSize: 13, lineHeight: 1.7 }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, color: '#e2e8f0' }}>
              <span><b>Worker:</b> {qh.worker_status || '-'}</span>
              <span><b>Queue health:</b> <span style={{ color: queueHealthColor(qh.queue_health), fontWeight: 700 }}>{qh.queue_health}</span></span>
              <span><b>BullMQ active:</b> {qh.bullmq_active ?? '-'}</span>
              <span><b>BullMQ stalled:</b> {qh.bullmq_stalled ?? '-'}</span>
              <span><b>DB running:</b> {qh.db_running ?? '-'}</span>
              <span><b>Recovery needed:</b> {qh.recovery_needed ? 'yes' : 'no'}</span>
              {qh.queued_recovery_needed ? (
                <span style={{ color: '#f59e0b' }}><b>Stale queued:</b> {qh.stale_queued_count}</span>
              ) : null}
            </div>
            {(qh.warnings || []).length ? (
              <ul className="queue-health-warnings">
                {qh.warnings.map((w) => <li key={w}>{w}</li>)}
              </ul>
            ) : null}
          </div>
        ) : null}
        {recoverError ? <div className="queue-recover-error" style={{ marginBottom: 8, fontSize: 13 }}>{recoverError}</div> : null}
        {loadError ? <div className="queue-recover-error" style={{ marginBottom: 8, fontSize: 13 }}>{loadError}</div> : null}
        {recoverPreview ? (
          <div className="queue-recover-preview" style={{ marginBottom: 12, padding: 12, borderRadius: 8, fontSize: 13 }}>
            <div><b>Dry-run:</b> would reconcile <b>{recoverPreview.reconciled_count || 0}</b> item(s).</div>
            {(recoverPreview.stale_queued_jobs || []).length > 0 ? (
              <div style={{ marginTop: 6 }}>
                <b>Stale queued jobs ({recoverPreview.stale_queued_jobs.length}):</b>
                <ul style={{ margin: '4px 0 0 0', paddingLeft: 18 }}>
                  {recoverPreview.stale_queued_jobs.map((j) => (
                    <li key={j.job_id} style={{ color: '#fcd34d' }}>
                      #{j.job_id} · {j.integration_key} · queued {Math.round((j.age_seconds || 0) / 60)}m ago
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
              <button type="button" onClick={() => applyRecover().catch(() => {})} disabled={recoverLoading}>Confirm recover</button>
              <button type="button" onClick={() => setRecoverPreview(null)}>Cancel</button>
            </div>
          </div>
        ) : null}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
          <input
            value={search}
            onChange={(e) => { setPage(1); setSearch(e.target.value); }}
            placeholder="Search all columns..."
            style={{ minWidth: 220, ...queuePageInputStyle }}
          />
          <select value={windowValue} onChange={(e) => { setPage(1); setWindowValue(e.target.value); }} style={queuePageInputStyle}>
            <option value="24h">24 hours</option>
            <option value="7d">7 days</option>
            <option value="30d">30 days</option>
            <option value="custom">Custom</option>
          </select>
          <select
            value={integrationFilter}
            onChange={(e) => { setPage(1); setIntegrationFilter(e.target.value); }}
            style={queuePageInputStyle}
          >
            <option value="">All integrations</option>
            {feedOptions.map((f) => (
              <option key={f.key} value={f.key}>{f.name}</option>
            ))}
          </select>
          <select
            value={stateFilter}
            onChange={(e) => { setPage(1); setStateFilter(e.target.value); }}
            style={queuePageInputStyle}
          >
            <option value="">All states</option>
            <option value="queued">Queued</option>
            <option value="running">Running</option>
            <option value="success">Success</option>
            <option value="failed">Failed</option>
            <option value="skipped">Skipped</option>
          </select>
          <select value={pageSize} onChange={(e) => { setPage(1); setPageSize(Number(e.target.value)); }} style={queuePageInputStyle}>
            <option value={25}>25 rows</option>
            <option value={50}>50 rows</option>
            <option value={100}>100 rows</option>
          </select>
        </div>
        {windowValue === 'custom' ? (
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
            <label style={{ color: '#94a3b8', fontSize: 12 }}>
              From
              <input
                type="datetime-local"
                value={customFrom}
                onChange={(e) => setCustomFrom(e.target.value)}
                style={{ display: 'block', marginTop: 4, ...queuePageInputStyle }}
              />
            </label>
            <label style={{ color: '#94a3b8', fontSize: 12 }}>
              To
              <input
                type="datetime-local"
                value={customTo}
                onChange={(e) => setCustomTo(e.target.value)}
                style={{ display: 'block', marginTop: 4, ...queuePageInputStyle }}
              />
            </label>
            <button type="button" onClick={() => applyCustomRange()} style={{ marginTop: 16 }}>Apply range</button>
          </div>
        ) : null}
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 10, fontSize: 14, color: '#cbd5e1' }}>
          <span>Waiting: <b style={{ color: '#f1f5f9' }}>{queue.counts?.waiting || 0}</b></span>
          <span>Active: <b style={{ color: '#f1f5f9' }}>{queue.counts?.active || 0}</b></span>
          <span>Delayed: <b style={{ color: '#f1f5f9' }}>{queue.counts?.delayed || 0}</b></span>
          <span>Failed: <b style={{ color: '#f1f5f9' }}>{queue.counts?.failed || 0}</b></span>
          <span>Completed: <b style={{ color: '#f1f5f9' }}>{queue.counts?.completed || 0}</b></span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', background: '#0f172a', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
            <colgroup>
              <col style={{ width: tableWidths.id }} />
              <col style={{ width: tableWidths.integration }} />
              <col style={{ width: tableWidths.name }} />
              <col style={{ width: tableWidths.state }} />
              <col style={{ width: tableWidths.queued }} />
              <col style={{ width: tableWidths.started }} />
              <col style={{ width: tableWidths.finished }} />
              <col style={{ width: tableWidths.duration }} />
              <col style={{ width: tableWidths.result }} />
            </colgroup>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', background: '#1f2937', color: '#e2e8f0' }}>
                <th style={{ position: 'relative' }}>Job ID<div onMouseDown={(e) => startResize('id', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Integration<div onMouseDown={(e) => startResize('integration', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Name<div onMouseDown={(e) => startResize('name', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>State<div onMouseDown={(e) => startResize('state', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Queued At<div onMouseDown={(e) => startResize('queued', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Started At<div onMouseDown={(e) => startResize('started', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Finished At<div onMouseDown={(e) => startResize('finished', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Duration<div onMouseDown={(e) => startResize('duration', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Result<div onMouseDown={(e) => startResize('result', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              </tr>
            </thead>
            <tbody>
              {loading ? <tr><td colSpan={colCount}>Loading...</td></tr> : (queue.jobs?.length ? queue.jobs.flatMap((j) => {
                const durationText = formatJobDuration(computeJobDurationMs(j));
                const resultView = presentQueueJobResult(j);
                const reasonText = integrationJobReasonLabel(j);
                const isExpanded = expandedId === String(j.id);
                const detailMetrics = isExpanded ? buildQueueJobDetailMetrics(j) : [];
                const mainRow = (
                  <tr
                    key={String(j.id)}
                    style={{ borderBottom: isExpanded ? 'none' : '1px solid #334155', cursor: 'pointer' }}
                    onClick={() => setExpandedId(isExpanded ? null : String(j.id))}
                  >
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#e2e8f0' }} title={String(j.id)}>{j.id}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#e2e8f0' }}>{j.integration_name || j.integration_key || '-'}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#e2e8f0' }}>{integrationJobDisplayName(j)}</td>
                    <td style={{ color: queueJobStateColor(j.state === 'fail' ? 'failed' : j.state), fontWeight: 700, textTransform: 'capitalize' }}>{j.state === 'fail' ? 'failed' : (j.state || '-')}{j.possibly_stuck ? ' ?' : ''}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#cbd5e1' }}>{formatUserDateTime(j.queued_at || j.timestamp)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#cbd5e1' }}>{formatUserDateTime(j.started_at)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#cbd5e1' }}>{formatUserDateTime(j.finished_at)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#cbd5e1' }} title={durationText}>{durationText}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: resultToneColor[resultView.tone] || '#cbd5e1', fontWeight: 600 }} title={resultView.title}>{resultView.text}</td>
                  </tr>
                );
                if (!isExpanded) return [mainRow];
                return [
                  mainRow,
                  <tr key={`${j.id}-detail`} style={{ borderBottom: '1px solid #334155', background: '#0b1220' }}>
                    <td colSpan={colCount} style={{ padding: 14, color: '#cbd5e1', fontSize: 12, lineHeight: 1.6 }}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10 }}>
                        <div><b style={{ color: '#94a3b8' }}>Integration</b><div>{j.integration_name || j.integration_key || '—'}</div></div>
                        <div><b style={{ color: '#94a3b8' }}>Job name</b><div>{integrationJobDisplayName(j)}</div></div>
                        <div>
                          <b style={{ color: '#94a3b8' }}>Job ID</b>
                          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                            <span style={{ wordBreak: 'break-all' }}>{j.id}</span>
                            <button
                              type="button"
                              style={{ fontSize: 11, padding: '2px 6px' }}
                              onClick={(e) => {
                                e.stopPropagation();
                                navigator.clipboard?.writeText(String(j.id)).catch(() => {});
                              }}
                            >
                              Copy
                            </button>
                          </div>
                        </div>
                        <div><b style={{ color: '#94a3b8' }}>State</b><div style={{ textTransform: 'capitalize' }}>{j.state === 'fail' ? 'failed' : (j.state || '—')}</div></div>
                        <div><b style={{ color: '#94a3b8' }}>Run mode</b><div>{formatQueueRunMode(j.run_mode || j.result?.run_mode)}</div></div>
                        <div><b style={{ color: '#94a3b8' }}>Trigger</b><div>{formatQueueTrigger(j.triggered_by)}</div></div>
                        <div><b style={{ color: '#94a3b8' }}>Queued</b><div>{formatUserDateTime(j.queued_at || j.timestamp)}</div></div>
                        <div><b style={{ color: '#94a3b8' }}>Started</b><div>{formatUserDateTime(j.started_at)}</div></div>
                        <div><b style={{ color: '#94a3b8' }}>Finished</b><div>{formatUserDateTime(j.finished_at)}</div></div>
                        <div><b style={{ color: '#94a3b8' }}>Duration</b><div>{durationText}</div></div>
                        <div><b style={{ color: '#94a3b8' }}>Result code</b><div>{j.result_code || j.result?.result_code || '—'}</div></div>
                        <div><b style={{ color: '#94a3b8' }}>Reason</b><div>{reasonText}</div></div>
                      </div>
                      {detailMetrics.length ? (
                        <div style={{ marginTop: 12 }}>
                          <b style={{ color: '#94a3b8' }}>Metrics</b>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 8, marginTop: 6 }}>
                            {detailMetrics.map((m) => (
                              <div key={m.label}><span style={{ color: '#64748b' }}>{m.label}:</span> {m.value}</div>
                            ))}
                          </div>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                ];
              }) : <tr><td colSpan={colCount} style={{ color: '#94a3b8' }}>No queued jobs</td></tr>)}
            </tbody>
          </table>
        </div>
        <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
          <div style={{ color: '#94a3b8', fontSize: 13 }}>
            Page {queue.pagination?.page || page} / {queue.pagination?.total_pages || 1} · Total {queue.pagination?.total || 0}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button disabled={(queue.pagination?.page || page) <= 1 || loading} onClick={() => setPage((p) => Math.max(1, p - 1))}>Prev</button>
            <button disabled={(queue.pagination?.page || page) >= (queue.pagination?.total_pages || 1) || loading} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      </section>
    </AppShell>
  );
}

function CustomFeedModalSection({ title, first = false, children }) {
  return (
    <section style={{
      borderTop: first ? undefined : '1px solid #1e293b',
      paddingTop: first ? 0 : 16,
      marginTop: first ? 0 : 8
    }}>
      <h4 style={{
        margin: '0 0 12px',
        color: '#94a3b8',
        fontSize: 11,
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.04em'
      }}>
        {title}
      </h4>
      {children}
    </section>
  );
}

const CTF_FIELD_LABEL = { display: 'grid', gap: 6, marginBottom: 10 };
const CTF_INPUT_STYLE = {
  padding: '6px 8px',
  borderRadius: 6,
  border: '1px solid #475569',
  background: '#0f172a',
  color: '#e2e8f0',
  fontSize: 13,
  width: '100%'
};

function buildCustomFeedAuthPayload(draftAuth) {
  const t = draftAuth?.auth_type || 'none';
  if (t === 'none') return { auth_type: 'none' };
  if (t === 'bearer_token') {
    const token = String(draftAuth.token || '').trim();
    return token ? { auth_type: 'bearer_token', token } : { auth_type: 'bearer_token' };
  }
  if (t === 'api_key_header') {
    const headerName = String(draftAuth.header_name || '').trim();
    const headerValue = String(draftAuth.header_value || '').trim();
    const out = { auth_type: 'api_key_header', header_name: headerName };
    if (headerValue) out.header_value = headerValue;
    return out;
  }
  if (t === 'basic_auth') {
    const username = String(draftAuth.username || '').trim();
    const password = String(draftAuth.password || '').trim();
    const out = { auth_type: 'basic_auth', username };
    if (password) out.password = password;
    return out;
  }
  return { auth_type: 'none' };
}

function CustomFeedAuthSection({ draftAuth, onAuthChange, existingAuth, disabled }) {
  const t = draftAuth?.auth_type || 'none';
  const existing = existingAuth || {};

  function setAuthType(type) {
    onAuthChange({ auth_type: type });
  }

  const helpText = { color: '#64748b', fontSize: 11, marginTop: 2 };
  const configuredBadge = (
    <span style={{ color: '#86efac', fontSize: 11, marginLeft: 6 }}>configured</span>
  );

  return (
    <div>
      <label style={CTF_FIELD_LABEL}>
        <span style={{ color: '#94a3b8', fontSize: 12 }}>Auth Type</span>
        <select
          value={t}
          disabled={disabled}
          onChange={(e) => setAuthType(e.target.value)}
          style={CTF_INPUT_STYLE}
        >
          <option value="none">None</option>
          <option value="bearer_token">Bearer Token</option>
          <option value="api_key_header">API Key Header</option>
          <option value="basic_auth">Basic Auth</option>
        </select>
      </label>

      {t === 'bearer_token' && (
        <label style={CTF_FIELD_LABEL}>
          <span style={{ color: '#94a3b8', fontSize: 12 }}>
            Token
            {existing.auth_type === 'bearer_token' && existing.configured ? configuredBadge : null}
          </span>
          <input
            type="password"
            value={draftAuth.token || ''}
            disabled={disabled}
            onChange={(e) => onAuthChange({ ...draftAuth, token: e.target.value })}
            style={CTF_INPUT_STYLE}
            placeholder={existing.auth_type === 'bearer_token' && existing.configured ? `current: ${existing.masked_token || '****'}` : 'Enter bearer token'}
            autoComplete="new-password"
          />
          <span style={helpText}>Leave empty to keep existing token. Secrets are never shown again.</span>
        </label>
      )}

      {t === 'api_key_header' && (
        <>
          <label style={CTF_FIELD_LABEL}>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>Header Name</span>
            <input
              type="text"
              value={draftAuth.header_name || ''}
              disabled={disabled}
              onChange={(e) => onAuthChange({ ...draftAuth, header_name: e.target.value })}
              style={CTF_INPUT_STYLE}
              placeholder="X-API-Key"
            />
          </label>
          <label style={CTF_FIELD_LABEL}>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>
              Header Value
              {existing.auth_type === 'api_key_header' && existing.configured ? configuredBadge : null}
            </span>
            <input
              type="password"
              value={draftAuth.header_value || ''}
              disabled={disabled}
              onChange={(e) => onAuthChange({ ...draftAuth, header_value: e.target.value })}
              style={CTF_INPUT_STYLE}
              placeholder={existing.auth_type === 'api_key_header' && existing.configured ? `current: ${existing.masked_header_value || '****'}` : 'Enter header value'}
              autoComplete="new-password"
            />
            <span style={helpText}>Leave empty to keep existing value. Secrets are never shown again.</span>
          </label>
        </>
      )}

      {t === 'basic_auth' && (
        <>
          <label style={CTF_FIELD_LABEL}>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>Username</span>
            <input
              type="text"
              value={draftAuth.username || ''}
              disabled={disabled}
              onChange={(e) => onAuthChange({ ...draftAuth, username: e.target.value })}
              style={CTF_INPUT_STYLE}
              placeholder="username"
              autoComplete="off"
            />
          </label>
          <label style={CTF_FIELD_LABEL}>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>
              Password
              {existing.auth_type === 'basic_auth' && existing.password_configured ? configuredBadge : null}
            </span>
            <input
              type="password"
              value={draftAuth.password || ''}
              disabled={disabled}
              onChange={(e) => onAuthChange({ ...draftAuth, password: e.target.value })}
              style={CTF_INPUT_STYLE}
              placeholder={existing.auth_type === 'basic_auth' && existing.password_configured ? '(current password set)' : 'Enter password'}
              autoComplete="new-password"
            />
            <span style={helpText}>Leave empty to keep existing password. Secrets are never shown again.</span>
          </label>
        </>
      )}
    </div>
  );
}

function CustomFeedLifecycleFields({
  feedActive,
  draftCron,
  onCronChange,
  draftConfidence,
  onConfidenceChange,
  draftExpiration,
  onExpirationChange,
  onRequestActiveChange,
  disabled = false
}) {
  const exp = draftExpiration || defaultExpirationDraft();
  const showTtl = exp.enabled && ['fixed_ttl', 'last_seen_ttl'].includes(exp.expiration_mode);
  const showGrace = exp.enabled && exp.expiration_mode === 'missing_from_feed_ttl';
  const state = feedStatePresentation(feedActive !== false);

  return (
    <div style={{ display: 'grid', gap: 10 }}>
      <div>
        <div style={{ color: '#94a3b8', marginBottom: 6, fontSize: 12 }}>Current state</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span style={{
          display: 'inline-block',
          padding: '2px 8px',
          borderRadius: 999,
          fontSize: 11,
          fontWeight: 700,
          color: state.color,
          background: state.bg,
          border: `1px solid ${state.border}`
        }}>
          {state.label}
        </span>
        {!disabled ? (
          <button
            type="button"
            onClick={onRequestActiveChange}
            style={{
              fontSize: 12,
              padding: '4px 10px',
              borderRadius: 6,
              border: '1px solid #475569',
              background: 'transparent',
              color: feedActive !== false ? '#fca5a5' : '#86efac',
              cursor: 'pointer'
            }}
          >
            {feedActive !== false ? 'Disable feed' : 'Enable feed'}
          </button>
        ) : null}
        </div>
      </div>

      <label style={CTF_FIELD_LABEL}>
        <span style={{ color: '#94a3b8', fontSize: 12 }}>Schedule</span>
        <select
          value={draftCron}
          onChange={(e) => onCronChange(e.target.value)}
          disabled={disabled}
          style={CTF_INPUT_STYLE}
        >
          {FEED_SCHEDULE_OPTIONS.map((opt) => (
            <option key={opt.cron} value={opt.cron}>{opt.label}</option>
          ))}
        </select>
        <FeedRunOnceScheduleHint cron={draftCron} />
      </label>

      <label style={CTF_FIELD_LABEL}>
        <span style={{ color: '#94a3b8', fontSize: 12 }}>Default confidence</span>
        <span style={{ color: '#64748b', fontSize: 11 }}>Inherited IOC confidence only; explicit overrides are unchanged.</span>
        <select
          value={draftConfidence || 'medium'}
          onChange={(e) => onConfidenceChange(e.target.value)}
          disabled={disabled}
          style={CTF_INPUT_STYLE}
        >
          {CONFIDENCE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </label>

      <div style={{ display: 'grid', gap: 10 }}>
        <span style={{ color: '#94a3b8', fontSize: 12 }}>Expiration policy</span>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <input
            type="checkbox"
            checked={exp.enabled}
            disabled={disabled}
            onChange={(e) => onExpirationChange({ ...exp, enabled: e.target.checked })}
          />
          <span style={{ color: '#e2e8f0', fontSize: 13 }}>Enable expiration</span>
        </label>
        <label style={CTF_FIELD_LABEL}>
          <span style={{ color: '#94a3b8', fontSize: 12 }}>Mode</span>
          <select
            value={exp.expiration_mode}
            disabled={disabled || !exp.enabled}
            onChange={(e) => onExpirationChange({ ...exp, expiration_mode: e.target.value })}
            style={CTF_INPUT_STYLE}
          >
            {EXPIRATION_MODE_OPTIONS.map((opt) => (
              <option key={opt.id} value={opt.id}>{opt.label}</option>
            ))}
          </select>
        </label>
        {showTtl ? (
          <label style={CTF_FIELD_LABEL}>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>TTL days</span>
            <input
              type="number"
              min={1}
              value={exp.ttl_days}
              disabled={disabled}
              onChange={(e) => onExpirationChange({ ...exp, ttl_days: e.target.value })}
              style={CTF_INPUT_STYLE}
            />
          </label>
        ) : null}
        {showGrace ? (
          <label style={CTF_FIELD_LABEL}>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>Grace days</span>
            <input
              type="number"
              min={1}
              value={exp.grace_days}
              disabled={disabled}
              onChange={(e) => onExpirationChange({ ...exp, grace_days: e.target.value })}
              style={CTF_INPUT_STYLE}
            />
          </label>
        ) : null}
        {exp.enabled ? (
          <div style={{ borderTop: '1px solid #1e293b', paddingTop: 10, marginTop: 2 }}>
            <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>IOC Type Overrides</div>
            <div style={{ color: '#64748b', fontSize: 11, marginBottom: 8 }}>
              Overrides take precedence over the feed default expiration policy.
            </div>
            <div style={{ display: 'grid', gap: 8 }}>
              {EXPIRATION_TYPE_OVERRIDE_TYPES.map((t) => {
                const ovr = (exp.type_overrides && exp.type_overrides[t.id]) || { mode: 'inherit', ttl_days: '' };
                const isFixed = ovr.mode === 'fixed_ttl';
                const setOverride = (patch) => onExpirationChange({
                  ...exp,
                  type_overrides: { ...(exp.type_overrides || {}), [t.id]: { ...ovr, ...patch } }
                });
                return (
                  <div key={t.id} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 100px', gap: 6, alignItems: 'center' }}>
                    <span style={{ color: '#e2e8f0', fontSize: 13 }}>{t.label}</span>
                    <select
                      value={ovr.mode}
                      disabled={disabled}
                      onChange={(e) => setOverride({ mode: e.target.value })}
                      style={CTF_INPUT_STYLE}
                    >
                      {EXPIRATION_TYPE_OVERRIDE_MODES.map((m) => (
                        <option key={m.id} value={m.id}>{m.label}</option>
                      ))}
                    </select>
                    <input
                      type="number"
                      min={1}
                      placeholder="TTL days"
                      value={isFixed ? ovr.ttl_days : ''}
                      disabled={disabled || !isFixed}
                      onChange={(e) => setOverride({ ttl_days: e.target.value })}
                      style={{ ...CTF_INPUT_STYLE, opacity: isFixed ? 1 : 0.4 }}
                    />
                  </div>
                );
              })}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function CustomThreatFeedsPage() {
  const { canWrite, isAdmin, role } = useSession();
  const canRunActions = canWrite;
  const [loading, setLoading] = useState(true);
  const [feeds, setFeeds] = useState([]);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [editingFeed, setEditingFeed] = useState(null);
  const [form, setForm] = useState({
    name: '', url: '', format: 'auto', ioc_type_mode: 'auto', fixed_ioc_type: 'domain', description: '', color: ''
  });
  const [formError, setFormError] = useState('');
  const [saving, setSaving] = useState(false);
  const [actionFeedId, setActionFeedId] = useState('');
  const [toast, setToast] = useState('');
  const [draftCron, setDraftCron] = useState('0 * * * *');
  const [draftConfidence, setDraftConfidence] = useState('medium');
  const [draftExpiration, setDraftExpiration] = useState(defaultExpirationDraft());
  const [editActive, setEditActive] = useState(true);
  const [togglingKeys, setTogglingKeys] = useState({});
  const [activeConfirm, setActiveConfirm] = useState(null);
  const [activeConfirmError, setActiveConfirmError] = useState('');
  const [purgeFeed, setPurgeFeed] = useState(null);
  const [showPurgeModal, setShowPurgeModal] = useState(false);
  const [editUrlMissing, setEditUrlMissing] = useState(false);
  const [deleteModal, setDeleteModal] = useState(null);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [draftAuth, setDraftAuth] = useState({ auth_type: 'none' });

  const emptyForm = {
    name: '', url: '', format: 'auto', ioc_type_mode: 'auto', fixed_ioc_type: 'domain', description: '', color: ''
  };

  const emptyAuth = { auth_type: 'none' };

  async function loadFeeds() {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get('/custom-threat-feeds');
      setFeeds(data?.feeds || []);
    } catch (err) {
      setFeeds([]);
      setError(apiErrorMessage(err, 'Failed to load Custom Threat Feeds'));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadFeeds().catch(() => {}); }, []);

  function openCreate() {
    if (!isAdmin) return;
    setEditingFeed(null);
    setForm(emptyForm);
    setFormError('');
    setDraftCron('0 * * * *');
    setEditUrlMissing(false);
    setDraftAuth(emptyAuth);
    setShowModal(true);
  }

  async function openEdit(feed) {
    if (!isAdmin) return;
    setEditingFeed(feed);
    const currentUrl = String(feed.url_display || feed.url || '').trim();
    const urlMissing = !currentUrl || currentUrl === '[invalid-url]';
    setForm({
      name: feed.name || '',
      url: urlMissing ? '' : currentUrl,
      format: feed.format || 'auto',
      ioc_type_mode: feed.ioc_type_mode || 'auto',
      fixed_ioc_type: feed.fixed_ioc_type || 'domain',
      description: feed.description || '',
      color: feed.color || ''
    });
    setEditUrlMissing(urlMissing);
    setDraftCron(feed.schedule || '0 * * * *');
    setDraftConfidence(String(feed.default_confidence || 'medium').trim().toLowerCase());
    setDraftExpiration(defaultExpirationDraft(feed.expiration_policy));
    setEditActive(feed.active !== false);
    setDraftAuth({ auth_type: feed.auth?.auth_type || 'none' });
    setFormError('');
    setShowModal(true);
    const feedKey = feed.integration_key || feed.key;
    if (feedKey) {
      try {
        const { data } = await api.get(`/threat-feeds/${encodeURIComponent(feedKey)}/expiration-policy`);
        setDraftExpiration(defaultExpirationDraft(data?.policy, data?.expiration_type_policies));
      } catch {
        setDraftExpiration(defaultExpirationDraft(feed.expiration_policy));
      }
    }
  }

  async function saveFeed() {
    if (!isAdmin) return;
    setSaving(true);
    setFormError('');
    try {
      const name = String(form.name || '').trim();
      if (!name) {
        setFormError('Name is required');
        setSaving(false);
        return;
      }
      if (!isSavableColor(form.color)) {
        setFormError('Badge color must be a hex value like #16a34a, or left blank.');
        setSaving(false);
        return;
      }
      if (editingFeed) {
        const url = String(form.url || '').trim();
        if (!url) {
          setFormError(editUrlMissing ? 'Current URL is not available. Enter a valid feed URL.' : 'Feed URL is required');
          setSaving(false);
          return;
        }
        const authPayload = buildCustomFeedAuthPayload(draftAuth);
        const payload = { ...form, name, url, auth: authPayload };
        await api.put(`/custom-threat-feeds/${encodeURIComponent(editingFeed.id)}`, payload);

        const feedKey = editingFeed.integration_key || editingFeed.key;
        const origSchedule = editingFeed.schedule || '0 * * * *';
        const origConfidence = String(editingFeed.default_confidence || 'medium').trim().toLowerCase();

        if (draftCron !== origSchedule) {
          await api.put(`/integrations/${encodeURIComponent(feedKey)}/schedule`, { schedule_cron: draftCron });
        }
        if (draftConfidence && draftConfidence !== origConfidence) {
          await api.patch(`/integrations/${encodeURIComponent(feedKey)}/default-confidence`, {
            default_confidence: draftConfidence
          });
        }
        const expPayload = buildExpirationFullPatchPayload(draftExpiration);
        await api.patch(`/threat-feeds/${encodeURIComponent(feedKey)}/expiration-policy`, expPayload);

        setShowModal(false);
        setEditingFeed(null);
        setToast('Custom Threat Feed updated');
      } else {
        const url = String(form.url || '').trim();
        if (!url) {
          setFormError('Feed URL is required');
          setSaving(false);
          return;
        }
        const authPayload = buildCustomFeedAuthPayload(draftAuth);
        await api.post('/custom-threat-feeds', { ...form, name, url, schedule_cron: draftCron, auth: authPayload });
        setShowModal(false);
        setToast('Custom Threat Feed created');
      }
      invalidateSourceColorCatalog();
      await loadFeeds();
    } catch (err) {
      setFormError(apiErrorMessage(err, editingFeed ? 'Failed to update Custom Threat Feed' : 'Failed to create Custom Threat Feed'));
    } finally {
      setSaving(false);
    }
  }

  async function confirmActiveChange() {
    if (!isAdmin || !activeConfirm) return;
    const { key, mode } = activeConfirm;
    const nextActive = mode === 'enable';
    if (togglingKeys[key]) return;
    setActiveConfirmError('');
    setTogglingKeys((prev) => ({ ...prev, [key]: true }));
    try {
      await api.patch(`/integrations/${encodeURIComponent(key)}/active`, { active: nextActive });
      setActiveConfirm(null);
      setEditActive(nextActive);
      setEditingFeed((prev) => (prev ? { ...prev, active: nextActive } : null));
      setToast(nextActive ? 'Feed enabled' : 'Feed disabled');
      await loadFeeds();
    } catch (err) {
      setActiveConfirmError(apiErrorMessage(err, 'Failed to update feed active state'));
    } finally {
      setTogglingKeys((prev) => ({ ...prev, [key]: false }));
    }
  }

  function openPurgeFromEdit() {
    if (!isAdmin || !editingFeed) return;
    setPurgeFeed({
      key: editingFeed.integration_key || editingFeed.key,
      name: editingFeed.name
    });
    setShowPurgeModal(true);
    setShowModal(false);
  }

  function requestActiveChange() {
    if (!isAdmin || !editingFeed) return;
    setActiveConfirmError('');
    setActiveConfirm({
      key: editingFeed.integration_key || editingFeed.key,
      name: editingFeed.name,
      mode: editActive ? 'disable' : 'enable'
    });
  }

  function closeActiveConfirm() {
    if (togglingKeys[activeConfirm?.key]) return;
    setActiveConfirm(null);
    setActiveConfirmError('');
  }

  async function runNowFeed(feed) {
    if (!canRunActions) return;
    setActionFeedId(feed.id);
    try {
      const { data } = await api.post(`/custom-threat-feeds/${encodeURIComponent(feed.id)}/sync`);
      setToast(data?.message || 'Custom threat feed run queued');
    } catch (err) {
      alert(apiErrorMessage(err, 'Failed to queue feed run'));
    } finally {
      setActionFeedId('');
    }
  }

  async function openDeleteCheck(feed) {
    if (!isAdmin) return;
    setDeleteLoading(true);
    try {
      const { data: check } = await api.get(`/custom-threat-feeds/${encodeURIComponent(feed.id)}/delete-check`);
      setDeleteModal({ feed, check });
    } catch (err) {
      alert(apiErrorMessage(err, 'Failed to check delete eligibility'));
    } finally {
      setDeleteLoading(false);
    }
  }

  async function confirmDelete() {
    if (!isAdmin || !deleteModal) return;
    setDeleteLoading(true);
    try {
      const { data } = await api.delete(`/custom-threat-feeds/${encodeURIComponent(deleteModal.feed.id)}`);
      setDeleteModal(null);
      const unlinkCount = data?.unlinked_published_feed_count;
      setToast(
        unlinkCount > 0
          ? `Custom threat feed deleted. Removed ${unlinkCount} Published Feed reference(s).`
          : 'Custom Threat Feed deleted'
      );
      await loadFeeds();
    } catch (err) {
      const msg = err?.response?.data?.message || apiErrorMessage(err, 'Failed to delete Custom Threat Feed');
      alert(msg);
    } finally {
      setDeleteLoading(false);
    }
  }

  const statusLabel = (status) => {
    if (status === 'partial_success') return 'Partial success';
    if (status === 'success') return 'Sync completed';
    if (status === 'failed') return 'Failed';
    if (status === 'running') return 'Running';
    return status || '—';
  };

  function renderStateBadge(feed) {
    const state = feedStatePresentation(feed.active !== false);
    return (
      <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: state.color, background: state.bg, border: `1px solid ${state.border}` }}>
        {state.label}
      </span>
    );
  }

  return (
    <AppShell>
      <div className="page-content">
        <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
            <div>
              <h2 style={{ margin: 0, color: '#f1f5f9' }}>Custom Threat Feeds</h2>
              <p style={{ margin: '6px 0 0', color: '#94a3b8', fontSize: 13 }}>
                Sync IOCs from purchased TI feed URLs (TXT/CSV). Role: {role}.
              </p>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" onClick={() => loadFeeds().catch(() => {})}>Refresh</button>
              {isAdmin ? <button type="button" onClick={openCreate}>Add Custom Threat Feed</button> : null}
            </div>
          </div>

          {toast ? <div style={{ marginBottom: 10, color: '#86efac' }}>{toast}</div> : null}
          {error ? <div style={{ marginBottom: 10, color: '#fca5a5' }}>{error}</div> : null}
          {loading ? <p style={{ color: '#94a3b8' }}>Loading…</p> : null}

          {!loading && feeds.length === 0 ? (
            <p style={{ color: '#94a3b8' }}>No Custom Threat Feeds configured.</p>
          ) : null}

          {!loading && feeds.length > 0 ? (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ textAlign: 'left', color: '#cbd5e1' }}>
                    <th style={{ padding: 8 }}>State</th>
                    <th style={{ padding: 8 }}>Name</th>
                    <th style={{ padding: 8 }}>URL host</th>
                    <th style={{ padding: 8 }}>Format</th>
                    <th style={{ padding: 8 }}>IOC type</th>
                    <th style={{ padding: 8 }}>Schedule</th>
                    <th style={{ padding: 8 }}>Confidence</th>
                    <th style={{ padding: 8 }}>Expiration</th>
                    <th style={{ padding: 8 }}>Last success</th>
                    <th style={{ padding: 8 }}>Last run</th>
                    <th style={{ padding: 8 }}>Last error</th>
                    <th style={{ padding: 8 }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {feeds.map((feed) => (
                    <tr key={feed.id} style={{ borderTop: '1px solid #334155', color: '#e2e8f0' }}>
                      <td style={{ padding: 8 }}>{renderStateBadge(feed)}</td>
                      <td style={{ padding: 8 }}><span style={{ display: 'inline-flex', borderRadius: 999, padding: '2px 9px', fontSize: 12, fontWeight: 700, ...sourceColorBadgeStyle(feed.color || DEFAULT_SOURCE_COLOR) }}>{feed.name}</span></td>
                      <td style={{ padding: 8 }}>{feed.url_host || feed.url_display}</td>
                      <td style={{ padding: 8 }}>{feed.format}</td>
                      <td style={{ padding: 8 }}>{feed.ioc_type_mode}{feed.fixed_ioc_type ? ` (${feed.fixed_ioc_type})` : ''}</td>
                      <td style={{ padding: 8 }}>{formatFeedScheduleLabel(feed.schedule)}</td>
                      <td style={{ padding: 8, textTransform: 'capitalize' }}>{feed.default_confidence || 'medium'}</td>
                      <td style={{ padding: 8 }}>{feed.expiration_summary || 'Never'}</td>
                      <td style={{ padding: 8 }}>{feed.last_success_at ? formatUserDateTime(feed.last_success_at) : '—'}</td>
                      <td style={{ padding: 8 }}>{statusLabel(feed.last_run_status)}</td>
                      <td style={{ padding: 8, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>{feed.last_error || '—'}</td>
                      <td style={{ padding: 8, whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-start' }}>
                          {isAdmin ? (
                            <button type="button" disabled={actionFeedId === feed.id} onClick={() => openEdit(feed).catch(() => {})} style={{ fontSize: 11, padding: '4px 8px' }}>
                              Edit
                            </button>
                          ) : null}
                          {canRunActions ? (
                            <button
                              type="button"
                              disabled={actionFeedId === feed.id || !feed.active}
                              onClick={() => runNowFeed(feed)}
                              style={{ fontSize: 11, padding: '4px 8px' }}
                              title={!feed.active ? 'Enable the feed before running manually.' : undefined}
                            >
                              {actionFeedId === feed.id ? 'Queueing...' : 'Run now'}
                            </button>
                          ) : null}
                          {isAdmin ? (
                            <button
                              type="button"
                              disabled={deleteLoading && deleteModal?.feed?.id === feed.id}
                              onClick={() => openDeleteCheck(feed).catch(() => {})}
                              style={{ fontSize: 11, padding: '4px 8px', background: 'transparent', color: '#f87171', border: '1px solid #7f1d1d' }}
                            >
                              {deleteLoading && deleteModal?.feed?.id === feed.id ? '...' : 'Delete'}
                            </button>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </section>

        {showModal ? (
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}>
            <div style={{
              background: '#111827',
              color: '#e2e8f0',
              borderRadius: 12,
              width: 'min(620px, 94vw)',
              maxHeight: 'min(90vh, 860px)',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid #334155'
            }}>
              <div style={{ padding: '16px 20px', borderBottom: '1px solid #334155', flexShrink: 0 }}>
                <h3 style={{ margin: 0, fontSize: 18, color: '#f1f5f9' }}>
                  {editingFeed ? 'Edit Custom Threat Feed' : 'Add Custom Threat Feed'}
                </h3>
              </div>
              <div style={{ padding: '16px 20px', overflowY: 'auto', flex: 1 }}>
                {formError ? <p style={{ color: '#fca5a5', marginTop: 0 }}>{formError}</p> : null}

                <CustomFeedModalSection title="Source" first>
                  <label style={CTF_FIELD_LABEL}>
                    <span style={{ color: '#94a3b8', fontSize: 12 }}>Name</span>
                    <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} style={CTF_INPUT_STYLE} />
                  </label>
                  <label style={CTF_FIELD_LABEL}>
                    <span style={{ color: '#94a3b8', fontSize: 12 }}>Feed URL</span>
                    <input
                      value={form.url}
                      onChange={(e) => {
                        setEditUrlMissing(false);
                        setForm({ ...form, url: e.target.value });
                      }}
                      style={{ ...CTF_INPUT_STYLE, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', overflowX: 'auto' }}
                      placeholder={editingFeed ? undefined : 'https://ti.example.com/feed.txt'}
                      required
                    />
                    {editingFeed ? (
                      editUrlMissing ? (
                        <span style={{ color: '#fcd34d', fontSize: 11 }}>Current URL is not available</span>
                      ) : (
                        <span style={{ color: '#64748b', fontSize: 11, lineHeight: 1.45 }}>
                          This is the full source URL used for this custom threat feed.
                        </span>
                      )
                    ) : null}
                  </label>
                  <label style={CTF_FIELD_LABEL}>
                    <span style={{ color: '#94a3b8', fontSize: 12 }}>Format</span>
                    <select value={form.format} onChange={(e) => setForm({ ...form, format: e.target.value })} style={CTF_INPUT_STYLE}>
                      <option value="auto">auto</option>
                      <option value="txt">txt</option>
                      <option value="csv">csv</option>
                    </select>
                  </label>
                  <label style={CTF_FIELD_LABEL}>
                    <span style={{ color: '#94a3b8', fontSize: 12 }}>IOC type mode</span>
                    <select value={form.ioc_type_mode} onChange={(e) => setForm({ ...form, ioc_type_mode: e.target.value })} style={CTF_INPUT_STYLE}>
                      <option value="auto">auto</option>
                      <option value="fixed">fixed</option>
                    </select>
                  </label>
                  {form.ioc_type_mode === 'fixed' ? (
                    <label style={CTF_FIELD_LABEL}>
                      <span style={{ color: '#94a3b8', fontSize: 12 }}>Fixed IOC type</span>
                      <select value={form.fixed_ioc_type} onChange={(e) => setForm({ ...form, fixed_ioc_type: e.target.value })} style={CTF_INPUT_STYLE}>
                        <option value="domain">domain</option>
                        <option value="ip">ip</option>
                        <option value="url">url</option>
                        <option value="file_hash">file_hash</option>
                      </select>
                    </label>
                  ) : null}
                  <label style={CTF_FIELD_LABEL}>
                    <span style={{ color: '#94a3b8', fontSize: 12 }}>Description</span>
                    <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} style={{ ...CTF_INPUT_STYLE, minHeight: 72, resize: 'vertical' }} rows={3} />
                  </label>
                  <div style={CTF_FIELD_LABEL}>
                    <span style={{ color: '#94a3b8', fontSize: 12 }}>Badge color</span>
                    <SourceColorField
                      value={form.color}
                      onChange={(next) => setForm({ ...form, color: next })}
                      previewLabel={form.name || 'Feed'}
                      label=""
                      helper="Leave blank to use the default badge color."
                    />
                  </div>
                </CustomFeedModalSection>

                <CustomFeedModalSection title="Authentication">
                  <CustomFeedAuthSection
                    draftAuth={draftAuth}
                    onAuthChange={setDraftAuth}
                    existingAuth={editingFeed?.auth || null}
                    disabled={saving}
                  />
                </CustomFeedModalSection>

                <CustomFeedModalSection title={editingFeed ? 'Schedule & Lifecycle' : 'Schedule'}>
                  {editingFeed ? (
                    <>
                      <CustomFeedLifecycleFields
                        feedActive={editActive}
                        draftCron={draftCron}
                        onCronChange={setDraftCron}
                        draftConfidence={draftConfidence}
                        onConfidenceChange={setDraftConfidence}
                        draftExpiration={draftExpiration}
                        onExpirationChange={setDraftExpiration}
                        onRequestActiveChange={requestActiveChange}
                      />
                      <div style={{ marginTop: 12 }}>
                        <button type="button" onClick={openPurgeFromEdit} style={{ fontSize: 12, color: '#fca5a5', background: 'transparent', border: '1px solid #7f1d1d', borderRadius: 6, padding: '4px 10px' }}>
                          Purge feed data
                        </button>
                      </div>
                    </>
                  ) : (
                    <label style={CTF_FIELD_LABEL}>
                      <span style={{ color: '#94a3b8', fontSize: 12 }}>Schedule</span>
                      <select value={draftCron} onChange={(e) => setDraftCron(e.target.value)} style={CTF_INPUT_STYLE}>
                        {FEED_SCHEDULE_OPTIONS.map((opt) => (
                          <option key={opt.cron} value={opt.cron}>{opt.label}</option>
                        ))}
                      </select>
                      <FeedRunOnceScheduleHint cron={draftCron} />
                    </label>
                  )}
                </CustomFeedModalSection>
              </div>
              <div style={{
                padding: '12px 20px',
                borderTop: '1px solid #334155',
                display: 'flex',
                justifyContent: 'flex-end',
                gap: 8,
                flexShrink: 0
              }}>
                <button type="button" onClick={() => { setShowModal(false); setEditingFeed(null); }} disabled={saving}>Cancel</button>
                <button type="button" onClick={() => saveFeed().catch(() => {})} disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
              </div>
            </div>
          </div>
        ) : null}

        {activeConfirm ? (
          <FeedActiveConfirmModal
            feed={activeConfirm}
            mode={activeConfirm.mode}
            loading={Boolean(togglingKeys[activeConfirm.key])}
            error={activeConfirmError}
            onCancel={closeActiveConfirm}
            onConfirm={() => confirmActiveChange().catch(() => {})}
          />
        ) : null}

        <FeedPurgeModal
          feed={purgeFeed}
          open={showPurgeModal && Boolean(purgeFeed)}
          onClose={() => { setShowPurgeModal(false); setPurgeFeed(null); }}
          onCompleted={(feedName) => {
            setToast(`Purge job started for ${feedName}.`);
            loadFeeds().catch(() => {});
          }}
        />

        {deleteModal ? (() => {
          const { feed, check } = deleteModal;
          const canDel = check.can_delete;
          const reason = check.reason;
          let title, body;
          if (!canDel) {
            if (reason === 'job_running_or_queued') {
              title = 'Cannot modify feed — jobs are active';
              body = 'Cannot modify this feed while jobs are queued or running. Please wait for the job to finish or clear the queued/running job before deleting or purging this feed.';
            } else if (reason === 'requires_purge') {
              title = 'Cannot delete — feed has active IOC data';
              body = `This feed has ${check.active_membership_count} active IOC membership(s). Purge the imported IOC data first, then delete the feed.${check.published_feed_dependency_count > 0 ? ` It is also linked to ${check.published_feed_dependency_count} published feed(s) — those links will be automatically cleaned up when you delete.` : ''}`;
            } else if (reason === 'requires_disable') {
              title = 'Cannot delete enabled feed';
              body = 'This feed has no active imported IOC data, but it is still enabled. Disable it before deleting.';
            } else {
              title = 'Cannot delete this feed';
              body = reason || 'Delete is not allowed for this feed.';
            }
          } else if (check.delete_mode === 'cleanup_delete') {
            title = 'Delete feed and remove from Published Feeds?';
            body = `This feed is linked to ${check.published_feed_dependency_count} published feed(s). Deleting will automatically remove this feed from those published feeds. This action cannot be undone.`;
          } else if (check.delete_mode === 'direct_delete') {
            title = 'Delete custom threat feed?';
            body = 'This feed has no successful runs and no imported IOC data. It will be permanently removed from the custom feed list.';
          } else {
            title = 'Delete custom threat feed?';
            body = 'This feed is disabled and has no active imported IOC memberships. It will be removed from the custom feed list. Audit and historical job records may remain.';
          }
          return (
            <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100, padding: 16 }}>
              <div style={{ background: '#111827', color: '#e2e8f0', borderRadius: 12, width: 'min(500px, 94vw)', border: '1px solid #334155', padding: 24 }}>
                <h3 style={{ margin: '0 0 10px', color: '#f1f5f9', fontSize: 16 }}>{title}</h3>
                <p style={{ margin: '0 0 6px', fontSize: 13, color: '#94a3b8' }}><b style={{ color: '#e2e8f0' }}>{feed.name}</b></p>
                <p style={{ margin: '0 0 16px', fontSize: 13, color: canDel ? '#e2e8f0' : '#fca5a5' }}>{body}</p>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 16px', fontSize: 12, color: '#94a3b8', marginBottom: 18 }}>
                  <span>Successful runs: <b style={{ color: '#e2e8f0' }}>{check.successful_run_count}</b></span>
                  <span>Active IOC memberships: <b style={{ color: check.active_membership_count > 0 ? '#fca5a5' : '#86efac' }}>{check.active_membership_count}</b></span>
                  <span>Historical memberships: <b style={{ color: '#e2e8f0' }}>{check.historical_membership_count}</b></span>
                  <span>Queued/running jobs: <b style={{ color: check.queued_or_running_job_count > 0 ? '#fca5a5' : '#e2e8f0' }}>{check.queued_or_running_job_count}</b></span>
                  <span>Published feed deps: <b style={{ color: check.published_feed_dependency_count > 0 ? '#fca5a5' : '#e2e8f0' }}>{check.published_feed_dependency_count}</b></span>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  {canDel ? (
                    <button
                      type="button"
                      disabled={deleteLoading}
                      onClick={() => confirmDelete().catch(() => {})}
                      style={{ padding: '6px 14px', background: '#7f1d1d', color: '#fca5a5', border: '1px solid #991b1b', borderRadius: 6, cursor: deleteLoading ? 'not-allowed' : 'pointer', fontWeight: 600 }}
                    >
                      {deleteLoading
                        ? 'Deleting…'
                        : check.delete_mode === 'cleanup_delete'
                          ? 'Delete and remove from Published Feeds'
                          : 'Confirm delete'}
                    </button>
                  ) : null}
                  <button type="button" onClick={() => setDeleteModal(null)} disabled={deleteLoading}>
                    {canDel ? 'Cancel' : 'Close'}
                  </button>
                </div>
              </div>
            </div>
          );
        })() : null}

      </div>
    </AppShell>
  );
}

const FEED_WINDOW_OPTIONS = [
  { value: '1d', label: 'Last 1 day' },
  { value: '3d', label: 'Last 3 days' },
  { value: '7d', label: 'Last 1 week' },
  { value: 'all', label: 'All' }
];

const NON_IOC_INTEGRATION_KEYS = new Set(['asn_enrichment']);

function FeedIntegrationMultiSelect({ ui, options, value, onChange }) {
  const selected = Array.isArray(value) ? value : [];
  const linkBtn = {
    background: 'none',
    border: 'none',
    color: '#60a5fa',
    cursor: 'pointer',
    padding: 0,
    fontSize: 11,
    fontWeight: 600
  };

  const integrationOptions = options.filter((o) => o.type === 'integration');
  const customOptions = options.filter((o) => o.type === 'custom');
  const manualOptions = options.filter((o) => o.type === 'manual_source');
  const selectableKeys = options.filter((o) => o.selectable !== false).map((o) => o.key);

  function renderOption(o) {
    const alreadySelected = selected.includes(o.key);
    // Non-selectable items can still be unchecked if already selected (allow cleanup without re-enabling).
    const disabled = o.selectable === false && !alreadySelected;
    // display_name from backend is fully normalized — includes state suffix, no frontend duplication needed.
    const label = o.display_name || o.name || o.key;
    const isInactiveSelected = alreadySelected && o.selectable === false && !o.missing;
    return (
      <div key={o.key} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <label style={{ ...ui.checkLabel, display: 'flex', opacity: disabled ? 0.6 : (o.selectable === false ? 0.8 : 1) }}>
          <input
            type="checkbox"
            checked={alreadySelected}
            disabled={disabled}
            onChange={(e) => {
              const next = e.target.checked
                ? [...selected, o.key]
                : selected.filter((k) => k !== o.key);
              onChange(next);
            }}
          />
          <span>{label}</span>
        </label>
        {isInactiveSelected ? (
          <div style={{ marginLeft: 26, display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#fbbf24', lineHeight: 1.45 }}>
              This source is disabled. Uncheck to remove this reference, then save.
            </span>
            <button
              type="button"
              style={{ ...linkBtn, fontSize: 10 }}
              onClick={() => onChange(selected.filter((k) => k !== o.key))}
            >
              Remove reference
            </button>
          </div>
        ) : null}
        {o.missing ? (
          <div style={{ marginLeft: 26, display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#fbbf24', lineHeight: 1.45 }}>
              This source no longer exists. Save to remove it from this Published Feed.
            </span>
            <button
              type="button"
              style={{ ...linkBtn, fontSize: 10 }}
              onClick={() => onChange(selected.filter((k) => k !== o.key))}
            >
              Remove missing
            </button>
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <div>
      {options.length ? (
        <div style={{ display: 'flex', gap: 12, marginBottom: 8 }}>
          <button type="button" style={linkBtn} onClick={() => onChange(selectableKeys)}>
            Select all
          </button>
          <button type="button" style={linkBtn} onClick={() => onChange([])}>
            Clear
          </button>
        </div>
      ) : null}
      <div style={{
        ...ui.input,
        padding: '8px 10px',
        maxHeight: 220,
        overflowY: 'auto',
        display: 'flex',
        flexDirection: 'column',
        gap: 10
      }}>
        {!options.length ? (
          <span style={{ fontSize: 13, color: '#64748b' }}>No source feeds available</span>
        ) : null}
        {integrationOptions.length ? (
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Integration Feeds
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {integrationOptions.map(renderOption)}
            </div>
          </div>
        ) : null}
        {customOptions.length ? (
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Custom Threat Feeds
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {customOptions.map(renderOption)}
            </div>
          </div>
        ) : null}
        {manualOptions.length ? (
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Manual IOC Sources
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {manualOptions.map(renderOption)}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

const PUBLISHED_FEEDS_UI = {
  section: { border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 },
  pageTitle: { margin: 0, fontSize: 22, fontWeight: 700, color: '#f1f5f9' },
  formPanel: {
    marginBottom: 20,
    padding: 16,
    border: '1px solid #334155',
    borderRadius: 10,
    background: '#0f172a'
  },
  formTitle: { marginTop: 0, marginBottom: 14, fontSize: 16, fontWeight: 600, color: '#e2e8f0' },
  label: { display: 'block', fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6 },
  input: {
    width: '100%',
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#020617',
    color: '#e2e8f0',
    fontSize: 14,
    boxSizing: 'border-box'
  },
  select: {
    width: '100%',
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#020617',
    color: '#e2e8f0',
    fontSize: 14,
    boxSizing: 'border-box',
    cursor: 'pointer'
  },
  textarea: {
    width: '100%',
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#020617',
    color: '#e2e8f0',
    fontSize: 14,
    boxSizing: 'border-box',
    minHeight: 72,
    resize: 'vertical'
  },
  helper: { display: 'block', fontSize: 11, color: '#64748b', marginTop: 4, lineHeight: 1.45 },
  checkRow: { display: 'flex', flexWrap: 'wrap', gap: 16, marginTop: 10 },
  checkLabel: { display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#cbd5e1', cursor: 'pointer' },
  btn: {
    padding: '8px 14px',
    borderRadius: 8,
    border: '1px solid #475569',
    background: '#1f2937',
    color: '#e2e8f0',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer'
  },
  btnPrimary: {
    padding: '8px 18px',
    borderRadius: 8,
    border: 'none',
    background: '#2563eb',
    color: '#fff',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer'
  },
  thead: { textAlign: 'left', borderBottom: '1px solid #334155', background: '#0f172a' },
  th: {
    padding: '10px 8px',
    color: '#94a3b8',
    fontSize: 11,
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.05em'
  },
  tr: { borderBottom: '1px solid #1e293b' },
  td: { padding: '10px 8px', color: '#e2e8f0', verticalAlign: 'middle' },
  expandCell: { background: '#0f172a', padding: 12, borderTop: '1px solid #334155' },
  linkBtn: { background: 'none', border: 'none', padding: 0, cursor: 'pointer', fontWeight: 600, color: '#93c5fd' },
  muted: { color: '#64748b' },
  modal: {
    width: 560,
    maxWidth: '96vw',
    background: 'linear-gradient(180deg, #111827 0%, #0f172a 100%)',
    borderRadius: 12,
    padding: 20,
    border: '1px solid #334155',
    color: '#e2e8f0',
    boxShadow: '0 24px 60px rgba(2,6,23,0.55)'
  },
  pageSub: { margin: '0 0 16px', fontSize: 14, color: '#94a3b8', lineHeight: 1.55, maxWidth: 720 },
  formModal: {
    width: 'min(720px, 96vw)',
    maxHeight: '90vh',
    overflowY: 'auto',
    background: 'linear-gradient(180deg, #111827 0%, #0f172a 100%)',
    borderRadius: 12,
    padding: 24,
    border: '1px solid #334155',
    color: '#e2e8f0',
    boxShadow: '0 24px 60px rgba(2,6,23,0.55)'
  },
  sectionHeading: {
    fontSize: 12,
    fontWeight: 700,
    color: '#94a3b8',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    margin: '0 0 12px',
    paddingBottom: 8,
    borderBottom: '1px solid #1e293b'
  },
  banner: {
    marginBottom: 16,
    padding: '12px 14px',
    borderRadius: 8,
    border: '1px solid #1d4ed8',
    background: 'rgba(37, 99, 235, 0.12)',
    color: '#bfdbfe',
    fontSize: 13,
    lineHeight: 1.5
  },
  badge: (on) => ({
    display: 'inline-block',
    marginLeft: 8,
    padding: '2px 8px',
    borderRadius: 999,
    fontSize: 10,
    fontWeight: 700,
    textTransform: 'uppercase',
    background: on ? 'rgba(34, 197, 94, 0.15)' : 'rgba(148, 163, 184, 0.15)',
    color: on ? '#86efac' : '#94a3b8',
    border: `1px solid ${on ? '#166534' : '#475569'}`
  }),
  modalSub: { fontSize: 13, color: '#94a3b8', margin: '0 0 12px', lineHeight: 1.5 },
  code: {
    display: 'block',
    wordBreak: 'break-all',
    padding: 10,
    background: '#020617',
    border: '1px solid #334155',
    borderRadius: 6,
    fontSize: 12,
    color: '#cbd5e1'
  }
};

// Standard Published Feed pull URL. Replace {API_KEY} with a Published Feed type key.
function publishedFeedUrlTemplate(slug) {
  const s = slug || '{slug}';
  return `${window.location.origin}/api/published-feeds/${s}?api_key={API_KEY}`;
}

function publishedFeedCurlExample(slug) {
  const s = slug || '{slug}';
  return `curl "${window.location.origin}/api/published-feeds/${s}?api_key=YOUR_API_KEY"`;
}

function FeedFormField({ ui, label, helper, children, fullWidth = false }) {
  return (
    <div style={fullWidth ? { gridColumn: '1 / -1' } : undefined}>
      <span style={ui.label}>{label}</span>
      {children}
      {helper ? <span style={ui.helper}>{helper}</span> : null}
    </div>
  );
}

function FeedFormSection({ title, children }) {
  const ui = PUBLISHED_FEEDS_UI;
  return (
    <div style={{ marginBottom: 22 }}>
      <h4 style={ui.sectionHeading}>{title}</h4>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
        {children}
      </div>
    </div>
  );
}

function PublishedFeedsPage() {
  const { canWrite } = useSession();
  const [loading, setLoading] = useState(true);
  const [feeds, setFeeds] = useState([]);
  const [sourceFeeds, setSourceFeeds] = useState([]);
  const [showFormModal, setShowFormModal] = useState(false);
  const [editing, setEditing] = useState(null);
  const [regenerating, setRegenerating] = useState({});
  const [urlTemplateFeed, setUrlTemplateFeed] = useState(null);
  const [form, setForm] = useState({
    name: '',
    description: '',
    enabled: true,
    ioc_type: 'ip',
    exclude_false_positive: true,
    exclude_expired: true,
    include_feed_keys: [],
    include_tags: '',
    exclude_tags: '',
    time_window: 'all',
    max_items: '',
    refresh_interval_minutes: 15
  });

  async function loadFeeds() {
    setLoading(true);
    try {
      const { data } = await api.get('/published-feeds');
      setFeeds(data?.feeds || []);
    } catch {
      setFeeds([]);
    } finally {
      setLoading(false);
    }
  }

  async function loadSourceFeeds(selectedKeys = []) {
    try {
      const params = selectedKeys.length ? { selected_keys: selectedKeys.join(',') } : {};
      const { data } = await api.get('/published-feeds/source-options', { params });
      setSourceFeeds(Array.isArray(data?.sources) ? data.sources : []);
    } catch {
      setSourceFeeds([]);
    }
  }

  useEffect(() => {
    loadFeeds().catch(() => {});
    loadSourceFeeds().catch(() => {});
  }, []);

  function closeFormModal() {
    setShowFormModal(false);
    setEditing(null);
  }

  function openCreateForm() {
    setEditing(null);
    setForm({
      name: '',
      description: '',
      enabled: true,
      ioc_type: 'ip',
      exclude_false_positive: true,
      exclude_expired: true,
      include_feed_keys: [],
      include_tags: '',
      exclude_tags: '',
      time_window: 'all',
      max_items: '',
      refresh_interval_minutes: 15
    });
    loadSourceFeeds([]).catch(() => {});
    setShowFormModal(true);
  }

  function openEditForm(feed) {
    const selectedKeys = Array.isArray(feed.include_feed_keys) ? feed.include_feed_keys : [];
    setEditing(feed);
    setForm({
      name: feed.name || '',
      description: feed.description || '',
      enabled: Boolean(feed.enabled),
      ioc_type: feed.ioc_type || 'ip',
      exclude_false_positive: feed.exclude_false_positive !== false,
      exclude_expired: feed.exclude_expired !== false,
      include_feed_keys: selectedKeys,
      include_tags: (feed.include_tags || []).join(', '),
      exclude_tags: (feed.exclude_tags || []).join(', '),
      time_window: feed.time_window || 'all',
      max_items: feed.max_items ?? '',
      refresh_interval_minutes: feed.refresh_interval_minutes || 15
    });
    loadSourceFeeds(selectedKeys).catch(() => {});
    setShowFormModal(true);
  }

  function splitCsv(s) {
    return String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
  }

  function buildPayload() {
    return {
      name: form.name.trim(),
      description: form.description.trim() || null,
      enabled: Boolean(form.enabled),
      ioc_type: form.ioc_type,
      format: 'txt',
      exclude_false_positive: Boolean(form.exclude_false_positive),
      exclude_expired: Boolean(form.exclude_expired),
      include_feed_keys: form.include_feed_keys,
      include_tags: splitCsv(form.include_tags),
      exclude_tags: splitCsv(form.exclude_tags),
      time_window: form.time_window,
      max_items: form.max_items === '' ? null : Number(form.max_items),
      refresh_interval_minutes: Number(form.refresh_interval_minutes) || 15
    };
  }

  async function saveFeed(e) {
    e.preventDefault();
    if (!canWrite) return;
    const payload = buildPayload();
    try {
      if (editing?.id) {
        await api.patch(`/published-feeds/${editing.id}`, payload);
        closeFormModal();
        await loadFeeds();
      } else {
        const { data } = await api.post('/published-feeds', payload);
        const created = data?.feed;
        closeFormModal();
        await loadFeeds();
        // Feed URL is generated automatically from the slug; show its template.
        if (created?.slug) setUrlTemplateFeed(created);
      }
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to save feed');
    }
  }

  async function deleteFeed(id) {
    if (!canWrite || !window.confirm('Delete this published feed?')) return;
    try {
      await api.delete(`/published-feeds/${id}`);
      await loadFeeds();
    } catch {
      alert('Failed to delete feed');
    }
  }

  async function regenerateFeed(id) {
    if (!canWrite || regenerating[id]) return;
    setRegenerating((p) => ({ ...p, [id]: true }));
    try {
      await api.post(`/published-feeds/${id}/regenerate`);
      await loadFeeds();
    } catch {
      alert('Regenerate failed');
    } finally {
      setRegenerating((p) => ({ ...p, [id]: false }));
    }
  }

  const windowLabel = (w) => FEED_WINDOW_OPTIONS.find((o) => o.value === w)?.label || w;
  const ui = PUBLISHED_FEEDS_UI;

  return (
    <AppShell>
      <section className="published-feeds-page" style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, marginBottom: 8, flexWrap: 'wrap' }}>
          <div>
            <h2 style={ui.pageTitle}>Published Feeds</h2>
            <p style={ui.pageSub}>
              Publish filtered IOC snapshots as pull-based threat feeds for internal tools such as firewalls, proxies, DNS security, EDR, SIEM, or SOAR platforms.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button type="button" style={ui.btn} onClick={() => loadFeeds().catch(() => {})}>Refresh</button>
            {canWrite ? <button type="button" style={ui.btnPrimary} onClick={openCreateForm}>Create Feed</button> : null}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table published-feeds-table" width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 13, background: 'transparent' }}>
            <thead>
              <tr style={ui.thead}>
                <th style={ui.th}>Name</th>
                <th style={ui.th}>IOC Type</th>
                <th style={ui.th}>Window</th>
                <th style={ui.th}>Max Items</th>
                <th style={ui.th}>Last Generated</th>
                <th style={ui.th}>Status</th>
                <th style={ui.th}>Items</th>
                <th style={ui.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr style={ui.tr}><td colSpan={8} style={ui.td}>Loading...</td></tr>
              ) : feeds.length ? feeds.map((f) => (
                <tr key={f.id} style={ui.tr}>
                    <td style={ui.td}>
                      <span style={{ fontWeight: 600 }}>{f.name}</span>
                      {!f.enabled ? <span style={ui.badge(false)}>disabled</span> : null}
                      <span style={{ ...ui.badge(true), marginLeft: 6, background: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', border: '1px solid #1e40af' }}>txt</span>
                      {f.last_error ? <div style={{ color: '#fca5a5', fontSize: 11, marginTop: 4 }}>Last error: {f.last_error}</div> : null}
                    </td>
                    <td style={ui.td}>{f.ioc_type}</td>
                    <td style={ui.td}>{windowLabel(f.time_window)}</td>
                    <td style={ui.td}>{f.max_items ?? '—'}</td>
                    <td style={ui.td}>{formatUserDateTime(f.last_generated_at)}</td>
                    <td style={{
                      ...ui.td,
                      color: f.last_status === 'success' ? '#86efac' : f.last_status === 'failed' ? '#fca5a5' : '#fcd34d',
                      fontWeight: 600
                    }}>{f.last_status || '—'}</td>
                    <td style={ui.td}>{f.last_item_count ?? '—'}</td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>
                      {canWrite ? (
                        <button type="button" style={ui.btn} onClick={() => openEditForm(f)}>Edit</button>
                      ) : null}
                      {canWrite ? (
                        <button type="button" style={{ ...ui.btn, marginLeft: 6 }} disabled={regenerating[f.id]} onClick={() => regenerateFeed(f.id)}>
                          {regenerating[f.id] ? '...' : 'Regenerate'}
                        </button>
                      ) : null}
                      {canWrite ? (
                        <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => deleteFeed(f.id)}>Delete</button>
                      ) : null}
                      <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => setUrlTemplateFeed(f)}>URL</button>
                    </td>
                  </tr>
              )) : (
                <tr>
                  <td colSpan={8} style={{ ...ui.td, padding: '28px 12px', textAlign: 'center' }}>
                    <p style={{ margin: '0 0 12px', color: '#94a3b8', lineHeight: 1.5 }}>
                      No published feeds yet. Create a feed to publish filtered IOC snapshots for internal security products.
                    </p>
                    {canWrite ? (
                      <button type="button" style={ui.btnPrimary} onClick={openCreateForm}>Create Feed</button>
                    ) : null}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {showFormModal ? (
        <div
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}
          onClick={closeFormModal}
        >
          <div style={ui.formModal} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
            <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>
              {editing ? 'Edit Published Feed' : 'Create Published Feed'}
            </h3>
            <p style={ui.modalSub}>
              {editing
                ? 'Update filters and delivery settings. Regenerate snapshots after changing filters.'
                : 'Create a filtered IOC snapshot feed. Its pull URL is generated automatically from the feed name — pull it with any Published Feed API key.'}
            </p>
            {!editing ? (
              <p style={{ ...ui.modalSub, marginTop: -6 }}>
                Choose the IOC type, filters, default time window, and delivery limits. The feed URL template is shown after creation.
              </p>
            ) : null}

            <form onSubmit={saveFeed}>
              <FeedFormSection title="Basic">
                <FeedFormField ui={ui} label="Name">
                  <input required value={form.name} onChange={(e) => setForm((x) => ({ ...x, name: e.target.value }))} style={ui.input} />
                </FeedFormField>
                <FeedFormField ui={ui} label="Enabled">
                  <label style={ui.checkLabel}>
                    <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((x) => ({ ...x, enabled: e.target.checked }))} />
                    Feed is active
                  </label>
                </FeedFormField>
                <FeedFormField ui={ui} label="Description" fullWidth>
                  <textarea value={form.description} onChange={(e) => setForm((x) => ({ ...x, description: e.target.value }))} style={ui.textarea} rows={2} />
                </FeedFormField>
              </FeedFormSection>

              <FeedFormSection title="Feed content">
                <FeedFormField ui={ui} label="IOC Type" helper="The type of indicators this feed will publish. One feed publishes one IOC type.">
                  <select required value={form.ioc_type} onChange={(e) => setForm((x) => ({ ...x, ioc_type: e.target.value }))} style={ui.select}>
                    <option value="ip">ip</option>
                    <option value="domain">domain</option>
                    <option value="url">url</option>
                    <option value="hash">hash</option>
                  </select>
                </FeedFormField>
                <FeedFormField ui={ui} label="Default Window" helper="Default time range used when the consumer does not pass ?window=.">
                  <select value={form.time_window} onChange={(e) => setForm((x) => ({ ...x, time_window: e.target.value }))} style={ui.select}>
                    {FEED_WINDOW_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </FeedFormField>
                <FeedFormField
                  ui={ui}
                  label="Threat Feeds"
                  helper="Optional. Leave empty to include all feeds, or select integration feeds, custom threat feeds, and manual IOC sources to limit IOC provenance."
                  fullWidth
                >
                  <FeedIntegrationMultiSelect
                    ui={ui}
                    options={sourceFeeds}
                    value={form.include_feed_keys}
                    onChange={(next) => setForm((x) => ({ ...x, include_feed_keys: next }))}
                  />
                </FeedFormField>
              </FeedFormSection>

              <FeedFormSection title="Safety filters">
                <div style={{ gridColumn: '1 / -1', display: 'flex', flexWrap: 'wrap', gap: 16 }}>
                  <label style={ui.checkLabel}>
                    <input type="checkbox" checked={form.exclude_false_positive} onChange={(e) => setForm((x) => ({ ...x, exclude_false_positive: e.target.checked }))} />
                    Exclude false positives
                  </label>
                  <label style={ui.checkLabel}>
                    <input type="checkbox" checked={form.exclude_expired} onChange={(e) => setForm((x) => ({ ...x, exclude_expired: e.target.checked }))} />
                    Exclude expired
                  </label>
                </div>
                <FeedFormField ui={ui} label="Include Tags" helper="Optional. Comma-separated tag names.">
                  <input value={form.include_tags} onChange={(e) => setForm((x) => ({ ...x, include_tags: e.target.value }))} style={ui.input} />
                </FeedFormField>
                <FeedFormField ui={ui} label="Exclude Tags" helper="Optional. Comma-separated tag names.">
                  <input value={form.exclude_tags} onChange={(e) => setForm((x) => ({ ...x, exclude_tags: e.target.value }))} style={ui.input} />
                </FeedFormField>
              </FeedFormSection>

              <FeedFormSection title="Delivery">
                <FeedFormField ui={ui} label="Max Items" helper="Optional cap for products that support limited feed size, e.g. 40,000 IPs.">
                  <input type="number" min={1} placeholder="optional" value={form.max_items} onChange={(e) => setForm((x) => ({ ...x, max_items: e.target.value }))} style={ui.input} />
                </FeedFormField>
                <FeedFormField ui={ui} label="Refresh (minutes)" helper="How often snapshots should be regenerated. Minimum 5 minutes.">
                  <input type="number" min={5} value={form.refresh_interval_minutes} onChange={(e) => setForm((x) => ({ ...x, refresh_interval_minutes: e.target.value }))} style={ui.input} />
                </FeedFormField>
              </FeedFormSection>

              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 8, paddingTop: 16, borderTop: '1px solid #334155' }}>
                <button type="button" style={ui.btn} onClick={closeFormModal}>Cancel</button>
                <button type="submit" style={ui.btnPrimary} disabled={!canWrite}>
                  {editing ? 'Save changes' : 'Create Feed'}
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      {urlTemplateFeed ? (
        <FeedUrlTemplateModal ui={ui} feed={urlTemplateFeed} onClose={() => setUrlTemplateFeed(null)} />
      ) : null}
    </AppShell>
  );
}

function FeedUrlTemplateModal({ ui, feed, onClose }) {
  const template = publishedFeedUrlTemplate(feed.slug);
  const curl = publishedFeedCurlExample(feed.slug);
  const copy = (text) => navigator.clipboard?.writeText(text).then(() => alert('Copied')).catch(() => alert(text));
  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1001, padding: 16 }}
      onClick={onClose}
    >
      <div style={{ ...ui.modal, maxWidth: 640, width: '100%' }} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Feed URL Template — {feed.name}</h3>
        <p style={ui.modalSub}>Replace <code style={{ color: '#cbd5e1' }}>&#123;API_KEY&#125;</code> with a Published Feed type API key.</p>

        <span style={ui.label}>Feed URL Template</span>
        <code style={ui.code}>{template}</code>
        <button type="button" style={{ ...ui.btnPrimary, marginTop: 10 }} onClick={() => copy(template)}>Copy URL Template</button>

        <div style={{ marginTop: 18 }}>
          <span style={ui.label}>Example (curl)</span>
          <code style={ui.code}>{curl}</code>
          <button type="button" style={{ ...ui.btn, marginTop: 10 }} onClick={() => copy(curl)}>Copy curl</button>
        </div>

        <p style={{ ...ui.helper, marginTop: 16 }}>
          Create or reveal a Published Feed key under{' '}
          <Link to="/administration/api-keys" style={{ color: '#93c5fd', fontWeight: 600 }}>Administration › API Keys</Link>.
        </p>
        <button type="button" style={{ ...ui.btn, marginTop: 8, width: '100%' }} onClick={onClose}>Done</button>
      </div>
    </div>
  );
}

function AuditLogsPage() {
  const { isAdmin } = useSession();
  const ui = PUBLISHED_FEEDS_UI;
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [entityTypeFilter, setEntityTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [detailItem, setDetailItem] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const load = useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    setError('');
    try {
      const params = { page, pageSize };
      if (search) params.search = search;
      if (actionFilter) params.action = actionFilter;
      if (entityTypeFilter) params.entity_type = entityTypeFilter;
      if (severityFilter) params.severity = severityFilter;
      if (statusFilter) params.status = statusFilter;
      if (dateFrom) params.date_from = systemLocalInputToUtcIso(dateFrom);
      if (dateTo) params.date_to = systemLocalInputToUtcIso(dateTo);
      const { data } = await api.get('/audit-logs', { params });
      setItems(Array.isArray(data?.items) ? data.items : []);
      setTotal(Number(data?.total || 0));
    } catch (err) {
      setItems([]);
      setTotal(0);
      setError(apiErrorMessage(err, 'Failed to load audit logs'));
    } finally {
      setLoading(false);
    }
  }, [isAdmin, page, pageSize, search, actionFilter, entityTypeFilter, severityFilter, statusFilter, dateFrom, dateTo]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  async function openDetail(row) {
    if (!row?.id) return;
    setDetailLoading(true);
    setDetailItem(row);
    try {
      const { data } = await api.get(`/audit-logs/${row.id}`);
      if (data?.item) setDetailItem(data.item);
    } catch {
      /* keep list row data */
    } finally {
      setDetailLoading(false);
    }
  }

  function applyFilters() {
    setPage(1);
    setSearch(searchInput.trim());
  }

  async function exportCsv() {
    try {
      const params = {};
      if (search) params.search = search;
      if (actionFilter) params.action = actionFilter;
      if (entityTypeFilter) params.entity_type = entityTypeFilter;
      if (severityFilter) params.severity = severityFilter;
      if (statusFilter) params.status = statusFilter;
      if (dateFrom) params.date_from = systemLocalInputToUtcIso(dateFrom);
      if (dateTo) params.date_to = systemLocalInputToUtcIso(dateTo);
      const res = await api.get('/audit-logs/export.csv', { params, responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'text/csv' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = 'audit-logs.csv';
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(apiErrorMessage(err, 'Export failed'));
    }
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <section style={ui.section}>
          <h1 style={ui.pageTitle}>Audit Logs</h1>
          <p style={ui.pageSub}>Admin access required.</p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <h1 style={ui.pageTitle}>Audit Logs</h1>
            <p style={ui.pageSub}>Security and operational change history.</p>
          </div>
          <button type="button" style={ui.btn} onClick={exportCsv}>Export CSV</button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10, marginTop: 16 }}>
          <input style={ui.input} placeholder="Search…" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && applyFilters()} />
          <input style={ui.input} placeholder="Action (e.g. ioc.created)" value={actionFilter} onChange={(e) => { setActionFilter(e.target.value); setPage(1); }} />
          <input style={ui.input} placeholder="Entity type" value={entityTypeFilter} onChange={(e) => { setEntityTypeFilter(e.target.value); setPage(1); }} />
          <select style={ui.select} value={severityFilter} onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}>
            <option value="">All severities</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
          <select style={ui.select} value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}>
            <option value="">All statuses</option>
            <option value="success">Success</option>
            <option value="failed">Failed</option>
          </select>
          <input style={ui.input} type="datetime-local" value={dateFrom} onChange={(e) => { setDateFrom(e.target.value); setPage(1); }} title="From" />
          <input style={ui.input} type="datetime-local" value={dateTo} onChange={(e) => { setDateTo(e.target.value); setPage(1); }} title="To" />
          <select style={ui.select} value={pageSize} onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}>
            <option value={10}>10 / page</option>
            <option value={25}>25 / page</option>
            <option value={50}>50 / page</option>
            <option value={100}>100 / page</option>
          </select>
          <button type="button" style={ui.btnPrimary} onClick={applyFilters}>Apply</button>
        </div>

        {error ? <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{error}</div> : null}

        <div style={{ marginTop: 16, overflowX: 'auto' }}>
          <table className="ioc-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={ui.th}>Date</th>
                <th style={ui.th}>Actor</th>
                <th style={ui.th}>Action</th>
                <th style={ui.th}>Entity</th>
                <th style={ui.th}>Severity</th>
                <th style={ui.th}>Status</th>
                <th style={ui.th}>IP</th>
                <th style={ui.th}>Source</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} style={ui.td}>Loading…</td></tr>
              ) : !items.length ? (
                <tr><td colSpan={8} style={ui.td}>No audit logs found.</td></tr>
              ) : items.map((row) => (
                <tr key={row.id} style={{ cursor: 'pointer' }} onClick={() => openDetail(row)}>
                  <td style={ui.td}>{formatAuditDate(row.created_at)}</td>
                  <td style={ui.td}>{row.actor_username || row.actor_email || '—'}</td>
                  <td style={ui.td}>
                    <div style={{ fontWeight: 600 }}>{row.action_label || row.action}</div>
                    <div style={{ fontSize: 11, color: '#64748b' }}>{row.action}</div>
                  </td>
                  <td style={ui.td}>
                    <AuditEntityCell row={row} />
                  </td>
                  <td style={ui.td}><span style={auditSeverityBadgeStyle(row.severity)}>{row.severity}</span></td>
                  <td style={ui.td}><span style={auditStatusBadgeStyle(row.status)}>{row.status}</span></td>
                  <td style={ui.td}>{row.ip_address || '—'}</td>
                  <td style={ui.td}>{row.source || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14, gap: 10, flexWrap: 'wrap' }}>
          <span style={{ color: '#94a3b8', fontSize: 13 }}>{total} total · page {page} / {totalPages}</span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" style={ui.btn} disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</button>
            <button type="button" style={ui.btn} disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      </section>

      {detailItem ? (
        <ModalOverlay onClose={() => setDetailItem(null)}>
          <h3 style={{ margin: '0 0 12px', color: '#f8fafc' }}>Audit Log #{detailItem.id}</h3>
          {detailLoading ? <p style={ui.helper}>Loading details…</p> : null}
          <div style={{ display: 'grid', gap: 10, maxHeight: '70vh', overflowY: 'auto' }}>
            <div><strong>Date:</strong> {formatAuditDate(detailItem.created_at)}</div>
            <div><strong>Actor:</strong> {detailItem.actor_username || detailItem.actor_email || '—'} ({detailItem.actor_role || '—'})</div>
            <div><strong>Action:</strong> {detailItem.action_label || detailItem.action} <span style={{ color: '#64748b' }}>({detailItem.action})</span></div>
            <div><strong>Entity:</strong> {detailItem.entity_type} · <span title={formatAuditEntityPrimary(detailItem)}>{truncateAuditText(formatAuditEntityPrimary(detailItem), 120)}</span></div>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>{formatAuditEntitySubtitle(detailItem)}</div>
            <AuditExpirationSummary item={detailItem} />
            <AuditTaxonomySummary item={detailItem} />
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <span style={auditSeverityBadgeStyle(detailItem.severity)}>{detailItem.severity}</span>
              <span style={auditStatusBadgeStyle(detailItem.status)}>{detailItem.status}</span>
            </div>
            <div><strong>Request:</strong> IP {detailItem.ip_address || '—'} · {detailItem.user_agent || '—'} · req {detailItem.request_id || '—'} · source {detailItem.source || '—'}</div>
            <div>
              <strong>before_data</strong>
              <pre style={{ ...ui.code, marginTop: 6, whiteSpace: 'pre-wrap', maxHeight: 180, overflow: 'auto' }}>{auditJsonBlock(detailItem.before_data)}</pre>
            </div>
            <div>
              <strong>after_data</strong>
              <pre style={{ ...ui.code, marginTop: 6, whiteSpace: 'pre-wrap', maxHeight: 180, overflow: 'auto' }}>{auditJsonBlock(detailItem.after_data)}</pre>
            </div>
            <div>
              <strong>metadata</strong>
              <pre style={{ ...ui.code, marginTop: 6, whiteSpace: 'pre-wrap', maxHeight: 180, overflow: 'auto' }}>{auditJsonBlock(detailItem.metadata)}</pre>
            </div>
          </div>
          <div style={{ marginTop: 14, textAlign: 'right' }}>
            <button type="button" style={ui.btn} onClick={() => setDetailItem(null)}>Close</button>
          </div>
        </ModalOverlay>
      ) : null}
    </AppShell>
  );
}

function apiKeyStatusStyle(status) {
  const map = {
    active: { bg: 'rgba(34,197,94,0.15)', c: '#86efac', b: '#166534' },
    expired: { bg: 'rgba(234,179,8,0.15)', c: '#fcd34d', b: '#854d0e' },
    disabled: { bg: 'rgba(148,163,184,0.15)', c: '#94a3b8', b: '#475569' }
  };
  const s = map[status] || map.disabled;
  return {
    display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 10,
    fontWeight: 700, textTransform: 'uppercase', background: s.bg, color: s.c,
    border: `1px solid ${s.b}`
  };
}

const DELETE_KEY_WARNING = 'This API key will permanently stop working and cannot be restored.';

function ApiKeysPage() {
  const { isAdmin } = useSession();
  const ui = PUBLISHED_FEEDS_UI;
  const [loading, setLoading] = useState(true);
  const [keys, setKeys] = useState([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [form, setForm] = useState({ name: '', enabled: true });
  // Revealed plaintext values live only in component memory — never persisted.
  const [revealed, setRevealed] = useState({});
  const [revealing, setRevealing] = useState({});
  const [createdKey, setCreatedKey] = useState(null);
  // Delete requires explicit confirmation in a modal before any request is sent.
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [toast, setToast] = useState('');

  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(() => setToast(''), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  async function loadAll() {
    setLoading(true);
    try {
      const { data } = await api.get('/api-keys');
      setKeys(data?.api_keys || []);
    } catch {
      setKeys([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAll().catch(() => {}); }, []);

  function openCreateModal() {
    setForm({ name: '', enabled: true });
    setShowCreateModal(true);
  }

  function copyText(text) {
    navigator.clipboard?.writeText(text).then(() => alert('Copied')).catch(() => alert(text));
  }

  function hideKey(keyId) {
    setRevealed((p) => {
      const next = { ...p };
      delete next[keyId];
      return next;
    });
  }

  async function fetchReveal(keyId) {
    const { data } = await api.get(`/api-keys/${keyId}/reveal`);
    return data?.token;
  }

  async function toggleReveal(key) {
    if (!isAdmin || !key.revealable) return;
    if (revealed[key.id]) { hideKey(key.id); return; }
    setRevealing((p) => ({ ...p, [key.id]: true }));
    try {
      const token = await fetchReveal(key.id);
      if (token) setRevealed((p) => ({ ...p, [key.id]: token }));
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to reveal API key');
    } finally {
      setRevealing((p) => ({ ...p, [key.id]: false }));
    }
  }

  async function copyKey(key) {
    if (!isAdmin || !key.revealable) return;
    try {
      // Always fetch through the reveal endpoint so every copy is audited.
      const token = await fetchReveal(key.id);
      if (token) copyText(token);
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to copy API key');
    }
  }

  async function createKey(e) {
    e.preventDefault();
    if (!isAdmin) return;
    if (!form.name.trim()) { alert('Enter a key name.'); return; }
    try {
      const { data } = await api.post('/api-keys', {
        name: form.name.trim(),
        key_type: 'published_feed',
        enabled: Boolean(form.enabled)
      });
      setShowCreateModal(false);
      setCreatedKey({ title: 'Published Feed API key created', token: data.token });
      await loadAll();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to create API key');
    }
  }

  async function toggleEnabled(key) {
    if (!isAdmin || key.status === 'expired') return;
    try {
      await api.patch(`/api-keys/${key.id}`, { enabled: !key.enabled });
      setToast(key.enabled ? 'API key disabled' : 'API key enabled');
      await loadAll();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to update API key');
    }
  }

  async function confirmDelete() {
    if (!isAdmin || !deleteTarget) return;
    setDeleting(true);
    try {
      await api.delete(`/api-keys/${deleteTarget.id}`);
      hideKey(deleteTarget.id);
      setDeleteTarget(null);
      setToast('API key deleted');
      await loadAll();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to delete API key');
    } finally {
      setDeleting(false);
    }
  }

  return (
    <AppShell>
      <section className="published-feeds-page api-keys-page" style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, marginBottom: 8, flexWrap: 'wrap' }}>
          <div>
            <h2 style={ui.pageTitle}>API Keys</h2>
            <p style={ui.pageSub}>
              Published Feed keys let internal tools pull any published threat feed via
              <code style={{ margin: '0 4px', color: '#cbd5e1' }}>/api/published-feeds/&#123;slug&#125;?api_key=…</code>.
              They are read-only and grant no access to admin APIs, feed management, or other endpoints.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button type="button" style={ui.btn} onClick={() => loadAll().catch(() => {})}>Refresh</button>
            {isAdmin ? (
              <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Create API Key</button>
            ) : null}
          </div>
        </div>

        {toast ? <div style={{ marginBottom: 10, color: '#86efac' }}>{toast}</div> : null}

        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table published-feeds-table" width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 13, background: 'transparent' }}>
            <thead>
              <tr style={ui.thead}>
                <th style={ui.th}>Name</th>
                <th style={ui.th}>Type</th>
                <th style={ui.th}>Key</th>
                <th style={ui.th}>Status</th>
                <th style={ui.th}>Last Used</th>
                <th style={ui.th}>Created At</th>
                <th style={ui.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr style={ui.tr}><td colSpan={7} style={ui.td}>Loading...</td></tr>
              ) : keys.length ? keys.map((k) => (
                <tr key={k.id} style={ui.tr}>
                  <td style={ui.td}>{k.name}</td>
                  <td style={ui.td}>
                    <span style={{ ...apiKeyStatusStyle('active'), background: 'rgba(59,130,246,0.15)', color: '#93c5fd', border: '1px solid #1e40af' }}>
                      {k.key_type_label || 'Published Feed'}
                    </span>
                  </td>
                  <td style={ui.td}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <code style={{ fontSize: 12, color: '#cbd5e1', wordBreak: 'break-all' }}>
                        {revealed[k.id] || k.masked_key}
                      </code>
                      {isAdmin && k.revealable ? (
                        <>
                          <button type="button" style={{ ...ui.btn, padding: '4px 10px', fontSize: 12 }} disabled={revealing[k.id]} onClick={() => toggleReveal(k)}>
                            {revealing[k.id] ? '…' : (revealed[k.id] ? 'Hide' : 'Show')}
                          </button>
                          <button type="button" style={{ ...ui.btn, padding: '4px 10px', fontSize: 12 }} onClick={() => copyKey(k)}>Copy</button>
                        </>
                      ) : (
                        <span style={{ fontSize: 11, color: '#64748b' }} title={k.key_type === 'published_feed' ? 'Encryption key unavailable' : 'This legacy key cannot be revealed.'}>
                          {k.key_type === 'published_feed' ? 'Not revealable' : 'Legacy — not revealable'}
                        </span>
                      )}
                    </div>
                  </td>
                  <td style={ui.td}><span style={apiKeyStatusStyle(k.status)}>{k.status}</span></td>
                  <td style={ui.td}>{formatUserDateTime(k.last_used_at)}</td>
                  <td style={ui.td}>{formatUserDateTime(k.created_at)}</td>
                  <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>
                    {isAdmin ? (
                      <>
                        {k.status !== 'expired' ? (
                          <button type="button" style={ui.btn} onClick={() => toggleEnabled(k)}>
                            {k.enabled ? 'Disable' : 'Enable'}
                          </button>
                        ) : null}
                        <button
                          type="button"
                          style={{ ...ui.btn, marginLeft: k.status !== 'expired' ? 6 : 0, borderColor: '#7f1d1d', color: '#fca5a5' }}
                          onClick={() => setDeleteTarget(k)}
                        >
                          Delete
                        </button>
                      </>
                    ) : <span style={ui.muted}>—</span>}
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={7} style={{ ...ui.td, padding: '28px 12px', textAlign: 'center' }}>
                    <p style={{ margin: '0 0 12px', color: '#94a3b8', lineHeight: 1.5 }}>
                      No API keys yet. Create a Published Feed key to let internal tools pull any published feed.
                    </p>
                    {isAdmin ? (
                      <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Create API Key</button>
                    ) : null}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {showCreateModal ? (
        <div
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}
          onClick={() => setShowCreateModal(false)}
        >
          <div style={ui.formModal} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
            <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>Create API Key</h3>
            <p style={ui.modalSub}>
              A Published Feed key can pull any published feed. Authorization is by key type — no per-feed binding.
            </p>
            <form onSubmit={createKey}>
              <FeedFormField ui={ui} label="Key name" fullWidth>
                <input required value={form.name} onChange={(e) => setForm((x) => ({ ...x, name: e.target.value }))} style={ui.input} placeholder="e.g. Fortigate-01" />
              </FeedFormField>
              <FeedFormField ui={ui} label="Key type" fullWidth>
                <select value="published_feed" style={ui.select} disabled>
                  <option value="published_feed">Published Feed</option>
                </select>
              </FeedFormField>
              <FeedFormField ui={ui} label="Enabled" fullWidth>
                <label style={ui.checkLabel}>
                  <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((x) => ({ ...x, enabled: e.target.checked }))} />
                  Key is active
                </label>
              </FeedFormField>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
                <button type="button" style={ui.btn} onClick={() => setShowCreateModal(false)}>Cancel</button>
                <button type="submit" style={ui.btnPrimary} disabled={!isAdmin}>Create API Key</button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      {createdKey ? (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1001, padding: 16 }}>
          <div style={{ ...ui.modal, maxWidth: 560, width: '100%' }}>
            <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>{createdKey.title}</h3>
            <p style={ui.modalSub}>
              This is your Published Feed API key. You can also reveal it again later from the list.
            </p>
            <code style={ui.code}>{createdKey.token}</code>
            <button type="button" style={{ ...ui.btnPrimary, marginTop: 10 }} onClick={() => copyText(createdKey.token)}>Copy key</button>
            <p style={{ ...ui.helper, marginTop: 12 }}>
              Use it in a feed pull URL: <code style={{ color: '#cbd5e1' }}>/api/published-feeds/&#123;slug&#125;?api_key=YOUR_KEY</code>.
              Find the exact URL template on the Published Feeds page.
            </p>
            <button type="button" style={{ ...ui.btn, marginTop: 16, width: '100%' }} onClick={() => setCreatedKey(null)}>Done</button>
          </div>
        </div>
      ) : null}

      {deleteTarget ? (
        <div
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1002, padding: 16 }}
          onClick={() => { if (!deleting) setDeleteTarget(null); }}
        >
          <div style={{ ...ui.modal, maxWidth: 480, width: '100%' }} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
            <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Delete API key</h3>
            <p style={{ ...ui.modalSub, color: '#cbd5e1' }}>
              Delete <strong style={{ color: '#f1f5f9' }}>{deleteTarget.name}</strong>?
            </p>
            <p style={{ color: '#fca5a5', fontWeight: 600, margin: '12px 0 0' }}>
              {DELETE_KEY_WARNING}
            </p>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 20 }}>
              <button type="button" style={ui.btn} disabled={deleting} onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button
                type="button"
                style={{ ...ui.btnPrimary, background: '#b91c1c', borderColor: '#7f1d1d' }}
                disabled={deleting}
                onClick={() => confirmDelete().catch(() => {})}
              >
                {deleting ? 'Deleting…' : 'Delete key'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </AppShell>
  );
}

const TAG_CATEGORY_OPTIONS = ['behavior', 'campaign', 'theme', 'targeting', 'source-context', 'review-state', 'vulnerability', 'custom'];

const IOC_EXPIRE_POLICY_OPTIONS = [
  { value: 'never', label: 'Never expire' },
  { value: 'expire_after_days', label: 'Expire after days' },
  { value: 'custom_date', label: 'Custom date' }
];

const DEFAULT_THREAT_CLASSIFICATION_OPTIONS = [{ value: 'unknown', label: 'Unknown' }];

function useThreatClassifications() {
  const [options, setOptions] = useState(DEFAULT_THREAT_CLASSIFICATION_OPTIONS);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const { data } = await api.get('/threat-classifications');
        const list = Array.isArray(data) ? data : (Array.isArray(data?.classifications) ? data.classifications : []);
        if (active && list.length) setOptions(list);
      } catch {
        /* keep default */
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; };
  }, []);

  const labelFor = useCallback((value) => {
    const slug = String(value || 'unknown').trim() || 'unknown';
    return options.find((o) => o.value === slug)?.label || formatThreatClassificationLabel(slug);
  }, [options]);

  return { options, loading, labelFor };
}

function normalizeSelectedThreatClasses(selected) {
  const slugs = (Array.isArray(selected) ? selected : [])
    .map((s) => String(s || '').trim())
    .filter((s) => s && s !== 'unknown');
  return [...new Set(slugs)];
}

function threatClassesFromSummary(summary) {
  if (Array.isArray(summary?.threat_classifications)) {
    return summary.threat_classifications
      .map((x) => x?.value)
      .filter((v) => v && v !== 'unknown');
  }
  const legacy = summary?.threat_classification || summary?.primary_threat_classification;
  if (legacy && legacy !== 'unknown') return [legacy];
  return [];
}

function formatThreatClassificationsText(classifications, { emptyLabel = 'Unknown' } = {}) {
  const list = Array.isArray(classifications) ? classifications : [];
  const visible = list.filter((x) => x?.value && x.value !== 'unknown');
  if (!visible.length) return emptyLabel;
  return visible.map((x) => x.label || formatThreatClassificationLabel(x.value)).join(', ');
}

function ThreatClassificationBadges({ classifications, max = 5, emptyLabel = 'Unknown' }) {
  const list = Array.isArray(classifications) ? classifications : [];
  const visible = list.filter((x) => x?.value && x.value !== 'unknown');
  const items = visible.length ? visible : [{ label: emptyLabel, value: 'unknown' }];
  const shown = items.slice(0, max);
  return (
    <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
      {shown.map((c) => (
        <span
          key={c.value}
          style={{
            fontSize: 12,
            padding: '2px 8px',
            borderRadius: 999,
            background: '#1e293b',
            border: '1px solid #334155',
            color: '#e2e8f0'
          }}
        >
          {c.label || formatThreatClassificationLabel(c.value)}
          {c.active === false ? ' (Inactive)' : ''}
        </span>
      ))}
      {items.length > max ? <span style={{ color: '#94a3b8', fontSize: 12 }}>+{items.length - max}</span> : null}
    </span>
  );
}

function ThreatClassificationMultiSelect({
  value,
  onChange,
  options,
  inactiveOptions = [],
  disabled = false
}) {
  const selected = normalizeSelectedThreatClasses(value);
  const allOptions = [...options];
  for (const inactive of inactiveOptions) {
    if (inactive?.value && !allOptions.some((o) => o.value === inactive.value)) {
      allOptions.unshift(inactive);
    }
  }

  function toggle(slug) {
    if (disabled) return;
    if (slug === 'unknown') {
      onChange([]);
      return;
    }
    const set = new Set(selected);
    if (set.has(slug)) set.delete(slug);
    else set.add(slug);
    onChange([...set]);
  }

  return (
    <div style={{ display: 'grid', gap: 8 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, minHeight: 28 }}>
        {selected.length ? selected.map((slug) => {
          const label = allOptions.find((o) => o.value === slug)?.label || formatThreatClassificationLabel(slug);
          return (
            <span
              key={slug}
              style={{
                fontSize: 12,
                padding: '2px 8px',
                borderRadius: 999,
                background: '#172554',
                border: '1px solid #334155',
                color: '#bfdbfe'
              }}
            >
              {label}
              {!disabled ? (
                <button
                  type="button"
                  onClick={() => toggle(slug)}
                  style={{ marginLeft: 6, border: 'none', background: 'transparent', color: '#94a3b8', cursor: 'pointer' }}
                  aria-label={`Remove ${label}`}
                >
                  ×
                </button>
              ) : null}
            </span>
          );
        }) : <span style={{ color: '#94a3b8', fontSize: 13 }}>Unknown (no classifications selected)</span>}
      </div>
      <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, maxHeight: 180, overflowY: 'auto', background: '#0f172a' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, fontSize: 13 }}>
          <input type="checkbox" checked={!selected.length} onChange={() => onChange([])} disabled={disabled} />
          Unknown
        </label>
        {allOptions.filter((o) => o.value !== 'unknown').map((opt) => (
          <label key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, fontSize: 13 }}>
            <input
              type="checkbox"
              checked={selected.includes(opt.value)}
              onChange={() => toggle(opt.value)}
              disabled={disabled}
            />
            {opt.label}
            {inactiveOptions.some((x) => x.value === opt.value) ? ' (Inactive)' : ''}
          </label>
        ))}
      </div>
    </div>
  );
}

const IOC_SOURCE_MODAL_STYLE = {
  width: 'min(680px, 96vw)',
  maxHeight: '90vh',
  overflowY: 'auto',
  background: 'linear-gradient(180deg, #111827 0%, #0f172a 100%)',
  borderRadius: 12,
  padding: 24,
  border: '1px solid #334155',
  color: '#e2e8f0',
  boxShadow: '0 24px 60px rgba(2,6,23,0.55)'
};

const EMPTY_IOC_SOURCE_FORM = {
  name: '',
  description: '',
  default_confidence: '',
  default_threat_classification: '',
  default_expire_policy: 'never',
  default_expire_days: '',
  color: '',
  active: true
};

const EMPTY_TAG_FORM = {
  name: '',
  category: 'custom',
  description: '',
  color: '',
  is_active: true
};

function TagManagerPage() {
  const { isAdmin } = useSession();
  const [searchParams, setSearchParams] = useSearchParams();
  const ui = PUBLISHED_FEEDS_UI;
  const initial = useMemo(() => parseTagManagerUrlState(searchParams), []);
  const [tags, setTags] = useState([]);
  const [pagination, setPagination] = useState({
    page: initial.page,
    page_size: TAG_MANAGER_PAGE_SIZE,
    total_items: 0,
    total_pages: 1,
    has_previous: false,
    has_next: false
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showInactive, setShowInactive] = useState(initial.showInactive);
  const [page, setPage] = useState(initial.page);
  const [searchInput, setSearchInput] = useState(initial.search);
  const [search, setSearch] = useState(initial.search.trim());
  const [showFormModal, setShowFormModal] = useState(false);
  const [editingTag, setEditingTag] = useState(null);
  const [form, setForm] = useState(EMPTY_TAG_FORM);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');
  const requestSeqRef = useRef(0);
  const abortRef = useRef(null);

  const load = useCallback(async () => {
    if (!isAdmin) return;
    const seq = ++requestSeqRef.current;
    if (abortRef.current) abortRef.current.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setLoading(true);
    setError('');
    try {
      const params = buildTagManagerQueryParams({ page, search, showInactive });
      const { data } = await api.get('/admin/tags', { params, signal: controller.signal });
      if (seq !== requestSeqRef.current) return;
      const items = Array.isArray(data?.items) ? data.items : [];
      const pag = data?.pagination || {
        page,
        page_size: TAG_MANAGER_PAGE_SIZE,
        total_items: items.length,
        total_pages: 1,
        has_previous: false,
        has_next: false
      };
      setTags(items);
      setPagination(pag);
      const clamped = clampTagManagerPage(page, pag.total_items, TAG_MANAGER_PAGE_SIZE);
      if (clamped !== page) setPage(clamped);
    } catch (err) {
      if (err?.code === 'ERR_CANCELED' || err?.name === 'CanceledError' || err?.name === 'AbortError') return;
      if (seq !== requestSeqRef.current) return;
      setTags([]);
      setPagination({
        page: 1,
        page_size: TAG_MANAGER_PAGE_SIZE,
        total_items: 0,
        total_pages: 1,
        has_previous: false,
        has_next: false
      });
      setError(apiErrorMessage(err, 'Failed to load tags'));
    } finally {
      if (seq === requestSeqRef.current) setLoading(false);
    }
  }, [isAdmin, page, search, showInactive]);

  useEffect(() => {
    load().catch(() => {});
    return () => {
      if (abortRef.current) abortRef.current.abort();
    };
  }, [load]);

  useEffect(() => {
    const t = setTimeout(() => {
      const next = searchInput.trim();
      setSearch((prev) => {
        if (prev === next) return prev;
        setPage(1);
        return next;
      });
    }, TAG_MANAGER_SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [searchInput]);

  useEffect(() => {
    setSearchParams(buildTagManagerUrlSearchParams({ page, search, showInactive }), { replace: true });
  }, [page, search, showInactive, setSearchParams]);

  function openCreateModal() {
    setEditingTag(null);
    setForm(EMPTY_TAG_FORM);
    setFormError('');
    setShowFormModal(true);
  }

  function openEditModal(tag) {
    setEditingTag(tag);
    setForm({
      name: tag?.name || '',
      category: tag?.category || 'custom',
      description: tag?.description || '',
      color: tag?.color || '',
      is_active: tag?.is_active !== false
    });
    setFormError('');
    setShowFormModal(true);
  }

  async function submitForm(e) {
    e.preventDefault();
    if (!isAdmin) return;
    setSaving(true);
    setFormError('');
    try {
      if (editingTag?.id) {
        const payload = {
          category: form.category,
          description: form.description,
          color: form.color,
          is_active: form.is_active
        };
        await api.put(`/admin/tags/${editingTag.id}`, payload);
      } else {
        const payload = {
          name: form.name,
          category: form.category,
          description: form.description,
          color: form.color,
          is_active: form.is_active
        };
        const { data, status } = await api.post('/admin/tags', payload);
        if (status === 200 && data?.existing) {
          setFormError(`Tag "${data?.tag?.name || form.name}" already exists and will be reused.`);
          await load();
          setShowFormModal(false);
          setEditingTag(null);
          setForm(EMPTY_TAG_FORM);
          setSaving(false);
          return;
        }
      }
      setShowFormModal(false);
      setEditingTag(null);
      setForm(EMPTY_TAG_FORM);
      await load();
    } catch (err) {
      const code = err?.response?.data?.code;
      if (code === 'TAG_INACTIVE') {
        setFormError(err?.response?.data?.message || 'A disabled tag with this name already exists. Enable it instead.');
      } else {
        setFormError(apiErrorMessage(err, editingTag ? 'Update failed' : 'Create failed'));
      }
    } finally {
      setSaving(false);
    }
  }

  async function disableTag(tag) {
    if (!tag?.id || !isAdmin) return;
    const ok = window.confirm(
      `Disable tag "${tag.name}"? It will be hidden on IOC details and removed from pickers. Existing assignments are kept and will reappear if you enable the tag again.`
    );
    if (!ok) return;
    setError('');
    try {
      await api.delete(`/admin/tags/${tag.id}`);
      await load();
    } catch (err) {
      setError(apiErrorMessage(err, 'Disable failed'));
    }
  }

  async function enableTag(tag) {
    if (!tag?.id || !isAdmin) return;
    setError('');
    try {
      await api.put(`/admin/tags/${tag.id}`, { is_active: true });
      await load();
    } catch (err) {
      setError(apiErrorMessage(err, 'Enable failed'));
    }
  }

  const showingLabel = formatTagManagerShowingLabel({
    page: pagination.page,
    pageSize: pagination.page_size || TAG_MANAGER_PAGE_SIZE,
    totalItems: pagination.total_items
  });

  if (!isAdmin) {
    return (
      <AppShell>
        <section style={ui.section}>
          <h1 style={ui.pageTitle}>Tag Manager</h1>
          <p style={ui.pageSub}>Admin access required.</p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <h1 style={ui.pageTitle}>Tag Manager</h1>
            <p style={ui.pageSub}>Manage operational/context IOC tags. Threat classifications and threat actors are managed separately.</p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <label style={ui.checkLabel}>
              <input
                type="checkbox"
                checked={showInactive}
                onChange={(e) => {
                  setShowInactive(e.target.checked);
                  setPage(1);
                }}
              />
              Show inactive
            </label>
            <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Add Tag</button>
          </div>
        </div>

        <div style={{ marginTop: 14, maxWidth: 420 }}>
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            style={ui.input}
            placeholder="Search tags..."
            aria-label="Search tags"
          />
        </div>

        {error ? <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{error}</div> : null}

        <div style={{ marginTop: 16, overflowX: 'auto' }}>
          <table className="ioc-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={ui.th}>Name</th>
                <th style={ui.th}>Source</th>
                <th style={ui.th}>Category</th>
                <th style={ui.th}>Description</th>
                <th style={ui.th}>Active</th>
                <th style={ui.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && !tags.length ? (
                <tr><td colSpan={6} style={ui.td}>Loading…</td></tr>
              ) : !tags.length ? (
                <tr><td colSpan={6} style={ui.td}>No tags found.</td></tr>
              ) : tags.map((tag) => {
                const sourceCell = formatTagSourcesCell(tag.sources || []);
                return (
                <tr key={tag.id} style={loading ? { opacity: 0.72 } : undefined}>
                  <td style={ui.td}>
                    <div style={{ fontWeight: 600 }}>{tag.name}</div>
                    <div style={{ fontSize: 11, color: '#64748b' }}>{tag.slug || tag.name}</div>
                  </td>
                  <td style={{ ...ui.td, maxWidth: 220, whiteSpace: 'normal' }} title={sourceCell.title}>
                    {sourceCell.text}
                  </td>
                  <td style={ui.td}>{tag.category || '—'}</td>
                  <td style={{ ...ui.td, maxWidth: 280, whiteSpace: 'normal' }}>
                    {tag.description || '—'}
                    {(String(tag.description || '').includes('legacy-migrated') || tag.is_active === false) ? (
                      <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4, fontStyle: 'italic' }}>
                        Legacy migrated tag — use Threat Classification or Threat Actor fields instead.
                      </div>
                    ) : null}
                  </td>
                  <td style={ui.td}>{tag.is_active ? 'Yes' : 'No'}</td>
                  <td style={ui.td}>
                    <button type="button" style={ui.btn} onClick={() => openEditModal(tag)}>Edit</button>
                    {tag.is_active ? (
                      <button type="button" style={{ ...ui.btn, marginLeft: 6, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => disableTag(tag).catch(() => {})}>Disable</button>
                    ) : (
                      <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => enableTag(tag).catch(() => {})}>Enable</button>
                    )}
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {pagination.total_items > 0 ? (
          <div style={{
            marginTop: 14,
            display: 'flex',
            flexWrap: 'wrap',
            gap: 10,
            alignItems: 'center',
            justifyContent: 'space-between',
            color: '#94a3b8',
            fontSize: 13
          }}
          >
            <div>{showingLabel}{loading ? ' · Updating…' : ''}</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <button
                type="button"
                style={ui.btn}
                disabled={!pagination.has_previous || loading}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </button>
              <span style={{ color: '#e2e8f0', fontWeight: 600 }}>
                Page {pagination.page} of {pagination.total_pages}
              </span>
              <button
                type="button"
                style={ui.btn}
                disabled={!pagination.has_next || loading}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </button>
            </div>
          </div>
        ) : null}
      </section>

      {showFormModal ? (
        <ModalOverlay onClose={() => setShowFormModal(false)}>
          <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>{editingTag ? 'Edit Tag' : 'Add Tag'}</h3>
          <form onSubmit={submitForm}>
            <FeedFormField ui={ui} label="Name" fullWidth>
              <input
                required={!editingTag}
                value={form.name}
                onChange={(e) => setForm((x) => ({ ...x, name: e.target.value }))}
                style={{ ...ui.input, ...(editingTag ? { opacity: 0.75, cursor: 'not-allowed' } : null) }}
                placeholder="e.g. ransomware"
                readOnly={Boolean(editingTag)}
                disabled={Boolean(editingTag)}
              />
              {editingTag ? (
                <span style={{ ...ui.helper, display: 'block', marginTop: 6 }}>
                  Tag name cannot be renamed here. Disable and create a new tag if needed.
                </span>
              ) : null}
            </FeedFormField>
            <FeedFormField ui={ui} label="Category" fullWidth>
              <select value={form.category} onChange={(e) => setForm((x) => ({ ...x, category: e.target.value }))} style={ui.select}>
                {TAG_CATEGORY_OPTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </FeedFormField>
            <FeedFormField ui={ui} label="Description" fullWidth>
              <textarea value={form.description} onChange={(e) => setForm((x) => ({ ...x, description: e.target.value }))} style={ui.textarea} placeholder="Optional description" />
              <span style={{ ...ui.helper, display: 'block', marginTop: 6 }}>
                Do not use tags for threat classifications or threat actors — those are managed under Administration → Threat Actors and the IOC threat classification field.
              </span>
            </FeedFormField>
            <FeedFormField ui={ui} label="Color" helper="Optional hex or CSS color for UI chips." fullWidth>
              <input value={form.color} onChange={(e) => setForm((x) => ({ ...x, color: e.target.value }))} style={ui.input} placeholder="#ef4444" />
            </FeedFormField>
            <FeedFormField ui={ui} label="Active" fullWidth>
              <label style={ui.checkLabel}>
                <input type="checkbox" checked={form.is_active} onChange={(e) => setForm((x) => ({ ...x, is_active: e.target.checked }))} />
                Tag is active
              </label>
            </FeedFormField>
            {formError ? <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{formError}</div> : null}
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
              <button type="button" style={ui.btn} onClick={() => setShowFormModal(false)}>Cancel</button>
              <button type="submit" style={ui.btnPrimary} disabled={saving}>{saving ? 'Saving…' : (editingTag ? 'Save Changes' : 'Create Tag')}</button>
            </div>
          </form>
        </ModalOverlay>
      ) : null}
    </AppShell>
  );
}

function slugifyThreatClassificationName(name) {
  return String(name || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_')
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

const EMPTY_THREAT_CLASSIFICATION_FORM = {
  name: '',
  slug: '',
  description: '',
  active: true,
  sort_order: 100
};

function ThreatClassificationManagerPage() {
  const { isAdmin } = useSession();
  const ui = PUBLISHED_FEEDS_UI;
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showInactive, setShowInactive] = useState(true);
  const [showFormModal, setShowFormModal] = useState(false);
  const [editingItem, setEditingItem] = useState(null);
  const [form, setForm] = useState(EMPTY_THREAT_CLASSIFICATION_FORM);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');
  const [slugTouched, setSlugTouched] = useState(false);

  const load = useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    setError('');
    try {
      const params = showInactive ? { include_inactive: true } : { include_inactive: false };
      const { data } = await api.get('/admin/threat-classifications', { params });
      setItems(Array.isArray(data?.threat_classifications) ? data.threat_classifications : []);
    } catch (err) {
      setItems([]);
      setError(apiErrorMessage(err, 'Failed to load threat classifications'));
    } finally {
      setLoading(false);
    }
  }, [isAdmin, showInactive]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  function openCreateModal() {
    setEditingItem(null);
    setForm(EMPTY_THREAT_CLASSIFICATION_FORM);
    setSlugTouched(false);
    setFormError('');
    setShowFormModal(true);
  }

  function openEditModal(item) {
    setEditingItem(item);
    setForm({
      name: item?.name || '',
      slug: item?.slug || '',
      description: item?.description || '',
      active: item?.active !== false,
      sort_order: item?.sort_order ?? 100
    });
    setSlugTouched(true);
    setFormError('');
    setShowFormModal(true);
  }

  async function submitForm(e) {
    e.preventDefault();
    if (!isAdmin) return;
    setSaving(true);
    setFormError('');
    try {
      const payload = {
        name: form.name.trim(),
        slug: form.slug.trim(),
        description: form.description,
        active: form.active,
        sort_order: Number(form.sort_order)
      };
      if (editingItem?.id) {
        await api.patch(`/admin/threat-classifications/${editingItem.id}`, payload);
      } else {
        await api.post('/admin/threat-classifications', payload);
      }
      setShowFormModal(false);
      setEditingItem(null);
      setForm(EMPTY_THREAT_CLASSIFICATION_FORM);
      await load();
    } catch (err) {
      setFormError(apiErrorMessage(err, editingItem ? 'Update failed' : 'Create failed'));
    } finally {
      setSaving(false);
    }
  }

  async function disableItem(item) {
    if (!item?.id || !isAdmin) return;
    if (item.slug === 'unknown') {
      setError('Unknown classification cannot be disabled.');
      return;
    }
    const ok = window.confirm(`Disable classification "${item.name}"? Existing IOC assignments will remain visible, but it will no longer appear in pickers.`);
    if (!ok) return;
    setError('');
    try {
      await api.patch(`/admin/threat-classifications/${item.id}/disable`);
      await load();
    } catch (err) {
      setError(apiErrorMessage(err, 'Disable failed'));
    }
  }

  async function enableItem(item) {
    if (!item?.id || !isAdmin) return;
    setError('');
    try {
      await api.patch(`/admin/threat-classifications/${item.id}/enable`);
      await load();
    } catch (err) {
      setError(apiErrorMessage(err, 'Enable failed'));
    }
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <section style={ui.section}>
          <h1 style={ui.pageTitle}>Threat Classifications</h1>
          <p style={ui.pageSub}>Admin access required.</p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <h1 style={ui.pageTitle}>Threat Classifications</h1>
            <p style={ui.pageSub}>Manage platform threat classifications used on IOCs. Use display order to control picker and list sorting. Unknown is always active and cannot be disabled.</p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <label style={ui.checkLabel}>
              <input type="checkbox" checked={showInactive} onChange={(e) => setShowInactive(e.target.checked)} />
              Show inactive
            </label>
            <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Add Classification</button>
          </div>
        </div>

        {error ? <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{error}</div> : null}

        <div style={{ marginTop: 16, overflowX: 'auto', maxWidth: '100%' }}>
          <table className="ioc-table threat-classifications-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th className="tc-col-classification" style={ui.th}>Classification</th>
                <th className="tc-col-description" style={ui.th}>Description</th>
                <th className="tc-col-status" style={ui.th}>Status</th>
                <th className="tc-col-builtin" style={ui.th} title="Platform-managed classification">Built-in</th>
                <th className="tc-col-order" style={ui.th} title="Display order in dropdowns and lists">Order</th>
                <th className="tc-col-actions" style={ui.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} style={ui.td}>Loading…</td></tr>
              ) : !items.length ? (
                <tr><td colSpan={6} style={ui.td}>No classifications found.</td></tr>
              ) : items.map((item) => (
                <tr key={item.id} style={{ opacity: item.active ? 1 : 0.62 }}>
                  <td className="tc-col-classification" style={ui.td}>
                    <div style={{ fontWeight: 600 }}>{item.name}</div>
                    <code style={{ fontSize: 11, color: '#64748b' }}>{item.slug}</code>
                  </td>
                  <td className="tc-col-description tc-description-cell" style={ui.td} title={item.description || undefined}>
                    {item.description || '—'}
                  </td>
                  <td className="tc-col-status" style={ui.td}>
                    <span style={{
                      display: 'inline-block',
                      padding: '2px 8px',
                      borderRadius: 999,
                      fontSize: 11,
                      fontWeight: 600,
                      background: item.active ? 'rgba(22, 101, 52, 0.35)' : 'rgba(71, 85, 105, 0.35)',
                      color: item.active ? '#86efac' : '#94a3b8',
                      border: `1px solid ${item.active ? '#166534' : '#475569'}`
                    }}
                    >
                      {item.active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="tc-col-builtin" style={ui.td}>{item.system_default ? 'Yes' : '—'}</td>
                  <td className="tc-col-order" style={ui.td}>{item.sort_order ?? '—'}</td>
                  <td className="tc-col-actions tc-actions-cell" style={ui.td}>
                    <div className="tc-action-buttons">
                      <button type="button" style={ui.btn} onClick={() => openEditModal(item)}>Edit</button>
                      {item.slug === 'unknown' ? null : item.active ? (
                        <button type="button" style={{ ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => disableItem(item).catch(() => {})}>Disable</button>
                      ) : (
                        <button type="button" style={ui.btn} onClick={() => enableItem(item).catch(() => {})}>Enable</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {showFormModal ? (
        <ModalOverlay onClose={() => setShowFormModal(false)}>
          <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>{editingItem ? 'Edit Threat Classification' : 'Add Threat Classification'}</h3>
          <form onSubmit={submitForm}>
            <FeedFormField ui={ui} label="Name" fullWidth>
              <input
                required
                value={form.name}
                onChange={(e) => {
                  const name = e.target.value;
                  setForm((x) => ({
                    ...x,
                    name,
                    slug: !slugTouched && !editingItem ? slugifyThreatClassificationName(name) : x.slug
                  }));
                }}
                style={ui.input}
                placeholder="e.g. Phishing"
              />
            </FeedFormField>
            <FeedFormField ui={ui} label="Slug" helper="Lowercase snake_case. Used in API/DB." fullWidth>
              <input
                required
                value={form.slug}
                disabled={editingItem?.slug === 'unknown'}
                onChange={(e) => {
                  setSlugTouched(true);
                  setForm((x) => ({ ...x, slug: slugifyThreatClassificationName(e.target.value) }));
                }}
                style={ui.input}
                placeholder="phishing"
              />
            </FeedFormField>
            <FeedFormField ui={ui} label="Description" fullWidth>
              <textarea value={form.description} onChange={(e) => setForm((x) => ({ ...x, description: e.target.value }))} style={ui.textarea} placeholder="Optional description" />
            </FeedFormField>
            <FeedFormField ui={ui} label="Display order" helper="Controls the order in classification dropdowns and lists. Lower numbers appear first." fullWidth>
              <input type="number" min={0} step={1} value={form.sort_order} onChange={(e) => setForm((x) => ({ ...x, sort_order: e.target.value }))} style={ui.input} />
            </FeedFormField>
            <FeedFormField ui={ui} label="Active" fullWidth>
              <label style={ui.checkLabel}>
                <input type="checkbox" checked={form.active} disabled={editingItem?.slug === 'unknown'} onChange={(e) => setForm((x) => ({ ...x, active: e.target.checked }))} />
                Classification is active
              </label>
            </FeedFormField>
            {formError ? <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{formError}</div> : null}
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
              <button type="button" style={ui.btn} onClick={() => setShowFormModal(false)}>Cancel</button>
              <button type="submit" style={ui.btnPrimary} disabled={saving}>{saving ? 'Saving…' : (editingItem ? 'Save Changes' : 'Create Classification')}</button>
            </div>
          </form>
        </ModalOverlay>
      ) : null}
    </AppShell>
  );
}

const EMPTY_THREAT_ACTOR_FORM = {
  name: '',
  aliases: '',
  description: '',
  active: true
};

function formatThreatActorAliases(aliases) {
  if (!aliases) return '—';
  if (Array.isArray(aliases)) return aliases.length ? aliases.join(', ') : '—';
  return String(aliases).trim() || '—';
}

function ThreatActorManagerPage() {
  const { isAdmin } = useSession();
  const ui = PUBLISHED_FEEDS_UI;
  const [actors, setActors] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showInactive, setShowInactive] = useState(true);
  const [showFormModal, setShowFormModal] = useState(false);
  const [editingActor, setEditingActor] = useState(null);
  const [form, setForm] = useState(EMPTY_THREAT_ACTOR_FORM);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  const load = useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    setError('');
    try {
      const params = showInactive ? { include_inactive: true } : { include_inactive: false };
      const { data } = await api.get('/admin/threat-actors', { params });
      setActors(Array.isArray(data?.threat_actors) ? data.threat_actors : []);
    } catch (err) {
      setActors([]);
      setError(apiErrorMessage(err, 'Failed to load threat actors'));
    } finally {
      setLoading(false);
    }
  }, [isAdmin, showInactive]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  function openCreateModal() {
    setEditingActor(null);
    setForm(EMPTY_THREAT_ACTOR_FORM);
    setFormError('');
    setShowFormModal(true);
  }

  function openEditModal(actor) {
    setEditingActor(actor);
    setForm({
      name: actor?.name || '',
      aliases: formatThreatActorAliases(actor?.aliases) === '—' ? '' : formatThreatActorAliases(actor?.aliases),
      description: actor?.description || '',
      active: actor?.active !== false
    });
    setFormError('');
    setShowFormModal(true);
  }

  async function submitForm(e) {
    e.preventDefault();
    if (!isAdmin) return;
    setSaving(true);
    setFormError('');
    try {
      const payload = {
        name: form.name.trim(),
        aliases: form.aliases,
        description: form.description,
        active: form.active
      };
      if (editingActor?.id) {
        await api.patch(`/admin/threat-actors/${editingActor.id}`, payload);
      } else {
        await api.post('/admin/threat-actors', payload);
      }
      setShowFormModal(false);
      setEditingActor(null);
      setForm(EMPTY_THREAT_ACTOR_FORM);
      await load();
    } catch (err) {
      setFormError(apiErrorMessage(err, editingActor ? 'Update failed' : 'Create failed'));
    } finally {
      setSaving(false);
    }
  }

  async function disableActor(actor) {
    if (!actor?.id || !isAdmin) return;
    const ok = window.confirm(`Disable threat actor "${actor.name}"? Existing IOC assignments will remain visible, but the actor will no longer appear in pickers.`);
    if (!ok) return;
    setError('');
    try {
      await api.patch(`/admin/threat-actors/${actor.id}/disable`);
      await load();
    } catch (err) {
      setError(apiErrorMessage(err, 'Disable failed'));
    }
  }

  async function enableActor(actor) {
    if (!actor?.id || !isAdmin) return;
    setError('');
    try {
      await api.patch(`/admin/threat-actors/${actor.id}/enable`);
      await load();
    } catch (err) {
      setError(apiErrorMessage(err, 'Enable failed'));
    }
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <section style={ui.section}>
          <h1 style={ui.pageTitle}>Threat Actors</h1>
          <p style={ui.pageSub}>Admin access required.</p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <h1 style={ui.pageTitle}>Threat Actors</h1>
            <p style={ui.pageSub}>Manage named threat actors linked to IOCs. Classifications are configured separately.</p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <label style={ui.checkLabel}>
              <input type="checkbox" checked={showInactive} onChange={(e) => setShowInactive(e.target.checked)} />
              Show inactive
            </label>
            <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Add Threat Actor</button>
          </div>
        </div>

        {error ? <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{error}</div> : null}

        <div style={{ marginTop: 16, overflowX: 'auto' }}>
          <table className="ioc-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={ui.th}>Name</th>
                <th style={ui.th}>Aliases</th>
                <th style={ui.th}>Description</th>
                <th style={ui.th}>Active</th>
                <th style={ui.th}>Created At</th>
                <th style={ui.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} style={ui.td}>Loading…</td></tr>
              ) : !actors.length ? (
                <tr><td colSpan={6} style={ui.td}>No threat actors found.</td></tr>
              ) : actors.map((actor) => (
                <tr key={actor.id} style={{ opacity: actor.active ? 1 : 0.62 }}>
                  <td style={ui.td}>
                    <div style={{ fontWeight: 600 }}>{actor.name}</div>
                    <div style={{ fontSize: 11, color: '#64748b' }}>{actor.slug || actor.name}</div>
                  </td>
                  <td style={{ ...ui.td, maxWidth: 220, whiteSpace: 'normal' }}>{formatThreatActorAliases(actor.aliases)}</td>
                  <td style={{ ...ui.td, maxWidth: 280, whiteSpace: 'normal' }}>{actor.description || '—'}</td>
                  <td style={ui.td}>{actor.active ? 'Yes' : 'No'}</td>
                  <td style={ui.td}>{formatUserDateTime(actor.created_at)}</td>
                  <td style={ui.td}>
                    <button type="button" style={ui.btn} onClick={() => openEditModal(actor)}>Edit</button>
                    {actor.active ? (
                      <button type="button" style={{ ...ui.btn, marginLeft: 6, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => disableActor(actor).catch(() => {})}>Disable</button>
                    ) : (
                      <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => enableActor(actor).catch(() => {})}>Enable</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {showFormModal ? (
        <ModalOverlay onClose={() => setShowFormModal(false)}>
          <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>{editingActor ? 'Edit Threat Actor' : 'Add Threat Actor'}</h3>
          <form onSubmit={submitForm}>
            <FeedFormField ui={ui} label="Name" fullWidth>
              <input required value={form.name} onChange={(e) => setForm((x) => ({ ...x, name: e.target.value }))} style={ui.input} placeholder="e.g. APT29" />
            </FeedFormField>
            <FeedFormField ui={ui} label="Aliases" helper="Comma-separated alternate names." fullWidth>
              <input value={form.aliases} onChange={(e) => setForm((x) => ({ ...x, aliases: e.target.value }))} style={ui.input} placeholder="Cozy Bear, The Dukes" />
            </FeedFormField>
            <FeedFormField ui={ui} label="Description" fullWidth>
              <textarea value={form.description} onChange={(e) => setForm((x) => ({ ...x, description: e.target.value }))} style={ui.textarea} placeholder="Optional description" />
            </FeedFormField>
            <FeedFormField ui={ui} label="Active" fullWidth>
              <label style={ui.checkLabel}>
                <input type="checkbox" checked={form.active} onChange={(e) => setForm((x) => ({ ...x, active: e.target.checked }))} />
                Threat actor is active
              </label>
            </FeedFormField>
            {formError ? <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{formError}</div> : null}
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
              <button type="button" style={ui.btn} onClick={() => setShowFormModal(false)}>Cancel</button>
              <button type="submit" style={ui.btnPrimary} disabled={saving}>{saving ? 'Saving…' : (editingActor ? 'Save Changes' : 'Create Threat Actor')}</button>
            </div>
          </form>
        </ModalOverlay>
      ) : null}
    </AppShell>
  );
}

function formatIocSourceStateLabel(source) {
  const state = source?.state || (source?.archived_at ? 'archived' : source?.active === false ? 'disabled' : 'active');
  if (state === 'archived') return 'Archived';
  if (state === 'disabled') return 'Disabled';
  return 'Active';
}

function sourceIocCount(source) {
  return Number(source?.ioc_count ?? source?.usage_count ?? 0);
}

function IocSourcesPage() {
  const { isAdmin } = useSession();
  const ui = PUBLISHED_FEEDS_UI;
  const { options: threatClassOptions } = useThreatClassifications();
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showInactive, setShowInactive] = useState(true);
  const [showFormModal, setShowFormModal] = useState(false);
  const [disableTarget, setDisableTarget] = useState(null);
  const [disableBusy, setDisableBusy] = useState(false);
  const [archiveTarget, setArchiveTarget] = useState(null);
  const [archiveBusy, setArchiveBusy] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deletePreviewBusy, setDeletePreviewBusy] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [pageSuccess, setPageSuccess] = useState('');
  const [moveTarget, setMoveTarget] = useState(null);
  const [moveForm, setMoveForm] = useState({
    target_source_id: '',
    apply_target_defaults: true,
    archive_source_after_move: false
  });
  const [movePreview, setMovePreview] = useState(null);
  const [moveBusy, setMoveBusy] = useState(false);
  const [movePreviewBusy, setMovePreviewBusy] = useState(false);
  const [moveError, setMoveError] = useState('');
  const [moveSuccess, setMoveSuccess] = useState(null);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(EMPTY_IOC_SOURCE_FORM);
  const [typeOverridesDraft, setTypeOverridesDraft] = useState(defaultTypeOverridesDraft([]));
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  const load = useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    setError('');
    try {
      const params = showInactive ? { include_inactive: true } : {};
      const { data } = await api.get('/ioc-sources', { params });
      setSources(Array.isArray(data?.sources) ? data.sources : []);
    } catch (err) {
      setSources([]);
      setError(apiErrorMessage(err, 'Failed to load IOC sources'));
    } finally {
      setLoading(false);
    }
  }, [isAdmin, showInactive]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  function closeFormModal() {
    setShowFormModal(false);
    setEditing(null);
    setFormError('');
    setTypeOverridesDraft(defaultTypeOverridesDraft([]));
  }

  function openCreateModal() {
    setEditing(null);
    setForm(EMPTY_IOC_SOURCE_FORM);
    setTypeOverridesDraft(defaultTypeOverridesDraft([]));
    setFormError('');
    setShowFormModal(true);
  }

  function openEditModal(source) {
    setEditing(source);
    setForm({
      name: source?.name || '',
      description: source?.description || '',
	      default_confidence: source?.default_confidence || '',
	      default_threat_classification: source?.default_threat_classification || '',
	      default_expire_policy: source?.default_expire_policy || 'never',
      default_expire_days: source?.default_expire_days ?? '',
      color: source?.color || '',
      active: source?.active !== false
    });
    setTypeOverridesDraft(defaultTypeOverridesDraft(source?.expiration_type_policies || []));
    setFormError('');
    setShowFormModal(true);
  }

  function normalizeNameInput(value) {
    return String(value || '').trim().replace(/\s+/g, '_').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64);
  }

  function formatDefaultExpire(source) {
    if (source?.default_expire_policy === 'expire_after_days') {
      return `${source.default_expire_days || '?'} days`;
    }
    if (source?.default_expire_policy === 'custom_date') return 'Custom date';
    return 'Never';
  }

  async function submitForm(e) {
    e.preventDefault();
    if (!isAdmin) return;
    if (!isSavableColor(form.color)) {
      setFormError('Badge color must be a hex value like #7c3aed, or left blank.');
      return;
    }
    setSaving(true);
    setFormError('');
    try {
      const payload = {
        description: form.description.trim() || null,
	        default_confidence: form.default_confidence || null,
	        default_threat_classification: form.default_threat_classification || null,
	        default_expire_policy: form.default_expire_policy || null,
        default_expire_days: form.default_expire_policy === 'expire_after_days'
          ? Number(form.default_expire_days) || null
          : null,
        color: form.color.trim() || null,
        active: form.active,
        expiration_type_policies: buildExpirationTypePoliciesPayload(typeOverridesDraft)
      };
      if (editing?.id) {
        await api.patch(`/ioc-sources/${editing.id}`, payload);
      } else {
        const normalizedName = normalizeNameInput(form.name);
        if (normalizedName.length < 3) {
          setFormError('Name must be 3–64 characters: letters, numbers, underscore, hyphen.');
          return;
        }
        await api.post('/ioc-sources', { ...payload, name: normalizedName });
      }
      invalidateSourceColorCatalog();
      closeFormModal();
      setForm(EMPTY_IOC_SOURCE_FORM);
      await load();
    } catch (err) {
      setFormError(apiErrorMessage(err, editing ? 'Update failed' : 'Create failed'));
    } finally {
      setSaving(false);
    }
  }

  async function enableSource(source) {
    if (!source?.id || !isAdmin) return;
    setError('');
    try {
      await api.post(`/admin/ioc-sources/${source.id}/enable`);
      await load();
    } catch (err) {
      setError(apiErrorMessage(err, 'Enable failed'));
    }
  }

  async function confirmDisableSource() {
    if (!disableTarget?.id || !isAdmin) return;
    setDisableBusy(true);
    setError('');
    try {
      await api.post(`/admin/ioc-sources/${disableTarget.id}/disable`);
      setDisableTarget(null);
      await load();
    } catch (err) {
      setError(apiErrorMessage(err, 'Disable failed'));
    } finally {
      setDisableBusy(false);
    }
  }

  async function confirmArchiveSource() {
    if (!archiveTarget?.id || !isAdmin) return;
    setArchiveBusy(true);
    setError('');
    try {
      await api.post(`/admin/ioc-sources/${archiveTarget.id}/archive`);
      setArchiveTarget(null);
      await load();
    } catch (err) {
      setError(apiErrorMessage(err, 'Archive failed'));
    } finally {
      setArchiveBusy(false);
    }
  }

  async function confirmDeleteSource() {
    if (!deleteTarget?.id || !isAdmin) return;
    if (deleteTarget.deleteMode === 'blocked' || deleteTarget.deleteMode === 'published_feeds') return;
    setDeleteBusy(true);
    setDeleteError('');
    try {
      await api.delete(`/admin/ioc-sources/${deleteTarget.id}`);
      const deletedName = deleteTarget.name;
      setDeleteTarget(null);
      setPageSuccess(`Source "${deletedName}" deleted.`);
      await load();
    } catch (err) {
      const parsed = parseIocSourceDeleteError(err);
      setDeleteTarget((prev) => (prev ? {
        ...prev,
        deleteMode: parsed.mode || prev.deleteMode,
        deletePreview: {
          ...(prev.deletePreview || {}),
          published_feed_dependencies: parsed.published_feed_dependencies || prev.deletePreview?.published_feed_dependencies || []
        }
      } : prev));
      setDeleteError(parsed.message);
    } finally {
      setDeleteBusy(false);
    }
  }

  async function handleDeleteClick(source) {
    if (!source?.id || !isAdmin) return;
    setDeleteError('');
    setPageSuccess('');
    setDeletePreviewBusy(true);
    setDeleteTarget({ ...source, deleteMode: 'loading' });
    try {
      const { data } = await api.get(`/admin/ioc-sources/${source.id}/delete-preview`);
      setDeleteTarget({
        ...source,
        deleteMode: resolveDeleteModalMode(data),
        deletePreview: data
      });
    } catch (err) {
      setDeleteTarget({ ...source, deleteMode: 'empty', deletePreview: null });
      setDeleteError(apiErrorMessage(err, 'Failed to load delete preview'));
    } finally {
      setDeletePreviewBusy(false);
    }
  }

  function closeDeleteModal() {
    if (deleteBusy || deletePreviewBusy) return;
    setDeleteTarget(null);
    setDeleteError('');
  }

  function openMoveModal(source) {
    setMoveTarget(source);
    setMoveForm({
      target_source_id: '',
      apply_target_defaults: true,
      archive_source_after_move: false
    });
    setMovePreview(null);
    setMoveError('');
    setMoveSuccess(null);
  }

  function closeMoveModal() {
    if (moveBusy || movePreviewBusy) return;
    setMoveTarget(null);
    setMovePreview(null);
    setMoveError('');
    setMoveSuccess(null);
  }

  const moveTargetOptions = useMemo(
    () => sources.filter((s) => {
      if (!moveTarget?.id) return false;
      if (String(s.id) === String(moveTarget.id)) return false;
      const state = s.state || (s.archived_at ? 'archived' : s.active === false ? 'disabled' : 'active');
      return state === 'active';
    }),
    [sources, moveTarget]
  );

  async function runMovePreview() {
    if (!moveTarget?.id || !moveForm.target_source_id) {
      setMoveError('Select a target source.');
      return;
    }
    setMovePreviewBusy(true);
    setMoveError('');
    setMoveSuccess(null);
    try {
      const { data } = await api.post(`/admin/ioc-sources/${moveTarget.id}/move-preview`, moveForm);
      setMovePreview(data);
    } catch (err) {
      setMovePreview(null);
      setMoveError(apiErrorMessage(err, 'Preview failed'));
    } finally {
      setMovePreviewBusy(false);
    }
  }

  async function confirmMoveSource() {
    if (!moveTarget?.id || !moveForm.target_source_id || !isAdmin) return;
    setMoveBusy(true);
    setMoveError('');
    try {
      const { data } = await api.post(`/admin/ioc-sources/${moveTarget.id}/move`, moveForm);
      setMoveSuccess(data);
      setMovePreview(null);
      await load();
    } catch (err) {
      setMoveError(apiErrorMessage(err, 'Move failed'));
    } finally {
      setMoveBusy(false);
    }
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <section style={ui.section}>
          <h1 style={ui.pageTitle}>IOC Sources</h1>
          <p style={ui.pageSub}>Admin access required.</p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap', marginBottom: 16 }}>
          <div style={{ minWidth: 0, flex: '1 1 280px' }}>
            <h1 style={ui.pageTitle}>IOC Sources</h1>
            <p style={ui.pageSub}>Provenance labels for manual IOC entries. Archive or disable sources to hide them from Add IOC while preserving existing evidence.</p>
          </div>
          <button type="button" style={{ ...ui.btnPrimary, flexShrink: 0 }} onClick={openCreateModal}>Add Source</button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 14 }}>
          <label style={{ ...ui.checkLabel, display: 'inline-flex', margin: 0 }}>
            <input type="checkbox" checked={showInactive} onChange={(e) => setShowInactive(e.target.checked)} />
            Show inactive and archived sources
          </label>
        </div>

        {pageSuccess ? <div style={{ ...ui.banner, marginBottom: 12, borderColor: '#166534', color: '#86efac' }}>{pageSuccess}</div> : null}
        {error ? <div style={{ ...ui.banner, marginBottom: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{error}</div> : null}

        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table" style={{ width: '100%', minWidth: 640, borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={ui.thead}>
                <th style={ui.th}>Name</th>
	                  <th style={ui.th}>Default Confidence</th>
	                  <th style={ui.th}>Default Threat Class</th>
	                  <th style={ui.th}>Default Expire</th>
                <th style={ui.th}>IOCs</th>
                <th style={ui.th}>State</th>
                <th style={{ ...ui.th, textAlign: 'right', whiteSpace: 'nowrap' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
	                <tr><td colSpan={7} style={ui.td}>Loading…</td></tr>
              ) : sources.length ? sources.map((s) => {
                const iocCount = sourceIocCount(s);
                const state = s.state || (s.archived_at ? 'archived' : s.active === false ? 'disabled' : 'active');
                const isArchived = state === 'archived';
                return (
                <tr key={s.id} style={{ ...ui.tr, opacity: state === 'active' ? 1 : 0.72 }}>
	                  <td style={ui.td}>
	                    <span style={{ display: 'inline-flex', borderRadius: 999, padding: '2px 9px', fontSize: 12, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", ...sourceColorBadgeStyle(s.color || DEFAULT_SOURCE_COLOR) }}>{s.name}</span>
	                  </td>
	                  <td style={ui.td}>{s.default_confidence || '—'}</td>
	                  <td style={ui.td}>{String(s.default_threat_classification || '—').replaceAll('_', ' ')}</td>
	                  <td style={ui.td}>{formatDefaultExpire(s)}</td>
                  <td style={ui.td}>{iocCount.toLocaleString('en-US')}</td>
                  <td style={ui.td}>{formatIocSourceStateLabel(s)}</td>
                  <td style={{ ...ui.td, textAlign: 'right', whiteSpace: 'nowrap' }}>
                    <button type="button" style={ui.btn} onClick={() => openEditModal(s)}>Edit</button>
                    {!isArchived && s.active !== false ? (
                      <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => setDisableTarget(s)}>Disable</button>
                    ) : null}
                    {!isArchived && s.active === false ? (
                      <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => enableSource(s).catch(() => {})}>Enable</button>
                    ) : null}
                    {!isArchived ? (
                      <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => setArchiveTarget(s)}>Archive</button>
                    ) : null}
                    <button
                      type="button"
                      style={{ ...ui.btn, marginLeft: 6, opacity: iocCount > 0 ? 1 : 0.45 }}
                      disabled={iocCount <= 0}
                      onClick={() => openMoveModal(s)}
                    >
                      Move IOCs
                    </button>
                    <button
                      type="button"
                      style={{ ...ui.btn, marginLeft: 6, borderColor: '#7f1d1d', color: '#fca5a5' }}
                      onClick={() => handleDeleteClick(s)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              );}) : (
	                <tr><td colSpan={7} style={{ ...ui.td, color: '#64748b' }}>No IOC sources yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {showFormModal ? (
        <div
          role="presentation"
          onClick={closeFormModal}
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.78)', zIndex: 1100, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}
        >
          <div role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()} style={IOC_SOURCE_MODAL_STYLE}>
            <h3 style={{ ...ui.formTitle, fontSize: 18, marginTop: 0, marginBottom: 6 }}>
              {editing ? 'Edit IOC Source' : 'Add IOC Source'}
            </h3>
            <p style={{ ...ui.pageSub, marginTop: 0, marginBottom: 16 }}>
              {editing ? 'Update defaults for manual IOC provenance.' : 'Create a provenance label used when adding manual IOCs.'}
            </p>
            <form onSubmit={submitForm} style={{ display: 'grid', gap: 14 }}>
              {!editing ? (
                <FeedFormField ui={ui} label="Name" helper="3–64 chars: letters, numbers, underscore, hyphen." fullWidth>
                  <input
                    required
                    value={form.name}
                    onChange={(e) => setForm((x) => ({ ...x, name: e.target.value }))}
                    onBlur={() => setForm((x) => ({ ...x, name: normalizeNameInput(x.name) }))}
                    style={ui.input}
                    placeholder="Internal_Hunting"
                  />
                </FeedFormField>
              ) : (
                <FeedFormField ui={ui} label="Name" helper="Source name is immutable after creation." fullWidth>
                  <input value={form.name} readOnly style={{ ...ui.input, opacity: 0.85, cursor: 'not-allowed' }} />
                </FeedFormField>
              )}
              <FeedFormField ui={ui} label="Description" fullWidth>
                <textarea value={form.description} onChange={(e) => setForm((x) => ({ ...x, description: e.target.value }))} style={ui.textarea} rows={2} placeholder="Optional" />
              </FeedFormField>
              <FeedFormField ui={ui} label="Badge Color" fullWidth>
                <SourceColorField
                  value={form.color}
                  onChange={(next) => setForm((x) => ({ ...x, color: next }))}
                  previewLabel={form.name || editing?.name || 'Source'}
                  label=""
                  helper="Leave blank to use the default badge color."
                />
              </FeedFormField>
	              <FeedFormField ui={ui} label="Default Confidence" fullWidth>
                <select value={form.default_confidence} onChange={(e) => setForm((x) => ({ ...x, default_confidence: e.target.value }))} style={ui.select}>
                  <option value="">— None —</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
	              </FeedFormField>
	              <FeedFormField ui={ui} label="Default Threat Classification" helper="Optional but improves AI Insight quality." fullWidth>
	                <select value={form.default_threat_classification || 'unknown'} onChange={(e) => setForm((x) => ({ ...x, default_threat_classification: e.target.value }))} style={ui.select}>
	                  {threatClassOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
	                </select>
	              </FeedFormField>
              <FeedFormField ui={ui} label="Default Expire Policy" fullWidth>
                <select value={form.default_expire_policy} onChange={(e) => setForm((x) => ({ ...x, default_expire_policy: e.target.value }))} style={ui.select}>
                  {IOC_EXPIRE_POLICY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </FeedFormField>
              {form.default_expire_policy === 'expire_after_days' ? (
                <FeedFormField ui={ui} label="Default Expire Days" fullWidth>
                  <input type="number" min={1} max={3650} required value={form.default_expire_days} onChange={(e) => setForm((x) => ({ ...x, default_expire_days: e.target.value }))} style={ui.input} />
                </FeedFormField>
              ) : null}
              <div style={{ borderTop: '1px solid #1e293b', paddingTop: 10 }}>
                <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>IOC Type Overrides</div>
                <div style={{ color: '#64748b', fontSize: 12, marginBottom: 10, lineHeight: 1.5 }}>
                  Per-type expiration overrides take precedence over the source default.
                </div>
                <div style={{ display: 'grid', gap: 8 }}>
                  {EXPIRATION_TYPE_OVERRIDE_TYPES.map((t) => {
                    const ovr = (typeOverridesDraft && typeOverridesDraft[t.id]) || { mode: 'inherit', ttl_days: '' };
                    const isFixed = ovr.mode === 'fixed_ttl';
                    const setOverride = (patch) => setTypeOverridesDraft((prev) => ({
                      ...prev,
                      [t.id]: { ...ovr, ...patch }
                    }));
                    return (
                      <div key={t.id} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 110px', gap: 8, alignItems: 'center' }}>
                        <span style={{ color: '#e2e8f0', fontSize: 13 }}>{t.label}</span>
                        <select
                          value={ovr.mode}
                          onChange={(e) => setOverride({ mode: e.target.value })}
                          style={ui.select}
                        >
                          {EXPIRATION_TYPE_OVERRIDE_MODES.map((m) => (
                            <option key={m.id} value={m.id}>{m.label}</option>
                          ))}
                        </select>
                        <input
                          type="number"
                          min={1}
                          placeholder="TTL days"
                          value={isFixed ? ovr.ttl_days : ''}
                          disabled={!isFixed}
                          onChange={(e) => setOverride({ ttl_days: e.target.value })}
                          style={{ ...ui.input, opacity: isFixed ? 1 : 0.4 }}
                        />
                      </div>
                    );
                  })}
                </div>
                <div style={{ marginTop: 10, padding: 8, borderRadius: 6, border: '1px solid #1e293b', background: '#0b1220', color: '#94a3b8', fontSize: 12, lineHeight: 1.6 }}>
                  {EXPIRATION_TYPE_OVERRIDE_TYPES.map((t) => {
                    const mockFeedExp = {
                      enabled: form.default_expire_policy === 'expire_after_days',
                      expiration_mode: form.default_expire_policy === 'expire_after_days' ? 'fixed_ttl' : 'never',
                      ttl_days: form.default_expire_days
                    };
                    return <div key={t.id}>{formatTypeOverridePreview(t.label, (typeOverridesDraft || {})[t.id], mockFeedExp)}</div>;
                  })}
                </div>
              </div>
              <FeedFormField ui={ui} label="Active" fullWidth>
                <label style={ui.checkLabel}>
                  <input type="checkbox" checked={form.active} onChange={(e) => setForm((x) => ({ ...x, active: e.target.checked }))} />
                  Source is active (visible in Add IOC)
                </label>
              </FeedFormField>
              {formError ? <div style={{ ...ui.banner, borderColor: '#991b1b', color: '#fca5a5' }}>{formError}</div> : null}
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 16, borderTop: '1px solid #334155' }}>
                <button type="button" style={ui.btn} onClick={closeFormModal}>Cancel</button>
                <button type="submit" style={ui.btnPrimary} disabled={saving}>{saving ? 'Saving…' : (editing ? 'Save' : 'Create Source')}</button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      {disableTarget ? (
        <div
          role="presentation"
          onClick={() => !disableBusy && setDisableTarget(null)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.82)', zIndex: 1200, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}
        >
          <div role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()} style={{ ...IOC_SOURCE_MODAL_STYLE, width: 'min(520px, 96vw)' }}>
            <h3 style={{ ...ui.formTitle, fontSize: 18, marginTop: 0, marginBottom: 10 }}>Disable IOC Source?</h3>
            <p style={{ margin: '0 0 12px', color: '#cbd5e1', lineHeight: 1.55, fontSize: 14 }}>
              This source will no longer be available when adding new IOCs.
            </p>
            <p style={{ margin: '0 0 20px', color: '#94a3b8', lineHeight: 1.55, fontSize: 13 }}>
              Existing IOCs linked to <strong style={{ color: '#e2e8f0' }}>{disableTarget.name}</strong> will not be deleted, expired, or modified.
            </p>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button type="button" style={ui.btn} disabled={disableBusy} onClick={() => setDisableTarget(null)}>Cancel</button>
              <button type="button" style={{ ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }} disabled={disableBusy} onClick={() => confirmDisableSource().catch(() => {})}>
                {disableBusy ? 'Disabling…' : 'Disable Source'}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {archiveTarget ? (
        <div
          role="presentation"
          onClick={() => !archiveBusy && setArchiveTarget(null)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.82)', zIndex: 1200, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}
        >
          <div role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()} style={{ ...IOC_SOURCE_MODAL_STYLE, width: 'min(560px, 96vw)' }}>
            <h3 style={{ ...ui.formTitle, fontSize: 18, marginTop: 0, marginBottom: 10 }}>Archive IOC Source?</h3>
            <p style={{ margin: '0 0 20px', color: '#cbd5e1', lineHeight: 1.55, fontSize: 14 }}>
              Archive this source? Existing IOC evidence will be preserved, but the source will no longer be available when adding new IOCs.
            </p>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button type="button" style={ui.btn} disabled={archiveBusy} onClick={() => setArchiveTarget(null)}>Cancel</button>
              <button type="button" style={{ ...ui.btn, borderColor: '#92400e', color: '#fde68a' }} disabled={archiveBusy} onClick={() => confirmArchiveSource().catch(() => {})}>
                {archiveBusy ? 'Archiving…' : 'Archive Source'}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {deleteTarget ? (
        <div
          role="presentation"
          onClick={closeDeleteModal}
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.82)', zIndex: 1200, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}
        >
          <div role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()} style={{ ...IOC_SOURCE_MODAL_STYLE, width: 'min(560px, 96vw)' }}>
            {deleteTarget.deleteMode === 'loading' || deletePreviewBusy ? (
              <>
                <h3 style={{ ...ui.formTitle, fontSize: 18, marginTop: 0, marginBottom: 10 }}>Delete source</h3>
                <p style={{ margin: 0, color: '#94a3b8', lineHeight: 1.55, fontSize: 14 }}>Checking whether this source can be deleted…</p>
              </>
            ) : deleteTarget.deleteMode === 'blocked' ? (
              <>
                <h3 style={{ ...ui.formTitle, fontSize: 18, marginTop: 0, marginBottom: 10 }}>Source contains IOCs</h3>
                <p style={{ margin: '0 0 12px', color: '#cbd5e1', lineHeight: 1.55, fontSize: 14 }}>
                  {deleteTarget.deletePreview?.blocked_message || deleteError || 'This source contains IOC records and cannot be deleted directly. Move the IOCs to another source first.'}
                </p>
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                  <button type="button" style={ui.btn} onClick={closeDeleteModal}>Cancel</button>
                  <button
                    type="button"
                    style={ui.btnPrimary}
                    onClick={() => {
                      const src = deleteTarget;
                      setDeleteTarget(null);
                      setDeleteError('');
                      openMoveModal(src);
                    }}
                  >
                    Move IOCs
                  </button>
                </div>
              </>
            ) : deleteTarget.deleteMode === 'published_feeds' ? (
              <>
                <h3 style={{ ...ui.formTitle, fontSize: 18, marginTop: 0, marginBottom: 10 }}>Source used by Published Feeds</h3>
                <p style={{ margin: '0 0 12px', color: '#cbd5e1', lineHeight: 1.55, fontSize: 14 }}>
                  {deleteTarget.deletePreview?.blocked_message || deleteError || 'This source is used by Published Feeds and cannot be deleted.'}
                </p>
                {(deleteTarget.deletePreview?.published_feed_dependencies || []).length ? (
                  <ul style={{ margin: '0 0 16px', paddingLeft: 20, color: '#e2e8f0', lineHeight: 1.6, fontSize: 14 }}>
                    {(deleteTarget.deletePreview?.published_feed_dependencies || []).map((dep) => (
                      <li key={dep.id || dep.published_feed_id || dep.name}>{dep.name || dep.published_feed_name}</li>
                    ))}
                  </ul>
                ) : null}
                <p style={{ margin: '0 0 16px', color: '#94a3b8', lineHeight: 1.55, fontSize: 13 }}>
                  Remove this source from those Published Feed filters first.
                </p>
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', flexWrap: 'wrap' }}>
                  <button type="button" style={ui.btn} onClick={closeDeleteModal}>Cancel</button>
                  <Link to="/threat-intelligence/published-feeds" style={{ ...ui.btnPrimary, textDecoration: 'none', display: 'inline-flex', alignItems: 'center' }} onClick={closeDeleteModal}>
                    Open Published Feeds
                  </Link>
                </div>
              </>
            ) : (
              <>
                <h3 style={{ ...ui.formTitle, fontSize: 18, marginTop: 0, marginBottom: 10 }}>Delete source</h3>
                <p style={{ margin: '0 0 12px', color: '#cbd5e1', lineHeight: 1.55, fontSize: 14 }}>
                  Delete this unused source? This cannot be undone.
                </p>
                {deleteError ? (
                  <div style={{ ...ui.banner, marginBottom: 16, borderColor: '#991b1b', color: '#fca5a5' }}>{deleteError}</div>
                ) : null}
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                  <button type="button" style={ui.btn} disabled={deleteBusy} onClick={closeDeleteModal}>Cancel</button>
                  <button type="button" style={{ ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }} disabled={deleteBusy || deleteTarget.deletePreview?.can_delete === false} onClick={() => confirmDeleteSource().catch(() => {})}>
                    {deleteBusy ? 'Deleting…' : 'Delete source'}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      ) : null}

      {moveTarget ? (
        <div
          role="presentation"
          onClick={closeMoveModal}
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.82)', zIndex: 1200, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}
        >
          <div role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()} style={{ ...IOC_SOURCE_MODAL_STYLE, width: 'min(680px, 96vw)' }}>
            <h3 style={{ ...ui.formTitle, fontSize: 18, marginTop: 0, marginBottom: 8 }}>Move IOCs</h3>
            <p style={{ margin: '0 0 16px', color: '#94a3b8', lineHeight: 1.55, fontSize: 13 }}>
              All IOC records linked to this source will be moved to the target source. Move history is preserved in audit logs and IOC details.
            </p>
            <div style={{ display: 'grid', gap: 12 }}>
              <FeedFormField ui={ui} label="Source from" fullWidth>
                <input readOnly value={moveTarget.name} style={{ ...ui.input, opacity: 0.85, cursor: 'not-allowed' }} />
              </FeedFormField>
              <FeedFormField ui={ui} label="Target source" fullWidth>
                <select
                  value={moveForm.target_source_id}
                  onChange={(e) => {
                    setMoveForm((f) => ({ ...f, target_source_id: e.target.value }));
                    setMovePreview(null);
                    setMoveSuccess(null);
                  }}
                  style={ui.select}
                >
                  <option value="">Select target source…</option>
                  {moveTargetOptions.map((s) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </select>
              </FeedFormField>
              <label style={{ ...ui.checkLabel, display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                <input
                  type="checkbox"
                  checked={moveForm.apply_target_defaults}
                  onChange={(e) => {
                    setMoveForm((f) => ({ ...f, apply_target_defaults: e.target.checked }));
                    setMovePreview(null);
                    setMoveSuccess(null);
                  }}
                />
                <span>Apply target source defaults (confidence, threat class, expiration)</span>
              </label>
              <label style={{ ...ui.checkLabel, display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                <input
                  type="checkbox"
                  checked={moveForm.archive_source_after_move}
                  onChange={(e) => {
                    setMoveForm((f) => ({ ...f, archive_source_after_move: e.target.checked }));
                    setMovePreview(null);
                  }}
                />
                <span>Archive source after move</span>
              </label>
              {movePreview ? (
                <div style={{ padding: 12, borderRadius: 8, border: '1px solid #334155', background: '#0f172a', fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
                  <div><strong>Preview</strong></div>
                  <div>IOCs: {movePreview.ioc_count ?? 0}</div>
                  <div>Will move: {movePreview.will_move ?? 0}</div>
                  <div>Will merge: {movePreview.will_merge ?? 0}</div>
                  <div>Will skip: {movePreview.will_skip ?? 0}</div>
                  {movePreview.source_will_be_empty_after_move ? (
                    <div style={{ marginTop: 8, color: '#86efac' }}>Source will be empty after move — you can delete it.</div>
                  ) : null}
                </div>
              ) : null}
              {moveSuccess ? (
                <div style={{ padding: 12, borderRadius: 8, border: '1px solid #166534', background: 'rgba(22,163,74,0.12)', color: '#86efac', fontSize: 13 }}>
                  Move complete — moved {moveSuccess.moved ?? 0}, merged {moveSuccess.merged ?? 0}, skipped {moveSuccess.skipped ?? 0}.
                  Source IOC count: {moveSuccess.source_ioc_count_after ?? 0}. Target IOC count: {moveSuccess.target_ioc_count_after ?? 0}.
                  {moveSuccess.source_ioc_count_after === 0 ? ' You can now delete this source.' : ''}
                  {moveSuccess.archived_source ? ' Source archived.' : ''}
                </div>
              ) : null}
              {moveError ? <div style={{ ...ui.banner, borderColor: '#991b1b', color: '#fca5a5' }}>{moveError}</div> : null}
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 18 }}>
              <button type="button" style={ui.btn} disabled={moveBusy || movePreviewBusy} onClick={closeMoveModal}>Close</button>
              <button type="button" style={ui.btn} disabled={moveBusy || movePreviewBusy || !moveForm.target_source_id} onClick={() => runMovePreview().catch(() => {})}>
                {movePreviewBusy ? 'Previewing…' : 'Preview'}
              </button>
              <button type="button" style={ui.btnPrimary} disabled={moveBusy || movePreviewBusy || !moveForm.target_source_id} onClick={() => confirmMoveSource().catch(() => {})}>
                {moveBusy ? 'Moving…' : 'Confirm Move'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </AppShell>
  );
}

function EnrichmentProvidersPage() {
  return (
    <EnrichmentProvidersPageView
      AppShell={AppShell}
      useSession={useSession}
      useReasonPrompt={useReasonPrompt}
    />
  );
}

function BackupRestorePage() {
  return (
    <BackupRestorePageView
      AppShell={AppShell}
      useSession={useSession}
    />
  );
}

const EMPTY_CREATE_USER_FORM = {
  first_name: '',
  last_name: '',
  username: '',
  password: '',
  role: 'readonly'
};

const USERS_ACTION_BTN = {
  deactivate: {
    padding: '6px 10px',
    borderRadius: 8,
    border: '1px solid #b45309',
    background: 'rgba(180,83,9,0.2)',
    color: '#fcd34d',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer'
  },
  activate: {
    padding: '6px 10px',
    borderRadius: 8,
    border: '1px solid #166534',
    background: 'rgba(22,101,52,0.25)',
    color: '#86efac',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer'
  },
  delete: {
    padding: '6px 12px',
    borderRadius: 8,
    border: '1px solid #7f1d1d',
    background: 'rgba(127,29,29,0.25)',
    color: '#fca5a5',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6
  }
};

function formatUserDisplayName(u) {
  const t = `${u?.first_name || ''} ${u?.last_name || ''}`.trim();
  return t || 'Not set';
}

function userRoleLabel(role) {
  if (role === 'admin') return 'Admin';
  if (role === 'analyst') return 'Analyst';
  return 'Read Only';
}

function userStatusLabel(status) {
  return String(status || 'active') === 'passive' ? 'Inactive' : 'Active';
}

function userRoleBadgeStyle(role) {
  if (role === 'admin') {
    return {
      display: 'inline-block',
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: '0.04em',
      padding: '4px 10px',
      borderRadius: 6,
      background: 'rgba(185, 28, 28, 0.2)',
      color: '#fca5a5',
      border: '1px solid rgba(127, 29, 29, 0.8)'
    };
  }
  if (role === 'analyst') {
    return {
      display: 'inline-block',
      fontSize: 11,
      fontWeight: 600,
      letterSpacing: '0.03em',
      padding: '4px 10px',
      borderRadius: 6,
      background: 'rgba(37, 99, 235, 0.18)',
      color: '#93c5fd',
      border: '1px solid rgba(29, 78, 216, 0.65)'
    };
  }
  return {
    display: 'inline-block',
    fontSize: 11,
    fontWeight: 600,
    letterSpacing: '0.03em',
    padding: '4px 10px',
    borderRadius: 6,
    background: 'rgba(51, 65, 85, 0.5)',
    color: '#cbd5e1',
    border: '1px solid #475569'
  };
}

function userStatusBadgeStyle(status) {
  if (String(status || 'active') === 'passive') {
    return {
      display: 'inline-block',
      fontSize: 11,
      fontWeight: 600,
      letterSpacing: '0.03em',
      padding: '4px 10px',
      borderRadius: 6,
      background: 'rgba(71, 85, 105, 0.45)',
      color: '#cbd5e1',
      border: '1px solid #64748b'
    };
  }
  return {
    display: 'inline-block',
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: '0.04em',
    padding: '4px 10px',
    borderRadius: 6,
    background: 'rgba(22, 163, 74, 0.2)',
    color: '#86efac',
    border: '1px solid rgba(22, 101, 52, 0.85)'
  };
}

function UserRoleBadge({ role }) {
  return <span style={userRoleBadgeStyle(role)}>{userRoleLabel(role)}</span>;
}

function UserStatusBadge({ status }) {
  return <span style={userStatusBadgeStyle(status)}>{userStatusLabel(status)}</span>;
}

function AdministrationSettingsPage() {
  const { role, userId, refreshSession, isAdmin } = useSession();
  const ui = PUBLISHED_FEEDS_UI;
  const [timezoneInfo, setTimezoneInfo] = useState({
    system_timezone: getSystemTimezone(),
    timezone_restart_required: false,
    current_utc_time: '',
    current_system_time: '',
    common_timezones: COMMON_TIMEZONES
  });
  const [changeOpen, setChangeOpen] = useState(false);
  const [newTimezone, setNewTimezone] = useState('');
  const [confirmText, setConfirmText] = useState('');
  const [saving, setSaving] = useState(false);
  const [timezoneError, setTimezoneError] = useState('');
  const [timezoneSuccess, setTimezoneSuccess] = useState('');
  const [restartInstructions, setRestartInstructions] = useState(null);
  const [profile, setProfile] = useState({ first_name: '', last_name: '' });
  const [profileBusy, setProfileBusy] = useState(false);
  const [profileError, setProfileError] = useState('');
  const [profileSuccess, setProfileSuccess] = useState('');

  async function loadTimezone() {
    const { data } = await api.get('/system/timezone');
    setTimezoneInfo(data);
    if (data?.active_system_timezone || data?.system_timezone) {
      setSystemTimezoneCache(data.active_system_timezone || data.system_timezone);
    }
  }

  useEffect(() => {
    loadTimezone().catch(() => {});
  }, []);

  async function loadSelfProfile() {
    if (role !== 'readonly' || userId == null) return;
    try {
      const { data } = await api.get('/users');
      const u = (data?.users || [])[0];
      if (u) setProfile({ first_name: u.first_name || '', last_name: u.last_name || '' });
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    loadSelfProfile().catch(() => {});
  }, [role, userId]);

  async function changeSystemTimezone() {
    setSaving(true);
    setTimezoneError('');
    setTimezoneSuccess('');
    setRestartInstructions(null);
    try {
      const { data } = await api.put('/system/timezone', {
        timezone: newTimezone,
        confirm: true,
        confirmation_text: confirmText
      });
      setSystemTimezoneCache(data.active_system_timezone || data.system_timezone);
      notifyTimezoneChanged();
      setTimezoneSuccess(data.message || 'Timezone change is pending restart');
      setRestartInstructions(data.restart_instructions || null);
      setChangeOpen(false);
      setConfirmText('');
      await loadTimezone();
    } catch (err) {
      setTimezoneError(apiErrorMessage(err, 'Failed to change system timezone'));
    } finally {
      setSaving(false);
    }
  }

  async function saveProfile(e) {
    e.preventDefault();
    if (userId == null) return;
    setProfileBusy(true);
    setProfileError('');
    setProfileSuccess('');
    try {
      await api.put(`/users/${userId}`, {
        first_name: profile.first_name,
        last_name: profile.last_name
      });
      await refreshSession();
      setProfileSuccess('Profile updated.');
    } catch (err) {
      setProfileError(apiErrorMessage(err, 'Failed to update profile'));
    } finally {
      setProfileBusy(false);
    }
  }

  const zoneOptions = timezoneInfo.common_timezones || COMMON_TIMEZONES;

  return (
    <AppShell>
      <section style={ui.section}>
        <h1 style={ui.pageTitle}>Settings</h1>
        <p style={ui.pageSub}>Manage platform-wide preferences and display settings.</p>

        <div style={{ ...ui.formPanel, marginTop: 8 }}>
          <h2 style={{ ...ui.formTitle, marginBottom: 6 }}>System Timezone</h2>
          <p style={{ margin: '0 0 16px', fontSize: 13, color: '#94a3b8', lineHeight: 1.45 }}>
            Configured during initial setup. Used for every timestamp in the UI, API responses,
            schedules, logs, and exports. Browser timezone is never used.
          </p>
          <div style={{ fontSize: 14, marginBottom: 8 }}>
            <div><strong>Active timezone:</strong> {timezoneInfo.active_system_timezone || timezoneInfo.system_timezone || '—'}</div>
            <div style={{ marginTop: 4 }}>
              <strong>Pending timezone:</strong>{' '}
              {timezoneInfo.pending_system_timezone || 'None'}
            </div>
            <div style={{ marginTop: 4 }}>
              <strong>Status:</strong>{' '}
              {timezoneInfo.timezone_restart_required
                ? 'Restart required'
                : (timezoneInfo.timezone_configuration_required ? 'Configuration required' : 'Healthy')}
            </div>
            <div style={{ color: '#94a3b8', marginTop: 6 }}>Current UTC: {timezoneInfo.current_utc_time || '—'}</div>
            <div style={{ color: '#94a3b8' }}>
              Current active system time: {timezoneInfo.current_system_time || '—'}
            </div>
            {timezoneInfo.timezone_restart_required ? (
              <div style={{ marginTop: 10, color: '#fbbf24' }}>
                Timezone change is pending restart. Runtime continues using the active timezone until promotion.
              </div>
            ) : null}
          </div>
          {isAdmin ? (
            <div style={{ marginTop: 12 }}>
              {!changeOpen ? (
                <button type="button" style={ui.btnPrimary} onClick={() => setChangeOpen(true)}>
                  Change System Timezone
                </button>
              ) : (
                <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 14, background: '#0b1220' }}>
                  <p style={{ marginTop: 0, color: '#fde68a', fontSize: 13, lineHeight: 1.5 }}>
                    Changing timezone affects display, schedules, logs, and exports. Historical TIMESTAMPTZ
                    values are not rewritten. A full application restart (Docker Compose recreate or Kubernetes
                    rollout) is required. Type CHANGE SYSTEM TIMEZONE to confirm.
                  </p>
                  <label style={ui.label}>New timezone</label>
                  <select
                    value={newTimezone}
                    onChange={(e) => setNewTimezone(e.target.value)}
                    style={{ ...ui.select, maxWidth: 400, marginBottom: 10 }}
                  >
                    <option value="">Select…</option>
                    {zoneOptions.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
                  </select>
                  <label style={ui.label}>Confirmation</label>
                  <input
                    value={confirmText}
                    onChange={(e) => setConfirmText(e.target.value)}
                    placeholder="CHANGE SYSTEM TIMEZONE"
                    style={{ ...ui.input, maxWidth: 400, marginBottom: 12 }}
                  />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      type="button"
                      style={ui.btnPrimary}
                      disabled={saving || !newTimezone || confirmText !== 'CHANGE SYSTEM TIMEZONE'}
                      onClick={() => changeSystemTimezone().catch(() => {})}
                    >
                      {saving ? 'Saving…' : 'Confirm timezone change'}
                    </button>
                    <button type="button" onClick={() => setChangeOpen(false)}>Cancel</button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p style={{ fontSize: 13, color: '#94a3b8' }}>Only administrators can change the system timezone.</p>
          )}
          {timezoneError ? (
            <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
              {timezoneError}
            </div>
          ) : null}
          {timezoneSuccess ? (
            <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #166534', color: '#86efac', background: 'rgba(22,101,52,0.2)', fontSize: 13 }}>
              {timezoneSuccess}
            </div>
          ) : null}
          {restartInstructions ? (
            <pre style={{ marginTop: 12, padding: 12, background: '#020617', borderRadius: 8, fontSize: 12, overflow: 'auto', color: '#cbd5e1' }}>
{`Docker Compose:\n${restartInstructions.docker_compose}\n\nKubernetes:\n${restartInstructions.kubernetes}`}
            </pre>
          ) : null}
        </div>

        {role === 'readonly' && userId != null ? (
          <div style={{ ...ui.formPanel, marginTop: 16 }}>
            <h2 style={{ ...ui.formTitle, marginBottom: 6 }}>Your profile</h2>
            <p style={{ margin: '0 0 16px', fontSize: 13, color: '#94a3b8', lineHeight: 1.45 }}>
              Update the name shown on your account.
            </p>
            <form onSubmit={saveProfile} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 20, maxWidth: 560 }}>
              <div>
                <label htmlFor="profile-fn" style={ui.label}>First name</label>
                <input
                  id="profile-fn"
                  value={profile.first_name}
                  onChange={(e) => setProfile((p) => ({ ...p, first_name: e.target.value }))}
                  style={ui.input}
                  autoComplete="given-name"
                />
              </div>
              <div>
                <label htmlFor="profile-ln" style={ui.label}>Last name</label>
                <input
                  id="profile-ln"
                  value={profile.last_name}
                  onChange={(e) => setProfile((p) => ({ ...p, last_name: e.target.value }))}
                  style={ui.input}
                  autoComplete="family-name"
                />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <button
                  type="submit"
                  disabled={profileBusy}
                  style={{
                    ...ui.btnPrimary,
                    opacity: profileBusy ? 0.75 : 1,
                    cursor: profileBusy ? 'wait' : 'pointer'
                  }}
                >
                  {profileBusy ? 'Saving…' : 'Update name'}
                </button>
              </div>
            </form>
            {profileError ? (
              <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
                {profileError}
              </div>
            ) : null}
            {profileSuccess ? (
              <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #166534', color: '#86efac', background: 'rgba(22,101,52,0.2)', fontSize: 13 }}>
                {profileSuccess}
              </div>
            ) : null}
          </div>
        ) : null}
      </section>
    </AppShell>
  );
}

function CreateUserModal({ onClose, onCreated }) {
  const ui = PUBLISHED_FEEDS_UI;
  const [form, setForm] = useState(EMPTY_CREATE_USER_FORM);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  async function submit(e) {
    e.preventDefault();
    const username = String(form.username || '').trim();
    const password = form.password;
    const first_name = String(form.first_name || '').trim();
    const last_name = String(form.last_name || '').trim();
    const role = String(form.role || 'readonly').trim();
    if (!username || !password) {
      setError('Username and password are required.');
      return;
    }
    setSaving(true);
    setError('');
    try {
      await api.post('/users', { username, password, first_name, last_name, role });
      onClose?.();
      onCreated?.();
    } catch (err) {
      const status = Number(err?.response?.status || 0);
      const backendMsg = String(err?.response?.data?.message || '').trim();
      if (status === 409 || /already exists/i.test(backendMsg)) {
        setError('This username is already in use. Please choose another one.');
      } else {
        setError(backendMsg || err?.message || 'Failed to create user');
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <ModalOverlay onClose={saving ? undefined : onClose}>
      <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>Create User</h3>
      <p style={{ margin: '0 0 16px', fontSize: 13, color: '#94a3b8', lineHeight: 1.45 }}>
        Create a new account and assign a role.
      </p>
      <form onSubmit={submit}>
        <FeedFormField ui={ui} label="First name" fullWidth>
          <input
            value={form.first_name}
            onChange={(e) => setForm((x) => ({ ...x, first_name: e.target.value }))}
            style={ui.input}
            autoComplete="given-name"
          />
        </FeedFormField>
        <FeedFormField ui={ui} label="Last name" fullWidth>
          <input
            value={form.last_name}
            onChange={(e) => setForm((x) => ({ ...x, last_name: e.target.value }))}
            style={ui.input}
            autoComplete="family-name"
          />
        </FeedFormField>
        <FeedFormField ui={ui} label="Username" fullWidth>
          <input
            required
            value={form.username}
            onChange={(e) => setForm((x) => ({ ...x, username: e.target.value }))}
            style={ui.input}
            autoComplete="username"
          />
        </FeedFormField>
        <FeedFormField ui={ui} label="Password" fullWidth>
          <input
            required
            type="password"
            value={form.password}
            onChange={(e) => setForm((x) => ({ ...x, password: e.target.value }))}
            style={ui.input}
            autoComplete="new-password"
          />
        </FeedFormField>
        <FeedFormField ui={ui} label="User Role" fullWidth>
          <select
            value={form.role}
            onChange={(e) => setForm((x) => ({ ...x, role: e.target.value }))}
            style={ui.select}
          >
            <option value="admin">Admin (Full Access)</option>
            <option value="analyst">Analyst (Triage)</option>
            <option value="readonly">Read Only (View Only)</option>
          </select>
        </FeedFormField>
        {error ? (
          <div style={{ marginTop: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>
            {error}
          </div>
        ) : null}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
          <button type="button" style={ui.btn} onClick={onClose} disabled={saving}>Cancel</button>
          <button type="submit" style={ui.btnPrimary} disabled={saving}>
            {saving ? 'Creating…' : 'Create User'}
          </button>
        </div>
      </form>
    </ModalOverlay>
  );
}

function UsersTable({ users, usersLoading, userId, statusBusyId, onSetStatus, onRemove }) {
  const ui = PUBLISHED_FEEDS_UI;

  if (usersLoading) {
    return <div style={{ color: '#94a3b8', padding: '12px 0' }}>Loading…</div>;
  }
  if (!users.length) {
    return <div style={{ color: '#64748b', fontSize: 14, padding: '12px 0' }}>No users yet.</div>;
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="ioc-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={ui.thead}>
            <th style={ui.th}>Username</th>
            <th style={ui.th}>Name</th>
            <th style={ui.th}>Role</th>
            <th style={ui.th}>Status</th>
            <th style={{ ...ui.th, textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => {
            const isPassive = String(u.status || 'active') === 'passive';
            const isOwnRow = userId != null && String(userId) === String(u.id);
            const busy = statusBusyId === u.id;
            return (
              <tr key={u.id} style={{ ...ui.tr, opacity: isPassive ? 0.62 : 1 }}>
                <td style={{ ...ui.td, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>{u.username}</td>
                <td style={ui.td}>{formatUserDisplayName(u)}</td>
                <td style={ui.td}><UserRoleBadge role={u.role} /></td>
                <td style={ui.td}><UserStatusBadge status={u.status} /></td>
                <td style={{ ...ui.td, textAlign: 'right' }}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'flex-end', alignItems: 'center' }}>
                    {!isPassive ? (
                      <button
                        type="button"
                        onClick={() => onSetStatus(u.id, 'passive')}
                        disabled={isOwnRow || busy}
                        style={{
                          ...USERS_ACTION_BTN.deactivate,
                          opacity: isOwnRow || busy ? 0.4 : 1,
                          cursor: isOwnRow || busy ? 'not-allowed' : 'pointer'
                        }}
                        title={isOwnRow ? 'You cannot deactivate your own account' : 'Deactivate user'}
                      >
                        {busy ? '…' : 'Deactivate'}
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => onSetStatus(u.id, 'active')}
                        disabled={busy}
                        style={{
                          ...USERS_ACTION_BTN.activate,
                          opacity: busy ? 0.4 : 1,
                          cursor: busy ? 'wait' : 'pointer'
                        }}
                        title="Activate user"
                      >
                        {busy ? '…' : 'Activate'}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => onRemove(u.id)}
                      style={USERS_ACTION_BTN.delete}
                      title="Delete user"
                    >
                      <span aria-hidden style={{ fontSize: 14, lineHeight: 1 }}>—</span>
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function UsersPage() {
  const { isAdmin, userId } = useSession();
  const requestRequiredReason = useReasonPrompt();
  const ui = PUBLISHED_FEEDS_UI;
  const [users, setUsers] = useState([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [statusBusyId, setStatusBusyId] = useState(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [actionError, setActionError] = useState('');

  async function loadUsers() {
    setUsersLoading(true);
    setActionError('');
    try {
      const { data } = await api.get('/users');
      setUsers(data?.users || []);
    } catch (err) {
      setUsers([]);
      setActionError(apiErrorMessage(err, 'Failed to load users'));
    } finally {
      setUsersLoading(false);
    }
  }

  useEffect(() => {
    if (!isAdmin) return;
    loadUsers().catch(() => {});
  }, [isAdmin]);

  function openCreateModal() {
    setSuccessMessage('');
    setActionError('');
    setShowCreateModal(true);
  }

  function closeCreateModal() {
    setShowCreateModal(false);
  }

  async function handleUserCreated() {
    setSuccessMessage('User created successfully.');
    await loadUsers();
  }

  async function removeUser(id) {
    if (!window.confirm('Are you sure you want to delete this user?')) return;
    setActionError('');
    try {
      await api.delete(`/users/${id}`);
      await loadUsers();
    } catch (err) {
      setActionError(apiErrorMessage(err, 'Failed to delete user'));
    }
  }

  async function setUserStatus(targetId, next) {
    const confirmMsg =
      next === 'passive'
        ? 'Are you sure you want to deactivate this user?'
        : 'Are you sure you want to activate this user?';
    if (!window.confirm(confirmMsg)) return;
    const reason = await requestRequiredReason(next === 'passive' ? 'Deactivate user' : 'Activate user');
    if (!reason) return;
    setStatusBusyId(targetId);
    setActionError('');
    try {
      await api.patch(`/users/${targetId}/status`, { status: next, reason });
      await loadUsers();
    } catch (err) {
      setActionError(apiErrorMessage(err, 'Failed to update status'));
    } finally {
      setStatusBusyId(null);
    }
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <section style={ui.section}>
          <h1 style={ui.pageTitle}>Users</h1>
          <p style={ui.pageSub}>Admin access required.</p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <h1 style={ui.pageTitle}>Users</h1>
            <p style={ui.pageSub}>Manage platform accounts, roles, and account status.</p>
          </div>
          <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>+ Create User</button>
        </div>

        {successMessage ? (
          <div style={{ ...ui.banner, marginTop: 12, borderColor: '#166534', color: '#86efac', background: 'rgba(22,101,52,0.18)' }}>
            {successMessage}
          </div>
        ) : null}
        {actionError ? (
          <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5', background: 'rgba(127,29,29,0.18)' }}>
            {actionError}
          </div>
        ) : null}

        <div style={{ ...ui.formPanel, marginTop: 16 }}>
          <UsersTable
            users={users}
            usersLoading={usersLoading}
            userId={userId}
            statusBusyId={statusBusyId}
            onSetStatus={setUserStatus}
            onRemove={removeUser}
          />
        </div>
      </section>

      {showCreateModal ? (
        <CreateUserModal
          onClose={closeCreateModal}
          onCreated={handleUserCreated}
        />
      ) : null}
    </AppShell>
  );
}


function SuppressionExpirationFields({ ui, preset, setPreset, customDate, setCustomDate, disabled = false }) {
  return (
    <div style={{ marginTop: 12 }}>
      <span style={ui.label}>Expiration</span>
      <div style={{ display: 'grid', gap: 8, marginTop: 6 }}>
        {[
          { id: 'never', label: 'Never' },
          { id: '7d', label: '7 days' },
          { id: '30d', label: '30 days' },
          { id: 'custom', label: 'Custom date' }
        ].map((opt) => (
          <label key={opt.id} style={ui.checkLabel}>
            <input type="radio" name="suppression-expiration" value={opt.id} checked={preset === opt.id} onChange={() => setPreset(opt.id)} disabled={disabled} />
            {opt.label}
          </label>
        ))}
      </div>
      {preset === 'custom' ? (
        <input type="datetime-local" value={customDate} onChange={(e) => setCustomDate(e.target.value)} disabled={disabled} style={{ ...ui.input, marginTop: 8 }} />
      ) : null}
    </div>
  );
}

function IOCSuppressionsPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { isAdmin } = useSession();
  const requestRequiredReason = useReasonPrompt();
  const ui = PUBLISHED_FEEDS_UI;

  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState({ active: 0, disabled: 0, expired: 0, total: 0 });
  const [page, setPage] = useState(Math.max(1, Number(searchParams.get('page') || 1)));
  const [pageSize] = useState(25);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [searchInput, setSearchInput] = useState(String(searchParams.get('search') || ''));
  const [search, setSearch] = useState(String(searchParams.get('search') || ''));
  const [iocType, setIocType] = useState(String(searchParams.get('ioc_type') || 'all'));
  const initialStatus = String(searchParams.get('status') || 'all');
  const [statusFilter, setStatusFilter] = useState(initialStatus === 'inactive' ? 'disabled' : initialStatus);
  const [createdBy, setCreatedBy] = useState(String(searchParams.get('created_by') || ''));
  const [showAdd, setShowAdd] = useState(false);
  const [addValue, setAddValue] = useState('');
  const [addType, setAddType] = useState('auto');
  const [addTypeTouched, setAddTypeTouched] = useState(false);
  const [addReason, setAddReason] = useState('');
  const [addPreset, setAddPreset] = useState('never');
  const [addCustomDate, setAddCustomDate] = useState('');
  const [addSaving, setAddSaving] = useState(false);
  const [addError, setAddError] = useState('');
  const [editItem, setEditItem] = useState(null);
  const [editReason, setEditReason] = useState('');
  const [editEnabled, setEditEnabled] = useState(true);
  const [editPreset, setEditPreset] = useState('never');
  const [editCustomDate, setEditCustomDate] = useState('');
  const [editSaving, setEditSaving] = useState(false);
  const [editError, setEditError] = useState('');
  const [deleteItem, setDeleteItem] = useState(null);
  const [deleteSaving, setDeleteSaving] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [toast, setToast] = useState('');

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = { page, pageSize, sort: 'created_at_desc' };
      if (search) params.search = search;
      if (iocType && iocType !== 'all') params.ioc_type = iocType;
      if (createdBy.trim()) params.created_by = createdBy.trim();
      if (statusFilter && statusFilter !== 'all') {
        params.status = statusFilter === 'inactive' ? 'disabled' : statusFilter;
      }
      const { data } = await api.get('/ioc-suppressions', { params });
      const loaded = Array.isArray(data?.items) ? data.items : [];
      const nextTotal = Number(data?.total || 0);
      setItems(loaded);
      setTotal(nextTotal);
      setStats({
        active: Number(data?.stats?.active || 0),
        disabled: Number(data?.stats?.disabled || 0),
        expired: Number(data?.stats?.expired || 0),
        total: Number(data?.stats?.total || 0)
      });
      const nextTotalPages = Math.max(1, Math.ceil(nextTotal / pageSize));
      if (page > nextTotalPages) setPage(nextTotalPages);
    } catch (err) {
      setItems([]);
      setTotal(0);
      setStats({ active: 0, disabled: 0, expired: 0, total: 0 });
      setError(apiErrorMessage(err, 'Failed to load suppressions'));
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search, iocType, statusFilter, createdBy]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  useEffect(() => {
    const next = new URLSearchParams();
    if (search) next.set('search', search);
    if (page > 1) next.set('page', String(page));
    if (iocType !== 'all') next.set('ioc_type', iocType);
    if (statusFilter !== 'all') next.set('status', statusFilter);
    if (createdBy.trim()) next.set('created_by', createdBy.trim());
    setSearchParams(next, { replace: true });
  }, [search, page, iocType, statusFilter, createdBy, setSearchParams]);

  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(() => setToast(''), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  function applyFilters() {
    setPage(1);
    setSearch(searchInput.trim());
  }

  function resetAddForm() {
    setAddValue('');
    setAddType('auto');
    setAddTypeTouched(false);
    setAddReason('');
    setAddPreset('never');
    setAddCustomDate('');
    setAddError('');
  }

  async function submitAdd() {
    if (addSaving) return;
    const value = String(addValue || '').trim();
    const reason = String(addReason || '').trim();
    if (!value) { setAddError('IOC value is required'); return; }
    if (reason.length < 3) { setAddError('Reason is required (min 3 characters)'); return; }
    const body = { ioc_value: value, reason };
    if (addTypeTouched && addType && addType !== 'auto') body.ioc_type = addType;
    const expiresAt = expiresAtFromPreset(addPreset, addCustomDate);
    if (expiresAt) body.expires_at = expiresAt;
    setAddSaving(true);
    setAddError('');
    try {
      await api.post('/ioc-suppressions', body);
      setShowAdd(false);
      resetAddForm();
      setToast('Suppression created');
      setPage(1);
      await load();
    } catch (err) {
      const msg = apiErrorMessage(err, 'Failed to create suppression');
      setAddError(msg.includes('Forbidden') ? 'You do not have permission to create suppressions' : msg);
    } finally {
      setAddSaving(false);
    }
  }

  function openEdit(item) {
    setEditItem(item);
    setEditReason(String(item?.reason || ''));
    setEditEnabled(item?.active !== false);
    setEditError('');
    if (!item?.expires_at) {
      setEditPreset('never');
      setEditCustomDate('');
    } else {
      setEditPreset('custom');
      const d = new Date(item.expires_at);
      if (!Number.isNaN(d.getTime())) {
        const pad = (n) => String(n).padStart(2, '0');
        setEditCustomDate(`${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`);
      } else {
        setEditCustomDate('');
      }
    }
  }

  async function saveEdit() {
    if (!editItem?.id || editSaving) return;
    const reason = String(editReason || '').trim();
    if (!reason) {
      setEditError('Reason is required');
      return;
    }
    setEditSaving(true);
    setEditError('');
    try {
      await api.patch(`/ioc-suppressions/${editItem.id}`, {
        reason,
        expires_at: expiresAtFromPreset(editPreset, editCustomDate),
        active: Boolean(editEnabled)
      });
      setEditItem(null);
      setToast('Suppression updated');
      await load();
    } catch (err) {
      const msg = apiErrorMessage(err, 'Suppression failed');
      setEditError(msg.includes('Forbidden') ? 'You do not have permission to modify suppressions' : msg);
    } finally {
      setEditSaving(false);
    }
  }

  async function confirmDelete() {
    if (!deleteItem?.id || deleteSaving) return;
    const reason = await requestRequiredReason('Delete IOC suppression');
    if (!reason) return;
    setDeleteSaving(true);
    setDeleteError('');
    try {
      await api.delete(`/ioc-suppressions/${deleteItem.id}`, { data: { reason } });
      setDeleteItem(null);
      setToast('Suppression deleted');
      await load();
    } catch (err) {
      const msg = apiErrorMessage(err, 'Suppression failed');
      setDeleteError(msg.includes('Forbidden') ? 'You do not have permission to modify suppressions' : msg);
    } finally {
      setDeleteSaving(false);
    }
  }

  async function resolveIocDetailsUrl(item) {
    const iocValue = String(item?.ioc_value || '').trim();
    try {
      await navigateToIocDetailsFromSuppression(item, navigate);
    } catch (err) {
      console.warn('[ioc-suppressions] View IOC failed', { item, detail: err?.message || err });
      setToast(`Could not resolve IOC details for ${iocValue || 'this IOC'}`);
    }
  }

  return (
    <AppShell>
      <section className="published-feeds-page" style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <h2 style={ui.pageTitle}>IOC Suppressions</h2>
            <p style={ui.pageSub}>Manage false positives and suppressed indicators to prevent recurring feed noise.</p>
          </div>
          {isAdmin ? (
            <button type="button" style={ui.btnPrimary} onClick={() => { resetAddForm(); setShowAdd(true); }}>Add Suppression</button>
          ) : null}
        </div>

        {!isAdmin ? (
          <div style={{ ...ui.banner, borderColor: '#475569', background: 'rgba(100,116,139,0.15)', color: '#cbd5e1', marginBottom: 16 }}>
            Readonly users can view suppression status but cannot modify it.
          </div>
        ) : null}

        {toast ? <div style={{ ...ui.banner, marginBottom: 12 }}>{toast}</div> : null}
        {error ? <div style={{ marginBottom: 12, padding: 12, borderRadius: 8, border: '1px solid #7f1d1d', background: 'rgba(127,29,29,0.25)', color: '#fca5a5' }}>{error}</div> : null}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(120px, 1fr))', gap: 10, marginBottom: 16 }}>
          {[
            ['Active', stats.active],
            ['Disabled', stats.disabled],
            ['Expired', stats.expired],
            ['Total', stats.total]
          ].map(([label, val]) => (
            <div key={label} style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>{label}</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{val}</div>
            </div>
          ))}
        </div>

        <div style={{ ...ui.formPanel, marginBottom: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            <div>
              <span style={ui.label}>Search IOC</span>
              <input value={searchInput} onChange={(e) => setSearchInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && applyFilters()} placeholder="IOC value or reason" style={ui.input} />
            </div>
            <div>
              <span style={ui.label}>IOC Type</span>
              <select value={iocType} onChange={(e) => { setIocType(e.target.value); setPage(1); }} style={ui.select}>
                <option value="all">All</option>
                {SUPPRESSION_IOC_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <span style={ui.label}>Status</span>
              <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }} style={ui.select}>
                <option value="all">All</option>
                <option value="active">Active</option>
                <option value="disabled">Disabled</option>
                <option value="expired">Expired</option>
              </select>
            </div>
            <div>
              <span style={ui.label}>Created by</span>
              <input value={createdBy} onChange={(e) => setCreatedBy(e.target.value)} placeholder="Optional" style={ui.input} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button type="button" style={ui.btnPrimary} onClick={applyFilters}>Apply filters</button>
            <button type="button" style={ui.btn} onClick={() => { setSearchInput(''); setSearch(''); setIocType('all'); setStatusFilter('all'); setCreatedBy(''); setPage(1); }}>Reset</button>
          </div>
          <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>Summary cards show global totals for the current search/type filters.</div>
        </div>

        {loading ? <div style={{ color: '#94a3b8', marginBottom: 12 }}>Loading suppressions…</div> : null}
        {!loading && !items.length ? (
          <div style={{ padding: 16, border: '1px solid #334155', borderRadius: 10, background: '#0f172a', color: '#94a3b8' }}>
            <div style={{ fontWeight: 600, color: '#e2e8f0', marginBottom: 6 }}>No IOC suppressions yet.</div>
            False positives marked from IOC Details will appear here.
          </div>
        ) : null}

        {items.length ? (
          <div style={{ overflowX: 'auto', border: '1px solid #334155', borderRadius: 10 }}>
            <table className="ioc-table published-feeds-table" width="100%" style={{ borderCollapse: 'collapse', minWidth: 900 }}>
              <thead style={ui.thead}>
                <tr>
                  {['IOC', 'Type', 'Reason', 'Created by', 'Created at', 'Expires', 'Status', 'Actions'].map((h) => (
                    <th key={h} style={ui.th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id} style={ui.tr}>
                    <td style={{ ...ui.td, maxWidth: 220, overflowWrap: 'anywhere' }}>{item.ioc_value}</td>
                    <td style={ui.td}>{item.ioc_type}</td>
                    <td style={{ ...ui.td, maxWidth: 260, overflowWrap: 'anywhere' }}>{item.reason}</td>
                    <td style={ui.td}>{item.created_by || '—'}</td>
                    <td style={ui.td}>{formatUserDateTime(item.created_at)}</td>
                    <td style={ui.td}>{item.expires_at ? formatUserDateTime(item.expires_at) : 'Never'}</td>
                    <td style={ui.td}><span style={suppressionStatusBadgeStyle(item.status)}>{formatSuppressionStatusLabel(item.status)}</span></td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>
                      <button type="button" style={ui.linkBtn} onClick={() => resolveIocDetailsUrl(item).catch(() => {})}>View IOC</button>
                      {isAdmin ? (
                        <>
                          {' · '}
                          <button type="button" style={ui.linkBtn} onClick={() => openEdit(item)}>Edit</button>
                          {' · '}
                          <button
                            type="button"
                            style={{ ...ui.linkBtn, color: '#fca5a5' }}
                            onClick={() => { setDeleteItem(item); setDeleteError(''); }}
                          >
                            Delete
                          </button>
                        </>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14 }}>
          <div style={{ color: '#94a3b8', fontSize: 13 }}>Page {page} / {totalPages} · {total} total</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" style={ui.btn} disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</button>
            <button type="button" style={ui.btn} disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>Next</button>
          </div>
        </div>
      </section>

      {showAdd ? (
        <ModalOverlay onClose={() => !addSaving && setShowAdd(false)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Add suppression</h3>
          <p style={ui.modalSub}>Creates an active global suppression. The IOC does not need to exist yet — if a feed imports it later, it stays effectively Suppressed / False Positive.</p>
          <div style={{ display: 'grid', gap: 12 }}>
            <div>
              <span style={ui.label}>IOC Value <span style={{ color: '#f87171' }}>*</span></span>
              <input
                value={addValue}
                onChange={(e) => setAddValue(e.target.value)}
                placeholder="e.g. 1.1.1.1, evil.com, https://bad/x, or a hash"
                style={ui.input}
                disabled={addSaving}
                autoFocus
              />
            </div>
            <div>
              <span style={ui.label}>IOC Type</span>
              <select
                value={addType}
                onChange={(e) => { setAddType(e.target.value); setAddTypeTouched(e.target.value !== 'auto'); }}
                style={ui.select}
                disabled={addSaving}
              >
                <option value="auto">Auto-detect{(() => { const d = detectSuppressionTypeUI(addValue); return d ? ` (${d})` : ''; })()}</option>
                {SUPPRESSION_IOC_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <span style={ui.label}>Reason <span style={{ color: '#f87171' }}>*</span></span>
              <textarea value={addReason} onChange={(e) => setAddReason(e.target.value)} style={ui.textarea} disabled={addSaving} maxLength={500} placeholder="Why is this a false positive?" />
            </div>
            <SuppressionExpirationFields ui={ui} preset={addPreset} setPreset={setAddPreset} customDate={addCustomDate} setCustomDate={setAddCustomDate} disabled={addSaving} />
            <div>
              <span style={ui.label}>Status</span>
              <input readOnly value="Active" style={ui.input} />
            </div>
            {addError ? <div style={{ color: '#fca5a5', fontSize: 13 }}>{addError}</div> : null}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button type="button" style={ui.btn} onClick={() => { setShowAdd(false); resetAddForm(); }} disabled={addSaving}>Cancel</button>
              <button type="button" style={ui.btnPrimary} onClick={() => submitAdd().catch(() => {})} disabled={addSaving}>{addSaving ? 'Creating…' : 'Create suppression'}</button>
            </div>
          </div>
        </ModalOverlay>
      ) : null}

      {editItem ? (
        <ModalOverlay onClose={() => !editSaving && setEditItem(null)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Edit suppression</h3>
          <div style={{ display: 'grid', gap: 12 }}>
            <div><span style={ui.label}>IOC</span><input readOnly value={editItem.ioc_value} style={ui.input} /></div>
            <div><span style={ui.label}>Type</span><input readOnly value={editItem.ioc_type} style={ui.input} /></div>
            <div>
              <span style={ui.label}>Reason</span>
              <textarea value={editReason} onChange={(e) => setEditReason(e.target.value)} style={ui.textarea} disabled={!isAdmin || editSaving} />
            </div>
            <SuppressionExpirationFields ui={ui} preset={editPreset} setPreset={setEditPreset} customDate={editCustomDate} setCustomDate={setEditCustomDate} disabled={!isAdmin || editSaving} />
            <div>
              <span style={ui.label}>Status</span>
              <select
                value={editEnabled ? 'enabled' : 'disabled'}
                onChange={(e) => setEditEnabled(e.target.value === 'enabled')}
                style={ui.select}
                disabled={!isAdmin || editSaving}
              >
                <option value="enabled">Enabled</option>
                <option value="disabled">Disabled</option>
              </select>
              <div style={{ marginTop: 6, fontSize: 12, color: '#64748b' }}>
                Enabled with a past expiration date shows as Expired until you extend expiration.
              </div>
            </div>
            {editError ? <div style={{ color: '#fca5a5', fontSize: 13 }}>{editError}</div> : null}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button type="button" style={ui.btn} onClick={() => setEditItem(null)} disabled={editSaving}>Cancel</button>
              <button type="button" style={ui.btnPrimary} onClick={() => saveEdit().catch(() => {})} disabled={!isAdmin || editSaving}>{editSaving ? 'Saving…' : 'Save changes'}</button>
            </div>
          </div>
        </ModalOverlay>
      ) : null}

      {deleteItem ? (
        <ModalOverlay onClose={() => !deleteSaving && setDeleteItem(null)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Delete suppression</h3>
          <p style={ui.modalSub}>Permanently delete this suppression? This action cannot be undone.</p>
          <div style={{ ...ui.code, marginBottom: 12 }}>{deleteItem.ioc_value} ({deleteItem.ioc_type})</div>
          {deleteError ? <div style={{ color: '#fca5a5', fontSize: 13, marginBottom: 10 }}>{deleteError}</div> : null}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button type="button" style={ui.btn} onClick={() => setDeleteItem(null)} disabled={deleteSaving}>Cancel</button>
            <button type="button" style={{ ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => confirmDelete().catch(() => {})} disabled={!isAdmin || deleteSaving}>{deleteSaving ? 'Deleting…' : 'Delete suppression'}</button>
          </div>
        </ModalOverlay>
      ) : null}
    </AppShell>
  );
}

function ActionCenterPage() {
  const navigate = useNavigate();
  const { canWrite } = useSession();
  const ui = PUBLISHED_FEEDS_UI;
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionBusyId, setActionBusyId] = useState('');
  const [nowTick, setNowTick] = useState(Date.now());
  const mountedRef = useRef(true);

  const totalPages = Math.max(1, Math.ceil(total / ACTION_CENTER_PAGE_SIZE));

  const load = useCallback(async ({ silent, page: pageOverride, status: statusOverride } = {}) => {
    if (!silent) setLoading(true);
    if (!silent) setError('');
    try {
      const params = buildActionCenterListParams({
        page: pageOverride ?? page,
        pageSize: ACTION_CENTER_PAGE_SIZE,
        status: statusOverride ?? statusFilter
      });
      const { data } = await api.get('/iocs/search-exports', { params });
      if (!mountedRef.current) return;
      setItems(Array.isArray(data?.items) ? data.items : []);
      setTotal(Number(data?.total || 0));
    } catch (err) {
      if (!mountedRef.current) return;
      if (!silent) {
        setItems([]);
        setTotal(0);
        setError(apiErrorMessage(err, 'Failed to load Action Center tasks'));
      }
    } finally {
      if (mountedRef.current && !silent) setLoading(false);
    }
  }, [page, statusFilter]);

  useEffect(() => {
    mountedRef.current = true;
    load().catch(() => {});
    return () => {
      mountedRef.current = false;
    };
  }, [load]);

  // Controlled polling while this page is mounted; clears on unmount.
  useEffect(() => {
    const intervalMs = actionCenterPollIntervalMs(items);
    const timer = setInterval(() => {
      load({ silent: true }).catch(() => {});
      setNowTick(Date.now());
    }, intervalMs);
    return () => clearInterval(timer);
  }, [items, load]);

  async function cancelTask(id) {
    setActionBusyId(id);
    try {
      await api.post(`/iocs/search-exports/${id}/cancel`);
      await load({ silent: true });
    } catch (err) {
      setError(apiErrorMessage(err, 'Failed to cancel export'));
    } finally {
      setActionBusyId('');
    }
  }

  async function retryTask(id) {
    setActionBusyId(id);
    try {
      await api.post(`/iocs/search-exports/${id}/retry`);
      setStatusFilter('all');
      setPage(1);
      await load({ silent: true, page: 1, status: 'all' });
    } catch (err) {
      setError(apiErrorMessage(err, 'Failed to retry export'));
    } finally {
      setActionBusyId('');
    }
  }

  async function createAgain(id) {
    setActionBusyId(id);
    try {
      await api.post(`/iocs/search-exports/${id}/create-again`);
      setStatusFilter('all');
      setPage(1);
      await load({ silent: true, page: 1, status: 'all' });
    } catch (err) {
      setError(apiErrorMessage(err, 'Failed to recreate export'));
    } finally {
      setActionBusyId('');
    }
  }

  function renderActions(row) {
    const busy = actionBusyId === row.id;
    if (row.status === 'ready') {
      return (
        <a href={`/api/iocs/search-exports/${row.id}/download`} style={{ color: '#86efac', fontWeight: 600 }}>
          Download
        </a>
      );
    }
    if (row.status === 'queued' || row.status === 'processing') {
      return (
        <button type="button" style={ui.btn} disabled={busy} onClick={() => cancelTask(row.id)}>
          {busy ? '…' : 'Cancel'}
        </button>
      );
    }
    if (row.status === 'failed') {
      if (!canWrite) return <span style={{ color: '#64748b' }}>—</span>;
      return (
        <button type="button" style={ui.btn} disabled={busy} onClick={() => retryTask(row.id)}>
          {busy ? '…' : 'Retry'}
        </button>
      );
    }
    if (row.status === 'expired') {
      if (!canWrite) return <span style={{ color: '#64748b' }}>—</span>;
      return (
        <button type="button" style={ui.btn} disabled={busy} onClick={() => createAgain(row.id)}>
          {busy ? '…' : 'Create again'}
        </button>
      );
    }
    return <span style={{ color: '#64748b' }}>—</span>;
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <h1 style={ui.pageTitle}>Action Center</h1>
            <p style={ui.pageSub}>Track asynchronous jobs such as IOC Search exports. More task types can appear here over time.</p>
          </div>
          <button type="button" style={ui.btn} onClick={() => load().catch(() => {})} disabled={loading}>
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 14 }}>
          {ACTION_CENTER_FILTERS.map((f) => {
            const active = statusFilter === f.key;
            return (
              <button
                key={f.key}
                type="button"
                onClick={() => { setStatusFilter(f.key); setPage(1); }}
                style={{
                  ...ui.btn,
                  ...(active ? { borderColor: '#2563eb', color: '#93c5fd', background: '#1e293b' } : {})
                }}
              >
                {f.label}
              </button>
            );
          })}
        </div>

        {error ? (
          <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{error}</div>
        ) : null}

        <div style={{ marginTop: 16, overflowX: 'auto' }}>
          <table className="ioc-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={ui.th}>Task type</th>
                <th style={ui.th}>Query</th>
                <th style={ui.th}>Status</th>
                <th style={ui.th}>Created</th>
                <th style={ui.th}>Ready</th>
                <th style={ui.th}>Records</th>
                <th style={ui.th}>Size</th>
                <th style={ui.th}>Expiration</th>
                <th style={ui.th}>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading && items.length === 0 ? (
                <tr><td colSpan={9} style={ui.td}>Loading…</td></tr>
              ) : !items.length ? (
                <tr>
                  <td colSpan={9} style={ui.td}>
                    No tasks yet. Start an IOC Search export from the IOC List page.
                    {' '}
                    <button type="button" style={ui.linkBtn} onClick={() => navigate('/ioc')}>Open IOC List</button>
                  </td>
                </tr>
              ) : items.map((row) => {
                const queryText = row.normalized_query || row.original_query || '';
                return (
                  <tr key={row.id} style={ui.tr}>
                    <td style={ui.td}>{taskTypeLabel(row.task_type)}</td>
                    <td style={{ ...ui.td, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={queryText}>
                      {truncateQuery(queryText, 80)}
                    </td>
                    <td style={ui.td}>
                      <span style={{
                        display: 'inline-block',
                        padding: '2px 8px',
                        borderRadius: 999,
                        fontSize: 12,
                        fontWeight: 600,
                        ...actionCenterStatusBadgeStyle(row.status)
                      }}
                      >
                        {formatActionCenterStatus(row)}
                      </span>
                      {row.status === 'failed' && row.failure_reason ? (
                        <div style={{ color: '#fca5a5', fontSize: 11, marginTop: 4, maxWidth: 220 }} title={row.failure_reason}>
                          {truncateQuery(row.failure_reason, 120)}
                        </div>
                      ) : null}
                    </td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>
                      {row.created_at ? formatUserDateTime(row.created_at) : '—'}
                    </td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>
                      {(row.ready_at || row.completed_at)
                        ? formatUserDateTime(row.ready_at || row.completed_at)
                        : '—'}
                    </td>
                    <td style={ui.td}>
                      {row.record_count == null ? '—' : Number(row.record_count).toLocaleString('en-US')}
                    </td>
                    <td style={ui.td}>{formatFileSize(row.file_size)}</td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }} title={row.expires_at || ''}>
                      {row.status === 'ready' ? formatExpiresIn(row.expires_at, nowTick) : (row.status === 'expired' ? 'Expired' : '—')}
                    </td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>{renderActions(row)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14, gap: 10, flexWrap: 'wrap' }}>
          <span style={{ color: '#94a3b8', fontSize: 13 }}>{total} total · page {page} / {totalPages}</span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" style={ui.btn} disabled={page <= 1 || loading} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</button>
            <button type="button" style={ui.btn} disabled={page >= totalPages || loading} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      </section>
    </AppShell>
  );
}

function IOCListPage() {
  const navigate = useNavigate();
  const { canWrite } = useSession();
  const sourceColorIndex = useSourceColorIndex();
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState({ total: 0, unique_ips: 0, by_source: [], by_type: [] });
  const [statsMeta, setStatsMeta] = useState({ calculated_at: null, stale: true, missing: true, refresh_in_progress: false });
  const [pageSize, setPageSize] = useState(25);
  const [page, setPage] = useState(1);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [columnWidths, setColumnWidths] = useState({
    index: 52,
    ip: 360,
    asn: 84,
    country: 90,
    status: 110,
    source: 260,
    confidence: 120,
    category: 120,
    classifications: 220,
    timestamp: 170
  });
  const [sortState, setSortState] = useState({ key: null, dir: null });
  const [resizeState, setResizeState] = useState(null);
  const [pagination, setPagination] = useState({ page: 1, page_size: 25, listed_items: 0, page_count: 1, mode: 'browse' });
  const [detailObservable, setDetailObservable] = useState('');
  const [detailType, setDetailType] = useState('');
  const [detailSources, setDetailSources] = useState([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [listLoading, setListLoading] = useState(false);
  const [listStatusText, setListStatusText] = useState('');
  const [searchError, setSearchError] = useState('');
  // --- DSL search + async export state ---
  const [dslActive, setDslActive] = useState(false);
  const [dslLoading, setDslLoading] = useState(false);
  const [dslResult, setDslResult] = useState(null); // { normalized_query, conditions, count_display, has_more, next_cursor, warnings, timed_out }
  const [appliedQuery, setAppliedQuery] = useState('');
  const [dslCursorStack, setDslCursorStack] = useState([]); // cursors for previous pages
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [advMatch, setAdvMatch] = useState('all');
  const [advConditions, setAdvConditions] = useState([newCondition('ioc')]);
  const [syntaxHelpOpen, setSyntaxHelpOpen] = useState(false);
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [exportFormat, setExportFormat] = useState('csv');
  const [exportScope, setExportScope] = useState('all');
  const [exportColumns, setExportColumns] = useState([...DEFAULT_EXPORT_COLUMNS]);
  const [exportBusy, setExportBusy] = useState(false);
  const [exportToast, setExportToast] = useState('');
  const dslSearchInputRef = useRef(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [statsRefreshBusy, setStatsRefreshBusy] = useState(false);
  const [statsToast, setStatsToast] = useState('');
  const statsPollRef = useRef(null);
  const [suppressionIndex, setSuppressionIndex] = useState(new Map());
  const [suppressionIndexLoading, setSuppressionIndexLoading] = useState(false);

  const loadSummary = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setSummaryLoading(true);
    try {
      const { data } = await api.get('/ioc/stats', {
        params: { status: 'active' }
      });
      setSummary(data || { total: 0, by_source: [], by_type: [] });
      setStatsMeta({
        calculated_at: data?.calculated_at || data?.last_update || null,
        stale: Boolean(data?.stale),
        missing: Boolean(data?.missing),
        refresh_in_progress: Boolean(data?.refresh_in_progress)
      });
      return data;
    } catch {
      setSummary({ total: 0, by_source: [], by_type: [] });
      setStatsMeta({ calculated_at: null, stale: true, missing: true, refresh_in_progress: false });
      return null;
    } finally {
      if (!silent) setSummaryLoading(false);
    }
  }, []);

  function stopStatsPoll() {
    if (statsPollRef.current) {
      clearInterval(statsPollRef.current);
      statsPollRef.current = null;
    }
  }

  function startStatsPoll() {
    stopStatsPoll();
    let attempts = 0;
    statsPollRef.current = setInterval(async () => {
      attempts += 1;
      if (attempts > 60) {
        stopStatsPoll();
        return;
      }
      try {
        const data = await loadSummary({ silent: true });
        if (!data?.refresh_in_progress) {
          stopStatsPoll();
          if (data?.calculated_at && !data?.missing) {
            setStatsToast('IOC stats refreshed.');
          }
        }
      } catch {
        /* keep polling until timeout */
      }
    }, 5000);
  }

  async function refreshStatsSnapshot() {
    if (!canWrite || statsRefreshBusy) return;
    setStatsRefreshBusy(true);
    setStatsToast('');
    stopStatsPoll();
    try {
      const { data } = await api.post('/ioc/stats/refresh');
      setStatsToast(data?.message || 'IOC stats refresh started. Updated stats will appear shortly.');
      await loadSummary({ silent: true });
      if (data?.queued || data?.in_progress || data?.status === 'queued' || data?.status === 'in_progress') {
        startStatsPoll();
      } else {
        setStatsToast('IOC stats refreshed.');
      }
    } catch (err) {
      setStatsToast(apiErrorMessage(err, 'Failed to start IOC stats refresh'));
    } finally {
      setStatsRefreshBusy(false);
    }
  }

  function formatStatsCalculatedAt(value) {
    if (!value) return null;
    const formatted = formatUserDateTime(value);
    return formatted === '-' ? null : formatted;
  }

  const loadData = useCallback(async (targetPage, targetSize) => {
    // When DSL search results are active, the numeric browse pager is disabled and the
    // rows come from /api/iocs/search; do not overwrite them with a browse fetch.
    if (dslActive) return;
    setListLoading(true);
    setListStatusText('Query is running. Please wait while IOC results are being processed...');
    try {
      const params = {
        page: targetPage,
        page_size: targetSize,
      };
      const listRes = await api.get('/ioc/list', { params });
      const items = listRes.data.items || [];
      setRows(items);
      setPagination(listRes.data.pagination || { page: 1, page_size: 25, listed_items: 0, page_count: 1, mode: 'browse' });
      setListStatusText('');
    } catch {
      setRows([]);
      setListStatusText('Query failed. Please try again.');
    } finally {
      setListLoading(false);
    }
  }, [dslActive]);

  useEffect(() => {
    loadSummary().catch(() => {});
    return () => { stopStatsPoll(); };
  }, [loadSummary]);

  useEffect(() => {
    let active = true;
    setSuppressionIndexLoading(true);
    fetchActiveSuppressionIndex()
      .then((idx) => { if (active) setSuppressionIndex(idx); })
      .catch(() => { if (active) setSuppressionIndex(new Map()); })
      .finally(() => { if (active) setSuppressionIndexLoading(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    loadData(page, pageSize);
  }, [page, pageSize, loadData]);

  // Search is triggered only by Enter or Search button.

  useEffect(() => {
    if (!resizeState) return undefined;

    function onMove(e) {
      const delta = e.clientX - resizeState.startX;
      const next = Math.max(60, resizeState.startWidth + delta);
      setColumnWidths((prev) => ({ ...prev, [resizeState.key]: next }));
    }

    function onUp() {
      setResizeState(null);
    }

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);

    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [resizeState]);

  function startResize(key, e) {
    e.preventDefault();
    e.stopPropagation();
    setResizeState({ key, startX: e.clientX, startWidth: columnWidths[key] || 120 });
  }

  function nextSort(key) {
    setSortState((prev) => {
      if (prev.key !== key) return { key, dir: 'asc' };
      if (prev.dir === 'asc') return { key, dir: 'desc' };
      if (prev.dir === 'desc') return { key: null, dir: null };
      return { key, dir: 'asc' };
    });
  }

  function sortIndicator(key) {
    if (sortState.key !== key || !sortState.dir) return '';
    return sortState.dir === 'asc' ? ' ?' : ' ?';
  }

  const sortedRows = useMemo(() => {
    if (!sortState.key || !sortState.dir) return rows;

    const val = (r) => {
      if (sortState.key === 'ip') return String(r.ip || '');
      if (sortState.key === 'source') return String(r.display_source || (r.source_names && r.source_names[0]) || '');
      if (sortState.key === 'status') return String(r.lifecycle_status || r.status || '');
      if (sortState.key === 'confidence') return String(r.confidence_effective || (r.confidence_set && r.confidence_set[0]) || '');
      if (sortState.key === 'category') return String(r.observable_type || 'ip');
      if (sortState.key === 'timestamp') return new Date(resolveIocListTimestamp(r) || 0).getTime();
      return '';
    };

    const copy = [...rows];
    copy.sort((a, b) => {
      const av = val(a);
      const bv = val(b);
      const cmp = typeof av === 'number' && typeof bv === 'number'
        ? av - bv
        : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: 'base' });
      return sortState.dir === 'asc' ? cmp : -cmp;
    });
    return copy;
  }, [rows, sortState]);

  async function openSourceDetails(row) {
    const obs = row.observable || row.ip;
    const obsType = row.observable_type || 'ip';
    setDetailObservable(obs);
    setDetailType(obsType);
    setDetailSources([]);
    setDetailLoading(true);
    try {
      const res = await api.get('/ioc/observable/sources', { params: { observable: obs, type: obsType } });
      setDetailSources(res.data?.sources || []);
    } catch {
      setDetailSources([]);
    } finally {
      setDetailLoading(false);
    }
  }

  function iocListSourceLabel(row) {
    return row.display_source || (row.source_names && row.source_names[0]) || 'No active source';
  }

  function formatIocListPaginationText(pag, summaryTotal, searchQuery) {
    const fmt = (n) => Number(n || 0).toLocaleString('en-US');
    const page = pag.page ?? 1;
    const pageCount = pag.page_count ?? pag.total_pages ?? 1;
    const listed = pag.listed_items ?? pag.total ?? 0;
    const global = pag.global_total ?? summaryTotal ?? listed;
    const mode = pag.mode ?? (searchQuery ? 'search' : 'browse');

    let scope;
    if (mode === 'search' || searchQuery) {
      if (listed === 0) {
        scope = 'No matching IOC found across active, expired, and suppressed records';
      } else if (!pag.is_capped && listed < 2000) {
        scope = `Showing ${fmt(listed)} matching IOC${listed === 1 ? '' : 's'} across all statuses`;
      } else {
        scope = `Showing first ${fmt(listed)} matches across all statuses`;
      }
    } else if (mode === 'filter') {
      scope = pag.is_capped
        ? `Showing latest ${fmt(listed)} filtered IOCs`
        : `Showing ${fmt(listed)} filtered IOC${listed === 1 ? '' : 's'}`;
    } else if (pag.is_capped) {
      scope = `Showing latest ${fmt(listed)} active IOCs`;
    } else {
      scope = `Showing ${fmt(listed)} active IOC${listed === 1 ? '' : 's'}`;
    }
    return `${scope} | Page ${page} / ${pageCount}`;
  }

  const typeCounts = {
    ip: summary.by_type?.find((x) => x.observable_type === 'ip')?.count || 0,
    url: summary.by_type?.find((x) => x.observable_type === 'url')?.count || 0,
    domain: summary.by_type?.find((x) => x.observable_type === 'domain')?.count || 0,
    ipv6: summary.by_type?.find((x) => x.observable_type === 'ipv6')?.count || 0,
    hash: summary.by_type?.find((x) => x.observable_type === 'hash')?.count
      ?? summary.by_type?.reduce((acc, x) => acc + (FILE_HASH_TYPES.has(x.observable_type) ? Number(x.count || 0) : 0), 0)
      ?? 0
  };

  const statsCalculatedLabel = formatStatsCalculatedAt(statsMeta.calculated_at);
  const statsNumber = (n) => summaryLoading ? '—' : Number(n || 0).toLocaleString('en-US');

  const confidenceBadgeStyle = (confidence) => ({
    display: 'inline-block',
    borderRadius: 999,
    padding: '4px 10px',
    fontSize: 12,
    fontWeight: 700,
    textTransform: 'capitalize',
    background: confidence === 'high' ? '#fee2e2' : confidence === 'medium' ? '#fef3c7' : '#dcfce7',
    color: confidence === 'high' ? '#991b1b' : confidence === 'medium' ? '#92400e' : '#166534'
  });

  // Structural parse errors map to the single friendly hint; field/operator-level
  // errors (Unknown field, unsupported operator, invalid date, ...) surface verbatim.
  const STRUCTURAL_ERROR_CODES = new Set([
    'empty_query', 'no_conditions', 'expected_field', 'expected_operator',
    'unexpected_token', 'unexpected_character', 'unclosed_quote', 'unclosed_parenthesis'
  ]);
  const INVALID_SYNTAX_HINT = 'Invalid search syntax. Example: ioc contains "example.com"';

  const runDsl = useCallback(async (query, cursor, { prevStack } = {}) => {
    setDslLoading(true);
    setSearchError('');
    try {
      const { data } = await api.post('/iocs/search', { query, page_size: pageSize, cursor: cursor || null });
      if (data.timed_out) {
        setSearchError(data.message || 'Search timed out because the query is too broad. Refine the query or create an asynchronous export.');
        setRows([]);
      } else {
        setRows(data.items || []);
      }
      setDslResult((prev) => ({
        normalized_query: data.normalized_query,
        conditions: data.conditions || [],
        // The count is computed on the first page only; preserve it while paging.
        count_display: cursor ? (prev?.count_display ?? data.count_display) : data.count_display,
        exact_count: cursor ? (prev?.exact_count ?? data.exact_count) : data.exact_count,
        has_more: Boolean(data.has_more),
        next_cursor: data.next_cursor || null,
        warnings: data.warnings || [],
        timed_out: Boolean(data.timed_out)
      }));
      setDslActive(true);
      setAppliedQuery(query);
      if (prevStack) setDslCursorStack(prevStack);
    } catch (err) {
      const payload = err?.response?.data;
      const code = payload?.error?.code;
      const msg = STRUCTURAL_ERROR_CODES.has(code)
        ? INVALID_SYNTAX_HINT
        : (payload?.message || INVALID_SYNTAX_HINT);
      setSearchError(msg);
    } finally {
      setDslLoading(false);
    }
  }, [pageSize]);

  function applyDsl() {
    const query = String(searchInput || '').trim();
    if (!query) {
      setSearchError(INVALID_SYNTAX_HINT);
      return;
    }
    setDslCursorStack([]);
    runDsl(query, null, { prevStack: [] });
  }

  function clearDsl() {
    setSearchInput('');
    setSearchError('');
    setAppliedQuery('');
    setDslResult(null);
    setDslCursorStack([]);
    setDslActive(false);
    setPage(1);
  }

  function dslNextPage() {
    if (!dslResult?.next_cursor) return;
    setDslCursorStack((stack) => [...stack, dslResult.next_cursor]);
    runDsl(appliedQuery, dslResult.next_cursor);
  }

  function dslPrevPage() {
    setDslCursorStack((stack) => {
      const next = stack.slice(0, -1);
      const cursor = next.length ? next[next.length - 1] : null;
      runDsl(appliedQuery, cursor, { prevStack: next });
      return next;
    });
  }

  function addAdvCondition() {
    setAdvConditions((list) => [...list, newCondition('ioc')]);
  }
  function removeAdvCondition(idx) {
    setAdvConditions((list) => (list.length <= 1 ? list : list.filter((_, i) => i !== idx)));
  }
  function updateAdvCondition(idx, patch) {
    setAdvConditions((list) => list.map((c, i) => {
      if (i !== idx) return c;
      const next = { ...c, ...patch };
      if (patch.field && patch.field !== c.field) {
        next.operator = defaultOperatorFor(patch.field);
        next.value = '';
        next.value2 = '';
      }
      return next;
    }));
  }
  function resetAdvanced() {
    setAdvMatch('all');
    setAdvConditions([newCondition('ioc')]);
  }
  function applyAdvancedSearch() {
    const dsl = buildDslFromConditions(advMatch, advConditions);
    if (!dsl) {
      setSearchError('Add at least one complete condition.');
      return;
    }
    setSearchInput(dsl);
    setDslCursorStack([]);
    runDsl(dsl, null, { prevStack: [] });
  }

  // Remove a single active-condition chip: rebuild the query from the remaining
  // conditions (Match All / AND) and re-run, or clear when none remain.
  function removeChip(idx) {
    const remaining = (dslResult?.conditions || []).filter((_, i) => i !== idx);
    if (!remaining.length) { clearDsl(); return; }
    const dsl = remaining.map((c) => {
      const field = c.field;
      const op = c.operator;
      const q = (v) => `"${String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
      if (op === 'in' || op === 'not_in') return `${field} ${op} (${(c.values || []).map(q).join(', ')})`;
      if (op === 'between') return `${field} between ${q(c.dates[0])} AND ${q(c.dates[1])}`;
      if (op === 'before' || op === 'after') return `${field} ${op} ${q(c.dates[0])}`;
      return `${field} ${op} ${q((c.values || [])[0] ?? '')}`;
    }).join(' AND ');
    setSearchInput(dsl);
    setDslCursorStack([]);
    runDsl(dsl, null, { prevStack: [] });
  }

  useEffect(() => {
    if (!exportToast) return undefined;
    const t = setTimeout(() => setExportToast(''), 8000);
    return () => clearTimeout(t);
  }, [exportToast]);

  async function createExport() {
    if (!appliedQuery || exportBusy) return;
    setExportBusy(true);
    try {
      await api.post('/iocs/search-exports', {
        query: appliedQuery,
        format: exportFormat,
        scope: exportScope,
        columns: exportColumns
      });
      setExportModalOpen(false);
      setExportToast('Export task created. Track its progress in Action Center.');
    } catch (err) {
      setSearchError(apiErrorMessage(err, 'Failed to create export'));
    } finally {
      setExportBusy(false);
    }
  }

  const paginationLabel = formatIocListPaginationText(pagination, summary.total, search);
  const isSearchMode = Boolean(search) || dslActive;

  return (
    <AppShell>
      <section className="ioc-list-page" style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
      <h2 style={{ marginTop: 0 }}>IOC List</h2>

      <div style={{ marginBottom: 14, padding: '12px 14px', border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: '#e2e8f0' }}>IOC Stats</div>
            <div style={{ fontSize: 11, color: '#64748b', marginTop: 4, lineHeight: 1.45 }}>
              Stats are calculated every 6 hours
              {statsCalculatedLabel ? ` · Last calculated: ${statsCalculatedLabel}` : ''}
              {statsMeta.refresh_in_progress ? ' · Stats refresh is running…' : ''}
              {statsMeta.missing || statsMeta.stale ? ' · Stats are being prepared' : ''}
            </div>
          </div>
          {canWrite ? (
            <button
              type="button"
              disabled={statsRefreshBusy}
              onClick={() => refreshStatsSnapshot().catch(() => {})}
              style={{ padding: '6px 10px', borderRadius: 8, border: '1px solid #475569', background: '#1f2937', color: '#e2e8f0', fontSize: 12, fontWeight: 600, cursor: statsRefreshBusy ? 'not-allowed' : 'pointer', opacity: statsRefreshBusy ? 0.72 : 1 }}
            >
              {statsRefreshBusy ? 'Refreshing…' : 'Refresh stats'}
            </button>
          ) : null}
        </div>
        {statsToast ? (
          <div style={{ marginBottom: 10, fontSize: 12, color: '#93c5fd' }}>{statsToast}</div>
        ) : null}
        {exportToast ? (
          <div style={{
            marginBottom: 10,
            padding: '10px 12px',
            borderRadius: 8,
            border: '1px solid #1d4ed8',
            background: 'rgba(37, 99, 235, 0.12)',
            color: '#93c5fd',
            fontSize: 13,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
            flexWrap: 'wrap'
          }}
          >
            <span>{exportToast}</span>
            <button
              type="button"
              onClick={() => navigate('/action-center')}
              style={{
                padding: '6px 10px',
                borderRadius: 8,
                border: '1px solid #2563eb',
                background: '#1e293b',
                color: '#93c5fd',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              Open Action Center
            </button>
          </div>
        ) : null}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(120px, 1fr))', gap: 10, marginBottom: 14 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827', opacity: summaryLoading ? 0.72 : 1 }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Records</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{statsNumber(summary.total)}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827', opacity: summaryLoading ? 0.72 : 1 }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>IP</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{statsNumber(typeCounts.ip)}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827', opacity: summaryLoading ? 0.72 : 1 }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>URL</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{statsNumber(typeCounts.url)}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827', opacity: summaryLoading ? 0.72 : 1 }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Hash (MD5/SHA*)</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{statsNumber(typeCounts.hash)}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827', opacity: summaryLoading ? 0.72 : 1 }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Domain</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{statsNumber(typeCounts.domain)}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827', opacity: summaryLoading ? 0.72 : 1 }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>IPv6</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{statsNumber(typeCounts.ipv6)}</div>
          </div>
        </div>
        <div style={{ borderTop: '1px solid #1e293b', paddingTop: 12 }}>
          <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8 }}>Top 5 sources</div>
          <div style={{ fontSize: 14, display: 'grid', gap: 6 }}>
            {summaryLoading ? (
              <span style={{ color: '#64748b' }}>Preparing cached stats…</span>
            ) : summary.by_source.length ? summary.by_source.slice(0, 5).map((s, idx) => (
              <div key={s.source_name} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, borderBottom: '1px dashed #334155', paddingBottom: 4 }}>
                <span style={{ color: '#cbd5e1' }}>{idx + 1}. {s.source_name}</span>
                <b style={{ color: '#e2e8f0' }}>{Number(s.count || 0).toLocaleString('en-US')}</b>
              </div>
            )) : (
              <span style={{ color: '#94a3b8' }}>{statsMeta.missing ? 'Stats are being prepared' : 'No data'}</span>
            )}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto auto auto', gap: 8, marginBottom: 10, alignItems: 'center' }}>
        <input
          ref={dslSearchInputRef}
          placeholder='Example: ioc contains "example.com" AND tag contains "mirai"'
          value={searchInput}
          onChange={(e) => {
            setSearchInput(e.target.value);
            if (searchError) setSearchError('');
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              applyDsl();
            }
          }}
        />
        <button onClick={applyDsl} disabled={dslLoading}>{dslLoading ? 'Searching…' : 'Search'}</button>
        <button onClick={() => setAdvancedOpen((v) => !v)} style={advancedOpen ? { borderColor: '#3b82f6', color: '#93c5fd' } : undefined}>Advanced Search</button>
        <button onClick={clearDsl}>Clear</button>
        <button onClick={() => setSyntaxHelpOpen((v) => !v)}>Syntax Help</button>
      </div>

      {searchError && (
        <div style={{ marginBottom: 10, padding: 10, background: '#fee2e2', border: '1px solid #fecaca', borderRadius: 6, color: '#991b1b', fontWeight: 600 }}>
          {searchError}
        </div>
      )}

      {advancedOpen && (
        <div style={{ marginBottom: 10, padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 10 }}>
            <span style={{ fontSize: 13, color: '#cbd5e1', fontWeight: 600 }}>Match:</span>
            <label style={{ color: '#e2e8f0', fontSize: 13 }}>
              <input type="radio" name="advMatch" checked={advMatch === 'all'} onChange={() => setAdvMatch('all')} /> All conditions (AND)
            </label>
            <label style={{ color: '#e2e8f0', fontSize: 13 }}>
              <input type="radio" name="advMatch" checked={advMatch === 'any'} onChange={() => setAdvMatch('any')} /> Any condition (OR)
            </label>
          </div>
          {advConditions.map((cond, idx) => {
            const spec = FIELD_BY_NAME[cond.field] || SEARCH_FIELDS[0];
            const inCell = { padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', background: '#111827', color: '#e2e8f0', fontSize: 13 };
            return (
              <div key={idx} style={{ display: 'flex', gap: 8, marginBottom: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <select style={inCell} value={cond.field} onChange={(e) => updateAdvCondition(idx, { field: e.target.value })}>
                  {SEARCH_FIELDS.map((f) => <option key={f.name} value={f.name}>{f.label}</option>)}
                </select>
                <select style={inCell} value={cond.operator} onChange={(e) => updateAdvCondition(idx, { operator: e.target.value })}>
                  {spec.operators.map((op) => <option key={op} value={op}>{OPERATOR_LABELS[op] || op}</option>)}
                </select>
                {cond.operator === 'between' ? (
                  <>
                    <input style={inCell} placeholder="YYYY-MM-DD" value={cond.value} onChange={(e) => updateAdvCondition(idx, { value: e.target.value })} />
                    <span style={{ color: '#94a3b8', fontSize: 13 }}>and</span>
                    <input style={inCell} placeholder="YYYY-MM-DD" value={cond.value2} onChange={(e) => updateAdvCondition(idx, { value2: e.target.value })} />
                  </>
                ) : (cond.operator === 'in' || cond.operator === 'not_in') ? (
                  <input style={{ ...inCell, minWidth: 260 }} placeholder="comma,separated,values" value={cond.value} onChange={(e) => updateAdvCondition(idx, { value: e.target.value })} />
                ) : spec.kind === 'enum' && spec.values ? (
                  <select style={inCell} value={cond.value} onChange={(e) => updateAdvCondition(idx, { value: e.target.value })}>
                    <option value="">— select —</option>
                    {spec.values.map((v) => <option key={v} value={v}>{v}</option>)}
                  </select>
                ) : (
                  <input style={{ ...inCell, minWidth: 220 }} placeholder={spec.kind === 'date' ? 'YYYY-MM-DD' : 'value'} value={cond.value} onChange={(e) => updateAdvCondition(idx, { value: e.target.value })} />
                )}
                <button onClick={() => removeAdvCondition(idx)} disabled={advConditions.length <= 1} title="Remove condition">✕</button>
              </div>
            );
          })}
          <div style={{ display: 'flex', gap: 8, marginTop: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <button onClick={addAdvCondition}>Add condition</button>
            <button onClick={resetAdvanced}>Reset</button>
            <button onClick={applyAdvancedSearch} style={{ borderColor: '#16a34a', color: '#86efac' }}>Apply Search</button>
            <code style={{ marginLeft: 'auto', fontSize: 12, color: '#7dd3fc', maxWidth: '60%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {buildDslFromConditions(advMatch, advConditions) || '—'}
            </code>
          </div>
        </div>
      )}

      {syntaxHelpOpen && (
        <div style={{ marginBottom: 10, padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#0b1120', color: '#cbd5e1', fontSize: 13, lineHeight: 1.6 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <b style={{ color: '#e2e8f0' }}>Search Syntax</b>
            <button onClick={() => setSyntaxHelpOpen(false)}>Close</button>
          </div>
          <p><b>Fields:</b> ioc, type, tag, source, classification, threat_actor, status, confidence, first_seen, last_changed, created_at</p>
          <p><b>Text operators:</b> contains, equals, not_equals, starts_with, ends_with, not_contains</p>
          <p><b>List operators:</b> in, not_in</p>
          <p><b>Date operators:</b> before, after, between</p>
          <p><b>Logical:</b> AND, OR, NOT, ( )</p>
          <pre style={{ background: '#111827', padding: 10, borderRadius: 8, overflowX: 'auto', color: '#93c5fd' }}>{`ioc contains "example.com"
ioc contains "example" AND tag contains "mirai"
type in ("domain", "url") AND status equals "active"
(source equals "USOM" OR source equals "URLHaus") AND confidence equals "high"
last_changed after "2026-07-01"
first_seen between "2026-07-01" AND "2026-07-22"
tag equals "mirai" AND tag equals "botnet"`}</pre>
        </div>
      )}

      {dslActive && dslResult && (
        <div style={{ marginBottom: 10, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center', marginBottom: 8 }}>
            {(dslResult.conditions || []).map((c, idx) => (
              <span key={idx} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 8px', borderRadius: 999, background: '#1e293b', border: '1px solid #334155', color: '#e2e8f0', fontSize: 12 }}>
                {chipLabel(c)}
                <button onClick={() => removeChip(idx)} style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 0 }}>✕</button>
              </span>
            ))}
            <button onClick={clearDsl} style={{ fontSize: 12 }}>Clear all</button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center' }}>
            <span style={{ color: '#e2e8f0', fontWeight: 600 }}>
              {dslResult.timed_out ? '—' : `${dslResult.count_display || '0'} matching IOCs`}
            </span>
            {dslResult.exact_count == null && !dslResult.timed_out && dslResult.count_display && String(dslResult.count_display).includes('+') ? (
              <span style={{ color: '#94a3b8', fontSize: 12 }}>Showing the latest {pageSize} · More results exist. Refine the search or export all matching IOCs.</span>
            ) : null}
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
              <button onClick={dslPrevPage} disabled={dslCursorStack.length === 0 || dslLoading}>Prev</button>
              <button onClick={dslNextPage} disabled={!dslResult.has_more || dslLoading}>Next</button>
              <button onClick={() => { setAdvancedOpen(true); if (dslSearchInputRef.current) dslSearchInputRef.current.focus(); }}>Refine search</button>
              <button onClick={() => { setExportScope('all'); setExportModalOpen(true); }} style={{ borderColor: '#16a34a', color: '#86efac' }} disabled={exportBusy}>Export matching IOCs</button>
            </div>
          </div>
          {(dslResult.warnings || []).map((w, i) => (
            <div key={i} style={{ marginTop: 6, color: '#fbbf24', fontSize: 12 }}>{w}</div>
          ))}
        </div>
      )}

      {exportModalOpen && (
        <ModalOverlay onClose={() => { if (!exportBusy) setExportModalOpen(false); }}>
          <h3 style={{ marginTop: 0 }}>Export matching IOCs</h3>
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Query</div>
            <code style={{ display: 'block', padding: 8, background: '#0b1120', borderRadius: 8, color: '#7dd3fc', fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{dslResult?.normalized_query || appliedQuery}</code>
          </div>
          <div style={{ marginBottom: 10, fontSize: 13, color: '#cbd5e1' }}>
            Estimated records: <b>{dslResult ? (dslResult.count_display || 'Calculating…') : 'Calculating…'}</b>
          </div>
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>Format</div>
            <label style={{ marginRight: 14, color: '#e2e8f0', fontSize: 13 }}><input type="radio" checked={exportFormat === 'csv'} onChange={() => setExportFormat('csv')} /> CSV</label>
            <label style={{ color: '#e2e8f0', fontSize: 13 }}><input type="radio" checked={exportFormat === 'csv_gz'} onChange={() => setExportFormat('csv_gz')} /> Compressed CSV (.csv.gz)</label>
          </div>
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>Columns</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
              {EXPORT_COLUMN_OPTIONS.map((col) => (
                <label key={col.key} style={{ color: '#e2e8f0', fontSize: 13 }}>
                  <input
                    type="checkbox"
                    checked={exportColumns.includes(col.key)}
                    onChange={(e) => setExportColumns((cols) => e.target.checked ? [...cols, col.key] : cols.filter((k) => k !== col.key))}
                  /> {col.label}
                </label>
              ))}
            </div>
          </div>
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>Export scope</div>
            <label style={{ marginRight: 14, color: '#e2e8f0', fontSize: 13 }}><input type="radio" checked={exportScope === 'all'} onChange={() => setExportScope('all')} /> All matching IOCs</label>
            <label style={{ color: '#e2e8f0', fontSize: 13 }}><input type="radio" checked={exportScope === 'preview'} onChange={() => setExportScope('preview')} /> Latest {pageSize > 0 ? 2000 : 2000} preview records</label>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button onClick={() => setExportModalOpen(false)} disabled={exportBusy}>Cancel</button>
            <button onClick={createExport} disabled={exportBusy || exportColumns.length === 0} style={{ borderColor: '#16a34a', color: '#86efac' }}>{exportBusy ? 'Creating…' : 'Create Export'}</button>
          </div>
        </ModalOverlay>
      )}

      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 10, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <label style={{ fontSize: 14, color: '#cbd5e1' }}>Page size:</label>
          <select
            value={pageSize}
            onChange={(e) => {
              const nextSize = Number(e.target.value);
              setPageSize(nextSize);
              setPage(1);
            }}
            style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', fontWeight: 600, background: '#111827', color: '#e2e8f0' }}
          >
            {[25, 50, 100].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </div>
        <div style={{ fontSize: 15, fontWeight: 600, color: '#e2e8f0' }}>
          {dslActive ? (dslResult?.timed_out ? '' : `${dslResult?.count_display || '0'} matching IOCs`) : paginationLabel}
        </div>
      </div>

      {(listLoading || listStatusText) && (
        <div style={{ marginBottom: 10, padding: 10, background: listLoading ? '#e0f2fe' : '#fff8e1', border: `1px solid ${listLoading ? '#7dd3fc' : '#ffe0a3'}`, borderRadius: 6, color: '#0f172a' }}>
          {listLoading ? 'Query is running. Please wait while IOC results are being processed...' : listStatusText}
        </div>
      )}

      {!listLoading && !listStatusText && rows.length === 0 && (
        <div style={{ marginBottom: 10, padding: 10, background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#94a3b8' }}>
          {isSearchMode
            ? 'No matching IOC found across active, expired, and suppressed records.'
            : 'No IOC records found.'}
        </div>
      )}

      <div style={{ overflowX: 'auto', border: '1px solid #e5e7eb', borderRadius: 10 }}>
        <table className="ioc-table ioc-list-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 980, background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
          <colgroup>
            <col style={{ width: columnWidths.index }} />
            <col style={{ width: columnWidths.ip }} />
            <col style={{ width: columnWidths.category }} />
            <col style={{ width: columnWidths.classifications }} />
            <col style={{ width: columnWidths.status }} />
            <col style={{ width: columnWidths.source }} />
            <col style={{ width: columnWidths.confidence }} />
            <col style={{ width: columnWidths.timestamp }} />
          </colgroup>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
              <th style={{ position: 'relative' }}>
                #
                <div onMouseDown={(e) => startResize('index', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} />
              </th>
              <th onClick={() => nextSort('ip')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>IOC{sortIndicator('ip')}<div onMouseDown={(e) => startResize('ip', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('category')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>IOC Type{sortIndicator('category')}<div onMouseDown={(e) => startResize('category', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th style={{ position: 'relative' }}>Classifications<div onMouseDown={(e) => startResize('classifications', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('status')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Status{sortIndicator('status')}<div onMouseDown={(e) => startResize('status', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('source')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Source{sortIndicator('source')}<div onMouseDown={(e) => startResize('source', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('confidence')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Confidence{sortIndicator('confidence')}<div onMouseDown={(e) => startResize('confidence', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('timestamp')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>{IOC_LIST_TIMESTAMP_PRESENTATION.label}{sortIndicator('timestamp')}<div onMouseDown={(e) => startResize('timestamp', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
            </tr>
          </thead>
          <tbody>
            {sortedRows.map((r, idx) => {
              const obs = r.observable || r.ip;
              const obsType = r.observable_type || 'ip';
              const isSuppressed = suppressionIndex.has(suppressionKey(obs, obsType));
              const lifecycleStatus = String(r.lifecycle_status || r.status || 'active').toLowerCase();
              const sourceLabel = iocListSourceLabel(r);
              const sourceExtra = Number(r.display_source_extra || 0) || Math.max(0, Number(r.source_count || 0) - 1);
              const sourceBadgeColors = r.display_source_kind === 'none'
                ? null
                : resolveSourceBadgeStyle(sourceColorIndex, sourceLabel);
              const sourceBadgeInline = sourceBadgeColors
                ? { background: sourceBadgeColors.background, color: sourceBadgeColors.color, border: sourceBadgeColors.border }
                : undefined;
              const classVisible = normalizeVisibleClassifications(r.threat_classifications);
              const classExtra = classVisible.length - 1;
              const classTitle = classVisible.length
                ? classVisible.map((x) => x.label || formatThreatClassificationLabel(x.value)).join(', ')
                : 'Unknown';
              return (
              <tr key={`${obsType}:${obs}`} style={{ borderBottom: '1px solid #f1f5f9' }}>
                <td style={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{(pagination.page - 1) * pagination.page_size + idx + 1}</td>
                <td title={obs} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                  <button
                    onClick={() => r.public_id && navigate(`/ioc/details/${encodeURIComponent(r.public_id)}`)}
                    style={{ background: 'transparent', border: 'none', color: '#93c5fd', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit', textAlign: 'left' }}
                  >
                    {obs}
                  </button>
                  {isSuppressed ? (
                    <>
                      <span style={suppressionBadgeStyle('suppressed')}>Suppressed</span>
                      <span style={suppressionBadgeStyle('fp')}>False Positive</span>
                    </>
                  ) : null}
                  {Number(r.analyst_intelligence_count || 0) > 0 ? (
                    Number(r.supports_malicious_count || 0) > 0 ? (
                      <span style={{ display: 'inline-block', borderRadius: 999, padding: '2px 8px', fontSize: 11, fontWeight: 700, border: '1px solid #7f1d1d', background: 'rgba(220,38,38,0.14)', color: '#991b1b' }}>
                        Malicious ref: {r.supports_malicious_count}
                      </span>
                    ) : (
                      <span style={{ display: 'inline-block', borderRadius: 999, padding: '2px 8px', fontSize: 11, fontWeight: 600, border: '1px solid #475569', background: '#f1f5f9', color: '#334155' }}>
                        Refs: {r.analyst_intelligence_count}
                      </span>
                    )
                  ) : null}
                </td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.observable_type || 'ip'}</td>
                <td title={classTitle} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', lineHeight: 1.35, fontSize: 12 }}>
                  {classVisible.length === 0
                    ? <span style={{ color: '#94a3b8' }}>Unknown</span>
                    : <>
                        <span>{classVisible[0].label || formatThreatClassificationLabel(classVisible[0].value)}</span>
                        {classExtra > 0 && (
                          <span style={{ marginLeft: 5, fontSize: 10, padding: '1px 5px', borderRadius: 999, background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', verticalAlign: 'middle', display: 'inline-block' }}>
                            +{classExtra}
                          </span>
                        )}
                      </>
                  }
                </td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  {iocStatusBadge(isSuppressed ? 'suppressed' : lifecycleStatus)}
                </td>
                <td title={sourceLabel} className="ioc-list-source-cell" style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                  {sourceExtra > 0 ? (
                    <button type="button" className="ioc-list-source-link" onClick={() => openSourceDetails(r)} style={sourceBadgeInline}>
                      <span className="ioc-list-source-badge-text">{sourceLabel}</span>
                      <span className="ioc-list-source-extra"> +{sourceExtra}</span>
                    </button>
                  ) : (
                    <span className={r.display_source_kind === 'none' ? 'ioc-list-source-muted' : 'ioc-list-source-badge'} style={sourceBadgeInline}>{sourceLabel}</span>
                  )}
                </td>
                <td><span style={confidenceBadgeStyle((r.confidence_effective || (r.confidence_set && r.confidence_set[0])) || 'low')}>{(r.confidence_effective || (r.confidence_set && r.confidence_set[0])) || 'low'}</span></td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontVariantNumeric: 'tabular-nums' }}>{formatUserDateTime(resolveIocListTimestamp(r))}</td>
              </tr>
            );})}
          </tbody>
        </table>
      </div>

      {!dslActive && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
          <button style={{ minWidth: 92, fontWeight: 600 }} disabled={pagination.page <= 1} onClick={() => setPage((p) => Math.max(p - 1, 1))}>Previous</button>
          <button
            style={{ minWidth: 92, fontWeight: 600 }}
            disabled={pagination.page >= (pagination.page_count ?? pagination.total_pages ?? 1)}
            onClick={() => setPage((p) => Math.min(p + 1, pagination.page_count ?? pagination.total_pages ?? 1))}
          >
            Next
          </button>
        </div>
      )}

      {detailObservable && (
        <div style={{ marginTop: 14, border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <b>Sources for {detailObservable}</b>
            <button onClick={() => { setDetailObservable(''); setDetailType(''); setDetailSources([]); }}>Close</button>
          </div>
          {detailLoading ? <div>Loading...</div> : (
            <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 13, background: '#0f172a', color: '#e2e8f0' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', background: '#111827' }}>
                  <th>Source</th><th>URL</th><th>Confidence</th><th>Category</th><th>Reported At</th>
                </tr>
              </thead>
              <tbody>
                {detailSources.map((s) => (
                  <tr key={s.id} style={{ borderBottom: '1px solid #334155' }}>
                    <td><SourceBadge index={sourceColorIndex} label={s.source_name} /></td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 260 }}>{s.source_url || '-'}</td>
                    <td>{s.confidence || '-'}</td>
                    <td>{s.category || '-'}</td>
                    <td>{formatUserDateTime(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
      </section>
    </AppShell>
  );
}

function LegacyIOCDetailsRedirect() {
  const { type, observable } = useParams();
  const navigate = useNavigate();

  useEffect(() => {
    let active = true;
    async function resolveAndRedirect() {
      try {
        const decodedType = decodeURIComponent(type || 'ip');
        const decodedObservable = decodeURIComponent(observable || '');
        if (!decodedObservable) {
          navigate('/ioc', { replace: true });
          return;
        }
        const res = await api.get('/ioc/details/resolve', { params: { type: decodedType, observable: decodedObservable } });
        const resolvedPublicId = String(res.data?.public_id || '').trim();
        if (active && resolvedPublicId) {
          navigate(`/ioc/details/${resolvedPublicId}`, { replace: true });
        } else if (active) {
          navigate('/ioc', { replace: true });
        }
      } catch {
        if (active) navigate('/ioc', { replace: true });
      }
    }
    resolveAndRedirect().catch(() => {});
    return () => { active = false; };
  }, [type, observable, navigate]);

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
        <div>Redirecting to IOC details...</div>
      </section>
    </AppShell>
  );
}

function isVtNotIndexedPayload(data) {
  return data?.status === 'not_found' && data?.is_error === false;
}

function VirusTotalEnrichmentCard({ iocId, active = true, compact = false, onSnapshot }) {
  const [state, setState] = useState({ status: 'loading', summary: null, message: '', fetchedAt: null, expiresAt: null });
  const [open, setOpen] = useState(true);
  const [showDetails, setShowDetails] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [hasLoaded, setHasLoaded] = useState(false);

  const load = useCallback(async () => {
    if (!iocId || !active) return;
    setState((s) => ({ ...s, status: 'loading' }));
    try {
      const { data } = await api.get(`/ioc/${iocId}/enrichments/virustotal`);
      if (data?.status === 'api_key_missing') return setState({ status: 'api_key_missing', summary: null, message: 'VirusTotal API key is not configured.', fetchedAt: null, expiresAt: null });
      if (isVtNotIndexedPayload(data)) {
        setHasLoaded(true);
        return setState({
          status: 'vt_not_indexed',
          summary: null,
          message: data.message || 'VirusTotal has no report for this URL yet. The URL may not have been submitted or indexed.',
          fetchedAt: data.fetched_at || null,
          expiresAt: data.expires_at || null
        });
      }
      if (data?.status === 'not_found') return setState({ status: 'not_found', summary: null, message: 'VirusTotal enrichment has not been run yet.', fetchedAt: null, expiresAt: null });
      setHasLoaded(true);
      return setState({ status: 'success', summary: data?.summary || null, message: '', fetchedAt: data?.fetched_at || null, expiresAt: data?.expires_at || null });
    } catch {
      setHasLoaded(true);
      setState({ status: 'error', summary: null, message: 'VirusTotal enrichment failed.', fetchedAt: null, expiresAt: null });
    }
  }, [iocId, active]);

  useEffect(() => {
    if (!active) return;
    load().catch(() => {});
  }, [load, active]);

  async function refresh() {
    setRefreshing(true);
    try {
      const { data } = await api.post(`/ioc/${iocId}/enrichments/virustotal/refresh`);
      setOpen(true);
      if (isVtNotIndexedPayload(data)) {
        setHasLoaded(true);
        setState({
          status: 'vt_not_indexed',
          summary: null,
          message: data.message || 'VirusTotal has no report for this URL yet. The URL may not have been submitted or indexed.',
          fetchedAt: data.fetched_at || null,
          expiresAt: data.expires_at || null
        });
        return;
      }
      setState({ status: 'success', summary: data?.summary || null, message: '', fetchedAt: data?.fetched_at || null, expiresAt: data?.expires_at || null });
    } catch (err) {
      const msg = err?.response?.status === 429
        ? 'VirusTotal rate limit reached. Try again later.'
        : (err?.response?.data?.message || 'VirusTotal enrichment failed.');
      setState({ status: 'error', summary: null, message: msg, fetchedAt: null, expiresAt: null });
    } finally { setRefreshing(false); }
  }

  const s = state.summary || {};
  const stats = s.stats || {};
  const detected = Number(s?.detection_ratio?.detected || 0);
  const total = Number(s?.detection_ratio?.total || 0);
  const severityDetected = detected > 0;
  const vendorResults = Array.isArray(s.vendor_results) ? s.vendor_results : [];
  const topDetections = (vendorResults.length ? vendorResults.filter((v) => v.category === 'malicious' || v.category === 'suspicious').slice(0, 5) : (Array.isArray(s.top_engines) ? s.top_engines : []));

  const chip = (label, value, c) => <span key={label} style={{ padding:'6px 10px', borderRadius:999, border:`1px solid ${c.b}`, background:c.bg, color:c.t, fontSize:12 }}>{label}: <b>{value}</b></span>;

  const hasDetails = state.status === 'success';
  const cardShellStyle = compact
    ? { marginBottom: 0, padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#0b1220' }
    : { marginBottom: 14, padding: 14, border: '1px solid #334155', borderRadius: 12, background: '#0f172a' };
  const compactCardStyle = { marginBottom: compact ? 0 : 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0b1220', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' };

  useEffect(() => {
    if (!onSnapshot) return;
    const s = state.summary || {};
    const stats = s.stats || {};
    onSnapshot({
      status: state.status,
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      detected: Number(s?.detection_ratio?.detected || 0),
      total: Number(s?.detection_ratio?.total || 0),
      stats
    });
  }, [state, onSnapshot]);

  if (!active && !hasLoaded) return null;

  if (!hasDetails) {
    if (state.status === 'loading') return <div style={compactCardStyle}><span style={{ color:'#94a3b8', fontSize:13 }}>Loading VirusTotal enrichment...</span></div>;
    if (state.status === 'not_found') return <div style={compactCardStyle}><span style={{ color:'#cbd5e1', fontSize:13 }}>VirusTotal enrichment has not been run yet.</span><button onClick={() => refresh().catch(()=>{})} disabled={refreshing}>{refreshing ? 'Running VirusTotal enrichment...' : 'Enrich with VirusTotal'}</button></div>;
    if (state.status === 'vt_not_indexed') {
      return (
        <div style={{ ...compactCardStyle, borderColor: '#334155', background: '#0f172a' }}>
          <span style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.5, flex: 1 }}>
            {state.message || 'VirusTotal has no report for this URL yet. The URL may not have been submitted or indexed.'}
          </span>
          <button onClick={() => refresh().catch(() => {})} disabled={refreshing}>
            {refreshing ? 'Checking VirusTotal…' : 'Check again'}
          </button>
        </div>
      );
    }
    if (state.status === 'api_key_missing') return <div style={{ ...compactCardStyle, borderColor:'#92400e' }}><span style={{ color:'#fcd34d', fontSize:13 }}>VirusTotal API key is not configured.</span><Link to="/administration/enrichment-providers" style={{ color:'#93c5fd', fontSize:13 }}>Configure in Administration</Link></div>;
    return <div style={{ ...compactCardStyle, borderColor:'#7f1d1d' }}><span style={{ color:'#fca5a5', fontSize:13 }}>{state.message || 'VirusTotal enrichment failed.'}</span><button onClick={() => refresh().catch(()=>{})} disabled={refreshing}>{refreshing ? 'Running VirusTotal enrichment...' : 'Retry'}</button></div>;
  }

  return <div style={cardShellStyle}>
    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:10 }}>
      <div>
        <div style={{ fontWeight:700, color:'#e2e8f0' }}>VirusTotal{compact ? '' : ' Intelligence'} <span style={{ marginLeft:8, border:'1px solid #1d4ed8', color:'#93c5fd', borderRadius:999, padding:'2px 8px', fontSize:11 }}>VirusTotal</span></div>
        {!compact ? <div style={{ color:'#94a3b8', fontSize:12, marginTop:4 }}>External reputation and analysis summary</div> : null}
      </div>
      <button onClick={() => setOpen((v) => !v)} style={{ padding:'6px 10px' }}>{open ? 'Collapse' : 'Expand'}</button>
    </div>

    {open ? <>
      <div style={{ display:'grid', gridTemplateColumns: compact ? '1fr' : '1.2fr 1fr', gap:12, marginTop:12 }}>
        <div style={{ border:'1px solid #334155', borderRadius:10, padding:12, background:'#0b1220' }}>
          <div style={{ fontSize: compact ? 24 : 30, fontWeight:800 }}>{detected} / {total}</div>
          <div style={{ color:'#94a3b8', fontSize:12 }}>engines flagged this IOC</div>
          <div style={{ marginTop:8, display:'inline-block', border:'1px solid #475569', borderRadius:999, padding:'3px 10px', fontSize:12, color: severityDetected ? '#fca5a5' : '#86efac' }}>{severityDetected ? 'Detected' : 'No detections'}</div>
        </div>
        <div style={{ border:'1px solid #334155', borderRadius:10, padding:12, background:'#0b1220' }}>
          <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
            {chip('Malicious', stats.malicious ?? 0, { bg:'rgba(220,38,38,.14)', b:'#7f1d1d', t:'#fca5a5' })}
            {chip('Suspicious', stats.suspicious ?? 0, { bg:'rgba(217,119,6,.14)', b:'#92400e', t:'#fcd34d' })}
            {chip('Harmless', stats.harmless ?? 0, { bg:'rgba(22,163,74,.14)', b:'#166534', t:'#86efac' })}
            {chip('Undetected', stats.undetected ?? 0, { bg:'rgba(71,85,105,.18)', b:'#475569', t:'#cbd5e1' })}
          </div>
          <div style={{ marginTop:10, fontSize:12, color:'#94a3b8' }}>Last analysis: {formatUserDateTime(s.last_analysis_date)} · Fetched: {formatUserDateTime(state.fetchedAt)}</div>
        </div>
      </div>

      {(!compact || showDetails) ? (
      <div style={{ marginTop:12, border:'1px solid #334155', borderRadius:10, overflow:'hidden' }}>
        <div style={{ padding:10, background:'#111827', borderBottom:'1px solid #334155', fontWeight:700 }}>Top detections</div>
        {topDetections.length ? <table width='100%' cellPadding='8' style={{ borderCollapse:'collapse', fontSize:13 }}><thead><tr style={{ textAlign:'left', background:'#0b1220' }}><th>Engine</th><th>Category</th><th>Result</th></tr></thead><tbody>{topDetections.map((r, i)=><tr key={`${r.engine}-${i}`} style={{ borderTop:'1px solid #334155' }}><td>{r.engine}</td><td>{r.category || '-'}</td><td style={{ whiteSpace:'normal', overflowWrap:'anywhere' }}>{r.result || '-'}</td></tr>)}</tbody></table> : <div style={{ padding:10, color:'#94a3b8' }}>Top detections are not available for this IOC.</div>}
      </div>
      ) : compact ? <div style={{ marginTop: 8 }}><button onClick={() => setShowDetails(true)}>Expand vendor results</button></div> : null}

      {showDetails && vendorResults.length > 5 ? <div style={{ marginTop:8 }}><button onClick={() => setShowAll((v) => !v)}>{showAll ? 'Hide vendor results' : 'Show all vendor results'}</button></div> : null}
      {(showDetails || !compact) && showAll ? <div style={{ marginTop:8, border:'1px solid #334155', borderRadius:10, maxHeight:260, overflow:'auto' }}><div style={{ padding:10, background:'#111827', borderBottom:'1px solid #334155', fontWeight:700 }}>Security vendors' analysis</div><table width='100%' cellPadding='8' style={{ borderCollapse:'collapse', fontSize:12 }}><thead><tr style={{ textAlign:'left', background:'#0b1220' }}><th>Vendor</th><th>Category</th><th>Result</th><th>Method</th></tr></thead><tbody>{vendorResults.map((r, i)=><tr key={`${r.engine}-${i}`} style={{ borderTop:'1px solid #334155' }}><td>{r.engine}</td><td>{r.category || '-'}</td><td style={{ maxWidth:360, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>{r.result || '-'}</td><td>{r.method || '-'}</td></tr>)}</tbody></table></div> : null}

      <div style={{ display:'flex', justifyContent:'flex-end', gap:8, marginTop:10, flexWrap:'wrap' }}>
        <button onClick={() => refresh().catch(()=>{})} disabled={refreshing}>{refreshing ? 'Refreshing...' : 'Refresh'}</button>
        {s.permalink ? <a href={s.permalink} target='_blank' rel='noopener noreferrer' style={{ padding:'7px 10px', border:'1px solid #334155', borderRadius:8, textDecoration:'none', color:'#93c5fd' }}>Open in VirusTotal</a> : null}
      </div>
    </> : null}
  </div>;
}

function isIpEnrichmentEligible(iocValue, iocType) {
  return getIpEnrichmentEligibility(iocValue, iocType);
}

function isAbuseIpdbEligible(iocValue, iocType) {
  return getAbuseIpdbEligibility(iocValue, iocType);
}

function AbuseIpdbTargetNote({ observable, ip }) {
  return (
    <div style={{ marginTop: 8, padding: 10, borderRadius: 8, border: '1px solid #334155', background: '#0b1220', fontSize: 12, minWidth: 0 }}>
      <div style={{ color: '#94a3b8' }}>Observed: <span style={{ color: '#e2e8f0', overflowWrap: 'anywhere' }}>{observable || '-'}</span></div>
      <div style={{ color: '#94a3b8', marginTop: 4 }}>Parsed IP: <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{ip || '-'}</span></div>
    </div>
  );
}

function abuseIpdbRiskMeta(label) {
  const l = String(label || '').toLowerCase();
  if (l === 'high') return { text: 'High', border: '#7f1d1d', bg: 'rgba(220,38,38,0.14)', color: '#fca5a5' };
  if (l === 'suspicious') return { text: 'Suspicious', border: '#b45309', bg: 'rgba(217,119,6,0.14)', color: '#fcd34d' };
  if (l === 'low') return { text: 'Low', border: '#1d4ed8', bg: 'rgba(37,99,235,0.14)', color: '#93c5fd' };
  if (l === 'clean') return { text: 'Clean / No reports', border: '#166534', bg: 'rgba(22,163,74,0.14)', color: '#86efac' };
  return { text: 'Unknown', border: '#475569', bg: 'rgba(71,85,105,0.18)', color: '#94a3b8' };
}

function AbuseIpdbEnrichmentCard({ iocId, iocValue, iocType, active = true, canRefresh = true, isAdmin = false, compact = false, onSnapshot }) {
  const target = useMemo(() => isAbuseIpdbEligible(iocValue, iocType), [iocValue, iocType]);
  if (!target.eligible || !target.ip) return null;

  const [state, setState] = useState({ status: 'loading', data: null, message: '' });
  const [refreshing, setRefreshing] = useState(false);
  const [hasLoaded, setHasLoaded] = useState(false);
  const ip = target.ip;

  const load = useCallback(async () => {
    if (!ip || !active) return;
    if (target.privateIp) {
      setHasLoaded(true);
      setState({ status: 'private_ip', data: null, message: 'AbuseIPDB only supports public IP reputation checks' });
      return;
    }
    setState((s) => ({ ...s, status: 'loading' }));
    try {
      const { data } = await api.get(`/enrichment/abuseipdb/ip/${encodeURIComponent(ip)}`);
      setHasLoaded(true);
      if (data?.provider_status === 'unsupported_private_ip') {
        setState({ status: 'private_ip', data, message: data?.message || 'AbuseIPDB only supports public IP reputation checks' });
      } else if (data?.provider_status === 'not_configured') {
        setState({ status: 'not_configured', data, message: 'AbuseIPDB API key is not configured' });
      } else if (data?.provider_status === 'disabled') {
        setState({ status: 'disabled', data, message: 'AbuseIPDB provider is disabled' });
      } else if (data?.enriched) {
        setState({ status: 'success', data, message: '' });
      } else if (data?.last_enriched_at && data?.provider_status && data.provider_status !== 'success') {
        setState({ status: 'failed', data, message: data?.error_message || 'AbuseIPDB lookup failed' });
      } else {
        setState({ status: 'not_found', data, message: '' });
      }
    } catch (err) {
      setHasLoaded(true);
      setState({ status: 'error', data: err?.response?.data || null, message: err?.response?.data?.message || 'Failed to load AbuseIPDB enrichment' });
    }
  }, [ip, active, target.privateIp]);

  useEffect(() => {
    if (!active) return;
    load().catch(() => {});
  }, [load, active]);

  async function refresh(force = false) {
    if (!canRefresh || target.privateIp) return;
    setRefreshing(true);
    try {
      const { data } = await api.post(`/enrichment/abuseipdb/ip/${encodeURIComponent(ip)}/refresh${force ? '?force=true' : ''}`, {
        ioc_id: iocId || undefined,
        value: iocValue || undefined,
        ioc_type: iocType || undefined
      });
      if (data?.enriched || data?.provider_status === 'success') {
        setState({ status: 'success', data, message: '' });
      } else {
        setState({ status: 'failed', data, message: data?.error_message || data?.error || data?.message || 'AbuseIPDB lookup failed' });
      }
    } catch (err) {
      const status = err?.response?.status;
      const body = err?.response?.data || {};
      const msg = status === 409
        ? (body.message || 'AbuseIPDB is not available')
        : (status === 429
          ? 'AbuseIPDB rate limit reached. Try again later.'
          : (body.message || body.error || 'AbuseIPDB lookup failed'));
      const nextStatus = body.provider_status === 'not_configured' ? 'not_configured'
        : (body.provider_status === 'disabled' ? 'disabled' : 'failed');
      setState({ status: nextStatus, data: body, message: msg });
    } finally {
      setRefreshing(false);
    }
  }

  const compactCardStyle = { marginBottom: compact ? 0 : 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0b1220', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' };
  const d = state.data || {};
  const risk = abuseIpdbRiskMeta(d.risk_label);

  useEffect(() => {
    if (!onSnapshot) return;
    onSnapshot({
      status: state.status,
      score: d.abuseConfidenceScore,
      country: d.countryCode,
      isp: d.isp,
      usage_type: d.usageType
    });
  }, [state, d.abuseConfidenceScore, d.countryCode, d.isp, d.usageType, onSnapshot]);

  if (!active && !hasLoaded) return null;

  if (state.status === 'loading') {
    return <div style={compactCardStyle}><span style={{ color: '#94a3b8', fontSize: 13 }}>Loading AbuseIPDB enrichment...</span></div>;
  }

  if (state.status === 'private_ip') {
    return (
      <div style={{ ...compactCardStyle, borderColor: '#475569', flexDirection: 'column', alignItems: 'stretch' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0' }}>AbuseIPDB <span style={{ marginLeft: 8, border: '1px solid #475569', color: '#94a3b8', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>IP only</span></div>
        <AbuseIpdbTargetNote observable={target.observable} ip={ip} />
        <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 6 }}>{state.message}</div>
      </div>
    );
  }

  if (state.status === 'not_configured') {
    return (
      <div style={{ ...compactCardStyle, borderColor: '#92400e', flexDirection: 'column', alignItems: 'stretch' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0' }}>AbuseIPDB</div>
        <div style={{ color: '#fcd34d', fontSize: 13, marginTop: 6 }}>{state.message}</div>
        {isAdmin ? <Link to="/administration/enrichment-providers" style={{ color: '#93c5fd', fontSize: 13, marginTop: 8 }}>Configure provider</Link> : null}
      </div>
    );
  }

  if (state.status === 'disabled') {
    return (
      <div style={{ ...compactCardStyle, flexDirection: 'column', alignItems: 'stretch' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0' }}>AbuseIPDB</div>
        <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 6 }}>AbuseIPDB provider is disabled</div>
      </div>
    );
  }

  if (state.status === 'not_found') {
    return (
      <div style={{ ...compactCardStyle, flexDirection: 'column', alignItems: 'stretch' }}>
        <div>
          <div style={{ fontWeight: 700, color: '#e2e8f0' }}>AbuseIPDB <span style={{ marginLeft: 8, border: '1px solid #1d4ed8', color: '#93c5fd', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>IP reputation</span></div>
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>Public IP abuse confidence and report summary</div>
        </div>
        <AbuseIpdbTargetNote observable={target.observable} ip={ip} />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ color: '#cbd5e1', fontSize: 13 }}>No AbuseIPDB data yet for {ip}</span>
          {canRefresh ? <button type="button" onClick={() => refresh(false).catch(() => {})} disabled={refreshing}>{refreshing ? 'Refreshing…' : 'Refresh AbuseIPDB'}</button> : null}
        </div>
      </div>
    );
  }

  if (state.status === 'error' || state.status === 'failed') {
    return (
      <div style={{ ...compactCardStyle, borderColor: '#7f1d1d', flexDirection: 'column', alignItems: 'stretch' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0' }}>AbuseIPDB</div>
        <span style={{ color: '#fca5a5', fontSize: 13 }}>{state.message}</span>
        {canRefresh ? <button type="button" onClick={() => refresh(false).catch(() => {})} disabled={refreshing}>{refreshing ? 'Refreshing…' : 'Retry'}</button> : null}
      </div>
    );
  }

  return (
    <div style={{ marginBottom: compact ? 0 : 14, padding: compact ? 12 : 14, border: '1px solid #334155', borderRadius: compact ? 10 : 12, background: compact ? '#0b1220' : '#0f172a' }}>
      <EnrichmentIntelligenceStyles />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontWeight: 700, color: '#e2e8f0' }}>
            AbuseIPDB
            <span style={{ marginLeft: 8, border: '1px solid #1d4ed8', color: '#93c5fd', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>IP reputation</span>
            {d.cached ? <span style={{ marginLeft: 8, border: '1px solid #475569', color: '#94a3b8', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>Cached</span> : null}
          </div>
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>
            {d.last_enriched_at || d.fetched_at ? `Last checked: ${formatUserDateTime(d.last_enriched_at || d.fetched_at)}` : 'On-demand IP reputation'}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {canRefresh ? <button type="button" onClick={() => refresh(false).catch(() => {})} disabled={refreshing}>{refreshing ? 'Refreshing…' : 'Refresh AbuseIPDB'}</button> : null}
          {canRefresh && isAdmin ? <button type="button" onClick={() => refresh(true).catch(() => {})} disabled={refreshing} title="Admin force refresh">Force</button> : null}
        </div>
      </div>

      <AbuseIpdbTargetNote observable={target.observable} ip={d.ipAddress || ip} />

      <div style={{ marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ border: `1px solid ${risk.border}`, background: risk.bg, color: risk.color, borderRadius: 999, padding: '4px 10px', fontSize: 12, fontWeight: 700 }}>
          Score: {Number.isFinite(Number(d.abuseConfidenceScore)) ? d.abuseConfidenceScore : '—'} · {risk.text}
        </span>
      </div>

      <div className="enrichment-summary-grid" style={{ marginTop: 12 }}>
        <EnrichmentFieldCard label="IP" value={d.ipAddress || ip} variant="compact" />
        <EnrichmentFieldCard label="Total Reports" value={d.totalReports} />
        <EnrichmentFieldCard label="Distinct Reporters" value={d.numDistinctUsers} />
        <EnrichmentFieldCard label="Last Reported" value={d.lastReportedAt ? formatUserDateTime(d.lastReportedAt) : null} />
        <EnrichmentFieldCard label="Country" value={d.countryCode} />
        <EnrichmentFieldCard label="ISP" value={d.isp} wide />
        <EnrichmentFieldCard label="Usage Type" value={d.usageType} wide />
        <EnrichmentFieldCard label="Domain" value={d.domain} />
        <EnrichmentFieldCard label="Hostnames" value={Array.isArray(d.hostnames) && d.hostnames.length ? d.hostnames.join(', ') : null} wide />
      </div>

      {(!compact && Array.isArray(d.recent_reports_summary) && d.recent_reports_summary.length) ? (
        <div style={{ marginTop: 12, padding: 10, borderRadius: 8, border: '1px solid #334155', background: '#0b1220', fontSize: 12 }}>
          <div style={{ color: '#cbd5e1', fontWeight: 600, marginBottom: 6 }}>Recent reports (summary)</div>
          {d.recent_reports_summary.slice(0, 5).map((r, idx) => (
            <div key={idx} style={{ color: '#94a3b8', marginTop: idx ? 6 : 0 }}>
              {r.reportedAt ? formatUserDateTime(r.reportedAt) : '—'}
              {r.categories?.length ? ` · categories: ${r.categories.join(', ')}` : ''}
              {r.comment ? ` · ${r.comment}` : ''}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function SpamhausDropEnrichmentCard({ iocId, iocValue, iocType, active = true, canRefresh = true, isAdmin = false, compact = false, onSnapshot }) {
  const [state, setState] = useState({ status: 'loading', data: null });
  const [refreshing, setRefreshing] = useState(false);
  const [hasEnriched, setHasEnriched] = useState(false);
  const [hasLoaded, setHasLoaded] = useState(false);

  const load = useCallback(async () => {
    if (!iocValue || !iocType || !active) return;
    setState((s) => ({ ...s, status: 'loading' }));
    try {
      const { data } = await api.get('/enrichment/spamhaus-drop/ioc', {
        params: { ioc_value: iocValue, ioc_type: iocType }
      });
      setHasLoaded(true);
      const status = String(data?.status || 'not_run');
      if (status === 'listed' || status === 'not_listed' || status === 'error' || status === 'failed') {
        setHasEnriched(true);
      }
      setState({ status: status === 'failed' ? 'error' : status, data });
    } catch {
      setHasLoaded(true);
      setState({ status: 'error', data: null });
    }
  }, [iocValue, iocType, active]);

  useEffect(() => {
    if (!active) return;
    load().catch(() => {});
  }, [load, active]);

  useEffect(() => {
    if (!onSnapshot) return;
    onSnapshot({ status: state.status, listed: state.data?.listed ?? null });
  }, [state, onSnapshot]);

  async function enrich() {
    if (!canRefresh) return;
    setRefreshing(true);
    try {
      const { data } = await api.post('/enrichment/spamhaus-drop/ioc/refresh', {
        ioc_value: iocValue,
        ioc_type: iocType,
        ioc_id: iocId || undefined
      });
      setHasEnriched(true);
      const status = String(data?.status || 'not_applicable');
      setState({ status: status === 'failed' ? 'error' : status, data });
    } catch {
      setHasEnriched(true);
      setState((s) => ({ ...s, status: 'error' }));
    } finally {
      setRefreshing(false);
    }
  }

  if (!active && !hasLoaded) return null;

  const d = state.data || {};
  const status = state.status;

  const cardBase = { marginBottom: compact ? 0 : 14, padding: compact ? 12 : 14, borderRadius: compact ? 10 : 12, background: compact ? '#0b1220' : '#0f172a' };

  const StatusBadge = ({ label, borderColor, color }) => (
    <span style={{ border: `1px solid ${borderColor}`, color, borderRadius: 999, padding: '2px 8px', fontSize: 11, marginLeft: 8, fontWeight: 600 }}>{label}</span>
  );

  const RefreshBtn = ({ label }) => canRefresh ? (
    <button type="button" onClick={() => enrich().catch(() => {})} disabled={refreshing} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
      {refreshing ? 'Enriching…' : label}
    </button>
  ) : null;

  if (status === 'loading') {
    return (
      <div style={{ ...cardBase, border: '1px solid #334155' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 14 }}>Spamhaus DROP</div>
        <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 6 }}>Loading Spamhaus DROP enrichment...</div>
      </div>
    );
  }

  if (status === 'not_run') {
    return (
      <div style={{ ...cardBase, border: '1px solid #334155' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 14 }}>Spamhaus DROP</div>
          {canRefresh ? (
            <button type="button" onClick={() => enrich().catch(() => {})} disabled={refreshing} style={{ fontSize: 12 }}>
              {refreshing ? 'Enriching…' : 'Enrich with Spamhaus DROP'}
            </button>
          ) : null}
        </div>
        <div style={{ color: '#64748b', fontSize: 12, marginTop: 4 }}>CIDR blocklist — click to check</div>
      </div>
    );
  }

  if (status === 'not_applicable' || status === 'disabled') {
    return null;
  }

  if (status === 'dataset_not_synced') {
    return (
      <div style={{ ...cardBase, border: '1px solid #334155' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 14 }}>
            Spamhaus DROP
            <StatusBadge label="Not synced" borderColor="#475569" color="#94a3b8" />
          </div>
          <RefreshBtn label="Refresh Spamhaus DROP" />
        </div>
        <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 6 }}>Dataset not yet synced</div>
        {isAdmin ? <Link to="/administration/enrichment-providers" style={{ color: '#93c5fd', fontSize: 12, marginTop: 6, display: 'inline-block' }}>Run sync in Administration</Link> : null}
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div style={{ ...cardBase, border: '1px solid #7f1d1d' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 14 }}>
            Spamhaus DROP
            <StatusBadge label="Error" borderColor="#7f1d1d" color="#fca5a5" />
          </div>
          <RefreshBtn label={hasEnriched ? 'Refresh Spamhaus DROP' : 'Enrich with Spamhaus DROP'} />
        </div>
        <div style={{ color: '#fca5a5', fontSize: 12, marginTop: 4 }}>Lookup failed</div>
      </div>
    );
  }

  if (status === 'listed') {
    return (
      <div style={{ ...cardBase, border: '1px solid #7f1d1d' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 14 }}>
              Spamhaus DROP
              <StatusBadge label="Listed" borderColor="#7f1d1d" color="#fca5a5" />
            </div>
            <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>IP found in Spamhaus DROP blocklist</div>
          </div>
          <RefreshBtn label="Refresh Spamhaus DROP" />
        </div>
        <div className="enrichment-summary-grid" style={{ marginTop: 10 }}>
          <EnrichmentFieldCard label="Target IP" value={d.target_ip} />
          <EnrichmentFieldCard label="Matched CIDR" value={d.matched_cidr} />
          <EnrichmentFieldCard label="List" value={d.list_type} />
          <EnrichmentFieldCard label="SBL ID" value={d.sblid} />
          <EnrichmentFieldCard label="RIR" value={d.rir} />
          <EnrichmentFieldCard label="Dataset status" value={d.dataset_status} />
        </div>
        {d.last_sync_at ? <div style={{ color: '#475569', fontSize: 11, marginTop: 10 }}>Last synced {formatUserDateTime(d.last_sync_at)}</div> : null}
      </div>
    );
  }

  if (status === 'not_listed') {
    return (
      <div style={{ ...cardBase, border: '1px solid #166534' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 14 }}>
              Spamhaus DROP
              <StatusBadge label="Not listed" borderColor="#166534" color="#86efac" />
            </div>
            <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>IP not found in Spamhaus DROP blocklist</div>
          </div>
          <RefreshBtn label="Refresh Spamhaus DROP" />
        </div>
        <div className="enrichment-summary-grid" style={{ marginTop: 10 }}>
          <EnrichmentFieldCard label="Target IP" value={d.target_ip} />
          {d.dataset_status && d.dataset_status !== 'healthy' ? <EnrichmentFieldCard label="Dataset status" value={d.dataset_status} /> : null}
        </div>
        {d.last_sync_at ? <div style={{ color: '#475569', fontSize: 11, marginTop: 8 }}>Last synced {formatUserDateTime(d.last_sync_at)}</div> : null}
      </div>
    );
  }

  return null;
}



const ENRICHMENT_INTELLIGENCE_LAYOUT_CSS = `
.enrichment-summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 10px;
  margin-top: 12px;
  align-items: stretch;
}
.enrichment-field-card {
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 8px 10px;
  background: #0b1220;
  min-width: 0;
}
.enrichment-field-card.enrichment-field-wide {
  grid-column: span 2;
}
@media (max-width: 1200px) {
  .enrichment-field-card.enrichment-field-wide {
    grid-column: span 1;
  }
}
.enrichment-field-label {
  font-size: 11px;
  color: #94a3b8;
}
.enrichment-field-value {
  font-size: 13px;
  font-weight: 700;
  color: #e2e8f0;
  margin-top: 4px;
  min-width: 0;
}
.enrichment-field-value.is-wrap {
  overflow-wrap: anywhere;
  word-break: break-word;
}
.enrichment-field-value.is-compact {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.enrichment-detail-stack {
  margin-top: 12px;
  display: grid;
  gap: 10px;
}
.enrichment-detail-block {
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 10px;
  background: #0b1220;
  min-width: 0;
}
.enrichment-detail-label {
  font-size: 11px;
  color: #94a3b8;
  margin-bottom: 6px;
}
.enrichment-detail-value {
  font-size: 13px;
  color: #e2e8f0;
  min-width: 0;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.enrichment-target-note-value.is-compact {
  display: inline-block;
  max-width: 100%;
  vertical-align: bottom;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.dnsmania-status-badge {
  display: inline-flex;
  align-items: center;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.02em;
  border-radius: 999px;
  padding: 3px 10px;
  border: 1px solid #475569;
  color: #cbd5e1;
  background: rgba(71, 85, 105, 0.18);
  white-space: nowrap;
}
.dnsmania-status-badge.is-found {
  border-color: #166534;
  color: #86efac;
  background: rgba(22, 163, 74, 0.14);
}
.dnsmania-status-badge.is-nodata {
  border-color: #475569;
  color: #94a3b8;
  background: rgba(71, 85, 105, 0.18);
}
.dnsmania-status-badge.is-failed {
  border-color: #7f1d1d;
  color: #fca5a5;
  background: rgba(220, 38, 38, 0.14);
}
.dnsmania-status-badge.is-disabled {
  border-color: #92400e;
  color: #fcd34d;
  background: rgba(217, 119, 6, 0.14);
}
.dnsmania-status-badge.is-nxdomain {
  border-color: #a16207;
  color: #fde68a;
  background: rgba(161, 98, 7, 0.16);
}
.dnsmania-status-badge.is-resolved {
  border-color: #166534;
  color: #86efac;
  background: rgba(22, 163, 74, 0.14);
}
.dnsmania-status-badge.is-warn {
  border-color: #a16207;
  color: #fde68a;
  background: rgba(161, 98, 7, 0.16);
}
.dnsmania-metric-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
  margin-top: 12px;
  align-items: start;
}
.dnsmania-metric-grid > .enrichment-field-card {
  min-height: 0;
}
@media (max-width: 900px) {
  .dnsmania-metric-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 520px) {
  .dnsmania-metric-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
.dnsmania-lookup-panel {
  margin-top: 10px;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 10px 12px;
  background: #0b1220;
  min-width: 0;
}
.dnsmania-lookup-label {
  font-size: 11px;
  color: #94a3b8;
  margin-bottom: 4px;
}
.dnsmania-lookup-value {
  font-size: 13px;
  font-weight: 700;
  color: #e2e8f0;
  overflow-wrap: anywhere;
  word-break: break-word;
  font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;
}
.dnsmania-latest-status-panel {
  margin-top: 10px;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 10px 12px;
  background: #0b1220;
  min-width: 0;
}
.dnsmania-latest-status-panel.is-nxdomain,
.dnsmania-latest-status-panel.is-warn {
  border-color: #a16207;
  background: rgba(161, 98, 7, 0.10);
}
.dnsmania-latest-status-panel.is-resolved {
  border-color: #166534;
  background: rgba(22, 163, 74, 0.08);
}
.dnsmania-latest-status-label {
  font-size: 11px;
  color: #94a3b8;
  margin-bottom: 6px;
}
.dnsmania-latest-status-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.dnsmania-latest-status-value {
  font-size: 16px;
  font-weight: 700;
  color: #e2e8f0;
  letter-spacing: 0.02em;
}
.dnsmania-latest-status-panel.is-nxdomain .dnsmania-latest-status-value,
.dnsmania-latest-status-panel.is-warn .dnsmania-latest-status-value {
  color: #fde68a;
}
.dnsmania-latest-status-panel.is-resolved .dnsmania-latest-status-value {
  color: #86efac;
}
.dnsmania-latest-status-meta {
  margin-top: 6px;
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.45;
}
.dnsmania-timeline {
  margin-top: 14px;
}
.dnsmania-timeline-list {
  display: grid;
  gap: 0;
  margin-top: 8px;
}
.dnsmania-timeline-item {
  display: grid;
  grid-template-columns: 14px minmax(0, 1fr);
  gap: 10px;
  position: relative;
}
.dnsmania-timeline-rail {
  position: relative;
  display: flex;
  justify-content: center;
}
.dnsmania-timeline-rail::before {
  content: '';
  position: absolute;
  top: 8px;
  bottom: -8px;
  width: 1px;
  background: #334155;
}
.dnsmania-timeline-item:last-child .dnsmania-timeline-rail::before {
  display: none;
}
.dnsmania-timeline-dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  border: 2px solid #64748b;
  background: #0f172a;
  margin-top: 4px;
  z-index: 1;
  box-sizing: border-box;
}
.dnsmania-timeline-item.is-latest .dnsmania-timeline-dot {
  border-color: #fde68a;
  background: #fde68a;
  box-shadow: 0 0 0 3px rgba(161, 98, 7, 0.2);
}
.dnsmania-timeline-item.is-latest.is-resolved .dnsmania-timeline-dot {
  border-color: #86efac;
  background: #86efac;
  box-shadow: 0 0 0 3px rgba(22, 163, 74, 0.18);
}
.dnsmania-timeline-body {
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 8px 10px;
  background: #0b1220;
  margin-bottom: 8px;
  min-width: 0;
}
.dnsmania-timeline-item.is-latest .dnsmania-timeline-body {
  border-color: #475569;
}
.dnsmania-timeline-title {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: 12px;
  font-weight: 700;
  color: #e2e8f0;
}
.dnsmania-timeline-values {
  margin-top: 4px;
  font-size: 12px;
  color: #cbd5e1;
  overflow-wrap: anywhere;
  font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;
}
.dnsmania-timeline-meta {
  margin-top: 4px;
  font-size: 11px;
  color: #94a3b8;
  line-height: 1.45;
}
.dnsmania-section-title {
  font-size: 12px;
  font-weight: 700;
  color: #e2e8f0;
  margin-bottom: 6px;
}
.associated-ip-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}
@media (max-width: 700px) {
  .associated-ip-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
.associated-ip-card {
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 10px;
  background: #0b1220;
  min-width: 0;
  min-height: 158px;
  box-sizing: border-box;
}
.associated-ip-card.is-error {
  border-color: #7f1d1d;
}
.associated-ip-card-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 8px;
}
.associated-ip-card-ip {
  color: #e2e8f0;
  font-size: 12px;
  font-weight: 700;
  font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;
  overflow-wrap: anywhere;
}
.associated-ip-card-body {
  display: grid;
  grid-template-columns: 26px minmax(0, 1fr);
  gap: 9px;
  margin-top: 9px;
}
.associated-ip-network-icon {
  width: 24px;
  height: 24px;
  color: #64748b;
}
.associated-ip-primary {
  color: #e2e8f0;
  font-size: 13px;
  font-weight: 700;
  overflow-wrap: anywhere;
}
.associated-ip-line {
  color: #cbd5e1;
  font-size: 11px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.associated-ip-muted {
  color: #64748b;
  font-size: 10px;
  line-height: 1.45;
}
.associated-ip-error {
  color: #fca5a5;
  font-size: 11px;
  line-height: 1.4;
  margin-top: 6px;
}
`;

function EnrichmentIntelligenceStyles() {
  return <style>{ENRICHMENT_INTELLIGENCE_LAYOUT_CSS}</style>;
}

function EnrichmentFieldCard({ label, value, variant = 'wrap', wide = false, title }) {
  const display = value == null || value === '' ? '-' : String(value);
  const valueTitle = title ?? (variant === 'compact' && display !== '-' ? display : undefined);
  const cardClass = wide ? 'enrichment-field-card enrichment-field-wide' : 'enrichment-field-card';
  const valueClass = variant === 'compact' ? 'enrichment-field-value is-compact' : 'enrichment-field-value is-wrap';
  return (
    <div className={cardClass}>
      <div className="enrichment-field-label">{label}</div>
      <div className={valueClass} title={valueTitle}>{display}</div>
    </div>
  );
}

function EnrichmentDetailBlock({ label, value }) {
  const display = value == null || value === '' ? '-' : String(value);
  return (
    <div className="enrichment-detail-block">
      <div className="enrichment-detail-label">{label}</div>
      <div className="enrichment-detail-value">{display}</div>
    </div>
  );
}

function IpEnrichmentCard({ iocId, iocValue, iocType, active = true, isAdmin = false, compact = false, onSnapshot }) {
  const target = useMemo(() => isIpEnrichmentEligible(iocValue, iocType), [iocValue, iocType]);
  if (!target.eligible || !target.ip) return null;

  const [state, setState] = useState({ status: 'loading', data: null, message: '', providerConfigured: true });
  const [enriching, setEnriching] = useState(false);
  const [hasLoaded, setHasLoaded] = useState(false);
  const ip = target.ip;

  const load = useCallback(async () => {
    if (!ip || !active) return;
    setState((s) => ({ ...s, status: 'loading' }));
    try {
      const { data } = await api.get(`/enrichment/ip/${encodeURIComponent(ip)}`);
      setHasLoaded(true);
      if (data?.enriched) {
        setState({ status: 'success', data, message: '', providerConfigured: true });
      } else if (data?.last_enriched_at && data?.provider_status && data.provider_status !== 'success') {
        setState({
          status: 'failed',
          data,
          message: data?.error_message || 'IP enrichment failed',
          providerConfigured: true
        });
      } else {
        setState({ status: 'not_found', data, message: '', providerConfigured: true });
      }
    } catch (err) {
      setHasLoaded(true);
      const msg = err?.response?.data?.error || err?.response?.data?.message || 'Failed to load IP enrichment';
      setState({ status: 'error', data: err?.response?.data || null, message: msg, providerConfigured: true });
    }
  }, [ip, active]);

  useEffect(() => {
    if (!active) return;
    load().catch(() => {});
  }, [load, active]);

  async function enrich(force = false) {
    setEnriching(true);
    try {
      const { data } = await api.post(`/enrichment/ip/${encodeURIComponent(ip)}/refresh${force ? '?force=true' : ''}`, {
        ioc_id: iocId || undefined,
        value: iocValue || undefined,
        ioc_type: iocType || undefined
      });
      if (data?.enriched || data?.provider_status === 'success') {
        setState({ status: 'success', data, message: '', providerConfigured: true });
      } else {
        setState({
          status: 'failed',
          data,
          message: data?.error_message || data?.error || data?.message || 'IP enrichment failed',
          providerConfigured: true
        });
      }
    } catch (err) {
      const notConfigured = err?.response?.status === 409;
      const msg = notConfigured
        ? 'IPinfo Lite provider is not configured'
        : (err?.response?.status === 429
          ? 'IPinfo Lite rate limit reached. Try again later.'
          : (err?.response?.data?.error || err?.response?.data?.message || 'IP enrichment failed'));
      const responseData = err?.response?.data || null;
      if (responseData?.enriched && responseData?.refresh_error) {
        setState({
          status: 'success',
          data: responseData,
          message: `${msg}. Showing the last successful cached result.`,
          providerConfigured: true
        });
      } else {
        setState({
          status: notConfigured ? 'not_configured' : 'failed',
          data: responseData,
          message: msg,
          providerConfigured: !notConfigured
        });
      }
    } finally {
      setEnriching(false);
    }
  }

  const compactCardStyle = { marginBottom: compact ? 0 : 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0b1220', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' };
  const d = state.data || {};
  const signals = d.derived_signals || {};

  useEffect(() => {
    if (!onSnapshot) return;
    onSnapshot({
      status: state.status,
      asn: d.asn,
      as_name: d.as_name,
      country: d.country || d.country_code,
      country_code: d.country_code,
      provider: 'IPinfo Lite'
    });
  }, [state.status, d.asn, d.as_name, d.country, d.country_code, onSnapshot]);

  const signalBadge = (label, on) => {
    const colors = on
      ? { b: '#166534', bg: 'rgba(22,163,74,.14)', t: '#86efac' }
      : { b: '#475569', bg: 'rgba(71,85,105,.18)', t: '#94a3b8' };
    return (
      <span key={label} style={{ padding: '4px 10px', borderRadius: 999, border: `1px solid ${colors.b}`, background: colors.bg, color: colors.t, fontSize: 11, fontWeight: 600 }}>
        {label}
      </span>
    );
  };

  if (!active && !hasLoaded) return null;

  if (state.status === 'loading') {
    return <div style={compactCardStyle}><span style={{ color: '#94a3b8', fontSize: 13 }}>Loading IP enrichment...</span></div>;
  }

  if (state.status === 'not_configured') {
    return (
      <div style={{ ...compactCardStyle, borderColor: '#92400e', flexDirection: 'column', alignItems: 'stretch' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0' }}>IP Enrichment</div>
        <div style={{ color: '#fcd34d', fontSize: 13, marginTop: 6 }}>IPinfo Lite provider is not configured</div>
        {isAdmin ? <Link to="/administration/enrichment-providers" style={{ color: '#93c5fd', fontSize: 13, marginTop: 8 }}>Configure provider</Link> : null}
      </div>
    );
  }

  if (state.status === 'not_found') {
    return (
      <div style={{ ...compactCardStyle, flexDirection: 'column', alignItems: 'stretch' }}>
        <div>
          <div style={{ fontWeight: 700, color: '#e2e8f0' }}>IP Enrichment <span style={{ marginLeft: 8, border: '1px solid #1d4ed8', color: '#93c5fd', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>IPinfo Lite</span></div>
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>ASN, country, and continent from IPinfo Lite (on-demand)</div>
        </div>
        <div style={{ marginTop: 8, padding: 10, borderRadius: 8, border: '1px solid #334155', background: '#0b1220', fontSize: 12 }}>
          <div style={{ color: '#94a3b8' }}>Observed: <span style={{ color: '#e2e8f0' }}>{target.observable || '-'}</span></div>
          <div style={{ color: '#94a3b8', marginTop: 4 }}>Parsed IP: <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{ip}</span></div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ color: '#cbd5e1', fontSize: 13 }}>No IP enrichment yet</span>
          <button type="button" onClick={() => enrich(false).catch(() => {})} disabled={enriching}>
            {enriching ? 'Enriching…' : 'Enrich IP'}
          </button>
        </div>
      </div>
    );
  }

  if (state.status === 'error' || state.status === 'failed') {
    return (
      <div style={{ ...compactCardStyle, borderColor: '#7f1d1d', flexDirection: 'column', alignItems: 'stretch' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0' }}>IP Enrichment</div>
        <span style={{ color: '#fca5a5', fontSize: 13 }}>{state.message || 'IP enrichment failed'}</span>
        <button type="button" onClick={() => enrich(false).catch(() => {})} disabled={enriching}>{enriching ? 'Enriching…' : 'Retry'}</button>
      </div>
    );
  }

  return (
    <div style={{ marginBottom: compact ? 0 : 14, padding: compact ? 12 : 14, border: '1px solid #334155', borderRadius: compact ? 10 : 12, background: compact ? '#0b1220' : '#0f172a' }}>
      <EnrichmentIntelligenceStyles />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontWeight: 700, color: '#e2e8f0' }}>
            IP Enrichment
            <span style={{ marginLeft: 8, border: '1px solid #1d4ed8', color: '#93c5fd', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>IPinfo Lite</span>
            {d.cached ? <span style={{ marginLeft: 8, border: '1px solid #475569', color: '#94a3b8', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>Cached</span> : null}
          </div>
          {!compact ? (
          <>
            <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>
              {d.last_enriched_at ? `Last enriched: ${formatUserDateTime(d.last_enriched_at)}` : 'On-demand IP intelligence'}
            </div>
            {state.message ? <div style={{ color: '#fcd34d', fontSize: 11, marginTop: 4 }}>{state.message}</div> : null}
          </>
          ) : null}
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={() => enrich(false).catch(() => {})} disabled={enriching}>{enriching ? 'Enriching…' : 'Refresh'}</button>
          {isAdmin ? <button type="button" onClick={() => enrich(true).catch(() => {})} disabled={enriching} title="Admin force refresh">Force</button> : null}
        </div>
      </div>

      <div style={{ marginTop: 8, padding: 10, borderRadius: 8, border: '1px solid #334155', background: '#0b1220', fontSize: 12, minWidth: 0 }}>
        <div style={{ color: '#94a3b8' }}>Observed: <span style={{ color: '#e2e8f0', overflowWrap: 'anywhere' }}>{target.observable || '-'}</span></div>
        <div style={{ color: '#94a3b8', marginTop: 4 }}>Parsed IP: <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{d.ip || ip}</span></div>
      </div>

      <div className="enrichment-summary-grid">
        <EnrichmentFieldCard label="IP" value={d.ip || ip} variant="compact" />
        <EnrichmentFieldCard label="ASN" value={d.asn} />
        <EnrichmentFieldCard label="AS Name" value={d.as_name} wide />
        <EnrichmentFieldCard label="AS Domain" value={d.as_domain} variant="compact" />
        <EnrichmentFieldCard label="Country" value={d.country} />
        <EnrichmentFieldCard label="Country Code" value={d.country_code} />
        <EnrichmentFieldCard label="Continent" value={d.continent} />
        <EnrichmentFieldCard label="Continent Code" value={d.continent_code} />
        <EnrichmentFieldCard label="Provider" value="IPinfo Lite" />
      </div>

      {!compact ? (
      <div style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {signalBadge('IPinfo Available', signals.ipinfo_available)}
        {signalBadge('ASN Available', signals.asn_available)}
        {signalBadge('Country Available', signals.country_available)}
        {d.cached ? signalBadge('Cached', true) : null}
      </div>
      ) : null}
    </div>
  );
}

function RdapTargetNote({ data }) {
  const host = data?.normalized_host || data?.observable_value || '-';
  const rdapDomain = data?.rdap_domain || data?.root_domain || '-';
  const differs = host !== '-' && rdapDomain !== '-' && String(host).toLowerCase() !== String(rdapDomain).toLowerCase();
  return (
    <div style={{ marginTop: 8, padding: 10, borderRadius: 8, border: '1px solid #334155', background: '#0b1220', fontSize: 12, minWidth: 0 }}>
      <div style={{ color: '#94a3b8' }}>Observed / IOC Host: <span className="enrichment-target-note-value is-compact" style={{ color: '#e2e8f0', fontWeight: 600 }} title={host !== '-' ? host : undefined}>{host}</span></div>
      <div style={{ color: '#94a3b8', marginTop: 4 }}>RDAP Domain: <span className="enrichment-target-note-value is-compact" style={{ color: '#e2e8f0', fontWeight: 600 }} title={rdapDomain !== '-' ? rdapDomain : undefined}>{rdapDomain}</span></div>
      {differs ? (
        <div style={{ color: '#fcd34d', marginTop: 8, lineHeight: 1.45 }}>
          RDAP lookup was performed for the registrable domain: <b>{rdapDomain}</b>. Threat content may appear on the observed host ({host}); WHOIS/RDAP reflects the parent domain registrant, not the tenant subdomain alone.
        </div>
      ) : null}
    </div>
  );
}

function RdapEnrichmentCard({ iocId, iocValue, iocType, active = true, isAdmin = false, compact = false, onSnapshot }) {
  const eligibility = useMemo(() => isRdapEligibleObservable(iocValue, iocType), [iocValue, iocType]);
  if (!eligibility.eligible) return null;

  const type = String(iocType || '').toLowerCase();
  const value = String(iocValue || '').trim();
  const [state, setState] = useState({ status: 'loading', data: null, message: '' });
  const [enriching, setEnriching] = useState(false);
  const [hasLoaded, setHasLoaded] = useState(false);

  const load = useCallback(async () => {
    if (!value || !active) return;
    setState((s) => ({ ...s, status: 'loading' }));
    try {
      const { data } = await api.get('/enrichment/rdap', { params: { value, ioc_type: type } });
      setHasLoaded(true);
      if (data?.enriched || data?.rdap_status === 'success') {
        setState({ status: 'success', data, message: data?.message || '' });
      } else if (data?.last_attempt_at && data?.rdap_status && data.rdap_status !== 'success') {
        setState({
          status: 'failed',
          data,
          message: data?.error_message || data?.error || 'RDAP lookup failed'
        });
      } else {
        setState({ status: 'not_found', data, message: '' });
      }
    } catch (err) {
      setHasLoaded(true);
      const msg = err?.response?.data?.error || err?.response?.data?.message || 'Failed to load RDAP enrichment';
      setState({ status: 'error', data: err?.response?.data || null, message: msg });
    }
  }, [value, type, active]);

  useEffect(() => {
    if (!active) return;
    load().catch(() => {});
  }, [load, active]);

  async function enrich(force = false) {
    setEnriching(true);
    try {
      const res = await api.post('/enrichment/rdap/refresh', {
        value,
        force: force || undefined,
        ioc_type: type,
        ioc_id: iocId || undefined
      }, {
        validateStatus: (status) => status >= 200 && status < 600,
        timeout: 30000
      });
      const data = res.data;
      if (data?.enriched || data?.rdap_status === 'success') {
        setState({ status: 'success', data, message: data?.message || '' });
      } else {
        const rawMsg = data?.error_message || data?.error || data?.message || 'RDAP lookup failed';
        const msg = /aborted/i.test(String(rawMsg))
          ? 'RDAP lookup timed out. Try Retry again.'
          : rawMsg;
        setState({ status: 'failed', data, message: msg });
      }
    } catch (err) {
      const rawMsg = err?.response?.status === 429
        ? 'RDAP rate limit reached. Try again later.'
        : (err?.response?.data?.error || err?.response?.data?.message || err?.response?.data?.error_message || err?.message || 'RDAP lookup failed');
      const msg = /aborted|timeout/i.test(String(rawMsg))
        ? 'RDAP lookup timed out. Try Retry again.'
        : rawMsg;
      setState({ status: 'failed', data: err?.response?.data || null, message: msg });
    } finally {
      setEnriching(false);
    }
  }

  const compactCardStyle = { marginBottom: compact ? 0 : 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0b1220', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' };
  const d = state.data || {};
  const signals = d.derived_signals || {};

  useEffect(() => {
    if (!onSnapshot) return;
    onSnapshot({
      status: state.status,
      root_domain: d.rdap_domain || d.root_domain,
      registrar: d.registrar,
      created: d.registration_date
    });
  }, [state.status, d.rdap_domain, d.root_domain, d.registrar, d.registration_date, onSnapshot]);

  const signalBadge = (label, on, tone = 'neutral') => {
    const colors = tone === 'warn'
      ? { b: '#92400e', bg: 'rgba(217,119,6,.14)', t: '#fcd34d' }
      : tone === 'ok'
        ? { b: '#166534', bg: 'rgba(22,163,74,.14)', t: '#86efac' }
        : { b: '#475569', bg: 'rgba(71,85,105,.18)', t: '#cbd5e1' };
    return (
      <span key={label} style={{ padding: '4px 10px', borderRadius: 999, border: `1px solid ${colors.b}`, background: colors.bg, color: colors.t, fontSize: 11, fontWeight: 600 }}>
        {label}{on === true ? '' : on === false ? ': No' : ''}
      </span>
    );
  };

  if (!active && !hasLoaded) return null;

  if (state.status === 'loading') {
    return <div style={compactCardStyle}><span style={{ color: '#94a3b8', fontSize: 13 }}>Loading RDAP enrichment...</span></div>;
  }

  if (state.status === 'not_found') {
    return (
      <div style={{ ...compactCardStyle, flexDirection: 'column', alignItems: 'stretch' }}>
        <div>
          <div style={{ fontWeight: 700, color: '#e2e8f0' }}>RDAP / WHOIS Enrichment</div>
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>Registration data from RDAP (on-demand only)</div>
        </div>
        {state.data ? <RdapTargetNote data={state.data} /> : <RdapTargetNote data={{ normalized_host: value, rdap_domain: value }} />}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ color: '#cbd5e1', fontSize: 13 }}>No RDAP enrichment yet</span>
          <button type="button" onClick={() => enrich(false).catch(() => {})} disabled={enriching}>
            {enriching ? 'Enriching…' : 'Enrich RDAP'}
          </button>
        </div>
      </div>
    );
  }

  if (state.status === 'error' || state.status === 'failed') {
    return (
      <div style={{ ...compactCardStyle, borderColor: '#7f1d1d', flexDirection: 'column', alignItems: 'stretch' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0' }}>RDAP / WHOIS Enrichment</div>
        {state.data ? <RdapTargetNote data={state.data} /> : null}
        <span style={{ color: '#fca5a5', fontSize: 13 }}>{state.message || 'RDAP lookup failed'}</span>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button type="button" onClick={() => enrich(false).catch(() => {})} disabled={enriching}>{enriching ? 'Enriching…' : 'Retry'}</button>
        </div>
      </div>
    );
  }

  const nsList = Array.isArray(d.nameservers) ? d.nameservers : [];
  const statusList = Array.isArray(d.statuses) ? d.statuses : [];

  const rdapDomainValue = d.rdap_domain || d.root_domain || '-';
  const dataSourceLabel = d.data_source === 'db'
    ? 'Database'
    : d.data_source === 'provider'
      ? 'Provider'
      : d.data_source === 'forced_provider'
        ? 'Forced Provider'
        : d.data_source === 'error'
          ? 'DB + refresh error'
          : null;
  const infoLine = d.message
    || (d.data_source === 'db' && d.last_success_at ? `Stored RDAP data found. Last fetched: ${formatUserDateTime(d.last_success_at)}` : '')
    || (d.data_source === 'provider' ? 'Fresh RDAP data fetched and stored.' : '')
    || (d.data_source === 'forced_provider' ? 'Fresh RDAP data fetched and stored.' : '');

  return (
    <div style={{ marginBottom: compact ? 0 : 14, padding: compact ? 12 : 14, border: '1px solid #334155', borderRadius: compact ? 10 : 12, background: compact ? '#0b1220' : '#0f172a' }}>
      <EnrichmentIntelligenceStyles />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontWeight: 700, color: '#e2e8f0' }}>
            RDAP / WHOIS Enrichment
            {dataSourceLabel ? <span style={{ marginLeft: 8, border: '1px solid #475569', color: '#cbd5e1', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>{dataSourceLabel}</span> : null}
            {d.cached ? <span style={{ marginLeft: 8, border: '1px solid #475569', color: '#94a3b8', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>Cached</span> : null}
          </div>
          {!compact ? (
          <>
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>
            {d.last_success_at ? `Last successful provider fetch: ${formatUserDateTime(d.last_success_at)}` : (d.last_enriched_at ? `Domain cache last enriched: ${formatUserDateTime(d.last_enriched_at)}` : 'Registration data from RDAP')}
          </div>
          {d.last_enriched_at ? (
            <div style={{ color: '#64748b', fontSize: 11, marginTop: 4, lineHeight: 1.45, maxWidth: 420 }}>
              RDAP data is cached by root domain and may predate this specific IOC record.
            </div>
          ) : null}
          </>
          ) : null}
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={() => enrich(false).catch(() => {})} disabled={enriching}>{enriching ? 'Enriching…' : 'Refresh'}</button>
          {isAdmin ? <button type="button" onClick={() => enrich(true).catch(() => {})} disabled={enriching} title="Admin force refresh (5 min cooldown)">Force</button> : null}
        </div>
      </div>

      <RdapTargetNote data={d} />

      {infoLine ? (
        <div style={{ marginTop: 8, color: d.data_source === 'error' ? '#fcd34d' : '#93c5fd', fontSize: 12, lineHeight: 1.45 }}>
          {infoLine}
        </div>
      ) : null}
      {d.last_error ? (
        <div style={{ marginTop: 6, color: '#fca5a5', fontSize: 12, lineHeight: 1.45 }}>
          Latest refresh failed{d.last_attempt_at ? ` at ${formatUserDateTime(d.last_attempt_at)}` : ''}: {d.last_error}
        </div>
      ) : null}

      <div className="enrichment-summary-grid">
        <EnrichmentFieldCard label="RDAP Domain" value={rdapDomainValue} variant="compact" wide />
        <EnrichmentFieldCard label="Registrar" value={d.registrar} variant="wrap" />
        <EnrichmentFieldCard
          label="Domain Age"
          value={Number.isFinite(Number(d.domain_age_days)) ? `${d.domain_age_days} days` : '-'}
        />
        <EnrichmentFieldCard label="Registration Date" value={formatUserDateTime(d.registration_date)} />
        <EnrichmentFieldCard label="Last Changed" value={formatUserDateTime(d.last_changed_date)} />
        <EnrichmentFieldCard label="Expiration Date" value={formatUserDateTime(d.expiration_date)} />
        <EnrichmentFieldCard label="RDAP Status" value={d.rdap_status} />
        <EnrichmentFieldCard label="Data Source" value={dataSourceLabel || d.data_source} />
      </div>

      {!compact ? (
      <div className="enrichment-detail-stack">
        <EnrichmentDetailBlock label="Nameservers" value={nsList.length ? nsList.join(', ') : '-'} />
        <EnrichmentDetailBlock label="Status Codes" value={statusList.length ? statusList.join(' · ') : '-'} />
      </div>
      ) : null}

      {!compact ? (
      <div style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {signalBadge('RDAP Available', signals.rdap_available, signals.rdap_available ? 'ok' : 'neutral')}
        {signals.newly_registered_domain ? signalBadge('Newly Registered', true, 'warn') : null}
        {signals.expiring_soon ? signalBadge('Expiring Soon', true, 'warn') : null}
        {signals.redacted_or_private ? signalBadge('Privacy / Redacted', true, 'neutral') : null}
        {signals.registrar_available ? signalBadge('Registrar Available', true, 'ok') : null}
        {signals.nameservers_available ? signalBadge('Nameservers Available', true, 'ok') : null}
      </div>
      ) : null}
    </div>
  );
}

function dnsmaniaIsNxRelation(rel) {
  const rt = String(rel?.record_type || '').toUpperCase();
  return rt === 'NXDOMAIN' || rt === 'SERVFAIL' || rt === 'REFUSED'
    || (rel?.value == null && rel?.domain == null && Boolean(rt));
}

function dnsmaniaIsResolvableRelation(rel, lookupType) {
  if (String(lookupType) === 'ip') return Boolean(rel?.domain);
  return Boolean(rel?.value);
}

function DnsmaniaStatusBadge({ kind, label }) {
  return <span className={`dnsmania-status-badge is-${kind}`}>{label}</span>;
}

function dnsmaniaLatestStatusKind(status) {
  const s = String(status || '').toUpperCase();
  if (s === 'NXDOMAIN') return 'nxdomain';
  if (s === 'SERVFAIL' || s === 'REFUSED' || s === 'TIMEOUT') return 'warn';
  if (s === 'A' || s === 'AAAA' || s === 'CNAME' || s === 'RESOLVED' || s === 'NOERROR') return 'resolved';
  return 'nodata';
}

function AssociatedIpNetworkIcon() {
  return (
    <svg className="associated-ip-network-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="4" y="3" width="16" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
      <rect x="4" y="15" width="16" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M8 6h.01M8 18h.01M12 9v6M9 12h6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function AssociatedIpEnrichmentCard({
  ip,
  result,
  loading,
  actionLoading,
  canWrite,
  isAdmin,
  onEnrich,
  onForce
}) {
  const view = compactAssociatedIpViewModel(result, ip);
  const noData = result?.data?.provider_status === 'unavailable';
  const showError = view.state === 'provider_error' && Boolean(view.error);
  const buttonStyle = { fontSize: 10, padding: '3px 7px' };

  return (
    <div className={`associated-ip-card${showError && !view.hasData ? ' is-error' : ''}`}>
      <div className="associated-ip-card-header">
        <div className="associated-ip-card-ip" title={view.ip || ip}>{view.ip || ip}</div>
        {view.hasData && isAdmin ? (
          <button type="button" style={buttonStyle} disabled={actionLoading} onClick={onForce}>
            {actionLoading ? 'Refreshing…' : 'Force'}
          </button>
        ) : null}
      </div>
      <div className="associated-ip-card-body">
        <AssociatedIpNetworkIcon />
        <div>
          {loading ? (
            <>
              <div className="associated-ip-primary">Loading IP intelligence…</div>
              <div className="associated-ip-muted" style={{ marginTop: 6 }}>Checking the central enrichment cache</div>
            </>
          ) : view.hasData ? (
            <>
              <div className="associated-ip-primary">{view.asName || '—'}</div>
              <div className="associated-ip-line">{view.asn || '—'}</div>
              <div className="associated-ip-line">AS Domain: {view.asDomain || '—'}</div>
              <div className="associated-ip-line" style={{ marginTop: 5 }}>{view.location || '—'}</div>
              <div className="associated-ip-muted" style={{ marginTop: 5 }}>{view.provider}</div>
              <div className="associated-ip-muted">
                Last checked: {view.lastChecked ? formatUserDateTime(view.lastChecked) : '—'}
              </div>
              {showError ? <div className="associated-ip-error">{view.error}. Cached data is still shown.</div> : null}
            </>
          ) : (
            <>
              <div className="associated-ip-primary">
                {noData ? 'No IP intelligence available' : (view.state === 'invalid_ip' ? 'Invalid IP' : 'Not enriched')}
              </div>
              <div className="associated-ip-muted" style={{ marginTop: 5 }}>
                {showError ? view.error : 'No central IPinfo Lite record was found.'}
              </div>
              {canWrite && view.state !== 'invalid_ip' ? (
                <button type="button" style={{ ...buttonStyle, marginTop: 8 }} disabled={actionLoading} onClick={onEnrich}>
                  {actionLoading ? 'Enriching…' : (showError ? 'Retry' : 'Enrich')}
                </button>
              ) : null}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function DnsmaniaEnrichmentCard({
  iocId,
  iocValue,
  iocType,
  active = true,
  canWrite = true,
  isAdmin = false,
  compact = false,
  onSnapshot
}) {
  const type = String(iocType || '').trim().toLowerCase();
  const value = String(iocValue || '').trim();
  const applicable = type === 'domain' || type === 'url' || type === 'ip' || type === 'ipv4' || type === 'ipv6' || type === 'hostname';
  if (!applicable || !value) return null;

  const [state, setState] = useState({ status: 'loading', data: null, message: '' });
  const [enriching, setEnriching] = useState(false);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [timelineExpanded, setTimelineExpanded] = useState(false);
  const [associatedIpIntel, setAssociatedIpIntel] = useState({ loading: false, byIp: {}, error: '' });
  const [associatedIpActions, setAssociatedIpActions] = useState({});
  const enrichInFlight = useRef(false);
  const isUrlIoc = type === 'url';
  const TIMELINE_DEFAULT_LIMIT = 5;

  const shellStyle = {
    marginBottom: compact ? 0 : 14,
    padding: compact ? 12 : 14,
    border: '1px solid #334155',
    borderRadius: compact ? 10 : 12,
    background: compact ? '#0b1220' : '#0f172a',
    minWidth: 0,
    alignSelf: 'start',
    width: '100%',
    boxSizing: 'border-box'
  };

  const load = useCallback(async () => {
    if (!value || !active) return;
    setState((s) => ({ ...s, status: 'loading' }));
    try {
      const { data } = await api.get('/enrichment/dnsmania', { params: { value, ioc_type: type } });
      setHasLoaded(true);
      const status = String(data?.status || 'not_run');
      if (status === 'completed') setState({ status: 'completed', data, message: '' });
      else if (status === 'no_data') setState({ status: 'no_data', data, message: data?.message || '' });
      else if (status === 'failed') setState({ status: 'failed', data, message: data?.error_message || data?.message || 'DNSMania enrichment failed' });
      else if (status === 'disabled') setState({ status: 'disabled', data, message: data?.message || 'DNSMania enrichment is currently disabled' });
      else if (status === 'not_configured') setState({ status: 'disabled', data, message: data?.message || 'DNSMania is not configured' });
      else setState({ status: 'not_run', data, message: '' });
    } catch (err) {
      setHasLoaded(true);
      const msg = err?.response?.data?.error || err?.response?.data?.message || 'Failed to load DNSMania enrichment';
      setState({ status: 'failed', data: err?.response?.data || null, message: msg });
    }
  }, [value, type, active]);

  useEffect(() => {
    if (!active) return;
    load().catch(() => {});
  }, [load, active]);

  async function enrich() {
    if (enrichInFlight.current || enriching) return;
    enrichInFlight.current = true;
    setEnriching(true);
    try {
      const res = await api.post('/enrichment/dnsmania/refresh', {
        value,
        ioc_type: type,
        ioc_id: iocId || undefined
      }, {
        validateStatus: (status) => status >= 200 && status < 600,
        timeout: 30000
      });
      const data = res.data || {};
      const status = String(data.status || (res.status >= 500 ? 'failed' : 'not_run'));
      if (status === 'completed') setState({ status: 'completed', data, message: '' });
      else if (status === 'no_data') setState({ status: 'no_data', data, message: data.message || '' });
      else if (status === 'disabled' || status === 'not_configured') {
        setState({ status: 'disabled', data, message: data.message || data.error || 'DNSMania enrichment is currently disabled' });
      } else {
        setState({
          status: 'failed',
          data,
          message: data.error_message || data.error || data.message || 'DNSMania enrichment failed. Please try again.'
        });
      }
    } catch (err) {
      const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'DNSMania enrichment failed. Please try again.';
      setState({ status: 'failed', data: err?.response?.data || null, message: msg });
    } finally {
      setEnriching(false);
      enrichInFlight.current = false;
    }
  }

  const d = state.data || {};
  const summary = d.summary || {};
  const relations = Array.isArray(d.relations) ? d.relations : [];
  const resolvableRelations = relations.filter((rel) => dnsmaniaIsResolvableRelation(rel, d.lookup_type));
  const nxRelations = relations.filter((rel) => dnsmaniaIsNxRelation(rel));
  const nxdomainOnly = Boolean(summary.nxdomain_observed) && resolvableRelations.length === 0 && nxRelations.length > 0;
  const latestDnsStatus = String(summary.latest_dns_status || '').toUpperCase() || null;
  const latestIsErrorStatus = latestDnsStatus === 'NXDOMAIN' || latestDnsStatus === 'SERVFAIL' || latestDnsStatus === 'REFUSED';
  const relationPresentation = getDnsmaniaPresentation({
    summary,
    relations: resolvableRelations,
    lookupType: d.lookup_type
  });
  const associatedCount = relationPresentation.formattedTotal;
  // Always prefer historical IP/domain relations for the list; NXDOMAIN-only falls back to NX rows.
  const relationList = resolvableRelations.length
    ? relationPresentation.shownRelations
    : (nxdomainOnly ? nxRelations.slice(0, 5) : []);
  const relationTotal = resolvableRelations.length
    ? relationPresentation.totalCount
    : (nxdomainOnly ? nxRelations.length : 0);
  const associatedIps = d.lookup_type === 'domain'
    ? relationList.map((rel) => String(rel?.value || '').trim()).filter(Boolean)
    : [];
  const associatedIpsKey = associatedIps.join(',');

  useEffect(() => {
    if (!active || state.status !== 'completed' || !associatedIpsKey) {
      setAssociatedIpIntel({ loading: false, byIp: {}, error: '' });
      return undefined;
    }
    let cancelled = false;
    setAssociatedIpIntel({ loading: true, byIp: {}, error: '' });
    api.get('/enrichment/ips', { params: { ips: associatedIpsKey } })
      .then(({ data }) => {
        if (cancelled) return;
        setAssociatedIpIntel({
          loading: false,
          byIp: indexAssociatedIpResults(data?.results),
          error: ''
        });
      })
      .catch((err) => {
        if (cancelled) return;
        const message = err?.response?.data?.message || err?.response?.data?.error || 'Failed to load IP intelligence';
        const failedResults = associatedIps.map((ip) => ({
          requested_ip: ip,
          normalized_ip: ip,
          state: 'provider_error',
          data: null,
          error: message
        }));
        setAssociatedIpIntel({
          loading: false,
          byIp: indexAssociatedIpResults(failedResults),
          error: message
        });
      });
    return () => { cancelled = true; };
  }, [active, state.status, associatedIpsKey]);

  async function enrichAssociatedIps(ips, force = false) {
    const requestedIps = [...new Set((Array.isArray(ips) ? ips : []).filter(Boolean))];
    if (!requestedIps.length || !canWrite || (force && !isAdmin)) return;
    setAssociatedIpActions((current) => ({
      ...current,
      ...Object.fromEntries(requestedIps.map((ip) => [ip.toLowerCase(), true]))
    }));
    try {
      const { data } = await api.post('/enrichment/ips/enrich', {
        ips: requestedIps,
        force: force || undefined,
        ioc_id: iocId || undefined,
        value: iocValue || undefined,
        ioc_type: iocType || undefined
      });
      const updated = indexAssociatedIpResults(data?.results);
      setAssociatedIpIntel((current) => ({
        loading: false,
        error: '',
        byIp: { ...current.byIp, ...updated }
      }));
    } catch (err) {
      const message = err?.response?.data?.message || err?.response?.data?.error || 'IP enrichment failed';
      setAssociatedIpIntel((current) => {
        const next = { ...current.byIp };
        for (const ip of requestedIps) {
          const key = ip.toLowerCase();
          next[key] = {
            requested_ip: ip,
            normalized_ip: ip,
            state: 'provider_error',
            data: next[key]?.data || null,
            error: message
          };
        }
        return { loading: false, byIp: next, error: message };
      });
    } finally {
      setAssociatedIpActions((current) => ({
        ...current,
        ...Object.fromEntries(requestedIps.map((ip) => [ip.toLowerCase(), false]))
      }));
    }
  }

  useEffect(() => {
    if (!onSnapshot) return;
    onSnapshot({
      status: state.status,
      known: d.known,
      relation_count: resolvableRelations.length,
      lookup_type: d.lookup_type,
      lookup_value: d.lookup_value,
      nxdomain_observed: summary.nxdomain_observed === true || latestIsErrorStatus || nxdomainOnly,
      latest_dns_status: latestDnsStatus
    });
  }, [state.status, d.known, d.lookup_type, d.lookup_value, summary.nxdomain_observed, resolvableRelations.length, nxdomainOnly, latestDnsStatus, latestIsErrorStatus, onSnapshot]);

  const header = (actionButton) => (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap', alignItems: 'flex-start' }}>
      <div style={{ minWidth: 0, flex: '1 1 180px' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0' }}>DNSMania Enrichment</div>
        <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>DNS history enrichment for the extracted IOC host.</div>
        {isUrlIoc ? (
          <div style={{ color: '#64748b', fontSize: 11, marginTop: 4 }}>Lookup extracted from URL hostname.</div>
        ) : null}
      </div>
      {actionButton}
    </div>
  );

  const lookupPanel = (lookupLabel, lookupValue, extraMuted) => (
    <div className="dnsmania-lookup-panel">
      <div className="dnsmania-lookup-label">{lookupLabel}</div>
      <div className="dnsmania-lookup-value" title={lookupValue || undefined}>{lookupValue || '—'}</div>
      {extraMuted ? <div style={{ color: '#64748b', fontSize: 11, marginTop: 6 }}>{extraMuted}</div> : null}
    </div>
  );

  if (!active && !hasLoaded) return null;

  if (state.status === 'loading') {
    return (
      <div style={shellStyle}>
        {header(
          <button type="button" disabled>Loading...</button>
        )}
        <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 12 }}>Loading DNSMania enrichment...</div>
      </div>
    );
  }

  if (state.status === 'not_run') {
    return (
      <div style={shellStyle}>
        {header(
          <button type="button" onClick={() => enrich().catch(() => {})} disabled={enriching}>
            {enriching ? 'Enriching...' : 'Enrich with DNSMania'}
          </button>
        )}
        <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <DnsmaniaStatusBadge kind="nodata" label="Not run" />
          <span style={{ color: '#cbd5e1', fontSize: 13 }}>DNS enrichment has not been run for this IOC.</span>
        </div>
      </div>
    );
  }

  if (state.status === 'disabled') {
    return (
      <div style={shellStyle}>
        {header(null)}
        <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <DnsmaniaStatusBadge kind="disabled" label="Disabled" />
          <span style={{ color: '#fcd34d', fontSize: 13 }}>{state.message || 'DNSMania enrichment is currently disabled.'}</span>
        </div>
      </div>
    );
  }

  if (state.status === 'failed') {
    return (
      <div style={{ ...shellStyle, borderColor: '#7f1d1d' }}>
        {header(
          <button type="button" onClick={() => enrich().catch(() => {})} disabled={enriching}>
            {enriching ? 'Enriching...' : 'Retry'}
          </button>
        )}
        <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <DnsmaniaStatusBadge kind="failed" label="Failed" />
          <span style={{ color: '#fca5a5', fontSize: 13 }}>{state.message || 'DNSMania enrichment failed.'}</span>
        </div>
      </div>
    );
  }

  const lookupLabel = d.lookup_type === 'ip' ? 'Lookup IP' : 'Lookup Domain';
  const associatedLabel = d.lookup_type === 'ip' ? 'Associated Domains' : 'Associated IPs';
  const refreshBtn = (
    <button type="button" onClick={() => enrich().catch(() => {})} disabled={enriching}>
      {enriching ? 'Enriching...' : 'Refresh DNSMania'}
    </button>
  );

  if (state.status === 'no_data') {
    return (
      <div style={shellStyle}>
        <EnrichmentIntelligenceStyles />
        {header(refreshBtn)}
        <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <DnsmaniaStatusBadge kind="nodata" label="No data" />
          <span style={{ color: '#cbd5e1', fontSize: 13 }}>No DNS history was found for this IOC.</span>
        </div>
        {lookupPanel(lookupLabel, d.lookup_value, d.last_attempt_at || d.enriched_at
          ? `Last checked: ${formatUserDateTime(d.last_attempt_at || d.enriched_at)}`
          : null)}
      </div>
    );
  }

  // completed — Found means historical data exists; latest DNS status is separate.
  const statusBadge = <DnsmaniaStatusBadge kind="found" label="Found" />;
  const latestKind = dnsmaniaLatestStatusKind(latestDnsStatus);
  const timelineAll = Array.isArray(summary.dns_timeline) ? summary.dns_timeline : [];
  const timelineVisible = timelineExpanded
    ? timelineAll
    : timelineAll.slice(Math.max(0, timelineAll.length - TIMELINE_DEFAULT_LIMIT));
  const timelineHiddenCount = Math.max(0, timelineAll.length - timelineVisible.length);
  const lastCheckedAt = summary.latest_dns_status_last_seen || summary.last_seen;

  const relationHint = relationTotal > relationList.length
    ? `Showing ${relationList.length.toLocaleString('en-US')} of ${relationTotal.toLocaleString('en-US')} relations`
    : null;
  const bulkCandidateIps = associatedIps.filter((ip) => (
    isAssociatedIpEnrichmentCandidate(associatedIpIntel.byIp[ip.toLowerCase()])
  ));
  const bulkActionLoading = bulkCandidateIps.some((ip) => associatedIpActions[ip.toLowerCase()]);

  return (
    <div style={shellStyle}>
      <EnrichmentIntelligenceStyles />
      {header(refreshBtn)}

      <div style={{ marginTop: 12, display: 'flex', alignItems: 'flex-start', gap: 10, flexWrap: 'wrap' }}>
        {statusBadge}
        <div>
          <div style={{ color: '#94a3b8', fontSize: 11 }}>Known in DNSMania</div>
          <div style={{ color: '#86efac', fontSize: 14, fontWeight: 700, marginTop: 2 }}>Yes</div>
        </div>
      </div>

      {lookupPanel(lookupLabel, d.lookup_value)}

      {latestDnsStatus ? (
        <div className={`dnsmania-latest-status-panel is-${latestKind}`}>
          <div className="dnsmania-latest-status-label">Latest DNS Status</div>
          <div className="dnsmania-latest-status-row">
            <span className="dnsmania-latest-status-value">{latestDnsStatus}</span>
            <DnsmaniaStatusBadge kind={latestKind} label={latestDnsStatus} />
          </div>
          <div className="dnsmania-latest-status-meta">
            {latestIsErrorStatus
              ? `Latest observation returned ${latestDnsStatus}.`
              : `Latest observation resolved as ${latestDnsStatus}.`}
            {lastCheckedAt ? ` Last checked: ${formatUserDateTime(lastCheckedAt)}.` : ''}
          </div>
          {latestIsErrorStatus && resolvableRelations.length > 0 ? (
            <div className="dnsmania-latest-status-meta">
              Previously resolved. Historical IP addresses are shown below.
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="dnsmania-metric-grid">
        <EnrichmentFieldCard label="First Seen" value={formatUserDateTime(summary.first_seen)} />
        <EnrichmentFieldCard label="Last Seen" value={formatUserDateTime(summary.last_seen)} />
        {summary.last_successfully_resolved ? (
          <EnrichmentFieldCard
            label="Last Successfully Resolved"
            value={formatUserDateTime(summary.last_successfully_resolved)}
          />
        ) : null}
        {!nxdomainOnly ? (
          <EnrichmentFieldCard label={associatedLabel} value={associatedCount} />
        ) : null}
        <EnrichmentFieldCard label="Last Enriched" value={formatUserDateTime(d.enriched_at || d.last_success_at)} />
      </div>

      {timelineAll.length ? (
        <div className="dnsmania-timeline">
          <div className="dnsmania-section-title">DNS Timeline</div>
          {timelineHiddenCount > 0 && !timelineExpanded ? (
            <div style={{ color: '#64748b', fontSize: 11, marginBottom: 6 }}>
              Showing latest {timelineVisible.length} of {timelineAll.length} periods
            </div>
          ) : null}
          <div className="dnsmania-timeline-list">
            {timelineVisible.map((period) => {
              const status = String(period?.status || period?.record_type || 'UNKNOWN').toUpperCase();
              const kind = dnsmaniaLatestStatusKind(status);
              const absoluteLatest = period === timelineAll[timelineAll.length - 1];
              const values = Array.isArray(period?.values) ? period.values.filter(Boolean) : [];
              const metaParts = [
                period?.last_seen ? `Last observed: ${formatUserDateTime(period.last_seen)}` : null
              ].filter(Boolean);
              return (
                <div
                  key={`${status}-${period?.first_seen || ''}-${period?.last_seen || ''}-${values.join(',')}`}
                  className={`dnsmania-timeline-item${absoluteLatest ? ` is-latest is-${kind}` : ''}`}
                >
                  <div className="dnsmania-timeline-rail">
                    <span className="dnsmania-timeline-dot" />
                  </div>
                  <div className="dnsmania-timeline-body">
                    <div className="dnsmania-timeline-title">
                      <span>{period?.first_seen ? formatUserDateTime(period.first_seen) : '—'}</span>
                      <span>—</span>
                      <DnsmaniaStatusBadge kind={kind} label={status} />
                    </div>
                    {values.length ? (
                      <div className="dnsmania-timeline-values">
                        {(period.record_type && status === 'RESOLVED') ? `${period.record_type}: ` : ''}
                        {values.join(', ')}
                      </div>
                    ) : null}
                    {metaParts.length ? (
                      <div className="dnsmania-timeline-meta">{metaParts.join(' · ')}</div>
                    ) : null}
                  </div>
                </div>
              );
            })}
          </div>
          {timelineHiddenCount > 0 ? (
            <button
              type="button"
              onClick={() => setTimelineExpanded((v) => !v)}
              style={{ marginTop: 4, fontSize: 12 }}
            >
              {timelineExpanded ? 'Show less' : `Show earlier periods (${timelineHiddenCount})`}
            </button>
          ) : null}
        </div>
      ) : null}

      {relationList.length ? (
        <div className="enrichment-detail-stack">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
              <div className="dnsmania-section-title">
                {resolvableRelations.length ? associatedLabel : (nxdomainOnly ? 'NXDOMAIN History' : associatedLabel)}
              </div>
              {associatedIps.length && bulkCandidateIps.length && canWrite ? (
                <button
                  type="button"
                  style={{ fontSize: 11, padding: '4px 8px' }}
                  disabled={bulkActionLoading || associatedIpIntel.loading}
                  onClick={() => enrichAssociatedIps(bulkCandidateIps, false).catch(() => {})}
                >
                  {bulkActionLoading ? 'Enriching IPs…' : `Enrich IPs (${bulkCandidateIps.length})`}
                </button>
              ) : null}
            </div>
            {relationHint ? (
              <div style={{ color: '#64748b', fontSize: 11, marginBottom: 8 }}>{relationHint}</div>
            ) : null}
            {associatedIps.length ? (
              <div className="associated-ip-grid">
                {associatedIps.map((ip) => {
                  const key = ip.toLowerCase();
                  return (
                    <AssociatedIpEnrichmentCard
                      key={ip}
                      ip={ip}
                      result={associatedIpIntel.byIp[key]}
                      loading={associatedIpIntel.loading || !associatedIpIntel.byIp[key]}
                      actionLoading={Boolean(associatedIpActions[key])}
                      canWrite={canWrite}
                      isAdmin={isAdmin}
                      onEnrich={() => enrichAssociatedIps([ip], false).catch(() => {})}
                      onForce={() => enrichAssociatedIps([ip], true).catch(() => {})}
                    />
                  );
                })}
              </div>
            ) : (
              <div style={{ display: 'grid', gap: 8 }}>
                {relationList.map((rel, idx) => {
                const recordType = rel.record_type || null;
                const primary = d.lookup_type === 'ip'
                  ? (rel.domain || '—')
                  : (rel.value || recordType || '—');
                const metaParts = [
                  rel.first_seen ? `First seen: ${formatUserDateTime(rel.first_seen)}` : null,
                  rel.last_seen ? `Last seen: ${formatUserDateTime(rel.last_seen)}` : null
                ].filter(Boolean);
                return (
                  <div key={`${primary}-${idx}`} className="enrichment-detail-block">
                    {recordType ? (
                      <div className="enrichment-detail-label">{recordType}</div>
                    ) : null}
                    <div className="enrichment-detail-value" title={primary !== '—' ? primary : undefined}>
                      {primary}
                    </div>
                    {metaParts.length ? (
                      <div style={{ marginTop: 6, color: '#94a3b8', fontSize: 11, lineHeight: 1.45 }}>
                        {metaParts.join(' · ')}
                      </div>
                    ) : null}
                  </div>
                );
                })}
              </div>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}

const TAG_PICKER_LIMIT = 5;
const TAG_PICKER_ITEM_HEIGHT = 34;
const TAG_PICKER_LIST_HEIGHT = TAG_PICKER_ITEM_HEIGHT * TAG_PICKER_LIMIT + 6 * (TAG_PICKER_LIMIT - 1);

const IOC_DETAIL_TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'intelligence', label: 'Intelligence' },
  { id: 'audit', label: 'Audit / History', adminOnly: true }
];

function IocDetailTabBar({ tabs, activeTab, onChange }) {
  return (
    <div
      role="tablist"
      aria-label="IOC detail sections"
      style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 14, borderBottom: '1px solid #334155' }}
    >
      {tabs.map((t) => {
        const active = activeTab === t.id;
        return (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.id)}
            style={{
              padding: '8px 12px',
              border: 'none',
              borderBottom: active ? '2px solid #93c5fd' : '2px solid transparent',
              marginBottom: -1,
              borderRadius: 0,
              background: 'transparent',
              color: active ? '#e2e8f0' : '#94a3b8',
              fontWeight: active ? 700 : 500,
              fontSize: 13,
              cursor: 'pointer'
            }}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

function iocAuditMetadataSummary(metadata) {
  if (!metadata || typeof metadata !== 'object') return '-';
  const confidenceText = formatConfidenceAuditMetadata(metadata);
  if (confidenceText) return confidenceText;
  const taxonomyText = formatTaxonomyAuditMetadata(metadata);
  if (taxonomyText) return taxonomyText;
  const expirationParts = [];
  const iocValue = auditMetadataValue(metadata, 'ioc_value');
  const iocType = auditMetadataValue(metadata, 'ioc_observable_type', 'observable_type');
  if (iocValue) expirationParts.push(String(iocValue));
  if (iocType) expirationParts.push(String(iocType));
  const statusTransition = formatAuditStatusTransition(metadata);
  if (statusTransition && statusTransition !== '—') expirationParts.push(statusTransition);
  const reason = auditMetadataValue(metadata, 'reason');
  if (reason) expirationParts.push(formatExpirationAuditReasonLabel(reason));
  const expirationPolicy = auditMetadataValue(metadata, 'expiration_policy');
  if (expirationPolicy) expirationParts.push(formatExpirationPolicyLabel(expirationPolicy));
  const expireDays = auditMetadataValue(metadata, 'expire_days');
  if (expireDays != null && expireDays !== '') expirationParts.push(`${expireDays} days`);
  const feedName = auditMetadataValue(metadata, 'feed_name');
  if (feedName) expirationParts.push(String(feedName));
  if (expirationParts.length) return expirationParts.join(' · ');
  if (metadata.reference_type || metadata.assessment_impact || metadata.title) {
    const refParts = [];
    if (metadata.title) refParts.push(String(metadata.title));
    if (metadata.reference_type) refParts.push(String(metadata.reference_type));
    if (metadata.assessment_impact) refParts.push(String(metadata.assessment_impact));
    if (metadata.tlp) refParts.push(`TLP:${String(metadata.tlp).toUpperCase()}`);
    if (metadata.url) refParts.push(String(metadata.url));
    if (refParts.length) return refParts.join(' · ');
  }
  const parts = [];
  if (metadata.provider) parts.push(String(metadata.provider));
  if (metadata.tag_name) parts.push(`tag: ${metadata.tag_name}`);
  if (metadata.tag && !metadata.tag_name) parts.push(`tag: ${metadata.tag}`);
  if (metadata.source_name || metadata.source) {
    const src = metadata.source_name || metadata.source;
    if (metadata.tag || metadata.tag_name) parts.push(`source: ${src}`);
  }
  if (metadata.cached === true) parts.push('cached');
  const target = metadata.target_value || metadata.root_domain || metadata.lookup_value || metadata.ip || metadata.target_ip;
  if (target) parts.push(`target: ${target}`);
  else if (metadata.root_domain) parts.push(`root: ${metadata.root_domain}`);
  if (metadata.ip && !String(target || '').includes(String(metadata.ip))) parts.push(`ip: ${metadata.ip}`);
  if (metadata.error_message) parts.push(String(metadata.error_message));
  if (metadata.malicious != null || metadata.suspicious != null) {
    parts.push(`detections: ${metadata.malicious ?? 0}/${metadata.suspicious ?? 0}`);
  }
  return parts.length ? parts.join(' · ') : '-';
}

function IocAuditHistoryPanel({ iocId, enabled }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!enabled || !iocId) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError('');
      try {
        const { data } = await api.get(`/ioc/${iocId}/audit-logs`, { params: { limit: 50 } });
        if (cancelled) return;
        setItems(Array.isArray(data?.items) ? data.items : []);
      } catch (err) {
        if (!cancelled) {
          setItems([]);
          setError(apiErrorMessage(err, 'Failed to load audit history'));
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })().catch(() => {});
    return () => { cancelled = true; };
  }, [enabled, iocId]);

  if (!enabled) return null;

  if (loading) return <div style={{ color: '#94a3b8', fontSize: 13 }}>Loading audit history...</div>;
  if (error) return <div style={{ color: '#fca5a5', fontSize: 13 }}>{error}</div>;
  if (!items.length) {
    return <div style={{ padding: 12, border: '1px solid #334155', borderRadius: 10, color: '#94a3b8', fontSize: 13 }}>No audit history for this IOC yet.</div>;
  }

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Audit / History</div>
      <div style={{ overflowX: 'auto' }}>
        <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', fontSize: 13, minWidth: 980 }}>
          <thead>
            <tr style={{ textAlign: 'left', background: '#111827' }}>
              <th>Date</th><th>Actor</th><th>Action</th><th>Entity</th><th>Status</th><th>Source</th><th>IP</th><th>Details</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id} style={{ borderTop: '1px solid #334155' }}>
                <td style={{ whiteSpace: 'nowrap' }}>{formatUserDateTime(row.created_at)}</td>
                <td>{row.actor_username || row.actor_email || '-'}</td>
                <td>{row.action_label || row.action}</td>
                <td style={{ overflowWrap: 'anywhere' }}>{formatAuditEntityLabel(row)}</td>
                <td>{row.status || '-'}</td>
                <td>{row.source || '-'}</td>
                <td style={{ whiteSpace: 'nowrap' }}>{row.ip_address || '-'}</td>
                <td style={{ color: '#94a3b8', overflowWrap: 'anywhere' }}>{iocAuditMetadataSummary(row.metadata)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function IOCDetailsPage() {
  const { publicId } = useParams();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { isAdmin, canWrite } = useSession();
  const sourceColorIndex = useSourceColorIndex();
  const requestRequiredReason = useReasonPrompt();
  const detailsPublicId = String(publicId || '').trim();
  const ui = PUBLISHED_FEEDS_UI;
  const aliasNotice = String(searchParams.get('alias_notice') || '').trim();

  const [loading, setLoading] = useState(true);
  const [data, setData] = useState({ summary: null, sources: [], matches: [], suppression: { active: false } });
  const [iocTags, setIocTags] = useState([]);
  const [hiddenSourceTags, setHiddenSourceTags] = useState([]);
  const [showHiddenSourceTags, setShowHiddenSourceTags] = useState(false);
  const [tagSuggestions, setTagSuggestions] = useState([]);
  const [tagSearch, setTagSearch] = useState('');
  const [tagsLoading, setTagsLoading] = useState(false);
  const [tagsSaving, setTagsSaving] = useState(false);
  const [tagDropdownOpen, setTagDropdownOpen] = useState(false);
  const tagDropdownRef = useRef(null);
  const [showSuppressModal, setShowSuppressModal] = useState(false);
  const [suppressReason, setSuppressReason] = useState('');
  const [suppressPreset, setSuppressPreset] = useState('never');
  const [suppressCustomDate, setSuppressCustomDate] = useState('');
  const [suppressSaving, setSuppressSaving] = useState(false);
  const [suppressError, setSuppressError] = useState('');
  const [showRemoveConfirm, setShowRemoveConfirm] = useState(false);
  const [removeSaving, setRemoveSaving] = useState(false);
  const [removeError, setRemoveError] = useState('');
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [actionToast, setActionToast] = useState('');
  const [activeTab, setActiveTab] = useState('overview');
  const [pendingAction, setPendingAction] = useState(null);
  const [actionReason, setActionReason] = useState('');
  const [actionExpireAt, setActionExpireAt] = useState('');
  const [actionExpirationPolicy, setActionExpirationPolicy] = useState('expire_after_days');
  const [actionExpireDays, setActionExpireDays] = useState('30');
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState('');
  const [actionRefreshWarn, setActionRefreshWarn] = useState(''); // page-level warning after modal closes
  const [showConfidenceModal, setShowConfidenceModal] = useState(false);
  const [confidenceDraft, setConfidenceDraft] = useState('medium');
  const [confidenceReason, setConfidenceReason] = useState('');
  const [confidenceSaving, setConfidenceSaving] = useState(false);
  const [confidenceError, setConfidenceError] = useState('');
  const { options: threatClassOptions, labelFor: threatClassLabelFor } = useThreatClassifications();
  const [threatActors, setThreatActors] = useState([]);
  const [showThreatClassModal, setShowThreatClassModal] = useState(false);
  const [threatClassDraft, setThreatClassDraft] = useState([]);
  const [threatClassSaving, setThreatClassSaving] = useState(false);
  const [threatClassError, setThreatClassError] = useState('');
  const [showThreatActorModal, setShowThreatActorModal] = useState(false);
  const [threatActorDraft, setThreatActorDraft] = useState('');
  const [threatActorSaving, setThreatActorSaving] = useState(false);
  const [threatActorError, setThreatActorError] = useState('');

  async function load() {
    setLoading(true);
    if (!detailsPublicId) {
      setData({ summary: null, sources: [], matches: [] });
      setLoading(false);
      return { ok: false };
    }
    try {
      const res = await api.get('/ioc/details', { params: { public_id: detailsPublicId } });
      const payload = res.data || { summary: null, sources: [], matches: [], suppression: { active: false } };
      const redirect = resolveCanonicalDetailRedirect({
        requestedPublicId: detailsPublicId,
        summary: payload.summary,
        fileArtifact: payload.file_artifact
      });
      if (redirect?.toPublicId) {
        const next = new URLSearchParams();
        next.set('alias_notice', redirect.message);
        navigate(`/ioc/details/${redirect.toPublicId}?${next.toString()}`, { replace: true });
        return { ok: true, redirected: true };
      }
      setData(payload);
      return { ok: true };
    } catch {
      setData({ summary: null, sources: [], matches: [] });
      return { ok: false };
    } finally {
      setLoading(false);
    }
  }

  async function loadIocTags(iocId) {
    if (!iocId) {
      setIocTags([]);
      return;
    }

    try {
      const res = await api.get(`/ioc/${iocId}/tags`);
      setIocTags(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.log('[ioc-tags] load failed', err);
      setIocTags([]);
    }
  }

  async function loadHiddenSourceTags(iocId) {
    if (!iocId) {
      setHiddenSourceTags([]);
      return;
    }
    try {
      const res = await api.get(`/ioc/${iocId}/tags/source/hidden`);
      setHiddenSourceTags(Array.isArray(res.data?.items) ? res.data.items : []);
    } catch (err) {
      console.log('[ioc-tags] hidden source load failed', err);
      setHiddenSourceTags([]);
    }
  }

  function patchFeedIntelligenceTags(nextTags) {
    setData((prev) => {
      if (!prev?.summary) return prev;
      const fi = prev.summary.feed_intelligence || {};
      return {
        ...prev,
        summary: {
          ...prev.summary,
          feed_intelligence: {
            ...fi,
            tags: Array.isArray(nextTags) ? nextTags : []
          }
        }
      };
    });
  }

  async function loadTagSuggestions(search = '') {
    setTagsLoading(true);
    try {
      const excludeIds = iocTags.map((t) => Number(t.id)).filter((id) => Number.isFinite(id) && id > 0);
      const res = await api.get('/tags', {
        params: {
          active: true,
          limit: TAG_PICKER_LIMIT,
          q: String(search || '').trim() || undefined,
          exclude_ids: excludeIds.length ? excludeIds.join(',') : undefined
        }
      });
      setTagSuggestions(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.log('[ioc-tags] list failed', err);
      setTagSuggestions([]);
    } finally {
      setTagsLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    (async () => {
      await load().catch(() => {});
      if (!active) return;
    })();
    return () => { active = false; };
  }, [detailsPublicId]);

  useEffect(() => {
    setActiveTab('overview');
  }, [detailsPublicId]);

  useEffect(() => {
    if (!isAdmin && activeTab === 'audit') setActiveTab('overview');
  }, [isAdmin, activeTab]);

  useEffect(() => {
    if (!canWrite) return undefined;
    let active = true;
    (async () => {
      try {
        const { data } = await api.get('/admin/threat-actors', { params: { include_inactive: false } });
        if (active) setThreatActors(Array.isArray(data?.threat_actors) ? data.threat_actors : []);
      } catch {
        if (active) setThreatActors([]);
      }
    })();
    return () => { active = false; };
  }, [canWrite]);

  useEffect(() => {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      setIocTags([]);
      setHiddenSourceTags([]);
      setShowHiddenSourceTags(false);
      return;
    }
    loadIocTags(iocId).catch(() => {});
    loadHiddenSourceTags(iocId).catch(() => {});
  }, [data?.summary?.id]);

  useEffect(() => {
    if (!tagDropdownOpen) {
      setTagSearch('');
      setTagSuggestions([]);
      return undefined;
    }
    const delayMs = String(tagSearch || '').trim() ? 250 : 0;
    const timer = setTimeout(() => {
      loadTagSuggestions(tagSearch).catch(() => {});
    }, delayMs);
    return () => clearTimeout(timer);
  }, [tagDropdownOpen, tagSearch, iocTags]);

  useEffect(() => {
    if (!actionToast) return undefined;
    const t = setTimeout(() => setActionToast(''), 3500);
    return () => clearTimeout(t);
  }, [actionToast]);

  useEffect(() => {
    if (!actionRefreshWarn) return undefined;
    const t = setTimeout(() => setActionRefreshWarn(''), 8000);
    return () => clearTimeout(t);
  }, [actionRefreshWarn]);

  async function submitSuppress() {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) return;
    const reason = String(suppressReason || '').trim();
    if (!reason) {
      setSuppressError('Reason is required');
      return;
    }
    setSuppressSaving(true);
    setSuppressError('');
    try {
      await api.post(`/ioc/${iocId}/suppress`, {
        scope: 'global',
        reason,
        expires_at: expiresAtFromPreset(suppressPreset, suppressCustomDate)
      });
      setShowSuppressModal(false);
      setSuppressReason('');
      setSuppressPreset('never');
      setSuppressCustomDate('');
      setActionToast('IOC marked as false positive');
      await load();
    } catch (err) {
      const msg = apiErrorMessage(err, 'Suppression failed');
      setSuppressError(msg.includes('Forbidden') ? 'You do not have permission to modify suppressions' : msg);
    } finally {
      setSuppressSaving(false);
    }
  }

  async function submitDisableSuppression() {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) return;
    const reason = await requestRequiredReason('Disable IOC suppression');
    if (!reason) return;
    setRemoveSaving(true);
    setRemoveError('');
    try {
      await api.delete(`/ioc/${iocId}/suppress`, { data: { reason } });
      setShowRemoveConfirm(false);
      setActionToast('Suppression disabled');
      await load();
    } catch (err) {
      const msg = apiErrorMessage(err, 'Suppression failed');
      setRemoveError(msg.includes('Forbidden') ? 'You do not have permission to modify suppressions' : msg);
    } finally {
      setRemoveSaving(false);
    }
  }

  async function submitDeleteIoc() {
    const pubId = summary?.public_id;
    if (!pubId) return;
    if (deleteConfirmText.trim().toLowerCase() !== 'delete') return;
    setDeleteLoading(true);
    setDeleteError('');
    try {
      await api.delete(`/ioc/${pubId}`, { data: { confirmation: deleteConfirmText.trim().toLowerCase() } });
      setShowDeleteModal(false);
      navigate('/ioc');
    } catch (err) {
      setDeleteError(apiErrorMessage(err, 'Failed to delete IOC'));
    } finally {
      setDeleteLoading(false);
    }
  }

  useEffect(() => {
    if (!tagDropdownOpen) return undefined;
    const onDocMouseDown = (evt) => {
      if (!tagDropdownRef.current) return;
      if (!tagDropdownRef.current.contains(evt.target)) {
        setTagDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', onDocMouseDown);
    return () => document.removeEventListener('mousedown', onDocMouseDown);
  }, [tagDropdownOpen]);

  async function addIocTag(tagId) {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) return;
    if (!Number.isFinite(Number(tagId)) || Number(tagId) <= 0) return;
    if (iocTags.some((t) => Number(t.id) === Number(tagId))) return;

    setTagsSaving(true);
    try {
      await api.post(`/ioc/${iocId}/tags`, { tag_id: Number(tagId) });
      const selected = tagSuggestions.find((t) => Number(t.id) === Number(tagId));
      if (selected) {
        setIocTags((prev) => prev.some((t) => Number(t.id) === Number(tagId)) ? prev : [...prev, {
          id: selected.id,
          name: selected.name,
          type: selected.type,
          category: selected.category,
          is_active: selected.is_active !== false
        }]);
      }
    } catch (err) {
      console.log('[ioc-tags] add failed', err);
    } finally {
      setTagsSaving(false);
    }
  }

  async function removeIocTag(tag) {
    const iocId = Number(data?.summary?.id);
    const tagId = Number(tag?.id ?? tag);
    if (!Number.isFinite(iocId) || iocId <= 0) return;
    if (!Number.isFinite(tagId) || tagId <= 0) return;

    const tagName = String(tag?.name || 'this tag').trim() || 'this tag';
    const ok = window.confirm(`Remove the analyst tag "${tagName}" from this IOC?`);
    if (!ok) return;

    setTagsSaving(true);
    try {
      await api.delete(`/ioc/${iocId}/tags/${tagId}`);
      setIocTags((prev) => prev.filter((t) => Number(t.id) !== tagId));
    } catch (err) {
      console.log('[ioc-tags] delete failed', err);
    } finally {
      setTagsSaving(false);
    }
  }

  async function hideSourceTag(ft) {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0 || !ft) return;
    const tag = String(ft.tag || ft.label || '').trim();
    const normalized = String(ft.normalized || tag).trim().toLowerCase();
    const explicitSources = Array.isArray(ft.sources)
      ? ft.sources.map((s) => String(s || '').trim()).filter(Boolean)
      : [];
    const singleSource = String(ft.source_name || '').trim();
    const sources = explicitSources.length
      ? [...new Set(explicitSources)]
      : (singleSource ? [singleSource] : []);
    if (!tag || !sources.length) return;

    const ok = window.confirm('Remove this source tag from this IOC? It will not affect other IOCs.');
    if (!ok) return;

    const prevTags = Array.isArray(data?.summary?.feed_intelligence?.tags)
      ? data.summary.feed_intelligence.tags
      : [];
    const sourceSet = new Set(sources.map((s) => s.toLowerCase()));
    const nextTags = prevTags.filter((t) => {
      const sameNorm = String(t.normalized || '').toLowerCase() === normalized;
      if (!sameNorm) return true;
      return !sourceSet.has(String(t.source_name || '').toLowerCase());
    });
    patchFeedIntelligenceTags(nextTags);
    setTagsSaving(true);
    try {
      for (const source of sources) {
        await api.post(`/ioc/${iocId}/tags/source/hide`, { tag, source });
      }
      await loadHiddenSourceTags(iocId);
    } catch (err) {
      console.log('[ioc-tags] hide source failed', err);
      patchFeedIntelligenceTags(prevTags);
      setActionToast(apiErrorMessage(err, 'Failed to hide source tag'));
    } finally {
      setTagsSaving(false);
    }
  }

  async function restoreSourceTag(item) {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0 || !item) return;
    const tag = String(item.tag || '').trim();
    const source = String(item.source || item.source_name || '').trim();
    if (!tag || !source) return;

    setTagsSaving(true);
    try {
      await api.post(`/ioc/${iocId}/tags/source/restore`, { tag, source });
      setHiddenSourceTags((prev) => prev.filter((h) => !(
        String(h.tag_normalized || h.tag || '').toLowerCase() === String(item.tag_normalized || item.tag || '').toLowerCase()
        && String(h.source || h.source_name || '').toLowerCase() === source.toLowerCase()
      )));
      // Soft-add restored tag into visible feed tags without full page reload
      const prevTags = Array.isArray(data?.summary?.feed_intelligence?.tags)
        ? data.summary.feed_intelligence.tags
        : [];
      const already = prevTags.some((t) => (
        String(t.normalized || t.tag || '').toLowerCase() === String(item.tag_normalized || tag).toLowerCase()
        && String(t.source_name || '').toLowerCase() === source.toLowerCase()
      ));
      if (!already) {
        patchFeedIntelligenceTags([
          ...prevTags,
          {
            tag,
            normalized: String(item.tag_normalized || tag).toLowerCase(),
            origin: 'feed',
            source_name: source
          }
        ]);
      }
    } catch (err) {
      console.log('[ioc-tags] restore source failed', err);
      setActionToast(apiErrorMessage(err, 'Failed to restore source tag'));
    } finally {
      setTagsSaving(false);
    }
  }

  const summary = data.summary;
  const threatClassEditInactiveOptions = useMemo(() => {
    const current = threatClassesFromSummary(summary);
    return current
      .filter((slug) => !threatClassOptions.some((o) => o.value === slug))
      .map((slug) => ({
        value: slug,
        label: `${summary?.threat_classifications?.find((x) => x.value === slug)?.label || threatClassLabelFor(slug)} (Inactive)`
      }));
  }, [summary, threatClassOptions, threatClassLabelFor]);
  const activeSources = Array.isArray(data.active_sources) ? data.active_sources : [];
  const historicalSources = Array.isArray(data.historical_sources) ? data.historical_sources : [];
  const feedMemberships = Array.isArray(data.feed_memberships) ? data.feed_memberships : [];
  const suppression = data?.suppression || { active: false };
  const suppressionActive = isSuppressionActiveRow(suppression);
  const iocStatusCard = summary ? getIocStatusCardPresentation(summary, { suppressionActive }) : null;
  const confidenceDetail = data?.confidence || summary?.confidence_detail || null;
  const confidenceCard = getIocConfidencePresentation(confidenceDetail);

  function openConfidenceEditor() {
    setConfidenceDraft(confidenceCard.effective || 'medium');
    setConfidenceReason('');
    setConfidenceError('');
    setShowConfidenceModal(true);
  }

  async function submitConfidenceOverride(clearOverride = false) {
    const iocId = Number(summary?.id);
    const observableType = String(summary?.observable_type || '').trim();
    if (!Number.isFinite(iocId) || !observableType) return;

    setConfidenceSaving(true);
    setConfidenceError('');
    try {
      const body = clearOverride
        ? { observable_type: observableType, clear_override: true, reason: confidenceReason || null }
        : { observable_type: observableType, confidence: confidenceDraft, reason: confidenceReason || null };
      const { data: patchData } = await api.patch(`/ioc/${iocId}/confidence`, body);
      if (!patchData?.success) {
        setConfidenceError(patchData?.error || 'Request failed');
        return;
      }
      setShowConfidenceModal(false);
      setConfidenceReason('');
      setActionToast(clearOverride ? 'Manual confidence override cleared' : 'IOC confidence updated');
      await load();
    } catch (err) {
      setConfidenceError(apiErrorMessage(err, 'Failed to update confidence'));
    } finally {
      setConfidenceSaving(false);
    }
  }

  async function clearConfidenceOverride() {
    await submitConfidenceOverride(true);
  }

  function openThreatClassEditor() {
    setThreatClassDraft(threatClassesFromSummary(summary));
    setThreatClassError('');
    setShowThreatClassModal(true);
  }

  async function submitThreatClassification() {
    const iocId = Number(summary?.id);
    const observableType = String(summary?.observable_type || '').trim();
    if (!Number.isFinite(iocId) || !observableType) return;

    setThreatClassSaving(true);
    setThreatClassError('');
    try {
      const { data: patchData } = await api.patch(`/ioc/${iocId}/threat-classifications`, {
        observable_type: observableType,
        classifications: normalizeSelectedThreatClasses(threatClassDraft),
        threat_classifications: normalizeSelectedThreatClasses(threatClassDraft)
      });
      if (!patchData?.success) {
        setThreatClassError(patchData?.error || 'Request failed');
        return;
      }
      setShowThreatClassModal(false);
      setActionToast('Threat classifications updated');
      await load();
    } catch (err) {
      setThreatClassError(apiErrorMessage(err, 'Failed to update threat classification'));
    } finally {
      setThreatClassSaving(false);
    }
  }

  function openThreatActorEditor() {
    setThreatActorDraft(summary?.threat_actor_id || '');
    setThreatActorError('');
    setShowThreatActorModal(true);
  }

  async function submitThreatActor() {
    const iocId = Number(summary?.id);
    const observableType = String(summary?.observable_type || '').trim();
    if (!Number.isFinite(iocId) || !observableType) return;

    setThreatActorSaving(true);
    setThreatActorError('');
    try {
      const body = {
        observable_type: observableType,
        threat_actor_id: threatActorDraft || null
      };
      const { data: patchData } = await api.patch(`/ioc/${iocId}/threat-actor`, body);
      if (!patchData?.success) {
        setThreatActorError(patchData?.error || 'Request failed');
        return;
      }
      setShowThreatActorModal(false);
      setActionToast('Threat actor updated');
      await load();
    } catch (err) {
      setThreatActorError(apiErrorMessage(err, 'Failed to update threat actor'));
    } finally {
      setThreatActorSaving(false);
    }
  }

  function openExpirationAction(type, membershipId = null) {
    const preset = IOC_EXPIRATION_ACTION_PRESETS[type];
    if (!preset) return;
    setActionError('');
    setActionRefreshWarn('');
    setActionReason('');
    setActionExpireAt('');
    if (preset.requiresExpirationPolicy) {
      setActionExpirationPolicy('expire_after_days');
      setActionExpireDays('30');
    }
    setPendingAction({ type, membershipId, ...preset });
  }

  function cancelExpirationAction() {
    if (actionLoading) return;
    setPendingAction(null);
    setActionReason('');
    setActionExpireAt('');
    setActionExpirationPolicy('expire_after_days');
    setActionExpireDays('30');
    setActionError('');
    setActionRefreshWarn('');
  }

  function applyMutationToLocalState(patchData) {
    if (!patchData) return;
    setData((prev) => {
      const next = { ...prev };
      if (patchData.ioc && next.summary) {
        next.summary = { ...next.summary, ...patchData.ioc };
      }
      if (patchData.membership && Array.isArray(next.feed_memberships)) {
        next.feed_memberships = next.feed_memberships.map((m) => (
          Number(m.id) === Number(patchData.membership.id) ? { ...m, ...patchData.membership } : m
        ));
      }
      return next;
    });
  }

  async function confirmExpirationAction() {
    if (!pendingAction || actionLoading || !summary) return;

    const iocId = Number(summary.id);
    if (!Number.isFinite(iocId)) return;

    const reason = String(actionReason || '').trim();
    if (pendingAction.requiresReason && !reason) {
      setActionError('Reason is required');
      return;
    }

    let manualExpiresAt = null;
    if (pendingAction.requiresDate) {
      if (!actionExpireAt) {
        setActionError('Expire date/time is required');
        return;
      }
      const d = new Date(actionExpireAt);
      if (Number.isNaN(d.getTime())) {
        setActionError('Enter a valid date/time');
        return;
      }
      if (d.getTime() <= Date.now()) {
        setActionError('Expire date/time must be in the future');
        return;
      }
      manualExpiresAt = d.toISOString();
    }

    if (pendingAction.requiresExpirationPolicy) {
      const policy = String(actionExpirationPolicy || '').trim();
      if (!policy) {
        setActionError('Expiration policy is required');
        return;
      }
      if (policy === 'expire_after_days') {
        const days = Number(actionExpireDays);
        if (!Number.isInteger(days) || days < 1) {
          setActionError('Expire after days must be a positive integer');
          return;
        }
      }
      if (policy === 'custom_date') {
        if (!actionExpireAt) {
          setActionError('Custom expire date is required');
          return;
        }
        const d = new Date(actionExpireAt);
        if (Number.isNaN(d.getTime())) {
          setActionError('Enter a valid custom expire date');
          return;
        }
        if (d.getTime() <= Date.now()) {
          setActionError('Custom expire date must be in the future');
          return;
        }
      }
    }

    setActionLoading(true);
    setActionError('');
    setActionRefreshWarn('');

    const observableType = summary.observable_type;
    let patchData = null;

    try {
      const { type, membershipId } = pendingAction;
      if (type === 'expire_ioc') {
        const { data } = await api.patch(`/ioc/${iocId}/status-override`, {
          observable_type: observableType,
          manual_status_override: true,
          manual_status: 'expired',
          reason
        });
        patchData = data;
      } else if (type === 'reactivate_ioc') {
        const payload = {
          observable_type: observableType,
          manual_status_override: true,
          manual_status: 'active',
          reason,
          expiration_policy: actionExpirationPolicy
        };
        if (actionExpirationPolicy === 'expire_after_days') {
          payload.expire_days = Number(actionExpireDays);
        }
        if (actionExpirationPolicy === 'custom_date') {
          payload.expires_at = new Date(actionExpireAt).toISOString();
        }
        const { data } = await api.patch(`/ioc/${iocId}/status-override`, payload);
        patchData = data;
      } else if (type === 'custom_expire_ioc') {
        const { data } = await api.patch(`/ioc/${iocId}/status-override`, {
          observable_type: observableType,
          manual_status_override: true,
          manual_status: 'active',
          manual_expires_at: manualExpiresAt,
          reason
        });
        patchData = data;
      } else if (type === 'clear_ioc_override') {
        const { data } = await api.patch(`/ioc/${iocId}/status-override`, {
          observable_type: observableType,
          manual_status_override: false,
          reason: reason || null
        });
        patchData = data;
      } else if (type === 'expire_membership' && membershipId) {
        const { data } = await api.patch(`/ioc/${iocId}/feed-memberships/${membershipId}/expiration-override`, {
          observable_type: observableType,
          override_enabled: true,
          override_status: 'expired',
          reason
        });
        patchData = data;
      } else if (type === 'reactivate_membership' && membershipId) {
        const { data } = await api.patch(`/ioc/${iocId}/feed-memberships/${membershipId}/expiration-override`, {
          observable_type: observableType,
          override_enabled: true,
          override_status: 'active',
          override_expires_at: null,
          reason
        });
        patchData = data;
      } else if (type === 'custom_expire_membership' && membershipId) {
        const { data } = await api.patch(`/ioc/${iocId}/feed-memberships/${membershipId}/expiration-override`, {
          observable_type: observableType,
          override_enabled: true,
          override_expires_at: manualExpiresAt,
          override_status: null,
          reason
        });
        patchData = data;
      } else if (type === 'clear_membership_override' && membershipId) {
        const { data } = await api.patch(`/ioc/${iocId}/feed-memberships/${membershipId}/expiration-override`, {
          observable_type: observableType,
          override_enabled: false,
          reason: reason || null
        });
        patchData = data;
      }
    } catch (err) {
      setActionError(apiErrorMessage(err, 'Request failed'));
      return;
    } finally {
      setActionLoading(false);
    }

    if (!isApiMutationSuccess(patchData)) {
      setActionError(patchData?.error || 'Request failed');
      return;
    }

    applyMutationToLocalState(patchData);
    setPendingAction(null);
    setActionReason('');
    setActionExpireAt('');
    setActionToast(
      patchData?.noop
        ? (patchData.message || 'No change required')
        : (pendingAction.successToast || 'Updated')
    );

    const refreshed = await load();
    if (!refreshed?.ok) {
      setActionRefreshWarn('Action succeeded but refreshing IOC details failed. Displayed values are from the server response.');
    } else {
      setActionRefreshWarn('');
    }
  }
  const displayObservable = summary?.observable || '-';
  const observableType = String(summary?.observable_type || '').toLowerCase();
  const isHashObservable = FILE_HASH_TYPES.has(observableType);
  const fileInfo = summary?.file_information || null;
  const hasMeaningfulFileInfo = Boolean(fileInfo && Object.values(fileInfo).some((v) => {
    if (v == null) return false;
    const t = String(v).trim();
    return t && t !== "-";
  }));

  const visibleTabs = IOC_DETAIL_TABS.filter((t) => !t.adminOnly || isAdmin);
  const intelligenceTabActive = activeTab === 'intelligence';
  const auditTabActive = activeTab === 'audit' && isAdmin;

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#0f172a', padding: 16 }}>
        <IocHeader
          observable={displayObservable}
          statusBadge={summary ? iocStatusBadge(suppressionActive ? 'false_positive' : summary.status) : null}
          ui={ui}
          showMarkFalsePositive={Boolean(summary && !suppressionActive && isAdmin)}
          showDelete={Boolean(summary && isAdmin)}
          onMarkFalsePositive={() => { setShowSuppressModal(true); setSuppressError(''); }}
          onDelete={() => { setShowDeleteModal(true); setDeleteConfirmText(''); setDeleteError(''); }}
          onBack={() => navigate('/ioc')}
          onRefresh={() => load().catch(() => {})}
        />

        {!isAdmin ? (
          <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, border: '1px solid #475569', color: '#cbd5e1', background: 'rgba(100,116,139,0.15)', fontSize: 13 }}>
            Readonly users can view suppression status but cannot modify it.
          </div>
        ) : null}

        {actionToast ? <div style={{ ...ui.banner, marginBottom: 12 }}>{actionToast}</div> : null}
        {actionRefreshWarn ? (
          <div style={{ padding: '8px 12px', borderRadius: 8, border: '1px solid #854d0e', color: '#fcd34d', background: 'rgba(120,53,15,0.2)', fontSize: 13, marginBottom: 12 }}>
            {actionRefreshWarn}
          </div>
        ) : null}
        {(!loading && summary && aliasNotice) ? (
          <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, border: '1px solid #1e3a5f', color: '#bfdbfe', background: 'rgba(30,58,95,0.35)', fontSize: 13 }}>
            {aliasNotice}
            <button
              type="button"
              onClick={() => {
                const next = new URLSearchParams(searchParams);
                next.delete('alias_notice');
                setSearchParams(next, { replace: true });
              }}
              style={{ marginLeft: 10, border: 'none', background: 'transparent', color: '#93c5fd', cursor: 'pointer', textDecoration: 'underline', fontSize: 12 }}
            >
              Dismiss
            </button>
          </div>
        ) : null}

        {loading ? <div>Loading...</div> : !summary ? (
          <div style={{ padding: 12, border: '1px solid #334155', borderRadius: 10 }}>No IOC detail found.</div>
        ) : (
          <>
            {suppressionActive ? (
              <div style={{ marginBottom: 14, padding: 14, borderRadius: 10, border: '1px solid #166534', background: 'rgba(34,197,94,0.08)' }}>
                <div style={{ fontWeight: 700, color: '#86efac', marginBottom: 8 }}>This IOC is marked as False Positive / Suppressed.</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, fontSize: 13, color: '#cbd5e1' }}>
                  <div><span style={{ color: '#94a3b8' }}>Reason:</span> {suppression.reason || '—'}</div>
                  <div><span style={{ color: '#94a3b8' }}>Created by:</span> {suppression.created_by || '—'}</div>
                  <div><span style={{ color: '#94a3b8' }}>Created at:</span> {formatUserDateTime(suppression.created_at)}</div>
                  <div><span style={{ color: '#94a3b8' }}>Expires at:</span> {suppression.expires_at ? formatUserDateTime(suppression.expires_at) : 'Never'}</div>
                </div>
                <div style={{ display: 'flex', gap: 10, marginTop: 12, flexWrap: 'wrap' }}>
                  <button type="button" style={ui.btn} onClick={() => navigate(`/operations/ioc-suppressions?search=${encodeURIComponent(summary.observable || '')}`)}>Manage suppression</button>
                  {isAdmin ? (
                    <button type="button" style={{ ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => { setShowRemoveConfirm(true); setRemoveError(''); }}>Disable suppression</button>
                  ) : null}
                </div>
              </div>
            ) : null}

            <IocDetailTabBar tabs={visibleTabs} activeTab={activeTab} onChange={setActiveTab} />

            {activeTab === 'overview' ? (
              <div style={{ display: 'grid', gap: 14 }}>
                <IocStatusSummary
                  presentation={iocStatusCard}
                  renderBadge={iocStatusBadge}
                  ui={ui}
                  isAdmin={isAdmin}
                  actionLoading={actionLoading}
                  onAction={openExpirationAction}
                />

                {activeSources.length || historicalSources.length ? (
                  <div style={{ display: 'grid', gap: 14 }}>
                    <ActiveSourcesTable
                      activeSources={activeSources}
                      sourceColorIndex={sourceColorIndex}
                      SourceBadge={SourceBadge}
                      iocSourceTypeLabel={iocSourceTypeLabel}
                      iocSourceStatusBadge={iocSourceStatusBadge}
                      isAdmin={isAdmin}
                      actionLoading={actionLoading}
                      onMembershipAction={(type, membershipId) => openExpirationAction(type, membershipId)}
                    />

                    {historicalSources.length ? (
                      <div style={{ padding: 14, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
                        <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>Historical / Inactive Sources</div>
                        <div style={{ overflowX: 'auto' }}>
                          <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 12, color: '#e2e8f0' }}>
                            <thead>
                              <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                                <th>Source</th><th>Type</th><th>Status</th>
                                <th title={IOC_SOURCE_TIMESTAMP_PRESENTATION.first.tooltip}>{IOC_SOURCE_TIMESTAMP_PRESENTATION.first.label}</th>
                                <th title={IOC_SOURCE_TIMESTAMP_PRESENTATION.last.tooltip}>{IOC_SOURCE_TIMESTAMP_PRESENTATION.last.label}</th>
                                <th>Purged at</th><th>Reason</th>
                              </tr>
                            </thead>
                            <tbody>
                              {historicalSources.map((src) => (
                                <tr key={src.id} style={{ borderBottom: '1px solid #1e293b' }}>
                                  <td><SourceBadge index={sourceColorIndex} label={src.name} /></td>
                                  <td>{iocSourceTypeLabel(src)}</td>
                                  <td>{iocSourceStatusBadge(src)}</td>
                                  <td>{formatIocDetailDateTime(src.first_seen_at)}</td>
                                  <td>{formatIocDetailDateTime(src.last_changed_at)}</td>
                                  <td>{formatIocDetailDateTime(src.purged_at)}</td>
                                  <td>{src.description || src.purge_reason || '—'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    ) : null}
                  </div>
                ) : feedMemberships.length ? (
                  <div style={{ padding: 14, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
                    <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>Feed Sources</div>
                    <div style={{ fontSize: 13, color: '#94a3b8' }}>Source details are loading or unavailable.</div>
                  </div>
                ) : null}

                <IocSummaryStrip summary={summary} />

                <IocTimestampCards
                  summary={summary}
                  activeSources={activeSources}
                  historicalSources={historicalSources}
                />

                <IocMetadataCards
                  confidenceCard={confidenceCard}
                  summary={summary}
                  canWrite={canWrite}
                  onEditConfidence={openConfidenceEditor}
                  onEditThreatClass={openThreatClassEditor}
                  onEditThreatActor={openThreatActorEditor}
                  ThreatClassificationBadges={ThreatClassificationBadges}
                />

                <div style={{ padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
                  <div style={{ fontSize: 13, marginBottom: 8, color: '#94a3b8' }}>Tags</div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                    {(() => {
                      const { manual, feed, hasTags } = buildIocTagBadges({
                        manualTags: iocTags,
                        feedTags: summary?.feed_intelligence?.tags || []
                      });
                      return (
                        <>
                          {manual.map((tag) => (
                              <span
                                key={tag.key}
                                title={tag.title}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 5,
                                  padding: '3px 8px',
                                  borderRadius: 999,
                                  border: '1px solid #92400e',
                                  fontSize: 12,
                                  color: '#fbbf24',
                                  background: 'rgba(146,64,14,0.12)'
                                }}
                              >
                                {tag.label}
                                <button
                                  type="button"
                                  onClick={() => removeIocTag({ id: tag.id, name: tag.label }).catch(() => {})}
                                  title="Remove tag"
                                  aria-label={`Remove ${tag.label}`}
                                  style={{ padding: 0, border: 'none', background: 'transparent', color: '#a16207', cursor: tagsSaving ? 'wait' : 'pointer', lineHeight: 1, fontSize: 14 }}
                                  disabled={tagsSaving}
                                >
                                  ×
                                </button>
                              </span>
                          ))}
                          {feed.map((ft) => (
                            <span
                              key={ft.key}
                              title={ft.title}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 5,
                                padding: '3px 8px',
                                borderRadius: 999,
                                border: '1px solid #1e40af',
                                fontSize: 12,
                                color: '#93c5fd',
                                background: 'rgba(30,64,175,0.12)'
                              }}
                            >
                              {ft.label}
                              {canWrite ? (
                                <button
                                  type="button"
                                  onClick={() => hideSourceTag({
                                    tag: ft.label,
                                    label: ft.label,
                                    normalized: ft.normalized,
                                    sources: ft.sources
                                  }).catch(() => {})}
                                  title="Remove this source tag from this IOC"
                                  aria-label={`Hide source tag ${ft.label}`}
                                  style={{ padding: 0, border: 'none', background: 'transparent', color: '#60a5fa', cursor: tagsSaving ? 'wait' : 'pointer', lineHeight: 1, fontSize: 14 }}
                                  disabled={tagsSaving}
                                >
                                  ×
                                </button>
                              ) : null}
                            </span>
                          ))}
                          {!hasTags ? <span style={{ color: '#64748b', fontSize: 12 }}>No tags</span> : null}
                        </>
                      );
                    })()}

                    <div style={{ position: 'relative' }} ref={tagDropdownRef}>
                      <button type="button" onClick={() => setTagDropdownOpen((v) => !v)} disabled={tagsSaving}>
                        + Add Tag {tagsLoading || tagsSaving ? '?' : ''}
                      </button>

                      {tagDropdownOpen ? (
                        <div style={{ position: 'absolute', top: 'calc(100% + 6px)', left: 0, width: 260, border: '1px solid #334155', borderRadius: 10, background: '#0b1220', zIndex: 30, padding: 8, overflow: 'hidden' }}>
                          <input
                            value={tagSearch}
                            onChange={(e) => setTagSearch(e.target.value)}
                            placeholder="Search tag..."
                            autoFocus
                            style={{ width: '100%', marginBottom: 8, padding: '8px 10px', borderRadius: 8, border: '1px solid #475569', background: '#020617', color: '#e2e8f0', boxSizing: 'border-box' }}
                          />
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, height: TAG_PICKER_LIST_HEIGHT, overflow: 'hidden' }}>
                            {tagsLoading ? (
                              <div style={{ color: '#94a3b8', fontSize: 12, padding: '4px 2px' }}>Loading…</div>
                            ) : tagSuggestions.map((t) => (
                              <button
                                key={`opt-tag-${t.id}`}
                                type="button"
                                onClick={() => addIocTag(t.id).catch(() => {})}
                                disabled={tagsSaving}
                                style={{
                                  textAlign: 'left',
                                  border: '1px solid #334155',
                                  borderRadius: 8,
                                  padding: '6px 8px',
                                  minHeight: TAG_PICKER_ITEM_HEIGHT,
                                  boxSizing: 'border-box',
                                  background: '#111827',
                                  color: '#e5e7eb',
                                  cursor: tagsSaving ? 'wait' : 'pointer',
                                  flex: '0 0 auto'
                                }}
                              >
                                {t.name}
                              </button>
                            ))}
                            {!tagsLoading && !tagSuggestions.length && !String(tagSearch || '').trim() ? (
                              <div style={{ color: '#94a3b8', fontSize: 12, padding: '4px 2px' }}>No tags available</div>
                            ) : null}
                            {!tagsLoading && !tagSuggestions.length && String(tagSearch || '').trim() ? (
                              <div style={{ color: '#94a3b8', fontSize: 12, padding: '4px 2px' }}>No tag found</div>
                            ) : null}
                          </div>
                        </div>
                      ) : null}
                    </div>
                  </div>
                  {canWrite && hiddenSourceTags.length > 0 ? (
                    <div style={{ marginTop: 10 }}>
                      <button
                        type="button"
                        onClick={() => setShowHiddenSourceTags((v) => !v)}
                        style={{ fontSize: 12, padding: '4px 8px', borderRadius: 8, border: '1px solid #334155', background: '#0b1220', color: '#93c5fd' }}
                      >
                        {showHiddenSourceTags ? 'Hide' : 'Restore'} source tags ({hiddenSourceTags.length})
                      </button>
                      {showHiddenSourceTags ? (
                        <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {hiddenSourceTags.map((h) => (
                            <div
                              key={`hidden-${h.tag_normalized || h.tag}-${h.source || h.source_name}`}
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                gap: 8,
                                padding: '6px 8px',
                                borderRadius: 8,
                                border: '1px dashed #334155',
                                background: '#0b1220'
                              }}
                            >
                              <div style={{ minWidth: 0 }}>
                                <div style={{ color: '#64748b', fontSize: 12, textDecoration: 'line-through' }}>{h.tag}</div>
                                <div style={{ color: '#475569', fontSize: 11 }}>{h.source || h.source_name}</div>
                              </div>
                              <button
                                type="button"
                                disabled={tagsSaving}
                                onClick={() => restoreSourceTag(h).catch(() => {})}
                                style={{ fontSize: 11, whiteSpace: 'nowrap' }}
                              >
                                Restore
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </div>

                {(() => {
                  const ai = data?.analyst_intelligence_summary;
                  if (!ai || !ai.total_count) return null;
                  const maliciousCnt = ai.supports_malicious_count || 0;
                  const benignCnt = ai.supports_benign_count || 0;
                  const reviewCnt = ai.needs_review_count || 0;
                  const contextCnt = ai.context_only_count || 0;
                  return (
                    <div style={{ padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
                      <div style={{ fontSize: 13, marginBottom: 8, color: '#94a3b8' }}>Analyst Intelligence</div>
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                        <span style={{ fontSize: 12, color: '#94a3b8' }}>{ai.total_count} entr{ai.total_count !== 1 ? 'ies' : 'y'}</span>
                        {maliciousCnt > 0 && (
                          <span style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, background: '#450a0a', color: '#fca5a5', border: '1px solid #7f1d1d' }}>
                            {maliciousCnt} malicious
                          </span>
                        )}
                        {benignCnt > 0 && (
                          <span style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, background: '#052e16', color: '#86efac', border: '1px solid #166534' }}>
                            {benignCnt} benign
                          </span>
                        )}
                        {reviewCnt > 0 && (
                          <span style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, background: '#422006', color: '#fbbf24', border: '1px solid #92400e' }}>
                            {reviewCnt} needs review
                          </span>
                        )}
                        {contextCnt > 0 && (
                          <span style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, background: '#1e293b', color: '#94a3b8', border: '1px solid #334155' }}>
                            {contextCnt} context only
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })()}

              </div>
            ) : null}

            {activeTab === 'intelligence' ? (
              <IntelligenceTabPanel
                iocId={summary.id}
                iocValue={summary.observable}
                iocType={summary.observable_type}
                active={intelligenceTabActive}
                canWrite={canWrite}
                isAdmin={isAdmin}
                formatUserDateTime={formatUserDateTime}
                isRdapEligible={isRdapEligibleObservable(summary.observable, summary.observable_type).eligible}
                isHashObservable={isHashObservable}
                hasMeaningfulFileInfo={hasMeaningfulFileInfo}
                fileInformation={summary.file_information}
                fileArtifact={data.file_artifact || null}
                VirusTotalEnrichmentCard={VirusTotalEnrichmentCard}
                IpEnrichmentCard={IpEnrichmentCard}
                AbuseIpdbEnrichmentCard={AbuseIpdbEnrichmentCard}
                RdapEnrichmentCard={RdapEnrichmentCard}
                SpamhausDropEnrichmentCard={SpamhausDropEnrichmentCard}
                DnsmaniaEnrichmentCard={DnsmaniaEnrichmentCard}
              />
            ) : null}

            {activeTab === 'audit' && isAdmin ? (
              <IocAuditHistoryPanel iocId={summary.id} enabled={auditTabActive} />
            ) : null}
          </>
        )}
      </section>

      <IocExpirationActionModal
        pending={pendingAction}
        reason={actionReason}
        onReasonChange={setActionReason}
        expireAt={actionExpireAt}
        onExpireAtChange={setActionExpireAt}
        expirationPolicy={actionExpirationPolicy}
        onExpirationPolicyChange={setActionExpirationPolicy}
        expireDays={actionExpireDays}
        onExpireDaysChange={setActionExpireDays}
        loading={actionLoading}
        error={actionError}
        onCancel={cancelExpirationAction}
        onConfirm={() => confirmExpirationAction().catch(() => {})}
        ui={ui}
      />

      {showSuppressModal ? (
        <ModalOverlay onClose={() => !suppressSaving && setShowSuppressModal(false)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Mark IOC as False Positive</h3>
          <div style={{ display: 'grid', gap: 12 }}>
            <div><span style={ui.label}>IOC value</span><input readOnly value={summary?.observable || ''} style={ui.input} /></div>
            <div><span style={ui.label}>IOC type</span><input readOnly value={summary?.observable_type || ''} style={ui.input} /></div>
            <div>
              <span style={ui.label}>Scope</span>
              <input readOnly value="Global suppression" style={ui.input} />
              <span style={ui.helper}>Source-specific suppression is not available in this phase.</span>
            </div>
            <div>
              <span style={ui.label}>Reason</span>
              <textarea value={suppressReason} onChange={(e) => setSuppressReason(e.target.value)} style={ui.textarea} placeholder="Why is this IOC a false positive?" disabled={suppressSaving} />
            </div>
            <SuppressionExpirationFields ui={ui} preset={suppressPreset} setPreset={setSuppressPreset} customDate={suppressCustomDate} setCustomDate={setSuppressCustomDate} disabled={suppressSaving} />
            {suppressError ? <div style={{ color: '#fca5a5', fontSize: 13 }}>{suppressError}</div> : null}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button type="button" style={ui.btn} onClick={() => setShowSuppressModal(false)} disabled={suppressSaving}>Cancel</button>
              <button type="button" style={ui.btnPrimary} onClick={() => submitSuppress().catch(() => {})} disabled={suppressSaving}>{suppressSaving ? 'Saving…' : 'Suppress IOC'}</button>
            </div>
          </div>
        </ModalOverlay>
      ) : null}

      {showRemoveConfirm ? (
        <ModalOverlay onClose={() => !removeSaving && setShowRemoveConfirm(false)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Disable suppression</h3>
          <p style={ui.modalSub}>Disable this suppression? It will no longer prevent matching activity, but the record will be kept.</p>
          {removeError ? <div style={{ color: '#fca5a5', fontSize: 13, marginBottom: 10 }}>{removeError}</div> : null}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button type="button" style={ui.btn} onClick={() => setShowRemoveConfirm(false)} disabled={removeSaving}>Cancel</button>
            <button type="button" style={{ ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => submitDisableSuppression().catch(() => {})} disabled={removeSaving}>{removeSaving ? 'Disabling…' : 'Disable suppression'}</button>
          </div>
        </ModalOverlay>
      ) : null}

      {showDeleteModal ? (
        <ModalOverlay onClose={() => !deleteLoading && (setShowDeleteModal(false), setDeleteConfirmText(''), setDeleteError(''))}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Delete IOC</h3>
          <p style={{ color: '#cbd5e1', fontSize: 13, marginBottom: 4 }}>You are about to permanently delete this IOC from the platform.</p>
          <div style={{ padding: '10px 12px', borderRadius: 8, border: '1px solid #334155', background: '#0f172a', fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: '#e2e8f0', marginBottom: 12, overflowWrap: 'anywhere' }}>{summary?.observable}</div>
          <p style={{ color: '#cbd5e1', fontSize: 13, marginBottom: 12 }}>This action will remove the IOC from active IOC operations and correlation lookup. This is intended for incorrectly imported or mistakenly added IOCs.</p>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>To confirm, type: <span style={{ color: '#fca5a5', fontFamily: 'monospace' }}>delete</span></div>
            <input
              type="text"
              value={deleteConfirmText}
              onChange={(e) => setDeleteConfirmText(e.target.value)}
              placeholder="delete"
              disabled={deleteLoading}
              autoFocus
              style={{ width: '100%', boxSizing: 'border-box', padding: '8px 10px', borderRadius: 6, border: '1px solid #475569', background: '#0f172a', color: '#e2e8f0', fontSize: 13, outline: 'none' }}
            />
          </div>
          {deleteError ? <div style={{ color: '#fca5a5', fontSize: 13, marginBottom: 10 }}>{deleteError}</div> : null}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button type="button" style={ui.btn} onClick={() => { setShowDeleteModal(false); setDeleteConfirmText(''); setDeleteError(''); }} disabled={deleteLoading}>Cancel</button>
            <button type="button" style={{ padding: '8px 18px', borderRadius: 8, border: '1px solid #7f1d1d', background: deleteConfirmText.trim().toLowerCase() === 'delete' ? '#991b1b' : 'rgba(127,29,29,0.2)', color: '#fca5a5', fontSize: 13, fontWeight: 600, cursor: deleteConfirmText.trim().toLowerCase() === 'delete' ? 'pointer' : 'not-allowed', opacity: deleteConfirmText.trim().toLowerCase() === 'delete' ? 1 : 0.5 }} onClick={() => submitDeleteIoc().catch(() => {})} disabled={deleteLoading || deleteConfirmText.trim().toLowerCase() !== 'delete'}>{deleteLoading ? 'Deleting…' : 'Delete IOC'}</button>
          </div>
        </ModalOverlay>
      ) : null}

      {showConfidenceModal ? (
        <ModalOverlay onClose={() => !confidenceSaving && setShowConfidenceModal(false)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Edit IOC confidence</h3>
          <div style={{ display: 'grid', gap: 12 }}>
            <div>
              <span style={ui.label}>Confidence</span>
              <select
                value={confidenceDraft}
                onChange={(e) => setConfidenceDraft(e.target.value)}
                disabled={confidenceSaving}
                style={ui.input}
              >
                {CONFIDENCE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>
            <div>
              <span style={ui.label}>Reason for override</span>
              <textarea
                value={confidenceReason}
                onChange={(e) => setConfidenceReason(e.target.value)}
                style={ui.textarea}
                placeholder="Why are you overriding this confidence?"
                disabled={confidenceSaving}
              />
            </div>
            {confidenceError ? <div style={{ color: '#fca5a5', fontSize: 13 }}>{confidenceError}</div> : null}
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
              {confidenceCard.hasOverride ? (
                <button
                  type="button"
                  style={{ ...ui.btn, borderColor: '#475569', color: '#cbd5e1' }}
                  onClick={() => clearConfidenceOverride().catch(() => {})}
                  disabled={confidenceSaving}
                >
                  Clear manual override
                </button>
              ) : <span />}
              <div style={{ display: 'flex', gap: 8 }}>
                <button type="button" style={ui.btn} onClick={() => setShowConfidenceModal(false)} disabled={confidenceSaving}>Cancel</button>
                <button type="button" style={ui.btnPrimary} onClick={() => submitConfidenceOverride(false).catch(() => {})} disabled={confidenceSaving}>
                  {confidenceSaving ? 'Saving…' : 'Save'}
                </button>
              </div>
            </div>
          </div>
        </ModalOverlay>
      ) : null}

      {showThreatClassModal ? (
        <ModalOverlay onClose={() => !threatClassSaving && setShowThreatClassModal(false)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Edit threat classifications</h3>
          <div style={{ display: 'grid', gap: 12 }}>
            <ThreatClassificationMultiSelect
              value={threatClassDraft}
              onChange={setThreatClassDraft}
              options={threatClassOptions}
              inactiveOptions={threatClassEditInactiveOptions}
              disabled={threatClassSaving}
            />
            {threatClassError ? <div style={{ color: '#fca5a5', fontSize: 13 }}>{threatClassError}</div> : null}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button type="button" style={ui.btn} onClick={() => setShowThreatClassModal(false)} disabled={threatClassSaving}>Cancel</button>
              <button type="button" style={ui.btnPrimary} onClick={() => submitThreatClassification().catch(() => {})} disabled={threatClassSaving}>
                {threatClassSaving ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </ModalOverlay>
      ) : null}

      {showThreatActorModal ? (
        <ModalOverlay onClose={() => !threatActorSaving && setShowThreatActorModal(false)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Edit threat actor</h3>
          <div style={{ display: 'grid', gap: 12 }}>
            <div>
              <span style={ui.label}>Threat actor</span>
              <select
                value={threatActorDraft}
                onChange={(e) => setThreatActorDraft(e.target.value)}
                disabled={threatActorSaving}
                style={ui.input}
              >
                <option value="">Not selected</option>
                {threatActors.map((actor) => (
                  <option key={actor.id} value={actor.id}>{actor.name}</option>
                ))}
              </select>
            </div>
            {threatActorError ? <div style={{ color: '#fca5a5', fontSize: 13 }}>{threatActorError}</div> : null}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button type="button" style={ui.btn} onClick={() => setShowThreatActorModal(false)} disabled={threatActorSaving}>Cancel</button>
              <button type="button" style={ui.btnPrimary} onClick={() => submitThreatActor().catch(() => {})} disabled={threatActorSaving}>
                {threatActorSaving ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </ModalOverlay>
      ) : null}
    </AppShell>
  );
}

function formatIocSourceDefaultExpiration(source) {
  const pol = source?.default_expire_policy || 'never';
  if (pol === 'never') return 'Never expires';
  if (pol === 'expire_after_days') {
    return `Expires after ${source?.default_expire_days || '?'} days`;
  }
  if (pol === 'custom_date') return 'Custom expire date';
  return formatExpirationPolicyLabel(pol);
}

function formatIocSourceDefaultsHelper(source, threatClassOptions) {
  if (!source) return null;
  const conf = confidenceLabel(source.default_confidence || 'medium');
  const threatSlug = source.default_threat_classification || 'unknown';
  const threatOption = threatClassOptions.find((o) => o.value === threatSlug);
  const threatLabel = threatOption?.label
    || String(threatSlug).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  return `Source defaults: Confidence ${conf} · Threat class ${threatLabel} · ${formatIocSourceDefaultExpiration(source)}`;
}

function IOCAddPage() {
  const navigate = useNavigate();
  const { canWrite } = useSession();
  const { options: threatClassOptions } = useThreatClassifications();
  const [threatActors, setThreatActors] = useState([]);
  const [threatActorsLoading, setThreatActorsLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState(null);
  const [recentRows, setRecentRows] = useState([]);
  const sourceColorIndex = useSourceColorIndex();
  const [recentSort, setRecentSort] = useState({ key: null, dir: null });
  const [recentWidths, setRecentWidths] = useState({ idx: 50, observable: 420, type: 110, source: 220, confidence: 110, ts: 170 });
  const [recentResize, setRecentResize] = useState(null);
  const [iocValue, setIocValue] = useState('');
  const [confidenceValue, setConfidenceValue] = useState('medium');
  const [sourceId, setSourceId] = useState('');
  const [sourceUrl, setSourceUrl] = useState('');
  const [primaryThreatClass, setPrimaryThreatClass] = useState([]);
  const [threatActorId, setThreatActorId] = useState('');
  const [note, setNote] = useState('');
  const [sources, setSources] = useState([]);
  const [sourcesLoading, setSourcesLoading] = useState(true);
  const iocFormRef = useRef(null);

  useEffect(() => {
    if (!message) return;
    const t = setTimeout(() => setMessage(null), 6000);
    return () => clearTimeout(t);
  }, [message]);

  async function loadSources() {
    setSourcesLoading(true);
    try {
      const { data } = await api.get('/ioc-sources');
      setSources(Array.isArray(data?.sources) ? data.sources : []);
    } catch {
      setSources([]);
    } finally {
      setSourcesLoading(false);
    }
  }

  useEffect(() => { loadSources().catch(() => {}); }, []);

  useEffect(() => {
    let active = true;
    (async () => {
      setThreatActorsLoading(true);
      try {
        const { data } = await api.get('/admin/threat-actors', { params: { include_inactive: false } });
        if (active) setThreatActors(Array.isArray(data?.threat_actors) ? data.threat_actors : []);
      } catch {
        if (active) setThreatActors([]);
      } finally {
        if (active) setThreatActorsLoading(false);
      }
    })();
    return () => { active = false; };
  }, []);

  function applySourceDefaults(nextSourceId) {
    const src = sources.find((s) => String(s.id) === String(nextSourceId));
    if (!src) return;
    if (src.default_confidence) setConfidenceValue(src.default_confidence);
    if (src.default_threat_classification && src.default_threat_classification !== 'unknown') {
      setPrimaryThreatClass([src.default_threat_classification]);
    } else setPrimaryThreatClass([]);
  }

  function handleSourceChange(e) {
    const next = e.target.value;
    setSourceId(next);
    applySourceDefaults(next);
  }

  function resetFormFields() {
    setIocValue('');
    setConfidenceValue('medium');
    setSourceId('');
    setSourceUrl('');
    setPrimaryThreatClass([]);
    setThreatActorId('');
    setNote('');
  }


  function detectIocType(value) {
    const v = String(value || '').trim();
    if (!v) return null;
    const ipv4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    const ipv6 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::)$/;
    const url = /^(https?:\/\/)[^\s/$.?#].[^\s]*$/i;
    const hash = /^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$/;
    const domain = /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;

    if (url.test(v)) return 'url';
    if (ipv4.test(v) || ipv6.test(v)) return 'ip';
    if (hash.test(v)) return 'hash';
    if (domain.test(v)) return 'domain';
    return 'unknown';
  }

  function iocTypeStyle(type) {
    const map = {
      url: { color: '#60a5fa', border: '#2563eb', bg: 'rgba(37,99,235,0.15)' },
      domain: { color: '#22d3ee', border: '#0891b2', bg: 'rgba(8,145,178,0.18)' },
      ip: { color: '#34d399', border: '#059669', bg: 'rgba(5,150,105,0.18)' },
      hash: { color: '#f472b6', border: '#db2777', bg: 'rgba(219,39,119,0.16)' },
      unknown: { color: '#94a3b8', border: '#475569', bg: 'rgba(71,85,105,0.2)' }
    };
    return map[type] || map.unknown;
  }

  function confidencePillStyle(value) {
    if (value === 'high') return { color: '#991b1b', bg: '#fee2e2' };
    if (value === 'medium') return { color: '#92400e', bg: '#fef3c7' };
    return { color: '#166534', bg: '#dcfce7' };
  }

  function relativeTime(dateVal) {
    const ts = new Date(dateVal || 0).getTime();
    if (!Number.isFinite(ts) || ts <= 0) return '-';
    const diffSec = Math.max(1, Math.floor((Date.now() - ts) / 1000));
    if (diffSec < 60) return `${diffSec}s ago`;
    const min = Math.floor(diffSec / 60);
    if (min < 60) return `${min} min ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.floor(hr / 24);
    if (day < 7) return `${day}d ago`;
    return formatUserDateTime(dateVal);
  }

  async function loadRecent() {
    const res = await api.get('/ioc/recent', { params: { limit: 10 } });
    setRecentRows(res.data?.items || []);
  }

  useEffect(() => {
    loadRecent().catch(() => {});
  }, []);

  useEffect(() => {
    if (!recentResize) return undefined;
    function onMove(e) {
      const delta = e.clientX - recentResize.startX;
      const next = Math.max(70, recentResize.startWidth + delta);
      setRecentWidths((prev) => ({ ...prev, [recentResize.col]: next }));
    }
    function onUp() { setRecentResize(null); }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [recentResize]);

  function toggleRecentSort(key) {
    setRecentSort((prev) => {
      if (prev.key !== key) return { key, dir: 'asc' };
      if (prev.dir === 'asc') return { key, dir: 'desc' };
      if (prev.dir === 'desc') return { key: null, dir: null };
      return { key, dir: 'asc' };
    });
  }

  function recentIndicator(key) {
    if (recentSort.key !== key || !recentSort.dir) return '';
    return recentSort.dir === 'asc' ? ' ?' : ' ?';
  }

  function startRecentResize(col, e) {
    e.preventDefault();
    e.stopPropagation();
    setRecentResize({ col, startX: e.clientX, startWidth: recentWidths[col] || 120 });
  }


  const sortedRecentRows = useMemo(() => {
    if (!recentSort.key || !recentSort.dir) return recentRows;
    const copy = [...recentRows];
    const value = (r, k) => {
      if (k === 'observable') return r.observable;
      if (k === 'type') return r.observable_type;
      if (k === 'source') return r.source_label || r.source_name || '';
      if (k === 'confidence') return r.confidence || '';
      if (k === 'ts') return new Date(r.created_at || 0).getTime();
      return '';
    };
    copy.sort((a, b) => {
      const av = value(a, recentSort.key);
      const bv = value(b, recentSort.key);
      const cmp = (typeof av === 'number' && typeof bv === 'number') ? av - bv : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: 'base' });
      return recentSort.dir === 'asc' ? cmp : -cmp;
    });
    return copy;
  }, [recentRows, recentSort]);

  const selectedSource = useMemo(
    () => sources.find((s) => String(s.id) === String(sourceId)) || null,
    [sources, sourceId]
  );
  const sourceDefaultsHelper = useMemo(
    () => formatIocSourceDefaultsHelper(selectedSource, threatClassOptions),
    [selectedSource, threatClassOptions]
  );

  async function onSubmit(e) {
    e.preventDefault();
    if (!canWrite || submitting) return;
    if (!sourceId) {
      setMessage({ type: 'error', text: 'Please select an IOC source.' });
      return;
    }
    setSubmitting(true);

    const selectedClasses = normalizeSelectedThreatClasses(primaryThreatClass);
    const payload = {
      ip: iocValue.trim(),
      source_id: Number(sourceId),
      source_url: sourceUrl.trim() || undefined,
      confidence: confidenceValue,
      threat_classifications: selectedClasses,
      threat_classification: selectedClasses[0] || 'unknown',
      primary_threat_classification: selectedClasses[0] || 'unknown',
      note: note.trim() || undefined
    };
    if (threatActorId) {
      payload.threat_actor_id = threatActorId;
    }

    try {
      const { data } = await api.post('/ioc/ip', payload);
      resetFormFields();
      loadRecent().catch(() => {});
      if (data?.skipped) {
        setMessage({ type: 'duplicate', text: 'Already in list (duplicate).' });
      } else {
        const srcLabel = data?.source?.name || data?.source_name || 'source';
        const expLabel = data?.expiration_policy === 'never'
          ? 'never expires'
          : (data?.expires_at ? `expires ${formatUserDateTime(data.expires_at)}` : 'expiration set');
        setMessage({ type: 'success', text: `IOC saved · source: ${srcLabel}, ${expLabel}.` });
      }
    } catch (err) {
      const msg = apiErrorMessage(err, 'Failed to save record');
      setMessage({ type: 'error', text: msg });
    } finally {
      setSubmitting(false);
    }
  }

  const detectedType = detectIocType(iocValue);
  const detectedStyle = iocTypeStyle(detectedType || 'unknown');

  const messageStyle = message?.type === 'success'
    ? { background: 'rgba(34,197,94,0.16)', border: '1px solid #22c55e', color: '#86efac' }
    : message?.type === 'duplicate'
      ? { background: 'rgba(234,179,8,0.16)', border: '1px solid #eab308', color: '#fde68a' }
      : { background: 'rgba(239,68,68,0.16)', border: '1px solid #ef4444', color: '#fca5a5' };

  const confidenceStyle = confidencePillStyle(confidenceValue);
  const inputStyle = { width: '100%', minWidth: 0, height: 42, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: '#020617', color: '#e2e8f0', boxSizing: 'border-box' };
  const fieldLabelStyle = { display: 'block', marginBottom: 6, fontSize: 12, color: '#cbd5e1', fontWeight: 600 };
  const twoColRowStyle = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14, alignItems: 'end' };

  return (
    <AppShell>
      <section style={{ display: 'grid', gap: 14 }}>
        <div style={{ border: '1px solid #334155', borderRadius: 14, background: '#0f172a', padding: 18, boxShadow: '0 8px 28px rgba(2, 6, 23, 0.35)' }}>
          <h2 style={{ marginTop: 0, marginBottom: 4 }}>Add IOC</h2>
          <p style={{ marginTop: 0, marginBottom: 14, color: '#94a3b8', fontSize: 13 }}>Insert indicator data with confidence and source metadata.</p>
          {!canWrite && (
            <div style={{ marginBottom: 12, padding: 10, borderRadius: 8, border: '1px solid #475569', color: '#94a3b8', fontSize: 14 }}>
              Read-only role: adding IOCs is disabled.
            </div>
          )}
          {!sourcesLoading && !sources.length && canWrite ? (
            <div style={{ marginBottom: 12, padding: '12px 14px', borderRadius: 8, border: '1px solid #92400e', background: 'rgba(217,119,6,0.12)', color: '#fde68a', fontSize: 14 }}>
              No active IOC sources defined. Please create or enable a source first.
              {' '}
              <Link to="/administration/ioc-sources" style={{ color: '#93c5fd', fontWeight: 600 }}>Administration → IOC Sources</Link>
            </div>
          ) : null}
              {message && (
            <div role="alert" style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, fontSize: 14, ...messageStyle }}>
              {message.text}
            </div>
              )}

          <form ref={iocFormRef} onSubmit={onSubmit} style={{ display: 'grid', gap: 14 }}>
            <div>
              <label htmlFor="ioc-value" style={{ ...fieldLabelStyle, letterSpacing: 0.3 }}>IOC Value</label>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <input id="ioc-value" name="ip" value={iocValue} onChange={(e) => setIocValue(e.target.value)} required disabled={!canWrite} spellCheck={false} style={{ ...inputStyle, flex: 1 }} />
                {detectedType && (
                  <span style={{ display: 'inline-flex', alignItems: 'center', whiteSpace: 'nowrap', padding: '6px 9px', borderRadius: 999, border: `1px solid ${detectedStyle.border}`, background: detectedStyle.bg, color: detectedStyle.color, fontWeight: 700, fontSize: 12, textTransform: 'uppercase', letterSpacing: 0.4 }}>
                    {detectedType}
                  </span>
                )}
              </div>
            </div>

            <div style={twoColRowStyle}>
              <div>
                <label htmlFor="source-id" style={fieldLabelStyle}>Source</label>
                <select
                  id="source-id"
                  required
                  value={sourceId}
                  onChange={handleSourceChange}
                  disabled={!canWrite || sourcesLoading || !sources.length}
                  style={inputStyle}
                >
                  <option value="">{sourcesLoading ? 'Loading sources…' : 'Select source…'}</option>
                  {sources.map((s) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="source-url" style={fieldLabelStyle}>Source URL</label>
                <input id="source-url" value={sourceUrl} onChange={(e) => setSourceUrl(e.target.value)} disabled={!canWrite} style={inputStyle} placeholder="Optional" />
              </div>
            </div>

            {sourceDefaultsHelper ? (
              <p className="ioc-add-source-defaults" style={{ margin: 0, fontSize: 12, color: '#94a3b8', lineHeight: 1.45 }}>
                {sourceDefaultsHelper}
              </p>
            ) : null}

            <div style={twoColRowStyle}>
              <div>
                <label htmlFor="confidence" style={fieldLabelStyle}>Confidence</label>
                <select id="confidence" value={confidenceValue} onChange={(e) => setConfidenceValue(e.target.value)} disabled={!canWrite} style={{ ...inputStyle, background: confidenceStyle.bg, color: confidenceStyle.color, fontWeight: 700, fontSize: 12, textTransform: 'capitalize' }}>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
            </div>
	            <div>
	              <label style={fieldLabelStyle}>Threat Classifications</label>
	              <ThreatClassificationMultiSelect
	                value={primaryThreatClass}
	                onChange={setPrimaryThreatClass}
	                options={threatClassOptions}
	                disabled={!canWrite}
	              />
	            </div>
	            <div>
	              <label htmlFor="threat-actor-id" style={fieldLabelStyle}>Threat Actor (optional)</label>
	              <select id="threat-actor-id" value={threatActorId} onChange={(e) => setThreatActorId(e.target.value)} disabled={!canWrite || threatActorsLoading} style={inputStyle}>
	                <option value="">{threatActorsLoading ? 'Loading threat actors…' : 'Not selected'}</option>
	                {threatActors.map((actor) => (
	                  <option key={actor.id} value={actor.id}>{actor.name}</option>
	                ))}
	              </select>
	            </div>

            <div>
              <label htmlFor="note" style={fieldLabelStyle}>Note</label>
              <input id="note" value={note} onChange={(e) => setNote(e.target.value)} disabled={!canWrite} style={inputStyle} />
            </div>

            <button type="submit" disabled={submitting || !canWrite || !sources.length} style={{ width: '100%', padding: '11px 14px', borderRadius: 10, border: '1px solid #1d4ed8', background: submitting || !canWrite || !sources.length ? '#1e3a8a' : '#2563eb', color: '#dbeafe', fontWeight: 700, letterSpacing: 0.3, cursor: submitting || !canWrite || !sources.length ? 'not-allowed' : 'pointer', opacity: submitting || !canWrite || !sources.length ? 0.7 : 1 }}>
              {submitting ? 'Adding...' : '+ Add IOC'}
            </button>
          </form>
        </div>

        <div style={{ border: '1px solid #334155', borderRadius: 14, background: '#0f172a', boxShadow: '0 8px 28px rgba(2, 6, 23, 0.35)' }}>
          <div style={{ padding: '14px 16px 10px', borderBottom: '1px solid #334155' }}>
            <h3 style={{ margin: 0 }}>Last 10 IOC entries</h3>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 860, background: '#0f172a', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
              <colgroup>
                <col style={{ width: recentWidths.idx }} /><col style={{ width: recentWidths.observable }} /><col style={{ width: recentWidths.type }} /><col style={{ width: recentWidths.source }} /><col style={{ width: recentWidths.confidence }} /><col style={{ width: recentWidths.ts }} />
              </colgroup>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', background: '#111827' }}>
                  <th style={{ position: 'relative' }}>#<div onMouseDown={(e) => startRecentResize('idx', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('observable')} style={{ position: 'relative', cursor:'pointer' }}>IOC{recentIndicator('observable')}<div onMouseDown={(e) => startRecentResize('observable', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('type')} style={{ position: 'relative', cursor:'pointer' }}>IOC Type{recentIndicator('type')}<div onMouseDown={(e) => startRecentResize('type', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('source')} style={{ position: 'relative', cursor:'pointer' }}>Source{recentIndicator('source')}<div onMouseDown={(e) => startRecentResize('source', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('confidence')} style={{ position: 'relative', cursor:'pointer' }}>Confidence{recentIndicator('confidence')}<div onMouseDown={(e) => startRecentResize('confidence', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('ts')} style={{ position: 'relative', cursor:'pointer' }}>Timestamp{recentIndicator('ts')}<div onMouseDown={(e) => startRecentResize('ts', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                </tr>
              </thead>
              <tbody>
                {sortedRecentRows.map((r, idx) => {
                  const conf = confidencePillStyle(r.confidence);
                  const sourceLabel = r.source_label || r.source_name;
                  const sourceStyle = resolveSourceBadgeStyle(sourceColorIndex, sourceLabel);
                  return (
                    <tr key={`${r.observable_type}-${r.id}-${idx}`} style={{ borderBottom: '1px solid #1f2937', transition: 'background 0.15s ease-in-out' }} onMouseEnter={(e) => { e.currentTarget.style.background = '#111827'; }} onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}>
                      <td>{idx + 1}</td>
                      <td title={r.observable} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <button
                            onClick={() => r.public_id ? navigate(`/ioc/details/${encodeURIComponent(r.public_id)}`) : navigate('/ioc')}
                            style={{ background: 'transparent', border: 'none', color: '#93c5fd', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit', textAlign: 'left' }}
                          >
                            <code style={{ whiteSpace: 'inherit', overflowWrap: 'anywhere', wordBreak: 'break-word' }}>{r.observable}</code>
                          </button>
                        </div>
                      </td>
                      <td>{r.observable_type || '-'}</td>
                      <td title={sourceLabel} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                        <span style={{ display: 'inline-flex', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700, ...sourceStyle }}>{sourceLabel || '-'}</span>
                      </td>
                      <td>
                        <span style={{ display: 'inline-flex', borderRadius: 999, padding: '4px 10px', fontSize: 12, fontWeight: 700, textTransform: 'capitalize', color: conf.color, background: conf.bg }}>{r.confidence || '-'}</span>
                      </td>
                      <td>{formatUserDateTime(r.created_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </AppShell>
  );
}

function SetupGatePage() {
  const navigate = useNavigate();
  return (
    <InitialSetupPage
      onCompleted={(data) => {
        if (data?.system_timezone) setSystemTimezoneCache(data.system_timezone);
        notifyTimezoneChanged();
        navigate('/login', { replace: true });
      }}
    />
  );
}

function Protected({ children }) {
  const { authState } = useSession();

  if (authState === 'loading') {
    return <div style={{ padding: 24, fontFamily: 'sans-serif', color: '#94a3b8' }}>Loading…</div>;
  }
  if (authState === 'anon') return <Navigate to="/login" replace />;
  return children;
}

function DefaultRedirect() {
  const { authState } = useSession();

  if (authState === 'loading') {
    return <div style={{ padding: 24, fontFamily: 'sans-serif', color: '#94a3b8' }}>Loading…</div>;
  }
  if (authState === 'anon') return <Navigate to="/login" replace />;
  return <Navigate to="/ioc" replace />;
}

function App() {
  return (
    <>
      <style>{`
        :root { color-scheme: dark; }
        html.modal-scroll-lock,
        body.modal-scroll-lock {
          overflow: hidden !important;
        }
        html.modal-scroll-lock .app-shell,
        body.modal-scroll-lock .app-shell {
          overflow: hidden;
        }
        .app-shell {
          width: 100%;
          box-sizing: border-box;
        }
        .main-content {
          flex: 1;
          min-width: 0;
        }
        .page-content {
          width: 100%;
          min-width: 0;
        }
        .modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(2, 6, 23, 0.72);
          z-index: 1000;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 24px;
        }
        .modal-overlay--purge {
          z-index: 1100;
        }
        .modal-dialog {
          width: min(720px, 96vw);
          max-height: calc(100vh - 48px);
          display: flex;
          flex-direction: column;
          overflow: hidden;
          background: linear-gradient(180deg, #111827 0%, #0f172a 100%);
          border-radius: 12px;
          padding: 0;
          border: 1px solid #334155;
          color: #e2e8f0;
          box-shadow: 0 24px 60px rgba(2, 6, 23, 0.55);
        }
        .modal-dialog--purge {
          width: min(560px, 100%);
        }
        .modal-dialog--legacy {
          padding: 24px;
          overflow-y: auto;
        }
        .modal-header {
          flex-shrink: 0;
          padding: 20px 24px 0;
        }
        .modal-title {
          margin: 0;
          color: #f1f5f9;
          font-size: 18px;
          font-weight: 700;
        }
        .modal-body {
          flex: 1 1 auto;
          min-height: 0;
          overflow-y: auto;
          padding: 16px 24px;
        }
        .modal-header + .modal-body {
          padding-top: 12px;
        }
        .modal-footer {
          flex-shrink: 0;
          display: flex;
          justify-content: flex-end;
          gap: 8px;
          flex-wrap: wrap;
          padding: 12px 24px 20px;
          border-top: 1px solid #334155;
          background: #0f172a;
        }
        html, body, #root {
          background: #0b1220 !important;
          color: #e2e8f0 !important;
        }
        * { scrollbar-color: #334155 #0b1220; }
        aside, section, main, table, thead, tbody, tr, th, td, div {
          border-color: #334155 !important;
        }
        section, aside, table, .card, [style*='background: #fff'], [style*='background: #ffffff'], [style*='background: #f8fafc'] {
          background: #111827 !important;
          color: #e2e8f0 !important;
        }
        input, select, textarea {
          background: #0f172a !important;
          color: #e2e8f0 !important;
          border: 1px solid #334155 !important;
        }
        button {
          background: #1f2937 !important;
          color: #e2e8f0 !important;
          border: 1px solid #475569 !important;
        }
        button:hover { background: #334155 !important; }
        a { color: #93c5fd !important; }
        thead tr { background: #1f2937 !important; }
        tbody tr { background: #111827 !important; }
        code { color: #93c5fd !important; }
        table th, table td { border-right: 1px solid #334155 !important; }
        table th:last-child, table td:last-child { border-right: none !important; }
        .ioc-table th, .ioc-table td { border-right: 1px solid #334155 !important; }
        .ioc-table th:last-child, .ioc-table td:last-child { border-right: none !important; }
        .ioc-list-page .ioc-list-table {
          background: #0f172a !important;
        }
        .ioc-list-page .ioc-list-table thead tr {
          background: #1f2937 !important;
        }
        .ioc-list-page .ioc-list-table th {
          color: #94a3b8;
        }
        .ioc-list-page .ioc-list-table td {
          color: #e2e8f0;
        }
        .ioc-list-page .ioc-list-table tbody tr {
          border-bottom: 1px solid #334155 !important;
        }
        .ioc-list-source-badge {
          display: inline;
          padding: 2px 8px;
          border-radius: 6px;
          background: rgba(148, 163, 184, 0.12);
          border: 1px solid rgba(148, 163, 184, 0.25);
          color: #e2e8f0;
          line-height: 1.35;
          word-break: break-word;
          overflow-wrap: anywhere;
        }
        .ioc-list-source-muted {
          display: inline;
          color: #94a3b8;
          font-style: italic;
          line-height: 1.35;
        }
        .ioc-list-page button.ioc-list-source-link {
          display: inline;
          max-width: 100%;
          background: rgba(148, 163, 184, 0.12);
          border: 1px solid rgba(148, 163, 184, 0.25);
          color: #e2e8f0;
          border-radius: 6px;
          padding: 2px 8px;
          font: inherit;
          text-align: left;
          cursor: pointer;
          text-decoration: none;
          line-height: 1.35;
          word-break: break-word;
          overflow-wrap: anywhere;
        }
        .ioc-list-page button.ioc-list-source-link:hover {
          filter: brightness(1.12);
        }
        .ioc-list-page button.ioc-list-source-link:focus-visible {
          outline: 2px solid #93c5fd;
          outline-offset: 2px;
        }
        .ioc-list-page button.ioc-list-source-link .ioc-list-source-extra {
          color: currentColor;
          opacity: 0.75;
          font-weight: 600;
        }
        .integrations-feeds-table-scroll {
          overflow-x: auto;
          max-width: 100%;
          -webkit-overflow-scrolling: touch;
        }
        .integrations-feeds-table {
          width: 100%;
          min-width: 760px;
          table-layout: auto;
        }
        .integrations-feeds-table .integrations-feeds-col-state { min-width: 88px; width: 88px; }
        .integrations-feeds-table .integrations-feeds-col-feed { min-width: 180px; }
        .integrations-feeds-table .integrations-feeds-col-health { min-width: 100px; width: 100px; }
        .integrations-feeds-table .integrations-feeds-col-last-run { min-width: 130px; }
        .integrations-feeds-table .integrations-feeds-col-metrics { min-width: 220px; }
        .integrations-feeds-table .integrations-feeds-col-next-run { min-width: 130px; }
        .integrations-feeds-table .integrations-feeds-col-action { min-width: 110px; width: 110px; }
        .integrations-feeds-table .integrations-feeds-feed-name {
          word-break: normal;
          overflow-wrap: normal;
          white-space: normal;
        }
        .integrations-feeds-table .integrations-feeds-action-cell {
          white-space: nowrap;
          vertical-align: top;
        }
        .integrations-feeds-table .integrations-feeds-action-buttons {
          min-width: 96px;
        }
        .integrations-feeds-table .integrations-feeds-action-buttons button {
          white-space: nowrap;
        }
        .threat-classifications-table {
          width: 100%;
          table-layout: fixed;
          font-size: 13px;
        }
        .threat-classifications-table .tc-col-classification { width: 24%; min-width: 160px; }
        .threat-classifications-table .tc-col-description { width: auto; }
        .threat-classifications-table .tc-col-status { width: 88px; }
        .threat-classifications-table .tc-col-builtin { width: 72px; text-align: center; }
        .threat-classifications-table .tc-col-order { width: 64px; text-align: center; }
        .threat-classifications-table .tc-col-actions { width: 160px; }
        .threat-classifications-table .tc-description-cell {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          max-width: 0;
        }
        .threat-classifications-table .tc-actions-cell {
          white-space: nowrap;
          vertical-align: middle;
        }
        .threat-classifications-table .tc-action-buttons {
          display: inline-flex;
          flex-wrap: nowrap;
          gap: 6px;
          align-items: center;
        }
        .threat-classifications-table .tc-action-buttons button {
          white-space: nowrap;
          padding: 6px 10px;
          font-size: 12px;
        }
        .published-feeds-page input:focus,
        .published-feeds-page select:focus,
        .published-feeds-page textarea:focus {
          outline: none !important;
          border-color: #3b82f6 !important;
          box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.35) !important;
        }
        .published-feeds-page input::placeholder,
        .published-feeds-page textarea::placeholder {
          color: #64748b !important;
          opacity: 1;
        }
        .published-feeds-page .published-feeds-table thead tr {
          background: #0f172a !important;
        }
        .queue-health-panel {
          background: #0f172a !important;
          color: #e2e8f0 !important;
          border: 1px solid #334155 !important;
        }
        .queue-health-panel--healthy {
          background: rgba(22, 101, 52, 0.22) !important;
          border-color: #166534 !important;
        }
        .queue-health-panel--degraded {
          background: rgba(120, 53, 15, 0.28) !important;
          border-color: #854d0e !important;
        }
        .queue-health-panel--blocked {
          background: rgba(127, 29, 29, 0.32) !important;
          border-color: #991b1b !important;
        }
        .queue-health-warnings {
          margin: 8px 0 0;
          padding-left: 18px;
          color: #fcd34d !important;
        }
        .queue-recover-preview {
          background: rgba(120, 53, 15, 0.28) !important;
          color: #e2e8f0 !important;
          border: 1px solid #854d0e !important;
        }
        .queue-recover-error {
          color: #fca5a5 !important;
        }

        /* --- Responsive layout ------------------------------- */

        .mobile-topbar {
          display: none;
          align-items: center;
          gap: 12px;
          padding: 0 14px;
          height: 52px;
          border-bottom: 1px solid #334155;
          position: sticky;
          top: 0;
          z-index: 100;
          box-sizing: border-box;
          flex-shrink: 0;
          background: #111827 !important;
          width: 100%;
        }
        button.mobile-menu-btn {
          background: transparent !important;
          border: none !important;
          box-shadow: none !important;
          color: #e2e8f0 !important;
          font-size: 22px;
          padding: 4px 8px !important;
          cursor: pointer;
          line-height: 1;
          flex-shrink: 0;
        }
        .mobile-topbar-title {
          flex: 1;
          font-weight: 700;
          font-size: 16px;
          color: #f1f5f9 !important;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        .mobile-topbar-user {
          font-size: 12px;
          color: #94a3b8 !important;
          white-space: nowrap;
          max-width: 120px;
          overflow: hidden;
          text-overflow: ellipsis;
          flex-shrink: 0;
        }
        .mobile-backdrop {
          position: fixed;
          inset: 0;
          background: rgba(2, 6, 23, 0.6) !important;
          z-index: 198;
          border: none !important;
        }
        .mobile-sidebar-close {
          display: none;
          padding: 8px 4px 4px;
          text-align: right;
        }
        .mobile-sidebar-close button {
          background: transparent !important;
          border: none !important;
          color: #94a3b8 !important;
          font-size: 18px;
          padding: 4px 8px !important;
          cursor: pointer;
          line-height: 1;
        }

        @media (max-width: 1023px) {
          html, body {
            overflow-x: hidden;
          }
          .app-shell {
            flex-direction: column !important;
            padding: 0 !important;
            margin: 0 !important;
            gap: 0 !important;
            align-items: stretch !important;
          }
          .mobile-topbar {
            display: flex !important;
          }
          .sidebar {
            position: fixed !important;
            left: 0 !important;
            top: 0 !important;
            height: 100vh !important;
            width: min(85vw, 300px) !important;
            overflow-y: auto !important;
            border-radius: 0 !important;
            border-top: none !important;
            border-bottom: none !important;
            border-left: none !important;
            transform: translateX(-100%);
            transition: transform 0.25s ease;
            z-index: 200 !important;
            box-sizing: border-box !important;
            flex: none !important;
          }
          .sidebar--open {
            transform: translateX(0) !important;
          }
          .mobile-sidebar-close {
            display: block;
          }
          .main-content {
            width: 100% !important;
            max-width: 100% !important;
            min-width: 0 !important;
            box-sizing: border-box !important;
            padding: 16px 14px !important;
          }
        }

        @media (max-width: 767px) {
          .main-content {
            padding: 12px 10px !important;
          }
          .modal-footer {
            flex-direction: column-reverse;
          }
          .modal-footer button {
            width: 100%;
          }
        }
      `}</style>
      <BrowserRouter>
        <SessionProvider>
        <ReasonPromptProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/setup" element={<SetupGatePage />} />
          <Route path="/system" element={<Protected><SystemStatusPage /></Protected>} />
          <Route path="/ioc" element={<Protected><IOCListPage /></Protected>} />
          <Route path="/ioc/details/:publicId" element={<Protected><IOCDetailsPage /></Protected>} />
          <Route path="/ioc/details/:type/:observable" element={<Protected><LegacyIOCDetailsRedirect /></Protected>} />
          <Route path="/ioc/new" element={<Protected><IOCAddPage /></Protected>} />
          <Route path="/operations/ioc-suppressions" element={<Protected><IOCSuppressionsPage /></Protected>} />
          <Route path="/action-center" element={<Protected><ActionCenterPage /></Protected>} />
          <Route path="/threat-intelligence" element={<Navigate to="/threat-intelligence/feeds" replace />} />
          <Route path="/threat-intelligence/feeds" element={<Protected><IntegrationsPage /></Protected>} />
          <Route path="/threat-intelligence/enrichment" element={<Navigate to="/administration/enrichment-providers" replace />} />
          <Route path="/threat-intelligence/queue" element={<Protected><IntegrationsQueueStatusPage /></Protected>} />
          <Route path="/threat-intelligence/custom-threat-feeds" element={<Protected><CustomThreatFeedsPage /></Protected>} />
          <Route path="/threat-intelligence/published-feeds" element={<Protected><PublishedFeedsPage /></Protected>} />
          <Route path="/administration/audit-logs" element={<Protected><AuditLogsPage /></Protected>} />
          <Route path="/administration/tags" element={<Protected><TagManagerPage /></Protected>} />
          <Route path="/administration/threat-classifications" element={<Protected><ThreatClassificationManagerPage /></Protected>} />
          <Route path="/administration/threat-actors" element={<Protected><ThreatActorManagerPage /></Protected>} />
          <Route path="/administration/ioc-sources" element={<Protected><IocSourcesPage /></Protected>} />
          <Route path="/administration/api-keys" element={<Protected><ApiKeysPage /></Protected>} />
          <Route path="/administration/enrichment-providers" element={<Protected><EnrichmentProvidersPage /></Protected>} />
          <Route path="/administration/backup-restore" element={<Protected><BackupRestorePage /></Protected>} />
          <Route path="/administration/users" element={<Protected><UsersPage /></Protected>} />
          <Route path="/administration" element={<Protected><AdministrationSettingsPage /></Protected>} />
          <Route path="/settings" element={<Navigate to="/administration" replace />} />
          <Route path="*" element={<DefaultRedirect />} />
        </Routes>
        </ReasonPromptProvider>
        </SessionProvider>
      </BrowserRouter>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
