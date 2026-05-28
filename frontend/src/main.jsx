import React, { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { parse as parseTld } from 'tldts';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import axios from 'axios';
import { getIocStatusCardPresentation, IOC_STATUS_ACTION_BUTTONS } from './lib/iocStatusCard.js';
import {
  CONFIDENCE_OPTIONS,
  getIocConfidencePresentation,
  formatConfidenceAuditMetadata,
  confidenceBadgeStyle,
  confidenceLabel
} from './lib/iocConfidenceCard.js';
import { ComposableMap, Geographies, Geography, ZoomableGroup } from 'react-simple-maps';

const CSRF_COOKIE_NAME = 'demo_csrf';

function readCookie(name) {
  const parts = `; ${document.cookie}`.split(`; ${name}=`);
  if (parts.length === 2) return decodeURIComponent(parts.pop().split(';').shift() || '');
  return '';
}

const api = axios.create({ baseURL: '/api', withCredentials: true });

api.interceptors.request.use((config) => {
  const method = String(config.method || 'get').toLowerCase();
  if (['post', 'put', 'patch', 'delete'].includes(method)) {
    const csrf = readCookie(CSRF_COOKIE_NAME);
    if (csrf) {
      config.headers = config.headers || {};
      config.headers['X-CSRF-Token'] = csrf;
    }
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const url = String(err.config?.url || '');
    const st = err.response?.status;
    if ((st === 401 || st === 403) && !url.includes('/auth/login')) {
      if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
        window.location.assign('/login');
      }
    }
    return Promise.reject(err);
  }
);

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

function formatUserDateTime(value) {
  if (!value && value !== 0) return '-';
  const timeZone = localStorage.getItem('demo_timezone') || 'UTC';

  let dt;
  if (value instanceof Date) {
    dt = value;
  } else if (typeof value === 'number') {
    const ms = value > 1e12 ? value : value * 1000;
    dt = new Date(ms);
  } else {
    const raw = String(value).trim();
    if (!raw) return '-';

    if (/^\d+$/.test(raw)) {
      const num = Number(raw);
      const ms = num > 1e12 ? num : num * 1000;
      dt = new Date(ms);
    } else {
      const hasTz = /([zZ]|[+\-]\d{2}:?\d{2})$/.test(raw);
      const normalized = raw.includes(' ') ? raw.replace(' ', 'T') : raw;
      dt = new Date(hasTz ? normalized : `${normalized}Z`);
    }
  }

  if (Number.isNaN(dt.getTime())) return '-';

  return dt.toLocaleString('en-GB', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

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

function retroHealthPresentation(stateHealth, fallbackLabel) {
  const key = String(stateHealth || 'ERROR').toUpperCase();
  const map = {
    OK: { label: 'OK', color: '#22c55e' },
    WARNING: { label: 'Warning', color: '#fbbf24' },
    STALE: { label: 'Stale', color: '#fb923c' },
    ERROR: { label: 'Error', color: '#f87171' }
  };
  const base = map[key] || map.ERROR;
  return fallbackLabel ? { ...base, label: fallbackLabel } : base;
}

function retroHealthLine(label, healthKey, labelOverride) {
  const presentation = retroHealthPresentation(healthKey, labelOverride);
  return (
    <div>
      <b>{label}:</b>{' '}
      <span style={{ color: presentation.color, fontWeight: 700 }}>{presentation.label}</span>
    </div>
  );
}

const RETRO_STATUS_TOOLTIPS = {
  lastRun: 'Retro worker’ın son başarılı run/state yazma zamanı. 1 saatlik periyoda göre 65 dakikayı aşarsa uyarı verilir.',
  lastRunAge: 'Son retro run’dan bu yana geçen süre. Varsayılan eşik: 60 dk interval + 5 dk grace → 65 dk uyarı, 90 dk stale.',
  processedCursor: 'Retro scan tarafından başarıyla kapsanan en son ClickHouse IOC lookup timestamp’i. Worker bitiş zamanı değildir.',
  chMaxLookup: 'Latest updated_at in ClickHouse ioc_lookup (active IOCs only). Retro scans IOCs up to this stream position after sync.',
  retroBacklog: 'IOCs in ClickHouse waiting for retro scan after the processed cursor.',
  cursorLag: 'Seconds between processed IOC cursor and latest ClickHouse ioc_lookup updated_at.',
  pgUnsynced: 'IOCs present in PostgreSQL but not yet synced into ClickHouse ioc_lookup. Retro can only scan after sync.',
  pgSyncLag: 'PostgreSQL’e gelen IOC’lerin ClickHouse ioc_lookup tablosuna sync edilmesindeki gecikme. Retro scan bu sync tamamlanmadan bu IOC’leri göremez.',
  workerHealth: 'Retro worker run periyodu (varsayılan saatlik). Son run yaşı 65 dk üstünde uyarı, 90 dk üstünde stale.',
  cursorHealth: 'Retro cursor ve CH backlog. Backlog 0 ve cursor lag düşükse OK.',
  syncHealth: 'PG→CH correlation sync gecikmesi. Retro worker health’ten bağımsız değerlendirilir.',
  overallHealth: 'Retro worker, cursor ve correlation sync health birleşimi.'
};

function integrationJobReasonLabel(job) {
  const state = String(job?.state || job?.status || '').toLowerCase();
  if (state === 'queued' && job?.queue_hint) return job.queue_hint;
  if (state === 'success') return 'Completed successfully';
  if (state === 'running') {
    const parts = [];
    if (job?.running_for_ms != null) parts.push(`running for ${formatDurationMs(job.running_for_ms)}`);
    if (job?.started_at) parts.push(`started ${formatUserDateTime(job.started_at)}`);
    if (job?.possibly_stuck) parts.push('Possibly stuck / stale');
    return parts.length ? parts.join(' · ') : '-';
  }
  if (job?.failed_reason) {
    if (job?.failure_type) return `[${job.failure_type}] ${job.failed_reason}`;
    return job.failed_reason;
  }
  return '-';
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
  return { ...base, background: 'rgba(148,163,184,0.15)', color: '#94a3b8', border: '1px solid #475569' };
}

function apiErrorMessage(err, fallback = 'Request failed') {
  const d = err?.response?.data;
  if (d?.error) return String(d.error);
  if (Array.isArray(d?.errors) && d.errors.length) return d.errors.join('; ');
  return String(d?.message || err?.message || fallback);
}

function isApiMutationSuccess(data) {
  if (data == null) return true;
  if (data.success === false) return false;
  return data.success === true || data.ok === true;
}

const IOC_EXPIRATION_ACTION_PRESETS = {
  expire_ioc: {
    title: 'Expire IOC now',
    description: 'This IOC will be marked as expired. It will not be published/exported and will not be used in syslog correlation. Existing incidents, detection events and audit history will remain unchanged.',
    requiresReason: true,
    requiresDate: false,
    confirmLabel: 'Expire IOC',
    danger: true,
    successToast: 'IOC marked as expired'
  },
  reactivate_ioc: {
    title: 'Reactivate IOC',
    description: 'This will manually reactivate the IOC. It may become eligible for publish/export and syslog correlation again unless disabled or suppressed.',
    requiresReason: true,
    requiresDate: false,
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

  return (
    <ModalOverlay onClose={loading ? undefined : onCancel}>
      <h3 style={{ marginTop: 0, color: '#f1f5f9', fontSize: 18 }}>{pending.title}</h3>
      <p style={{ color: '#cbd5e1', fontSize: 13, lineHeight: 1.55, marginTop: 0, marginBottom: 14 }}>{pending.description}</p>
      <div style={{ display: 'grid', gap: 12 }}>
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
  'ioc_feed_membership.expired',
  'ioc_feed_membership.expired_by_user'
]);

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
  if (row?.entity_display) return row.entity_display;
  const value = auditSnapshotValue(row, 'ioc_value', 'observable');
  if (value) return value;
  const type = auditSnapshotValue(row, 'ioc_observable_type', 'observable_type');
  if (type && row?.entity_id) return `${type} · #${row.entity_id}`;
  return row?.entity_id || '—';
}

function formatAuditEntitySubtitle(row) {
  const entityType = String(row?.entity_type || 'ioc').trim();
  const type = auditSnapshotValue(row, 'ioc_observable_type', 'observable_type');
  const id = auditSnapshotValue(row, 'ioc_id') || row?.entity_id;
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

function formatExpirationAuditReasonLabel(reason) {
  const value = String(reason || '').trim();
  if (!value) return '—';
  if (value === 'expires_at_reached') return 'Expires at reached';
  if (value === 'all_feed_memberships_expired') return 'All feed memberships expired';
  if (value === 'manual_override') return 'Manual override';
  return value.replace(/_/g, ' ');
}

function formatAuditStatusTransition(metadata) {
  const oldStatus = auditMetadataValue(metadata, 'old_status');
  const newStatus = auditMetadataValue(metadata, 'new_status');
  if (!oldStatus && !newStatus) return '—';
  if (oldStatus && newStatus) return `${oldStatus} → ${newStatus}`;
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

function formatAuditDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
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

function ModalOverlay({ children, onClose }) {
  return (
    <div
      role="presentation"
      onClick={onClose}
      style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}
    >
      <div role="dialog" onClick={(e) => e.stopPropagation()} style={PUBLISHED_FEEDS_UI.formModal}>
        {children}
      </div>
    </div>
  );
}

function sanitizeSourceNote(note) {
  const raw = String(note || '').trim();
  if (!raw) return '-';

  const duplicateFileInfoKeys = new Set([
    'file_name',
    'file_type',
    'mime',
    'md5',
    'sha1',
    'sha256',
    'imphash',
    'tlsh',
    'ssdeep'
  ]);

  const filtered = raw
    .split('|')
    .map((p) => p.trim())
    .filter(Boolean)
    .filter((part) => {
      const idx = part.indexOf('=');
      if (idx <= 0) return true;
      const key = part.slice(0, idx).trim().toLowerCase();
      return !duplicateFileInfoKeys.has(key);
    });

  return filtered.length ? filtered.join(' | ') : '-';
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
    event?.v2_context?.scenario_type,
    event?.matched_syslog_event
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

  async function onSubmit(e) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const email = form.get('email');
    const password = form.get('password');

    try {
      await api.post('/auth/login', { email, password });
      localStorage.removeItem('demo_timezone');
      await refreshSession();
      navigate('/analytics');
    } catch (err) {
      const msg = err?.response?.data?.message || 'Invalid email or password';
      alert(msg);
    }
  }

  return (
    <div style={{ maxWidth: 360, margin: '80px auto', fontFamily: 'sans-serif' }}>
      <h2>Demo Login</h2>
      <form onSubmit={onSubmit}>
        <input name="email" type="text" placeholder="username or email" autoComplete="username" required style={{ width: '100%', marginBottom: 8, padding: 8 }} />
        <input name="password" type="password" placeholder="password" autoComplete="current-password" required style={{ width: '100%', marginBottom: 8, padding: 8 }} />
        <button type="submit" style={{ width: '100%', padding: 10 }}>Sign In</button>
      </form>
      <p style={{ fontSize: 12, color: '#555' }}>Demo user: demo@demo.local / Password1!</p>
    </div>
  );
}

function AppShell({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { userEmail, role, canWrite, isAdmin, refreshSession } = useSession();
  const [timezone, setTimezone] = useState(localStorage.getItem('demo_timezone') || 'UTC');
  const [needsTimezoneSelection, setNeedsTimezoneSelection] = useState(false);

  useEffect(() => {
    let mounted = true;
    async function loadPreference() {
      try {
        const { data } = await api.get('/users/me/preferences');
        if (!mounted) return;

        if (data?.timezone) {
          localStorage.setItem('demo_timezone', data.timezone);
          setTimezone(data.timezone);
          setNeedsTimezoneSelection(false);
        } else {
          setNeedsTimezoneSelection(true);
        }
      } catch {
        if (!localStorage.getItem('demo_timezone')) {
          setNeedsTimezoneSelection(true);
        }
      }
    }

    loadPreference();
    return () => {
      mounted = false;
    };
  }, []);

  async function saveTimezone(value) {
    try {
      const { data } = await api.put('/users/me/preferences', { timezone: value });
      const tz = data?.timezone || value;
      localStorage.setItem('demo_timezone', tz);
      setTimezone(tz);
      setNeedsTimezoneSelection(false);
    } catch {
      alert('Failed to save timezone');
    }
  }

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
  const isOpsActive = location.pathname.startsWith('/ioc') || location.pathname.startsWith('/operations/ioc-suppressions');
  const isIntegrationsActive = location.pathname.startsWith('/threat-intelligence');

  const menuStyle = (active) => ({
    display: 'block',
    padding: '10px 12px',
    borderRadius: 6,
    textDecoration: 'none',
    color: active ? '#e2e8f0' : '#cbd5e1',
    background: active ? '#334155' : 'transparent',
    fontWeight: active ? 600 : 500
  });

  const subMenuStyle = (active) => ({
    display: 'block',
    padding: '8px 10px',
    marginLeft: 8,
    borderRadius: 6,
    textDecoration: 'none',
    color: active ? '#e2e8f0' : '#94a3b8',
    background: active ? '#1e293b' : 'transparent',
    fontSize: 14
  });

  return (
    <div style={{ width: '100%', margin: '16px 0', fontFamily: 'sans-serif', display: 'flex', gap: 16, alignItems: 'flex-start', padding: '0 16px', boxSizing: 'border-box' }}>
      <aside style={{ flex: '0 0 240px', border: '1px solid #e5e5e5', borderRadius: 10, padding: 12, height: 'fit-content', position: 'sticky', top: 16, background: '#fff' }}>
        <div style={{ marginBottom: 14, fontSize: 14 }}>User: <b>{userEmail || 'demo user'}</b> <span style={{ color: '#94a3b8' }}>({role})</span></div>

        <nav>
          <Link to="/system" style={menuStyle(isActive('/system'))}>0. System</Link>
          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(location.pathname.startsWith('/analytics'))}>2. Analytics</div>
            <Link to="/analytics" style={subMenuStyle(isActive('/analytics'))}>Overview</Link>
            <Link to="/analytics/statistics" style={subMenuStyle(isActive('/analytics/statistics'))}>Statistics</Link>
            <Link to="/analytics/detection-events" style={subMenuStyle(isActive('/analytics/detection-events'))}>Detection Events</Link>
            <Link to="/risk-overview" style={subMenuStyle(isActive('/risk-overview'))}>Risk Overview</Link>
          </div>
          <Link to="/incidents" style={menuStyle(location.pathname.startsWith('/incidents'))}>3. Incidents</Link>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(isOpsActive)}>4. Operations</div>
            <Link to="/ioc" style={subMenuStyle(isActive('/ioc'))}>IOC List</Link>
            <Link to="/ioc/hot" style={subMenuStyle(isActive('/ioc/hot'))}>Hot IOC List</Link>
            {canWrite ? (
              <Link to="/ioc/new" style={subMenuStyle(isActive('/ioc/new'))}>Add IOC</Link>
            ) : (
              <span style={{ ...subMenuStyle(false), opacity: 0.45, cursor: 'not-allowed' }} title="Read-only role">Add IOC</span>
            )}
            <Link to="/operations/ioc-suppressions" style={subMenuStyle(location.pathname.startsWith('/operations/ioc-suppressions'))}>IOC Suppressions</Link>
          </div>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(isIntegrationsActive)}>5. Threat Intelligence</div>
            <Link to="/threat-intelligence/feeds" style={subMenuStyle(isActive('/threat-intelligence/feeds') || isActive('/threat-intelligence'))}>Feeds</Link>
            <Link to="/threat-intelligence/queue" style={subMenuStyle(isActive('/threat-intelligence/queue'))}>Job Queue Status</Link>
            <Link to="/threat-intelligence/runs" style={subMenuStyle(isActive('/threat-intelligence/runs'))}>Recent Runs</Link>
            <Link to="/threat-intelligence/published-feeds" style={subMenuStyle(isActive('/threat-intelligence/published-feeds'))}>Published Feeds</Link>
          </div>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(location.pathname.startsWith('/administration'))}>6. Administration</div>
            <Link to="/administration" style={subMenuStyle(isActive('/administration') && !isActive('/administration/users') && !isActive('/administration/api-keys') && !isActive('/administration/audit-logs') && !isActive('/administration/enrichment-providers') && !isActive('/administration/tags'))}>Settings</Link>
            {isAdmin ? <Link to="/administration/users" style={subMenuStyle(isActive('/administration/users'))}>Users</Link> : null}
            <Link to="/administration/audit-logs" style={subMenuStyle(isActive('/administration/audit-logs'))}>Audit Logs</Link>
            <Link to="/administration/tags" style={subMenuStyle(isActive('/administration/tags'))}>Tags</Link>
            <Link to="/administration/api-keys" style={subMenuStyle(isActive('/administration/api-keys'))}>API Keys</Link>
            <Link to="/administration/enrichment-providers" style={subMenuStyle(isActive('/administration/enrichment-providers'))}>Enrichment Providers</Link>
          </div>
        </nav>

        <div style={{ marginTop: 16, fontSize: 12, color: '#475569' }}>Timezone: <b>{timezone}</b></div>
        <button onClick={logout} style={{ marginTop: 10, width: '100%', padding: 9 }}>Logout</button>
      </aside>

      <main style={{ flex: 1, minWidth: 0 }}>
        {children}
      </main>

      {needsTimezoneSelection && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}>
          <div style={{ width: 440, maxWidth: '96vw', background: 'linear-gradient(180deg, #111827 0%, #0f172a 100%)', borderRadius: 14, padding: 20, border: '1px solid #334155', boxShadow: '0 24px 60px rgba(2,6,23,0.55)' }}>
            <h3 style={{ margin: '0 0 8px', color: '#f8fafc', fontSize: 22, fontWeight: 700 }}>Select Timezone</h3>
            <p style={{ fontSize: 14, color: '#94a3b8', margin: '0 0 14px' }}>This is required once. You can change it later from Administration.</p>
            <select
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              style={{
                width: '100%',
                height: 42,
                borderRadius: 10,
                border: '1px solid #334155',
                background: '#0b1220',
                color: '#e2e8f0',
                padding: '0 12px',
                marginBottom: 12,
                outline: 'none'
              }}
            >
              {COMMON_TIMEZONES.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
            </select>
            <button
              type="button"
              onClick={() => saveTimezone(timezone)}
              style={{
                width: '100%',
                height: 42,
                borderRadius: 10,
                border: '1px solid #2563eb',
                background: 'linear-gradient(180deg, #3b82f6 0%, #2563eb 100%)',
                color: '#eff6ff',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Save Timezone
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function DashboardPage() {
  const [mapData, setMapData] = useState({ total: 0, unique_ips: 0, countries: [], snapshot_time: null, note: '' });
  const [hoverInfo, setHoverInfo] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [center, setCenter] = useState([0, 12]);

  useEffect(() => {
    api.get('/ioc/map/countries', { params: { day: 'all' } })
      .then(({ data }) => setMapData({
        total: data?.total || 0,
        unique_ips: data?.unique_ips || 0,
        countries: data?.countries || [],
        snapshot_time: data?.snapshot_time || null,
        note: data?.note || ''
      }))
      .catch(() => setMapData({ total: 0, unique_ips: 0, countries: [], snapshot_time: null, note: '' }));
  }, []);

  const normalizeCode = (value) => String(value || '').trim().toUpperCase();
  const normalizeName = (value) => String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');

  const countryCounts = mapData.countries.reduce((acc, row) => {
    acc[normalizeCode(row.country_code)] = row.total;
    return acc;
  }, {});

  const displayNames = typeof Intl !== 'undefined' && Intl.DisplayNames
    ? new Intl.DisplayNames(['en'], { type: 'region' })
    : null;

  const countryNameCounts = {};
  for (const [code, count] of Object.entries(countryCounts)) {
    try {
      const n = displayNames?.of(code);
      if (n) countryNameCounts[normalizeName(n)] = count;
    } catch {}
  }
  countryNameCounts.unitedstates = countryCounts.US || 0;
  countryNameCounts.unitedstatesofamerica = countryCounts.US || 0;
  countryNameCounts.russia = countryCounts.RU || 0;
  countryNameCounts.russianfederation = countryCounts.RU || 0;
  countryNameCounts.iran = countryCounts.IR || 0;
  countryNameCounts.iranislamicrepublicof = countryCounts.IR || 0;
  countryNameCounts.southkorea = countryCounts.KR || 0;
  countryNameCounts.republicofkorea = countryCounts.KR || 0;
  countryNameCounts.korearepublicof = countryCounts.KR || 0;

  const maxCount = Math.max(...Object.values(countryCounts), 0);

  const countryColor = (count) => {
    if (!count || maxCount === 0) return '#0f172a';
    const ratio = count / maxCount;
    if (ratio <= 0.2) return '#fde047';
    if (ratio <= 0.4) return '#facc15';
    if (ratio <= 0.6) return '#fb923c';
    if (ratio <= 0.8) return '#f97316';
    return '#ef4444';
  };

  const resolveCountryCount = (geo) => {
    const p = geo.properties || {};
    const geoName = p.name || p.ADMIN || 'Unknown';
    const key = normalizeName(geoName);

    if (
      key === 'us'
      || key === 'usa'
      || key === 'unitedstates'
      || key === 'unitedstatesofamerica'
      || key.includes('unitedstates')
    ) return countryCounts.US || 0;

    if (key.includes('russia') || key.includes('russianfederation')) return countryCounts.RU || 0;
    if (key.includes('iran')) return countryCounts.IR || 0;
    if (key.includes('korea')) return countryCounts.KR || 0;

    return countryNameCounts[key] || 0;
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16 }}>
        <h2 style={{ marginTop: 0 }}>Threat World Map</h2>
        <div style={{ marginBottom: 12, fontSize: 15 }}>
          Total records in snapshot: <b style={{ fontSize: 22 }}>{mapData.total}</b>
          <span style={{ marginLeft: 10, color: '#94a3b8' }}>| Unique IPs: <b>{mapData.unique_ips}</b></span>
        </div>
        <div style={{ marginBottom: 10, fontSize: 13, color: '#94a3b8' }}>
          {mapData.snapshot_time ? `As of ${new Date(mapData.snapshot_time).toLocaleString()}, this view reflects the last 24 hours of processed IOC data.` : 'Snapshot is being prepared from processed IOC data.'}
        </div>
        <div style={{ marginBottom: 12, fontSize: 13, color: '#94a3b8' }}>
          {mapData.note || 'This dashboard is refreshed once per day around midnight in server local time while new IOC data continues to be processed in the background.'}
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
          <button onClick={() => setZoom((z) => Math.max(1, Number((z - 0.2).toFixed(2))))}>- Zoom out</button>
          <button onClick={() => setZoom((z) => Math.min(4, Number((z + 0.2).toFixed(2))))}>+ Zoom in</button>
          <button onClick={() => { setZoom(1); setCenter([0, 12]); }}>Reset</button>
        </div>

        <div style={{ border: '1px solid #334155', borderRadius: 10, background: '#0b1220', padding: 8, position: 'relative' }}>
          <ComposableMap projectionConfig={{ scale: 155 }} width={1080} height={420} style={{ width: '100%', height: 'auto', display: 'block' }}>
            <ZoomableGroup
              zoom={zoom}
              center={center}
              onMoveEnd={({ zoom: nextZoom, coordinates }) => {
                setZoom(nextZoom);
                setCenter(coordinates);
              }}
            >
              <Geographies geography="/world-lite.geojson">
                {({ geographies }) => geographies.map((geo) => {
                  const count = resolveCountryCount(geo);
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={countryColor(count)}
                      stroke="#475569"
                      strokeWidth={0.35}
                      onMouseEnter={() => setHoverInfo({
                        name: geo.properties?.name || geo.properties?.ADMIN || 'Unknown',
                        countryCount: count,
                        globalTotal: mapData.total
                      })}
                      onMouseLeave={() => setHoverInfo(null)}
                      style={{
                        default: { outline: 'none' },
                        hover: { outline: 'none', opacity: 0.85 },
                        pressed: { outline: 'none' }
                      }}
                    />
                  );
                })}
              </Geographies>
            </ZoomableGroup>
          </ComposableMap>

          {hoverInfo && (
            <div style={{ position: 'absolute', right: 10, top: 10, background: '#0f172a', color: '#fff', padding: '8px 10px', borderRadius: 8, fontSize: 13 }}>
              <div><b>{hoverInfo.name}</b></div>
              <div>Total in 24h snapshot: <b>{hoverInfo.globalTotal}</b></div>
              <div>Country count: <b>{hoverInfo.countryCount}</b></div>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 10, fontSize: 13, color: '#475569' }}>
          <span>Low</span>
          <div style={{ height: 10, width: 180, background: 'linear-gradient(90deg, #fde047 0%, #fb923c 50%, #ef4444 100%)', borderRadius: 999 }} />
          <span>High</span>
        </div>
      </section>
    </AppShell>
  );
}


function AnalyticsPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [iocLoading, setIocLoading] = useState(false);
  const [sources, setSources] = useState([]);
  const [rawEvents, setRawEvents] = useState([]);
  const [iocMatches, setIocMatches] = useState([]);

  async function loadIocMatches() {
    setIocLoading(true);
    try {
      const { data } = await api.get('/analytics/ioc-matches', { params: { limit: 10 } });
      setIocMatches(data?.items || []);
    } catch {
      setIocMatches([]);
    } finally {
      setIocLoading(false);
    }
  }

  async function loadSources() {
    setLoading(true);
    try {
      const [{ data: sourceData }, { data: rawData }] = await Promise.all([
        api.get('/analytics/data-sources'),
        api.get('/analytics/raw-events', { params: { limit: 10 } })
      ]);
      setSources(sourceData?.sources || []);
      setRawEvents(rawData?.items || []);
    } catch {
      setSources([]);
      setRawEvents([]);
    } finally {
      setLoading(false);
    }

    loadIocMatches().catch(() => {});
  }

  useEffect(() => {
    loadSources().catch(() => {});
  }, []);

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
          <div>
            <h2 style={{ marginTop: 0, marginBottom: 6 }}>Analytics</h2>
            <p style={{ color: '#94a3b8', margin: 0 }}>Current telemetry coverage overview.</p>
          </div>
          <button onClick={() => loadSources().catch(() => {})}>Refresh</button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginTop: 12 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 12, padding: 14, background: '#0f172a' }}>
            <div style={{ fontSize: 13, color: '#94a3b8' }}>Connected Data Sources</div>
            <div style={{ fontSize: 34, fontWeight: 800, marginTop: 6 }}>{loading ? '-' : sources.length}</div>
            <div style={{ fontSize: 13, color: '#cbd5e1', marginTop: 4 }}>
              {loading ? 'Loading...' : (sources.length ? `${sources[0].name} (${sources[0].platform}) ${sources[0].status}` : 'No active source')}
            </div>
          </div>
        </div>

        <div style={{ marginTop: 16, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                <th>Source</th>
                <th>Platform</th>
                <th>Status</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={4} style={{ color: '#94a3b8' }}>Loading data sources...</td></tr>
              ) : sources.length ? sources.map((source) => (
                <tr key={source.key} style={{ borderTop: '1px solid #334155' }}>
                  <td>{source.name}</td>
                  <td>{source.platform}</td>
                  <td style={{ color: source.status === 'active' ? '#22c55e' : '#f59e0b', fontWeight: 700 }}>{source.status}</td>
                  <td>{formatUserDateTime(source.last_seen_at)}</td>
                </tr>
              )) : (
                <tr><td colSpan={4} style={{ color: '#94a3b8' }}>No data sources connected yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 16, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>
            Last 10 Raw Events
          </div>
          <table width="100%" cellPadding="10" style={{ borderCollapse: "collapse", tableLayout: "fixed" }}>
            <thead>
              <tr style={{ textAlign: "left", background: "#111827" }}>
                <th style={{ width: 190 }}>Received At</th>
                <th style={{ width: 180 }}>Source</th>
                <th>Raw Event</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={3} style={{ color: "#94a3b8" }}>Loading raw events...</td></tr>
              ) : rawEvents.length ? rawEvents.map((evt) => (
                <tr key={evt.id} style={{ borderTop: "1px solid #334155" }}>
                  <td style={{ whiteSpace: "nowrap" }}>{formatUserDateTime(evt.received_at || evt.event_time || evt.created_at)}</td>
                  <td>{evt.source_key || evt.source || evt.source_ip || "-"}</td>
                  <td style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{evt.raw_event || evt.raw?.raw_event || "-"}</td>
                </tr>
              )) : (
                <tr><td colSpan={3} style={{ color: "#94a3b8" }}>No raw events yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 16, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>
            Last 10 Detection Events
          </div>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                <th style={{ width: 80 }}>ID</th>
                <th style={{ width: 170 }}>Detected At</th>
                <th style={{ width: 220 }}>Matched IOC</th>
                <th style={{ width: 140 }}>Detection</th>
                <th style={{ width: 140 }}>Verdict</th>
                <th style={{ width: 140 }}>Assignee</th>
                <th style={{ width: 180 }}>Source</th>
                <th style={{ width: 120 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {iocLoading ? (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>Loading IOC matches...</td></tr>
              ) : iocMatches.length ? iocMatches.map((evt) => {
                const verdict = String(evt.verdict || '').toLowerCase();
                const vm = verdict === 'fp'
                  ? { label: 'FP', color: '#ef4444' }
                  : verdict === 'tp'
                    ? { label: 'TP', color: '#22c55e' }
                    : verdict === 'suspicious'
                      ? { label: 'Suspicious', color: '#f59e0b' }
                      : verdict === 'in_progress'
                        ? { label: 'In Progress', color: '#f59e0b' }
                        : { label: 'Unreviewed', color: '#94a3b8' };
                return (
                  <tr key={`ioc-${evt.id}-${evt.event_time}`} style={{ borderTop: '1px solid #334155' }}>
                    <td>{evt.id}</td>
                    <td>{formatUserDateTime(evt.detected_at || evt.last_seen_at || evt.event_time || evt.created_at)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{evt.matched_ioc || '-'}</td>
                    <td>
                      <span style={{
                        display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${evt.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e'}`,
                        color: evt.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e', background: '#020617'
                      }}>
                        {evt.detection_mode === 'retroactive' ? 'Retroactive Match' : 'Real-Time Match'}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${vm.color}`, color: vm.color, background: '#020617'
                      }}>{vm.label}</span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{evt.assigned_to || 'Unassigned'}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {evt.source_count > 1
                        ? `${(evt.source_names && evt.source_names[0]) || evt.source_name || '-'} +${evt.source_count - 1}`
                        : ((evt.source_names && evt.source_names[0]) || evt.source_name || '-')}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button onClick={() => navigate(`/analytics/detection-events/${evt.id}`)} title="View detail" aria-label="View detail" style={{ minWidth: 32, padding: '4px 8px' }}>🔍</button>
                        <button onClick={() => navigate(`/analytics/detection-events/${evt.id}`)} title="Review verdict" aria-label="Review verdict" style={{ minWidth: 32, padding: '4px 8px' }}>✏️</button>
                      </div>
                    </td>
                  </tr>
                );
              }) : (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>No detection events yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}

function AnalyticsStatisticsPage() {
  const [loading, setLoading] = useState(true);
  const [hours, setHours] = useState(24);
  const [topSources, setTopSources] = useState([]);
  const [topClients, setTopClients] = useState([]);
  const [riskyClients, setRiskyClients] = useState([]);
  const [timeline, setTimeline] = useState([]);

  async function loadStats(targetHours = hours) {
    setLoading(true);
    try {
      const { data } = await api.get('/analytics/statistics', { params: { hours: targetHours } });
      setTopSources(data?.top_sources || []);
      setTopClients(data?.top_clients || []);
      setRiskyClients(data?.risky_clients || []);
      setTimeline(data?.timeline || []);
    } catch {
      setTopSources([]);
      setTopClients([]);
      setRiskyClients([]);
      setTimeline([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadStats(24).catch(() => {});
  }, []);

  const maxSource = Math.max(...topSources.map((x) => Number(x.event_count ?? x.events ?? 0)), 1);
  const maxClient = Math.max(...topClients.map((x) => Number(x.event_count ?? x.events ?? 0)), 1);
  const maxRiskyClient = Math.max(...riskyClients.map((x) => Number(x.risky_event_count || 0)), 1);

  const timelineByBucket = timeline.reduce((acc, row) => {
    const key = formatUserDateTime(row.bucket || row.hour);
    acc[key] = (acc[key] || 0) + Number(row.event_count ?? row.events ?? 0);
    return acc;
  }, {});

  const timelineRows = Object.entries(timelineByBucket).slice(-12);
  const maxTimeline = Math.max(...timelineRows.map(([, v]) => Number(v || 0)), 1);

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <div>
            <h2 style={{ margin: 0 }}>Analytics Statistics</h2>
            <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 4 }}>Top active source and client activity overview.</div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
              <option value={6}>Last 6h</option>
              <option value={24}>Last 24h</option>
              <option value={48}>Last 48h</option>
              <option value={72}>Last 72h</option>
            </select>
            <button onClick={() => loadStats(hours).catch(() => {})}>Refresh</button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12 }}>
            <h3 style={{ marginTop: 0 }}>Top Active Sources</h3>
            {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
              <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                    <th>Source</th>
                    <th>Events</th>
                    <th>Activity</th>
                  </tr>
                </thead>
                <tbody>
                  {topSources.length ? topSources.map((row) => {
                    const count = Number(row.event_count ?? row.events ?? 0);
                    const w = Math.max(6, Math.round((count / maxSource) * 100));
                    return (
                      <tr key={row.source_key || row.source} style={{ borderTop: '1px solid #334155' }}>
                        <td>{row.source_key || row.source}</td>
                        <td>{count}</td>
                        <td>
                          <div style={{ background: '#0f172a', borderRadius: 999, height: 10 }}>
                            <div style={{ width: `${w}%`, height: 10, borderRadius: 999, background: '#38bdf8' }} />
                          </div>
                        </td>
                      </tr>
                    );
                  }) : <tr><td colSpan={3} style={{ color: '#94a3b8' }}>No source activity</td></tr>}
                </tbody>
              </table>
            )}
          </div>

          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12 }}>
            <h3 style={{ marginTop: 0 }}>Top Active Clients</h3>
            {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
              <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                    <th>Client</th>
                    <th>Events</th>
                    <th>Activity</th>
                  </tr>
                </thead>
                <tbody>
                  {topClients.length ? topClients.map((row) => {
                    const count = Number(row.event_count ?? row.events ?? 0);
                    const w = Math.max(6, Math.round((count / maxClient) * 100));
                    return (
                      <tr key={row.host_name || row.host} style={{ borderTop: '1px solid #334155' }}>
                        <td>{row.host_name || row.host}</td>
                        <td>{count}</td>
                        <td>
                          <div style={{ background: '#0f172a', borderRadius: 999, height: 10 }}>
                            <div style={{ width: `${w}%`, height: 10, borderRadius: 999, background: '#22c55e' }} />
                          </div>
                        </td>
                      </tr>
                    );
                  }) : <tr><td colSpan={3} style={{ color: '#94a3b8' }}>No client activity</td></tr>}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div style={{ marginTop: 12, border: '1px solid #334155', borderRadius: 10, padding: 12 }}>
          <h3 style={{ marginTop: 0 }}>Risky Clients (IOC Match Activity)</h3>
          {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
            <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                  <th>Client</th>
                  <th>Risky Events</th>
                  <th>Last Seen</th>
                  <th>Risk Activity</th>
                </tr>
              </thead>
              <tbody>
                {riskyClients.length ? riskyClients.map((row) => {
                  const count = Number(row.risky_event_count || 0);
                  const w = Math.max(6, Math.round((count / maxRiskyClient) * 100));
                  return (
                    <tr key={row.host_name} style={{ borderTop: '1px solid #334155' }}>
                      <td>{row.host_name}</td>
                      <td>{count}</td>
                      <td>{formatUserDateTime(row.last_risky_seen_at)}</td>
                      <td>
                        <div style={{ background: '#0f172a', borderRadius: 999, height: 10 }}>
                          <div style={{ width: `${w}%`, height: 10, borderRadius: 999, background: '#ef4444' }} />
                        </div>
                      </td>
                    </tr>
                  );
                }) : <tr><td colSpan={4} style={{ color: '#94a3b8' }}>No risky client activity</td></tr>}
              </tbody>
            </table>
          )}
        </div>

        <div style={{ marginTop: 12, border: '1px solid #334155', borderRadius: 10, padding: 12 }}>
          <h3 style={{ marginTop: 0 }}>Activity Timeline (hourly)</h3>
          {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
            <div style={{ display: 'grid', gap: 8 }}>
              {timelineRows.length ? timelineRows.map(([label, value]) => {
                const w = Math.max(4, Math.round((Number(value || 0) / maxTimeline) * 100));
                return (
                  <div key={label} style={{ display: 'grid', gridTemplateColumns: '180px 70px 1fr', gap: 10, alignItems: 'center' }}>
                    <div style={{ color: '#94a3b8', fontSize: 12 }}>{label}</div>
                    <div style={{ fontWeight: 700 }}>{value}</div>
                    <div style={{ background: '#0f172a', borderRadius: 999, height: 10 }}>
                      <div style={{ width: `${w}%`, height: 10, borderRadius: 999, background: '#f59e0b' }} />
                    </div>
                  </div>
                );
              }) : <div style={{ color: '#94a3b8' }}>No timeline data</div>}
            </div>
          )}
        </div>
      </section>
    </AppShell>
  );
}

function IOCMatchEventsPage() {
  const ALL_VERDICTS = ['unreviewed', 'in_progress', 'fp', 'tp'];
  const ALL_DETECTIONS = ['realtime', 'retroactive'];
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [rows, setRows] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [reviewVerdict, setReviewVerdict] = useState('');
  const [reviewNote, setReviewNote] = useState('');
  const [savingReview, setSavingReview] = useState(false);
  const [userLookup, setUserLookup] = useState({});
  const [detectionFilter, setDetectionFilter] = useState(ALL_DETECTIONS);
  const [verdictFilter, setVerdictFilter] = useState(ALL_VERDICTS);
  const [assigneeFilter, setAssigneeFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [activeDateQuick, setActiveDateQuick] = useState('24h');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [dateError, setDateError] = useState('');
  const filtersRef = useRef(null);
  const navigate = useNavigate();
  const { userEmail } = useSession();

  const toDateTimeLocal = (d) => {
    const dt = new Date(d);
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const day = String(dt.getDate()).padStart(2, '0');
    const hh = String(dt.getHours()).padStart(2, '0');
    const mm = String(dt.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${day}T${hh}:${mm}`;
  };

  const toIsoOrNull = (v) => {
    const raw = String(v || '').trim();
    if (!raw) return null;
    const d = new Date(raw);
    if (Number.isNaN(d.getTime())) return null;
    return d.toISOString();
  };

  const buildDefault24hRange = () => {
    const now = new Date();
    const from = new Date(now.getTime() - (24 * 60 * 60 * 1000));
    return { from: toDateTimeLocal(from), to: toDateTimeLocal(now) };
  };

  const formatRangeShort = (v) => {
    const d = new Date(String(v || '').trim());
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false });
  };

  const verdictMeta = (verdict) => {
    const v = String(verdict || '').toLowerCase();
    if (v === 'fp') return { label: 'FP', color: '#ef4444' };
    if (v === 'tp') return { label: 'TP', color: '#22c55e' };
    if (v === 'suspicious') return { label: 'Suspicious', color: '#f59e0b' };
    if (v === 'in_progress') return { label: 'In Progress', color: '#f59e0b' };
    return { label: 'Unreviewed', color: '#94a3b8' };
  };

  const loadEvents = useCallback(async (q = '', assignedTo = null, fromVal = '', toVal = '', verdictVals = [], detectionVals = []) => {
    const fromIso = toIsoOrNull(fromVal);
    const toIso = toIsoOrNull(toVal);
    if (fromIso && toIso && fromIso > toIso) {
      setDateError('Invalid date range: From must be earlier than or equal to To.');
      setRows([]);
      return;
    }
    setDateError('');
    setLoading(true);
    try {
      const params = { limit: 120, q: q || undefined };
      if (assignedTo) params.assigned_to = assignedTo; // UI hint, backend may ignore
      if (fromIso) params.from = fromIso;
      if (toIso) params.to = toIso;
      if (Array.isArray(verdictVals) && verdictVals.length && verdictVals.length < ALL_VERDICTS.length) params.verdict = verdictVals.join(',');
      if (Array.isArray(detectionVals) && detectionVals.length && detectionVals.length < ALL_DETECTIONS.length) params.detection = detectionVals.join(',');
      const { data } = await api.get('/ioc/match-events', { params });
      setRows(data?.items || []);
    } catch {
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadUsers = useCallback(async () => {
    try {
      const { data } = await api.get('/users');
      const next = {};
      for (const u of (data?.users || [])) {
        const username = String(u?.username || '').trim();
        if (!username) continue;
        next[username.toLowerCase()] = username;
      }
      setUserLookup(next);
    } catch {
      setUserLookup({});
    }
  }, []);

  const resolveAssignee = useCallback((assignedTo) => {
    const raw = String(assignedTo || '').trim();
    if (!raw) return 'Unassigned';
    return userLookup[raw.toLowerCase()] || raw;
  }, [userLookup]);

  const resetFilters = useCallback(() => {
    setDetectionFilter(ALL_DETECTIONS);
    setVerdictFilter(ALL_VERDICTS);
    setAssigneeFilter('all');
    setSourceFilter('all');
    const def = buildDefault24hRange();
    setDateFrom(def.from);
    setDateTo(def.to);
    setActiveDateQuick('24h');
    setQuery('');
    loadEvents('', null, def.from, def.to).catch(() => {});
  }, [loadEvents]);

  const openReview = useCallback((evt) => {
    setSelectedEvent(evt || null);
    setReviewVerdict(String(evt?.verdict || '').toLowerCase());
    setReviewNote(String(evt?.note || ''));
  }, []);

  const closeReview = useCallback(() => {
    setSelectedEvent(null);
    setReviewVerdict('');
    setReviewNote('');
    setSavingReview(false);
  }, []);

  const toggleMulti = useCallback((arr, val) => (arr.includes(val) ? arr.filter((x) => x !== val) : [...arr, val]), []);

  const submitReview = useCallback(async () => {
    if (!selectedEvent?.id) return;
    setSavingReview(true);
    try {
      const payload = {
        verdict: reviewVerdict || null,
        note: reviewNote.trim() || null
      };
      const { data } = await api.patch(`/ioc/match-events/${selectedEvent.id}/verdict`, payload);
      const updated = data?.item || null;
      if (updated) {
        setRows((prev) => prev.map((r) => (r.id === updated.id ? { ...r, ...updated } : r)));
      }
      closeReview();
    } catch {
      // keep modal open on failure
    } finally {
      setSavingReview(false);
    }
  }, [selectedEvent, reviewVerdict, reviewNote, closeReview]);

  useEffect(() => {
    const def = buildDefault24hRange();
    setDateFrom(def.from);
    setDateTo(def.to);
    setActiveDateQuick('24h');
    loadEvents('', null, def.from, def.to).catch(() => {});
    loadUsers().catch(() => {});
  }, [loadEvents, loadUsers]);

  useEffect(() => {
    const onDown = (e) => {
      if (!filtersRef.current) return;
      if (!filtersRef.current.contains(e.target)) setFiltersOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, []);

  const sourceOptions = useMemo(() => {
    const set = new Set();
    for (const r of rows) {
      const s = String((r.source_names && r.source_names[0]) || r.source_name || '').trim();
      if (s) set.add(s);
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [rows]);

  const assigneeOptions = useMemo(() => {
    const users = Object.values(userLookup);
    return Array.from(new Set(users)).sort((a, b) => a.localeCompare(b));
  }, [userLookup]);

  const searchTerm = String(query || '').trim().toLowerCase();
  const filteredRows = useMemo(() => {
    return (rows || []).filter((evt) => {
      const detection = String(evt.detection_mode || '').toLowerCase();
      const verdict = String(evt.verdict || '').toLowerCase();
      const assigneeRaw = String(evt.assigned_to || '').trim();
      const assignee = resolveAssignee(assigneeRaw);
      const source = String((evt.source_names && evt.source_names[0]) || evt.source_name || '').trim();

      if (Array.isArray(detectionFilter) && detectionFilter.length && detectionFilter.length < ALL_DETECTIONS.length && !detectionFilter.includes(detection)) return false;
      if (Array.isArray(verdictFilter) && verdictFilter.length && verdictFilter.length < ALL_VERDICTS.length) {
        const verdictNorm = verdict || 'unreviewed';
        if (!verdictFilter.includes(verdictNorm)) return false;
      }

      if (assigneeFilter === 'unassigned') {
        if (assigneeRaw) return false;
      } else if (assigneeFilter !== 'all') {
        if (assignee.toLowerCase() !== assigneeFilter.toLowerCase()) return false;
      }

      if (sourceFilter !== 'all' && source.toLowerCase() !== sourceFilter.toLowerCase()) return false;

      if (searchTerm) {
        const hay = [
          `#${evt.id}`,
          String(evt.id || ''),
          evt.matched_ioc,
          source,
          assignee,
          evt.destination_ip,
          evt.host_name
        ].map((x) => String(x || '').toLowerCase()).join(' | ');
        if (!hay.includes(searchTerm)) return false;
      }

      return true;
    });
  }, [rows, detectionFilter, verdictFilter, assigneeFilter, sourceFilter, resolveAssignee, userEmail, searchTerm]);

  useEffect(() => {
    setPage(1);
  }, [query, detectionFilter, verdictFilter, assigneeFilter, sourceFilter, activeDateQuick, dateFrom, dateTo, pageSize]);

  const totalRows = filteredRows.length;
  const totalPages = Math.max(1, Math.ceil(totalRows / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedRows = filteredRows.slice((safePage - 1) * pageSize, safePage * pageSize);

  const activeFilters = [];
  if (dateFrom || dateTo) {
    activeFilters.push({
      key: 'date',
      label: `${formatRangeShort(dateFrom) || '-'} → ${formatRangeShort(dateTo) || '-'}`,
      onClear: () => {
        setDateFrom('');
        setDateTo('');
        setActiveDateQuick('');
        loadEvents(query, null, '', '', verdictFilter, detectionFilter).catch(() => {});
      }
    });
  }
  if (detectionFilter.length && detectionFilter.length < ALL_DETECTIONS.length) activeFilters.push({ key: 'detection', label: `Detection: ${detectionFilter.map((d) => d === 'realtime' ? 'Real-time' : 'Retroactive').join(', ')}`, onClear: () => setDetectionFilter(ALL_DETECTIONS) });
  if (verdictFilter.length && verdictFilter.length < ALL_VERDICTS.length) activeFilters.push({ key: 'verdict', label: `Verdict: ${verdictFilter.map((v) => v === 'unreviewed' ? 'Unreviewed' : v === 'in_progress' ? 'In Progress' : v.toUpperCase()).join(', ')}`, onClear: () => setVerdictFilter(ALL_VERDICTS) });
  if (assigneeFilter !== 'all') activeFilters.push({ key: 'assignee', label: `Assignee: ${assigneeFilter === 'unassigned' ? 'Unassigned' : assigneeFilter}`, onClear: () => setAssigneeFilter('all') });
  if (sourceFilter !== 'all') activeFilters.push({ key: 'source', label: `Source: ${sourceFilter}`, onClear: () => setSourceFilter('all') });

  const highlight = (text) => {
    const raw = String(text || '');
    if (!searchTerm || searchTerm.length < 2) return raw || '-';
    const idx = raw.toLowerCase().indexOf(searchTerm);
    if (idx === -1) return raw || '-';
    return (
      <>
        {raw.slice(0, idx)}
        <mark style={{ background: '#fef08a', color: '#111827', padding: '0 2px', borderRadius: 3 }}>{raw.slice(idx, idx + searchTerm.length)}</mark>
        {raw.slice(idx + searchTerm.length)}
      </>
    );
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <div style={{ display: 'grid', gap: 10, marginBottom: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
            <div>
              <h2 style={{ margin: 0 }}>Detection Events</h2>
              <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 4 }}>Search and inspect detection events.</div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') loadEvents(query, null, dateFrom, dateTo, verdictFilter, detectionFilter).catch(() => {}); }}
              placeholder="Search by ID, IP, domain, hash, or source... (e.g., 47.104.248.7 or #21371)"
              style={{ minWidth: 560, flex: 1 }}
            />
            <button onClick={() => loadEvents(query, null, dateFrom, dateTo, verdictFilter, detectionFilter).catch(() => {})}>Search</button>
          </div>

          <div style={{ border: '1px solid #334155', borderRadius: 10, background: '#0b1220', padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ color: '#93c5fd', fontSize: 12, fontWeight: 700 }}>Active Filters</span>
            {activeFilters.length ? activeFilters.map((f) => (
              <span key={f.key + f.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, border: '1px solid #475569', borderRadius: 999, padding: '3px 8px', fontSize: 12, color: '#cbd5e1' }}>
                {f.label}
                <button onClick={f.onClear} style={{ border: 'none', background: 'transparent', color: '#94a3b8', cursor: 'pointer', padding: 0 }}>✕</button>
              </span>
            )) : <span style={{ color: '#64748b', fontSize: 12 }}>None</span>}
            <button onClick={resetFilters} style={{ marginLeft: 'auto', fontSize: 12 }}>Clear all</button>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <input type="datetime-local" value={dateFrom} onChange={(e) => { setDateFrom(e.target.value); setActiveDateQuick(''); }} />
            <input type="datetime-local" value={dateTo} onChange={(e) => { setDateTo(e.target.value); setActiveDateQuick(''); }} />
            {[['1h', 'Last 1 hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days']].map(([k, lbl]) => (
              <button
                key={k}
                onClick={() => {
                  setActiveDateQuick(k);
                  const now = new Date();
                  const from = new Date(now.getTime() - (k === '1h' ? 60*60*1000 : k === '24h' ? 24*60*60*1000 : 7*24*60*60*1000));
                  const f = toDateTimeLocal(from);
                  const t = toDateTimeLocal(now);
                  setDateFrom(f);
                  setDateTo(t);
                  loadEvents(query, null, f, t, verdictFilter, detectionFilter).catch(() => {});
                }}
                style={{
                  borderRadius: 999,
                  padding: '6px 12px',
                  border: activeDateQuick === k ? '1px solid #93c5fd' : '1px solid #334155',
                  color: activeDateQuick === k ? '#dbeafe' : '#cbd5e1',
                  background: activeDateQuick === k ? '#1e3a8a' : '#020617',
                  boxShadow: activeDateQuick === k ? '0 0 0 1px rgba(147,197,253,0.35) inset' : 'none',
                  fontWeight: activeDateQuick === k ? 700 : 500
                }}
              >
                {lbl}
              </button>
            ))}
          </div>

          {dateError ? (
            <div style={{ color: '#fca5a5', fontSize: 12 }}>{dateError}</div>
          ) : null}

          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr', gap: 8, alignItems: 'start' }}>
            <div ref={filtersRef} style={{ position: 'relative' }}>
              <button
                onClick={() => setFiltersOpen((v) => !v)}
                style={{ minWidth: 220 }}
              >
                {`Filters (${verdictFilter.length} Verdict, ${detectionFilter.length} Detection)`}
              </button>
              {filtersOpen ? (
                <div style={{ position: 'absolute', top: 'calc(100% + 6px)', left: 0, zIndex: 20, width: 360, border: '1px solid #334155', borderRadius: 10, background: '#0b1220', padding: 10, boxShadow: '0 10px 30px rgba(2,6,23,0.45)' }}>
                  <div style={{ fontWeight: 700, marginBottom: 8 }}>Verdict</div>
                  <div style={{ display: 'grid', gap: 6, marginBottom: 8 }}>
                    {[
                      ['unreviewed', 'Unreviewed'],
                      ['in_progress', 'In Progress'],
                      ['fp', 'False Positive'],
                      ['tp', 'True Positive']
                    ].map(([v, lbl]) => (
                      <label key={v} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: verdictFilter.includes(v) ? '#dbeafe' : '#cbd5e1' }}>
                        <input type="checkbox" checked={verdictFilter.includes(v)} onChange={() => setVerdictFilter((prev) => toggleMulti(prev, v))} />
                        <span>{lbl}</span>
                      </label>
                    ))}
                  </div>
                  <div style={{ marginBottom: 10, display: 'flex', gap: 8 }}>
                    <button onClick={() => setVerdictFilter(ALL_VERDICTS)}>Select All</button>
                    <button onClick={() => setVerdictFilter([])}>Clear</button>
                  </div>

                  <div style={{ fontWeight: 700, marginBottom: 8 }}>Detection</div>
                  <div style={{ display: 'grid', gap: 6, marginBottom: 8 }}>
                    {[
                      ['realtime', 'Real-time'],
                      ['retroactive', 'Retroactive']
                    ].map(([v, lbl]) => (
                      <label key={v} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: detectionFilter.includes(v) ? '#dbeafe' : '#cbd5e1' }}>
                        <input type="checkbox" checked={detectionFilter.includes(v)} onChange={() => setDetectionFilter((prev) => toggleMulti(prev, v))} />
                        <span>{lbl}</span>
                      </label>
                    ))}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => setDetectionFilter(ALL_DETECTIONS)}>Select All</button>
                    <button onClick={() => setDetectionFilter([])}>Clear</button>
                  </div>
                </div>
              ) : null}
            </div>

            <select value={assigneeFilter} onChange={(e) => setAssigneeFilter(e.target.value)}>
              <option value="all">Assignee: All</option>
              <option value="unassigned">Assignee: Unassigned</option>
              {assigneeOptions.map((u) => <option key={u} value={u}>{u}</option>)}
            </select>
            <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
              <option value="all">Source: All</option>
              {sourceOptions.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>

        <div style={{ border: '1px solid #334155', borderRadius: 10, overflowX: 'auto', overflowY: 'hidden' }}>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 1260 }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                <th style={{ width: 80 }}>ID</th>
                <th style={{ width: 170 }}>Detected At</th>
                <th style={{ width: 240 }}>Matched IOC</th>
                <th style={{ width: 140 }}>Detection</th>
                <th style={{ width: 140 }}>Verdict</th>
                <th style={{ width: 140 }}>Assignee</th>
                <th style={{ width: 170 }}>Source</th>
                <th style={{ width: 140 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>Loading detection events...</td></tr>
              ) : pagedRows.length ? pagedRows.map((evt) => {
                const vm = verdictMeta(evt.verdict);
                return (
                  <tr key={evt.id} style={{ borderTop: '1px solid #334155' }}>
                    <td>{evt.id}</td>
                    <td>{formatUserDateTime(evt.detected_at || evt.last_seen_at || evt.event_time || evt.created_at)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{highlight(evt.matched_ioc)}</td>
                    <td>
                      <span style={{
                        display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${evt.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e'}`,
                        color: evt.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e', background: '#020617'
                      }}>
                        {evt.detection_mode === 'retroactive' ? 'Retroactive Match' : 'Real-Time Match'}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${vm.color}`, color: vm.color, background: '#020617'
                      }}>
                        {vm.label}
                      </span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {highlight(resolveAssignee(evt.assigned_to))}
                    </td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {highlight(evt.source_count > 1
                        ? `${(evt.source_names && evt.source_names[0]) || evt.source_name || '-'} +${evt.source_count - 1}`
                        : ((evt.source_names && evt.source_names[0]) || evt.source_name || '-'))}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button onClick={() => navigate(`/analytics/detection-events/${evt.id}`)} title="View detail" aria-label="View detail" style={{ minWidth: 32, padding: '4px 8px' }}>🔍</button>
                        <button onClick={() => openReview(evt)} title="Review verdict" aria-label="Review verdict" style={{ minWidth: 32, padding: '4px 8px' }}>✏️</button>
                      </div>
                    </td>
                  </tr>
                );
              }) : (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>No detection events found.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10, gap: 10, flexWrap: 'wrap' }}>
          <div style={{ color: '#94a3b8', fontSize: 13 }}>
            Showing {totalRows === 0 ? 0 : ((safePage - 1) * pageSize + 1)}-{Math.min(safePage * pageSize, totalRows)} of {totalRows}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <select value={String(pageSize)} onChange={(e) => setPageSize(Number(e.target.value) || 20)}>
              <option value="10">10 / page</option>
              <option value="20">20 / page</option>
              <option value="50">50 / page</option>
            </select>
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={safePage <= 1}>Prev</button>
            <span style={{ color: '#cbd5e1', fontSize: 13 }}>Page {safePage} / {totalPages}</span>
            <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={safePage >= totalPages}>Next</button>
          </div>
        </div>
      </section>

      {selectedEvent ? (
        <div onClick={closeReview} style={{ position: 'fixed', inset: 0, background: 'rgba(2, 6, 23, 0.7)', display: 'grid', placeItems: 'center', zIndex: 50, padding: 16 }}>
          <div onClick={(e) => e.stopPropagation()} style={{ width: 'min(680px, 96vw)', background: '#0f172a', border: '1px solid #334155', borderRadius: 12, padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h3 style={{ margin: 0 }}>Review Detection Event #{selectedEvent.id}</h3>
              <button onClick={closeReview}>Close</button>
            </div>

            <div style={{ color: '#94a3b8', fontSize: 13, marginBottom: 10 }}>
              {selectedEvent.matched_ioc || '-'} • {formatUserDateTime(selectedEvent.detected_at || selectedEvent.last_seen_at || selectedEvent.event_time || selectedEvent.created_at)}
            </div>

            <div style={{ marginBottom: 10 }}>
              <label style={{ display: 'block', fontSize: 13, marginBottom: 6, color: '#94a3b8' }}>Verdict</label>
              <select value={reviewVerdict} onChange={(e) => setReviewVerdict(e.target.value)} style={{ minWidth: 220 }}>
                <option value="">Unreviewed</option>
                <option value="in_progress">In Progress</option>
                <option value="fp">FP (False Positive)</option>
                <option value="tp">TP (True Positive)</option>
                <option value="suspicious">Suspicious</option>
              </select>
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={{ display: 'block', fontSize: 13, marginBottom: 6, color: '#94a3b8' }}>Analyst Note</label>
              <textarea value={reviewNote} onChange={(e) => setReviewNote(e.target.value)} rows={5} placeholder="Optional analyst note" style={{ width: '100%' }} />
            </div>

            <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 12 }}>
              Reviewer: {userEmail || 'unknown'}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button onClick={closeReview} disabled={savingReview}>Cancel</button>
              <button onClick={() => submitReview().catch(() => {})} disabled={savingReview}>{savingReview ? 'Saving...' : 'Save Verdict'}</button>
            </div>
          </div>
        </div>
      ) : null}
    </AppShell>
  );
}

function IOCMatchEventDetailsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { userEmail } = useSession();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [item, setItem] = useState(null);
  const [verdict, setVerdict] = useState('');
  const [note, setNote] = useState('');

  const verdictMeta = (v, assignedTo) => {
    const x = String(v || '').toLowerCase();
    if (x === 'fp') return { label: 'FP', color: '#ef4444' };
    if (x === 'tp') return { label: 'TP', color: '#22c55e' };
    if (x === 'suspicious') return { label: 'Suspicious', color: '#f59e0b' };
    if (x === 'in_progress') return { label: `In Progress${assignedTo ? ` (${assignedTo})` : ''}`, color: '#f59e0b' };
    return { label: 'Unreviewed', color: '#94a3b8' };
  };

  const loadDetail = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const { data } = await api.get(`/ioc/match-events/${id}`);
      const it = data?.item || null;
      setItem(it);
      setVerdict(String(it?.verdict || '').toLowerCase());
      setNote(String(it?.note || ''));
    } catch {
      setItem(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  const saveVerdict = useCallback(async (nextVerdict = verdict, nextNote = note, extra = {}) => {
    if (!id) return;
    setSaving(true);
    try {
      const { data } = await api.patch(`/ioc/match-events/${id}/verdict`, {
        verdict: nextVerdict || null,
        note: String(nextNote || '').trim() || null,
        ...extra
      });
      const it = data?.item || null;
      if (it) {
        setItem((prev) => ({ ...(prev || {}), ...it }));
        setVerdict(String(it.verdict || '').toLowerCase());
        setNote(String(it.note || ''));
      }
    } finally {
      setSaving(false);
    }
  }, [id, verdict, note]);

  const takeOwnership = useCallback(async () => {
    await saveVerdict('in_progress', note, { assigned_to: userEmail || null });
  }, [saveVerdict, note, userEmail]);

  useEffect(() => {
    loadDetail().catch(() => {});
  }, [loadDetail]);

  const vm = verdictMeta(item?.verdict, item?.assigned_to);

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h2 style={{ margin: 0 }}>Detection Event Details #{id}</h2>
          <button onClick={() => navigate('/analytics/detection-events')}>Back</button>
        </div>

        {loading ? (
          <div style={{ color: '#94a3b8' }}>Loading detail...</div>
        ) : !item ? (
          <div style={{ color: '#94a3b8' }}>Event detail not found.</div>
        ) : (
          <div style={{ display: 'grid', gap: 12 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Detected At</div>
                <div style={{ fontWeight: 700 }}>{formatUserDateTime(item.detected_at || item.last_seen_at || item.event_time || item.created_at)}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Matched IOC</div>
                <div>{item.matched_ioc || '-'}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Verdict</div>
                <span style={{
                  display: 'inline-block', borderRadius: 999, padding: '4px 10px', fontSize: 12, fontWeight: 700,
                  border: `1px solid ${vm.color}`, color: vm.color, background: '#020617'
                }}>{vm.label}</span>
              </div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
              <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Event Context (v2)</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 8, fontSize: 13 }}>
                <div><b>Event Family:</b> {item?.v2_context?.event_family || '—'}</div>
                <div><b>Control Point:</b> {item?.v2_context?.control_point || '—'}</div>
                <div><b>Matched Field:</b> {item?.v2_context?.matched_field || '—'}</div>
                <div><b>Scenario:</b> {item?.v2_context?.scenario_type || '—'}</div>
                <div><b>Direction:</b> {item?.v2_context?.direction || '—'}</div>
                <div><b>Outcome:</b> {item?.v2_context?.outcome || '—'}</div>
                <div><b>Classification Confidence:</b> {Number.isFinite(Number(item?.v2_context?.classification_confidence)) ? Number(item.v2_context.classification_confidence).toFixed(2) : '—'}</div>
                <div><b>Outcome Confidence:</b> {Number.isFinite(Number(item?.v2_context?.outcome_confidence)) ? Number(item.v2_context.outcome_confidence).toFixed(2) : '—'}</div>
                <div style={{ gridColumn: '1 / -1' }}><b>Context Explanation:</b> {item?.v2_context?.context_explanation || '—'}</div>
              </div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
              <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Matched Syslog event</div>
              <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.45, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace', fontSize: 13, background: '#020617', border: '1px solid #334155', borderRadius: 8, padding: 10, maxHeight: 280, overflowY: 'auto' }}>
                {item.matched_syslog_event || '-'}
              </div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a', display: 'grid', gap: 10 }}>
              <h3 style={{ margin: 0 }}>Analyst Actions</h3>
              <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 12, alignItems: 'center' }}>
                <label style={{ color: '#94a3b8', fontSize: 13 }}>Verdict</label>
                <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
                  <option value="">Unreviewed</option>
                  <option value="in_progress">In Progress</option>
                  <option value="tp">TP</option>
                  <option value="fp">FP</option>
                  <option value="suspicious">Suspicious</option>
                </select>
              </div>

              <div style={{ display: 'grid', gap: 8 }}>
                <label style={{ color: '#94a3b8', fontSize: 13 }}>Analyst Note</label>
                <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={5} placeholder="Optional analyst note" style={{ width: '100%' }} />
              </div>

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button onClick={() => takeOwnership().catch(() => {})} disabled={saving}>Take Ownership</button>
                <button onClick={() => saveVerdict('tp', note).catch(() => {})} disabled={saving}>Mark as TP</button>
                <button onClick={() => saveVerdict('fp', note).catch(() => {})} disabled={saving}>Mark as FP</button>
                <button onClick={() => saveVerdict('suspicious', note).catch(() => {})} disabled={saving}>Mark as Suspicious</button>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ color: '#94a3b8', fontSize: 12 }}>
                  Assigned: {item.assigned_to || '-'} {item.assigned_at ? `• ${formatUserDateTime(item.assigned_at)}` : ''}
                </div>
                <button onClick={() => saveVerdict().catch(() => {})} disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
              </div>
            </div>
          </div>
        )}
      </section>
    </AppShell>
  );
}

function IncidentEventsTable({ activityId, refreshKey = 0 }) {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [offset, setOffset] = useState(0);
  const pageSize = 50;

  const load = useCallback(async (nextOffset = 0, append = false) => {
    if (!activityId) return;
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get(`/incidents/${activityId}/events`, { params: { limit: pageSize, offset: nextOffset } });
      const incoming = data?.events || data?.items || [];
      setRows((prev) => (append ? [...prev, ...incoming] : incoming));
      setTotal(Number.isFinite(Number(data?.total)) ? Number(data.total) : null);
      setOffset(nextOffset + incoming.length);
    } catch {
      if (!append) setRows([]);
      setError('Failed to load events');
      if (!append) setTotal(null);
    } finally {
      setLoading(false);
    }
  }, [activityId]);

  useEffect(() => { load(0, false).catch(() => {}); }, [load, refreshKey]);

  const hasMore = total == null ? false : rows.length < total;

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>
        {total == null ? 'Events' : `Events (${total})`}
      </div>
      <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 1260 }}>
        <thead>
          <tr style={{ textAlign: 'left', background: '#111827' }}>
            <th style={{ width: 80 }}>ID</th>
            <th style={{ width: 170 }}>Detected At</th>
            <th style={{ width: 220 }}>Matched IOC</th>
            <th style={{ width: 200 }}>Context</th>
            <th style={{ width: 140 }}>Detection</th>
            <th style={{ width: 140 }}>Verdict</th>
            <th style={{ width: 140 }}>Assignee</th>
            <th style={{ width: 180 }}>Source</th>
            <th style={{ width: 140 }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {loading && rows.length === 0 ? <tr><td colSpan={9} style={{ color: '#94a3b8' }}>Loading events...</td></tr> : error ? <tr><td colSpan={9} style={{ color: '#fca5a5' }}>{error}</td></tr> : rows.length ? rows.map((r) => {
            const verdict = String(r.verdict || '').toLowerCase();
            const vm = verdict === 'fp'
              ? { label: 'FP', color: '#ef4444' }
              : verdict === 'tp'
                ? { label: 'TP', color: '#22c55e' }
                : verdict === 'suspicious'
                  ? { label: 'Suspicious', color: '#f59e0b' }
                  : verdict === 'in_progress'
                    ? { label: 'In Progress', color: '#f59e0b' }
                    : { label: 'Unreviewed', color: '#94a3b8' };

            return (
              <tr key={r.id} style={{ borderTop: '1px solid #334155' }}>
                <td>{r.id}</td>
                <td>{formatUserDateTime(r.detected_at || r.event_time || r.created_at)}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.matched_ioc || '-'}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  <span
                    style={{
                      display: 'inline-block',
                      borderRadius: 999,
                      padding: '3px 10px',
                      fontSize: 12,
                      fontWeight: 700,
                      border: '1px solid #475569',
                      color: '#cbd5e1',
                      background: '#020617'
                    }}
                  >
                    {normalizeEventContext(r)}
                  </span>
                </td>
                <td>
                  <span style={{
                    display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                    border: `1px solid ${r.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e'}`,
                    color: r.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e', background: '#020617'
                  }}>
                    {r.detection_mode === 'retroactive' ? 'Retroactive Match' : 'Real-Time Match'}
                  </span>
                </td>
                <td>
                  <span style={{
                    display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                    border: `1px solid ${vm.color}`, color: vm.color, background: '#020617'
                  }}>{vm.label}</span>
                </td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.assigned_to || 'Unassigned'}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {r.source_count > 1
                    ? `${(r.source_names && r.source_names[0]) || r.source_name || '-'} +${r.source_count - 1}`
                    : ((r.source_names && r.source_names[0]) || r.source_name || '-')}
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => navigate(`/analytics/detection-events/${r.id}`)} title="View detail" aria-label="View detail" style={{ minWidth: 32, padding: '4px 8px' }}>🔍</button>
                    <button onClick={() => navigate(`/analytics/detection-events/${r.id}`)} title="Review verdict" aria-label="Review verdict" style={{ minWidth: 32, padding: '4px 8px' }}>✏️</button>
                  </div>
                </td>
              </tr>
            );
          }) : <tr><td colSpan={9} style={{ color: '#94a3b8' }}>No events linked to this incident.</td></tr>}
        </tbody>
      </table>
      <div style={{ padding: 10, borderTop: '1px solid #334155', background: '#0f172a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ color: '#94a3b8', fontSize: 12 }}>
          Showing {rows.length}{total == null ? '' : ` / ${total}`}
        </span>
        {hasMore ? <button onClick={() => load(offset, true).catch(() => {})} disabled={loading}>{loading ? 'Loading...' : 'Load more'}</button> : null}
      </div>
    </div>
  );
}

function RiskOverviewPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [trendData, setTrendData] = useState(null);
  const [range, setRange] = useState('24h');

  const load = useCallback(async (selectedRange = range) => {
    setLoading(true);
    try {
      const [ovRes, trRes] = await Promise.allSettled([
        api.get('/risk/overview'),
        api.get('/risk/trend', { params: { range: selectedRange } })
      ]);

      if (ovRes.status === 'fulfilled') {
        setData(ovRes.value?.data || null);
      } else {
        setData(null);
      }

      if (trRes.status === 'fulfilled') {
        setTrendData(trRes.value?.data || null);
      } else {
        setTrendData({ range: selectedRange, current: Number(ovRes.status === 'fulfilled' ? ovRes.value?.data?.institution_risk_score || 0 : 0), previous: 0, delta: 0, trend: 'stable', stats: { min: 0, max: 0, avg: 0 }, history: [] });
      }
    } catch {
      setData(null);
      setTrendData(null);
    } finally {
      setLoading(false);
    }
  }, [range]);

  useEffect(() => { load(range).catch(() => {}); }, [load, range]);

  const score = Math.max(0, Math.min(100, Number(data?.institution_risk_score || 0)));
  const level = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'GUARDED' : 'LOW';
  const levelColor = level === 'CRITICAL' ? '#ef4444' : level === 'HIGH' ? '#f97316' : level === 'MEDIUM' ? '#f59e0b' : level === 'GUARDED' ? '#eab308' : '#22c55e';
  const _deprecatedV2MetricsHidden = true;
  const top = Array.isArray(data?.top_contributing_incidents) ? data.top_contributing_incidents : [];
  const bd = data?.breakdown || {};
  const llmAggregate = data?.llm_adjustment_aggregate || bd?.llm_adjustment_aggregate || null;
  const dataTruncated = Boolean(data?.data_truncated);

  function formatAiDelta(value) {
    if (value === null || value === undefined) return '—';
    const n = Number(value);
    if (!Number.isFinite(n)) return '—';
    if (n > 0) return `+${n}`;
    if (n < 0) return `${n}`;
    return '0';
  }

  function aiDeltaStyle(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return { color: '#94a3b8', borderColor: '#475569', background: '#0f172a' };
    if (n > 0) return { color: '#fca5a5', borderColor: '#7f1d1d', background: 'rgba(127,29,29,0.25)' };
    if (n < 0) return { color: '#86efac', borderColor: '#14532d', background: 'rgba(20,83,45,0.25)' };
    return { color: '#cbd5e1', borderColor: '#475569', background: '#0f172a' };
  }
  const trend = String(trendData?.trend || 'stable');
  const delta = Number(trendData?.delta || 0);
  const trendArrow = trend === 'increasing' ? '↗' : trend === 'decreasing' ? '↘' : '→';
  const trendColor = trend === 'increasing' ? '#ef4444' : trend === 'decreasing' ? '#22c55e' : '#94a3b8';
  const history = Array.isArray(trendData?.history) ? trendData.history : [];
  const chartPoints = history.map((s, i) => {
    const x = history.length <= 1 ? 0 : (i / (history.length - 1)) * 100;
    const y = 100 - Math.max(0, Math.min(100, Number(s?.risk_score || 0)));
    return `${x},${y}`;
  }).join(' ');
  const stats = trendData?.stats || { min: 0, max: 0, avg: 0 };


  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
          <h2 style={{ margin: 0 }}>Risk Overview</h2>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {['24h', '7d', '30d'].map((r) => (
              <button
                key={r}
                onClick={() => setRange(r)}
                style={{ borderColor: range === r ? '#93c5fd' : '#475569' }}
              >
                {r.toUpperCase()}
              </button>
            ))}
            <button onClick={() => load(range).catch(() => {})}>Refresh</button>
          </div>
        </div>

        {loading ? <div style={{ color: '#94a3b8' }}>Loading risk overview...</div> : !data ? <div style={{ color: '#94a3b8' }}>Risk overview data is unavailable.</div> : (
          <>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a', marginBottom: 14 }}>
              <div style={{ fontSize: 13, color: '#94a3b8' }}>Institution Risk Estimate</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 6 }}>
                <div style={{ fontSize: 42, fontWeight: 800, lineHeight: 1 }}>{score.toFixed(2)}</div>
                <span style={{ border: `1px solid ${levelColor}`, color: levelColor, borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700 }}>{level}</span>
              </div>
              <div style={{ marginTop: 6, fontSize: 12, color: '#94a3b8' }}>Conservative estimate based on observed threat activity, exposure, and available event context.</div>
              <div style={{ marginTop: 10, height: 12, borderRadius: 999, background: '#1f2937', overflow: 'hidden' }}>
                <div style={{ width: `${score}%`, height: '100%', background: `linear-gradient(90deg, #22c55e 0%, #f59e0b 55%, #ef4444 100%)` }} />
              </div>
              <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8, color: trendColor, fontWeight: 700 }}>
                <span>{trendArrow}</span>
                <span style={{ textTransform: 'capitalize' }}>{trend}</span>
                <span style={{ color: '#94a3b8', fontWeight: 500 }}>Δ {delta >= 0 ? '+' : ''}{delta.toFixed(2)}</span>
              </div>
              {llmAggregate?.enabled ? (
                <div style={{ marginTop: 8, fontSize: 12, color: '#93c5fd', display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <span>AI adjusted risk enabled</span>
                  <span>AI Δ {Number(llmAggregate.total_adjustment || 0) >= 0 ? '+' : ''}{Number(llmAggregate.total_adjustment || 0).toFixed(2)}</span>
                </div>
              ) : null}
              <div style={{ marginTop: 10, border: '1px solid #334155', borderRadius: 8, padding: 8, background: '#0b1220' }}>
                {history.length >= 2 ? (
                  <svg viewBox="0 0 100 100" width="100%" height="110" preserveAspectRatio="none" aria-label="Institution risk trend">
                    <polyline fill="none" stroke="#60a5fa" strokeWidth="2" points={chartPoints} />
                    {history.map((p, i) => {
                      const x = history.length <= 1 ? 0 : (i / (history.length - 1)) * 100;
                      const y = 100 - Math.max(0, Math.min(100, Number(p?.risk_score || 0)));
                      return <circle key={`${p.ts}-${i}`} cx={x} cy={y} r="1.2" fill="#93c5fd"><title>{`${new Date(p.ts).toLocaleString()} • ${Number(p.risk_score || 0).toFixed(2)}`}</title></circle>;
                    })}
                  </svg>
                ) : (
                  <div style={{ color: '#64748b', fontSize: 12 }}>Not enough snapshots yet for trend chart.</div>
                )}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8, marginBottom: 12 }}>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Current</div><div style={{ fontSize: 18, fontWeight: 700 }}>{Number(trendData?.current || score).toFixed(2)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Peak</div><div style={{ fontSize: 18, fontWeight: 700 }}>{Number(stats.max || 0).toFixed(2)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Min</div><div style={{ fontSize: 18, fontWeight: 700 }}>{Number(stats.min || 0).toFixed(2)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Avg</div><div style={{ fontSize: 18, fontWeight: 700 }}>{Number(stats.avg || 0).toFixed(2)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Delta</div><div style={{ fontSize: 18, fontWeight: 700, color: trendColor }}>{delta >= 0 ? '+' : ''}{delta.toFixed(2)}</div></div>
            </div>

            {dataTruncated ? (
              <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, border: '1px solid #f59e0b', color: '#fcd34d', background: 'rgba(245, 158, 11, 0.12)' }}>
                Risk score is calculated on a partial dataset
              </div>
            ) : null}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10, marginBottom: 14 }}>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>Open Incidents</div>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{Number(data?.active_incident_count || 0)}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Considered Incidents</div>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{Number(data?.total_active_incidents || 0)}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Raw Contribution</div>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{Number(bd?.total_raw_contribution || 0).toFixed(6)}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>Score Model</div>
                <div style={{ fontSize: 24, fontWeight: 700 }}>evidence-aware</div>
              </div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
              <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Incident Evidence Breakdown</div>
              <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed' }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#111827' }}>
                    <th style={{ width: 100 }}>Incident ID</th>
                    <th>IOC</th>
                    <th style={{ width: 110 }}>Risk Score</th>
                    <th style={{ width: 110 }}>Contribution</th>
                    <th style={{ width: 90 }}>Verdict</th>
                    <th style={{ width: 110 }}>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {top.length ? top.map((it) => {
                    return (
                      <tr key={`${it.id}-${it.rank}`} style={{ borderTop: '1px solid #334155' }}>
                        <td>{it.incident_id || it.id ? <Link to={`/incidents/${it.incident_id || it.id}`}>#{it.incident_id || '-'}</Link> : '-'}</td>
                        <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{it.ioc_value || '-'}</td>
                        <td>{Number.isFinite(Number(it?.risk_score)) ? Number(it.risk_score).toFixed(2) : '—'}</td>
                        <td>{Number.isFinite(Number(it?.contribution)) ? Number(it.contribution).toFixed(3) : '—'}</td>
                        <td>{it.verdict || '—'}</td>
                        <td>{it.confidence || '—'}</td>
                      </tr>
                    );
                  }) : <tr><td colSpan={10} style={{ color: '#94a3b8' }}>No active incidents.</td></tr>}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>
    </AppShell>
  );
}

function IncidentDetailsPage() {
  const { id } = useParams();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [item, setItem] = useState(null);
  const [tab, setTab] = useState('summary');
  const [verdict, setVerdict] = useState('Unreviewed');
  const [note, setNote] = useState('');
  const [eventsRefreshKey, setEventsRefreshKey] = useState(0);
  const [showPropagateModal, setShowPropagateModal] = useState(false);
  const [propagationNote, setPropagationNote] = useState('');
  const [aiAnalyzing, setAiAnalyzing] = useState(false);
  const [aiStillAnalyzing, setAiStillAnalyzing] = useState(false);
  const [aiAnalyzeStartedAt, setAiAnalyzeStartedAt] = useState(null);
  const [aiError, setAiError] = useState('');
  const [evidenceSummary, setEvidenceSummary] = useState({ count: null, unavailable: false });

  useEffect(() => {
    const reason = item?.llm_risk_reason;
    if (typeof reason !== 'string' || !reason) return;
    console.log(reason.length, reason);
  }, [item?.llm_risk_reason]);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const { data } = await api.get(`/incidents/${id}`);
      const it = data?.item || null;
      setItem(it);
      setVerdict(String(it?.verdict || 'Unreviewed'));
      setNote(String(it?.note || ''));
    } catch {
      setItem(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    async function loadEvidenceSummary() {
      try {
        const { data } = await api.get(`/incidents/${id}/related-logs`, { params: { page: 1, pageSize: 1 } });
        if (cancelled) return;
        setEvidenceSummary({
          count: Number.isFinite(Number(data?.total)) ? Number(data.total) : null,
          unavailable: Boolean(data?.error === 'unavailable')
        });
      } catch {
        if (cancelled) return;
        setEvidenceSummary({ count: null, unavailable: true });
      }
    }
    loadEvidenceSummary().catch(() => {});
    return () => { cancelled = true; };
  }, [id, eventsRefreshKey]);

  useEffect(() => {
    if (!aiStillAnalyzing || !id) return undefined;

    let stopped = false;
    const timer = setInterval(async () => {
      if (stopped) return;
      try {
        const { data } = await api.get(`/incidents/${id}`);
        const it = data?.item || null;
        if (!it) return;
        setItem((prev) => ({ ...(prev || {}), ...it }));

        const hasAdjustment = it.llm_risk_adjustment !== null && it.llm_risk_adjustment !== undefined;
        const updatedAtMs = it.llm_last_updated_at ? Date.parse(it.llm_last_updated_at) : NaN;
        const startedAtMs = aiAnalyzeStartedAt ? Date.parse(aiAnalyzeStartedAt) : NaN;
        const isFresh = Number.isFinite(updatedAtMs) && Number.isFinite(startedAtMs) ? updatedAtMs >= startedAtMs : true;
        if (hasAdjustment && isFresh) {
          stopped = true;
          setAiStillAnalyzing(false);
          await load();
        }
      } catch {
        // keep polling silently
      }
    }, 2500);

    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [aiStillAnalyzing, aiAnalyzeStartedAt, id, load]);

  async function savePatch(patch = {}) {
    if (!id) return;
    setSaving(true);
    try {
      const { data } = await api.patch(`/incidents/${id}`, { verdict, note, ...patch });
      setItem((prev) => ({ ...(prev || {}), ...(data?.item || {}) }));
      if (data?.item?.note != null) setNote(String(data.item.note || ''));
      setEventsRefreshKey((k) => k + 1);
    } finally {
      setSaving(false);
    }
  }

  async function runAiAnalyze() {
    if (!id || aiAnalyzing) return;
    setAiAnalyzing(true);
    setAiStillAnalyzing(false);
    setAiAnalyzeStartedAt(new Date().toISOString());
    setAiError('');
    try {
      const { data, status } = await api.post(`/incidents/${id}/ai-analyze`);
      if (status === 202 || data?.status === 'processing') {
        setAiStillAnalyzing(true);
        return;
      }

      const nextItem = data?.item || null;
      if (nextItem) {
        setItem((prev) => ({ ...(prev || {}), ...nextItem }));
      }
      setAiStillAnalyzing(false);
      await load();
    } catch {
      setAiStillAnalyzing(false);
      setAiError('AI analysis failed');
      setTimeout(() => setAiError(''), 3000);
    } finally {
      setAiAnalyzing(false);
    }
  }

  const isFinalVerdict = verdict === 'TP' || verdict === 'FP' || verdict === 'Suspicious';

  async function onClickSave() {
    if (isFinalVerdict) {
      setPropagationNote(String(note || ''));
      setShowPropagateModal(true);
      return;
    }
    await savePatch({});
  }

  async function applyWithPropagation(shouldPropagate) {
    await savePatch({
      propagate_to_events: shouldPropagate,
      propagation_note: shouldPropagate ? propagationNote : undefined
    });
    setShowPropagateModal(false);
  }

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        {loading ? <div style={{ color: '#94a3b8' }}>Loading incident...</div> : !item ? <div style={{ color: '#94a3b8' }}>Incident not found.</div> : (
          <div style={{ display: 'grid', gap: 12 }}>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
              <h2 style={{ margin: 0, fontSize: 28, fontWeight: 800 }}>Incident #{item.incident_id || id}</h2>
              <div style={{ color: '#e2e8f0', marginTop: 6, fontSize: 16, fontWeight: 600 }}>{item.ioc_value}</div>
              <div style={{ color: '#94a3b8', marginTop: 6 }}>
                Type: {item.ioc_type}
                {' • '}Detection Events: {item.detection_event_count ?? item.event_count ?? 0}
                {' • '}Evidence Logs: {evidenceSummary.unavailable ? '-' : (Number.isFinite(Number(evidenceSummary.count)) ? Number(evidenceSummary.count) : (item.related_log_count ?? 0))}
                {' • '}Observed Hosts: {item.asset_count || 0}
              </div>
              <div style={{ color: '#94a3b8', marginTop: 4 }}>First Seen: {formatUserDateTime(item.first_seen)} • Last Seen: {formatUserDateTime(item.last_seen)}</div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a', display: 'grid', gap: 10 }}>
              <h3 style={{ margin: 0 }}>Analyst Actions</h3>
              <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr', gap: 8, alignItems: 'center' }}>
                <label>Verdict</label>
                <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
                  <option>TP</option><option>FP</option><option>Suspicious</option><option>Unreviewed</option><option>In Progress</option>
                </select>
                <label>Note</label>
                <textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => onClickSave().catch(() => {})} disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
                <button onClick={() => savePatch({ take_ownership: true, verdict: 'In Progress' }).catch(() => {})} disabled={saving}>Take Ownership</button>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => setTab('summary')} style={{ borderColor: tab === 'summary' ? '#93c5fd' : '#475569' }}>Summary</button>
              <button onClick={() => setTab('events')} style={{ borderColor: tab === 'events' ? '#93c5fd' : '#475569' }}>Detection Events ({item.detection_event_count ?? item.event_count ?? 0})</button>
              <button onClick={() => setTab('relatedLogs')} style={{ borderColor: tab === 'relatedLogs' ? '#93c5fd' : '#475569' }}>Evidence Logs ({evidenceSummary.unavailable ? '-' : (Number.isFinite(Number(evidenceSummary.count)) ? Number(evidenceSummary.count) : (item.related_log_count ?? 0))})</button>
            </div>

            {tab === 'summary' ? (
              <div style={{ display: 'grid', gap: 10 }}>
                <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                  <div>Risk Score: <b>{Number(item.risk_score || 0).toFixed(2)}</b></div>
                  <div>Status: <b>{item.status}</b></div>
                  <div>Verdict: <b>{item.verdict}</b></div>
                </div>

                <RiskExplanationPanel explanation={item.risk_explanation} item={item} />

                <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a', display: 'grid', gap: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <h4 style={{ margin: 0, fontSize: 14, color: '#cbd5e1' }}>AI Insight</h4>
                    <button
                      onClick={() => runAiAnalyze().catch(() => {})}
                      disabled={aiAnalyzing || aiStillAnalyzing}
                      style={{ fontSize: 12, padding: '4px 8px', borderColor: '#475569', background: '#111827' }}
                    >
                      {aiAnalyzing ? 'Analyzing...' : aiStillAnalyzing ? 'Still analyzing...' : ((item.llm_risk_adjustment === null || item.llm_risk_adjustment === undefined) ? 'Analyze with AI' : 'Update AI Insight')}
                    </button>
                  </div>

                  {aiStillAnalyzing ? (
                    <div style={{ fontSize: 12, color: '#93c5fd' }}>Still analyzing...</div>
                  ) : null}

                  {aiError ? (
                    <div style={{ fontSize: 12, color: '#fca5a5' }}>{aiError}</div>
                  ) : null}

                  {(item.llm_risk_adjustment === null || item.llm_risk_adjustment === undefined) ? (
                    <div style={{ color: '#94a3b8', fontSize: 13 }}>No AI analysis yet</div>
                  ) : (
                    <>
                      {(() => {
                        const adj = Number(item.llm_risk_adjustment || 0);
                        const adjColor = adj > 0 ? '#fca5a5' : adj < 0 ? '#86efac' : '#94a3b8';
                        const adjText = adj > 0 ? `+${adj}` : `${adj}`;
                        const conf = Number(item.llm_risk_confidence);
                        const confText = Number.isFinite(conf) ? `${Math.round(Math.min(Math.max(conf, 0), 1) * 100)}%` : '—';

                        return (
                          <>
                            <div style={{ fontSize: 13 }}>Adjustment: <b style={{ color: adjColor }}>{adjText}</b></div>
                            <div style={{ fontSize: 13 }}>Confidence: <b>{confText}</b></div>
                            <div style={{ fontSize: 13, display: 'grid', gridTemplateColumns: '60px 1fr', gap: 8, alignItems: 'start' }}>
                              <span>Reason:</span>
                              <span style={{ color: '#cbd5e1', whiteSpace: 'normal', overflow: 'visible', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.4 }}>
                                {item.llm_risk_reason || '—'}
                              </span>
                            </div>
                            {item.llm_related_evidence ? (
                              <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
                                <div style={{ color: '#cbd5e1', marginBottom: 4 }}>Related Evidence:</div>
                                <div>- Domain: {item.llm_related_evidence.domain || '—'}</div>
                                <div>- Resolved IP: {item.llm_related_evidence.resolved_ip || '—'}</div>
                                <div>- Resolved IP in IOC list: {item.llm_related_evidence.resolved_ip_in_ioc_list ? 'yes' : 'no'}</div>
                                <div>- Accepted traffic: {item.llm_related_evidence.accepted_traffic ? 'yes' : 'no'}</div>
                                <div>- Service/port: {item.llm_related_evidence.service_port || 'not specified'}</div>
                                <div>- Chain type: {String(item.llm_related_evidence.chain_type || 'related_infrastructure_activity').replaceAll('_', ' ')}</div>
                              </div>
                            ) : null}
                          </>
                        );
                      })()}
                    </>
                  )}
                </div>
              </div>
            ) : tab === 'events' ? (
              <IncidentEventsTable activityId={item.id} refreshKey={eventsRefreshKey} />
            ) : (
              <IncidentRelatedLogsTable incidentId={item.incident_id || id} />
            )}
          </div>
        )}

        {showPropagateModal && (
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.75)', display: 'grid', placeItems: 'center', zIndex: 60 }}>
            <div style={{ width: 'min(640px, 92vw)', border: '1px solid #334155', borderRadius: 12, background: '#0f172a', padding: 16, display: 'grid', gap: 10 }}>
              <h3 style={{ margin: 0 }}>Apply verdict to related events?</h3>
              <div style={{ color: '#94a3b8' }}>Do you also want to apply this verdict to related events?</div>
              <label style={{ color: '#cbd5e1', fontSize: 13 }}>Note for related events (optional)</label>
              <textarea rows={3} value={propagationNote} onChange={(e) => setPropagationNote(e.target.value)} />
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button onClick={() => setShowPropagateModal(false)} disabled={saving}>Cancel</button>
                <button onClick={() => applyWithPropagation(false).catch(() => {})} disabled={saving}>No</button>
                <button onClick={() => applyWithPropagation(true).catch(() => {})} disabled={saving}>Yes</button>
              </div>
            </div>
          </div>
        )}
      </section>
    </AppShell>
  );
}

function IncidentRelatedLogsTable({ incidentId }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [loading, setLoading] = useState(false);
  const [unavailable, setUnavailable] = useState(false);

  const load = useCallback(async () => {
    if (!incidentId) return;
    setLoading(true);
    setUnavailable(false);
    try {
      const { data } = await api.get(`/incidents/${incidentId}/related-logs`, { params: { page, pageSize } });
      setItems(data?.items || []);
      setTotal(Number(data?.total || 0));
      if (data?.error === 'unavailable') setUnavailable(true);
    } catch {
      setItems([]);
      setTotal(0);
      setUnavailable(true);
    } finally {
      setLoading(false);
    }
  }, [incidentId, page, pageSize]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  const start = total ? ((page - 1) * pageSize) + 1 : 0;
  const end = total ? Math.min(page * pageSize, total) : 0;

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a', display: 'grid', gap: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h4 style={{ margin: 0 }}>Evidence Logs</h4>
          <div style={{ color: '#94a3b8', fontSize: 12 }}>Raw logs captured for this incident. These are not additional detection events. Use CSV export for full review.</div>
        </div>
        <a href={`/api/incidents/${incidentId}/related-logs/export.csv`} target="_blank" rel="noreferrer"><button>Download CSV</button></a>
      </div>

      {loading ? <div style={{ color: '#94a3b8' }}>Loading evidence logs...</div> : unavailable ? (
        <div style={{ color: '#94a3b8' }}>Evidence logs are currently unavailable.</div>
      ) : !items.length ? (
        <div style={{ color: '#94a3b8' }}>No raw evidence logs found for this incident.</div>
      ) : (
        <>
          {items.some((r) => r?.fallback === true || r?.evidence_origin === 'pg_detection_event_snapshot') ? (
            <div style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid #f59e0b', background: 'rgba(245,158,11,0.12)', color: '#fcd34d', fontSize: 12 }}>
              Some evidence rows are fallback snapshots derived from normalized event data (raw log was not persisted at detection time).
            </div>
          ) : null}
          <div style={{ color: '#94a3b8', fontSize: 12 }}>Showing {start}-{end} of {total} evidence logs</div>
          <div style={{ overflowX: 'auto', border: '1px solid #334155', borderRadius: 8 }}>
            <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', minWidth: 1000 }}>
              <thead><tr style={{ background: '#1f2937', textAlign: 'left' }}>
                <th>Time</th><th>Observed Host</th><th>Matched IOC</th><th>Source Type</th><th>Evidence</th>
              </tr></thead>
              <tbody>
                {items.map((r, i) => {
                  const isFallback = r?.fallback === true || r?.evidence_origin === 'pg_detection_event_snapshot';
                  return (
                    <tr key={`${r.evidence_hash || i}`} style={{ borderTop: '1px solid #334155' }}>
                      <td>{formatUserDateTime(r.log_ts)}</td>
                      <td>{r.observed_host || '-'}</td>
                      <td>{r.matched_ioc || '-'}</td>
                      <td>{r.source_type || '-'}</td>
                      <td style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                        {isFallback ? <div style={{ marginBottom: 4, fontSize: 11, color: '#fcd34d' }}>Derived snapshot (not raw log)</div> : null}
                        {r.raw_message_sample || '-'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>Prev</button>
            <span>Page {page}</span>
            <button onClick={() => setPage((p) => (p * pageSize < total ? p + 1 : p))} disabled={page * pageSize >= total}>Next</button>
            <select value={String(pageSize)} onChange={(e) => { setPage(1); setPageSize(Math.min(Math.max(Number(e.target.value), 1), 200)); }}>
              <option value="50">50 / page</option><option value="100">100 / page</option><option value="200">200 / page</option>
            </select>
          </div>
        </>
      )}
    </div>
  );
}

function IncidentPage() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [verdict, setVerdict] = useState([]);
  const [assigneeFilter, setAssigneeFilter] = useState('all');
  const [from, setFrom] = useState(() => {
    const now = new Date();
    const d = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${day}T${hh}:${mm}`;
  });
  const [to, setTo] = useState(() => {
    const d = new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${day}T${hh}:${mm}`;
  });
  const [quickRange, setQuickRange] = useState('24h');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [pagination, setPagination] = useState({ page: 1, page_size: 20, total: 0, total_pages: 1 });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, page_size: pageSize, q: query || undefined, status: status || undefined, from: from || undefined, to: to || undefined };
      if (verdict.length) params.verdict = verdict.join(',');
      if (assigneeFilter && assigneeFilter !== 'all') params.assignee = assigneeFilter;
      const { data } = await api.get('/incidents', { params });
      setItems(data?.items || []);
      setPagination(data?.pagination || { page: 1, page_size: pageSize, total: 0, total_pages: 1 });
    } catch {
      setItems([]);
      setPagination({ page: 1, page_size: pageSize, total: 0, total_pages: 1 });
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, query, status, verdict, assigneeFilter, from, to]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  const toggleVerdict = (v) => setVerdict((prev) => prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v]);

  const toDateTimeLocal = (d) => {
    const dt = new Date(d);
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const day = String(dt.getDate()).padStart(2, '0');
    const hh = String(dt.getHours()).padStart(2, '0');
    const mm = String(dt.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${day}T${hh}:${mm}`;
  };

  const applyQuickRange = (key) => {
    const now = new Date();
    const fromDate = new Date(now.getTime() - (key === '1h' ? 60 * 60 * 1000 : key === '24h' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000));
    setFrom(toDateTimeLocal(fromDate));
    setTo(toDateTimeLocal(now));
    setQuickRange(key);
    setPage(1);
  };

  const resetFilters = () => {
    setQuery('');
    setStatus('');
    setVerdict([]);
    setAssigneeFilter('all');
    applyQuickRange('24h');
  };

  const assigneeOptions = useMemo(() => {
    const set = new Set();
    for (const it of items || []) {
      const a = String(it?.assigned_to || '').trim();
      if (a) set.add(a);
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [items]);

  const activeFilters = [];
  if (from || to) activeFilters.push({ key: 'date', label: `${from || '-'} → ${to || '-'}`, onClear: () => { setFrom(''); setTo(''); setQuickRange(''); } });
  if (status) activeFilters.push({ key: 'status', label: `Status: ${status}`, onClear: () => setStatus('') });
  if (verdict.length) activeFilters.push({ key: 'verdict', label: `Verdict: ${verdict.join(', ')}`, onClear: () => setVerdict([]) });
  if (assigneeFilter !== 'all') activeFilters.push({ key: 'assignee', label: `Assignee: ${assigneeFilter}`, onClear: () => setAssigneeFilter('all') });

  const [tableWidths, setTableWidths] = useState({
    incidentId: 110,
    createdAt: 170,
    ioc: 240,
    type: 90,
    observedHosts: 130,
    firstSeen: 170,
    lastSeen: 170,
    status: 100,
    verdict: 120,
    assignee: 160,
    action: 100
  });
  const [resizeState, setResizeState] = useState(null);

  useEffect(() => {
    if (!resizeState) return;
    const onMove = (e) => {
      const delta = e.clientX - resizeState.startX;
      const next = Math.max(80, resizeState.startWidth + delta);
      setTableWidths((prev) => ({ ...prev, [resizeState.col]: next }));
    };
    const onUp = () => setResizeState(null);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [resizeState]);

  const startResize = (e, col) => {
    e.preventDefault();
    e.stopPropagation();
    setResizeState({ col, startX: e.clientX, startWidth: tableWidths[col] || 120 });
  };

  const headerCell = (label, col, extraProps = {}) => (
    <th style={{ position: 'relative', ...(col ? { width: tableWidths[col] } : {}), ...extraProps }}>
      {label}
      {col && (
        <span
          onMouseDown={(e) => startResize(e, col)}
          style={{ position: 'absolute', right: 0, top: 0, width: 8, height: '100%', cursor: 'col-resize', userSelect: 'none' }}
          title="Resize"
        />
      )}
    </th>
  );

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <h2 style={{ marginTop: 0 }}>Incidents</h2>

        <div style={{ display: 'grid', gap: 8, marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <input placeholder="Search IOC or #IncidentID..." value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { setPage(1); load().catch(() => {}); } }} style={{ minWidth: 320 }} />
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">Status: All</option>
              <option value="open">Open</option>
              <option value="closed">Closed</option>
            </select>
            <select value={assigneeFilter} onChange={(e) => setAssigneeFilter(e.target.value)}>
              <option value="all">Assignee: All</option>
              <option value="unassigned">Assignee: Unassigned</option>
              {assigneeOptions.map((u) => <option key={u} value={u}>{u}</option>)}
            </select>
            <input type="datetime-local" value={from} onChange={(e) => { setFrom(e.target.value); setQuickRange(''); }} />
            <input type="datetime-local" value={to} onChange={(e) => { setTo(e.target.value); setQuickRange(''); }} />
            <button
              onClick={() => applyQuickRange('1h')}
              style={{ borderColor: quickRange === '1h' ? '#93c5fd' : '#475569' }}
            >
              Last 1 hour
            </button>
            <button
              onClick={() => applyQuickRange('24h')}
              style={{ borderColor: quickRange === '24h' ? '#93c5fd' : '#475569' }}
            >
              Last 24 hours
            </button>
            <button
              onClick={() => applyQuickRange('7d')}
              style={{ borderColor: quickRange === '7d' ? '#93c5fd' : '#475569' }}
            >
              Last 7 days
            </button>
            <button onClick={() => { setPage(1); load().catch(() => {}); }}>Filter</button>
            <button onClick={resetFilters}>Clear</button>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, background: '#0b1220', padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ color: '#93c5fd', fontSize: 12, fontWeight: 700 }}>Active Filters</span>
            {activeFilters.length ? activeFilters.map((f) => (
              <span key={f.key + f.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, border: '1px solid #475569', borderRadius: 999, padding: '3px 8px', fontSize: 12, color: '#cbd5e1' }}>
                {f.label}
                <button onClick={f.onClear} style={{ border: 'none', background: 'transparent', color: '#94a3b8', cursor: 'pointer', padding: 0 }}>✕</button>
              </span>
            )) : <span style={{ color: '#64748b', fontSize: 12 }}>None</span>}
            <button onClick={resetFilters} style={{ marginLeft: 'auto', fontSize: 12 }}>Clear all</button>
          </div>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {['TP', 'FP', 'Suspicious', 'Unreviewed', 'In Progress'].map((v) => (
              <label key={v} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <input type="checkbox" checked={verdict.includes(v)} onChange={() => toggleVerdict(v)} /> {v}
              </label>
            ))}
          </div>
        </div>

        <div style={{ border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 1500 }}>
            <colgroup>
              <col style={{ width: tableWidths.incidentId }} />
              <col style={{ width: tableWidths.createdAt }} />
              <col style={{ width: tableWidths.ioc }} />
              <col style={{ width: tableWidths.type }} />
              <col style={{ width: tableWidths.observedHosts }} />
              <col style={{ width: tableWidths.firstSeen }} />
              <col style={{ width: tableWidths.lastSeen }} />
              <col style={{ width: tableWidths.status }} />
              <col style={{ width: tableWidths.verdict }} />
              <col style={{ width: tableWidths.assignee }} />
              <col style={{ width: tableWidths.action }} />
            </colgroup>
            <thead>
              <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                {headerCell('Incident ID', 'incidentId')}
                {headerCell('Created At', 'createdAt')}
                {headerCell('IOC', 'ioc')}
                {headerCell('Type', 'type')}
                {headerCell(<span title="Number of unique hosts where this IOC was observed in logs">Observed Hosts</span>, 'observedHosts')}
                {headerCell('First Seen', 'firstSeen')}
                {headerCell('Last Seen', 'lastSeen')}
                {headerCell('Status', 'status')}
                {headerCell('Verdict', 'verdict')}
                {headerCell('Assignee', 'assignee')}
                {headerCell('Action', 'action')}
              </tr>
            </thead>
            <tbody>
              {loading ? <tr><td colSpan={11} style={{ color: '#94a3b8' }}>Loading incidents...</td></tr> : items.length ? items.map((it) => (
                <tr key={it.id} style={{ borderTop: '1px solid #334155', cursor: 'pointer' }} onClick={() => navigate(`/incidents/${it.incident_id || it.id}`)}>
                  <td><b>#{it.incident_id || '-'}</b></td>
                  <td>{formatUserDateTime(it.created_at)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{it.ioc_value}</td>
                  <td>{it.ioc_type}</td>
                  <td>{it.asset_count || 0}</td>
                  <td>{formatUserDateTime(it.first_seen)}</td>
                  <td>{formatUserDateTime(it.last_seen)}</td>
                  <td>{it.status}</td>
                  <td>{it.verdict}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{it.assigned_to || 'Unassigned'}</td>
                  <td><button onClick={(e) => { e.stopPropagation(); navigate(`/incidents/${it.incident_id || it.id}`); }}>View</button></td>
                </tr>
              )) : <tr><td colSpan={11} style={{ color: '#94a3b8' }}>No incidents.</td></tr>}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ color: '#94a3b8', fontSize: 13 }}>Total: {pagination.total}</div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <select value={String(pageSize)} onChange={(e) => { setPage(1); setPageSize(Number(e.target.value)); }}>
              <option value="10">10 / page</option>
              <option value="20">20 / page</option>
              <option value="50">50 / page</option>
            </select>
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={pagination.page <= 1}>Prev</button>
            <span>Page {pagination.page} / {pagination.total_pages}</span>
            <button onClick={() => setPage((p) => Math.min(p + 1, pagination.total_pages))} disabled={pagination.page >= pagination.total_pages}>Next</button>
          </div>
        </div>
      </section>
    </AppShell>
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
  const clickhouseStatus = status?.clickhouse || {};
  const retroStatus = status?.retro || {};
  const retroOverallKey = retroStatus.overall_health || retroStatus.state_health;
  const retroHealth = retroHealthPresentation(retroOverallKey, retroStatus.state_health_label);
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
              <span style={statusDot(database.ok)}>● {database.ok ? 'OK' : 'Down'}</span>
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
              <span style={statusDot(redisStatus.ok)}>● {redisStatus.ok ? 'OK' : 'Down'}</span>
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

          {/* ClickHouse card moved below as full-width section */}
        </div>

        <div style={{ marginTop: 20, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>ClickHouse</span>
            <span style={statusDot(clickhouseStatus.ok)}>● {clickhouseStatus.ok ? 'OK' : 'Down'}</span>
          </div>
          <div style={{ padding: 12, background: '#0f172a' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 6, fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Table:</b> {clickhouseStatus.table || 'syslog_logs'}</div>
              <div><b>Version:</b> {clickhouseStatus.version || '-'}</div>
              <div><b>Rows:</b> {clickhouseStatus.rows ?? '-'}</div>
              <div><b>Size:</b> {clickhouseStatus.size_mb !== undefined ? `${clickhouseStatus.size_mb} MB` : '-'}</div>
            </div>
            {clickhouseStatus.note && <div style={{ color: '#94a3b8', marginTop: 8 }}>{clickhouseStatus.note}</div>}
            {clickhouseStatus.error && <div style={{ color: '#f87171', marginTop: 8 }}>{clickhouseStatus.error}</div>}
          </div>
        </div>

        <div style={{ marginTop: 20, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Retro Scan</span>
            <span style={{ ...statusDot(retroOverallKey === 'OK' || retroOverallKey === 'WARNING'), color: retroHealth.color }}>
              ● Overall: {retroStatus.state_health_label || retroHealth.label}
            </span>
          </div>
          <div style={{ padding: 12, background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 10 }}>
              Retro worker (hourly), cursor coverage, and PG→CH sync are evaluated separately.
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 6, fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div title={RETRO_STATUS_TOOLTIPS.lastRun}><b>Last Retro Run:</b> {retroStatus.last_run_at_iso ? formatUserDateTime(retroStatus.last_run_at_iso) : (retroStatus.last_run_at || '-')}</div>
              <div title={RETRO_STATUS_TOOLTIPS.lastRunAge}><b>Last Run Age:</b> {formatDurationSeconds(retroStatus.last_run_age_seconds)}</div>
              <div title={RETRO_STATUS_TOOLTIPS.processedCursor}>
                <b>Processed IOC Cursor:</b> {retroStatus.cursor_ts_iso ? formatUserDateTime(retroStatus.cursor_ts_iso) : (retroStatus.cursor_ts || '-')}
              </div>
              <div title={RETRO_STATUS_TOOLTIPS.chMaxLookup}>
                <b>CH Lookup Max IOC TS:</b> {retroStatus.ch_max_lookup_updated_at_iso ? formatUserDateTime(retroStatus.ch_max_lookup_updated_at_iso) : (retroStatus.ch_max_lookup_updated_at || '-')}
              </div>
              <div title={RETRO_STATUS_TOOLTIPS.retroBacklog}><b>Retro Backlog:</b> {retroStatus.ch_pending_ioc_count ?? '-'} IOC</div>
              <div title={RETRO_STATUS_TOOLTIPS.cursorLag}><b>Retro Cursor Lag:</b> {retroStatus.ch_cursor_lag_seconds != null ? `${retroStatus.ch_cursor_lag_seconds} sec` : '-'}</div>
              <div title={RETRO_STATUS_TOOLTIPS.workerHealth}>
                {retroHealthLine('Retro Worker Health', retroStatus.retro_worker_health, retroStatus.retro_worker_health_label)}
              </div>
              <div title={RETRO_STATUS_TOOLTIPS.cursorHealth}>
                {retroHealthLine('Retro Cursor Health', retroStatus.retro_cursor_health, retroStatus.retro_cursor_health_label)}
              </div>
              <div title={RETRO_STATUS_TOOLTIPS.pgUnsynced}><b>{'PG \u2192 CH Unsynced IOC:'}</b> {retroStatus.pg_unsynced_ioc_count ?? '-'}</div>
              <div title={RETRO_STATUS_TOOLTIPS.pgSyncLag}><b>{'PG \u2192 CH Sync Lag:'}</b> {formatDurationSeconds(retroStatus.pg_to_ch_sync_lag_seconds)}</div>
              <div title={RETRO_STATUS_TOOLTIPS.syncHealth}>
                {retroHealthLine('Correlation Sync Health', retroStatus.correlation_sync_health, retroStatus.correlation_sync_health_label)}
              </div>
              <div title={RETRO_STATUS_TOOLTIPS.overallHealth}>
                {retroHealthLine('Overall', retroOverallKey, retroStatus.state_health_label)}
              </div>
              <div><b>Last Retro Duration:</b> {retroStatus.last_run_duration_ms !== undefined ? `${retroStatus.last_run_duration_ms} ms` : '-'}</div>
              <div><b>Last Chunk Scanned IOC:</b> {retroStatus.last_chunk_scanned_count ?? retroStatus.last_retro_scanned_ioc ?? '-'}</div>
              {Number(retroStatus.chunk_active) === 1 && (
                <div><b>Active Chunk:</b> {retroStatus.retro_chunk_ioc_count ?? 0} IOC ({retroStatus.retro_chunk_rows_processed ?? 0} match rows processed)</div>
              )}
              {retroStatus.correlation_sync && (
                <div><b>Correlation Sync:</b> last_sync_ts {renderTimestamp(retroStatus.correlation_sync.last_sync_ts)} · id {retroStatus.correlation_sync.last_sync_id ?? '-'}</div>
              )}
            </div>
            {retroStatus.error && <div style={{ color: '#f87171', marginTop: 8 }}>{retroStatus.error}</div>}
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
              <div><b>Signal events (24h):</b> {telemetry.signal_events_24h ?? '-'}</div>
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
  { cron: '0 * * * *', label: 'Every hour' }
];

const FEED_METRIC_TOOLTIPS = {
  processed: 'Total records/items processed during the last run.',
  inserted: 'New IOC observables or source evidence inserted during the last run.',
  duplicate: 'Records already known from previous imports.',
  updated: 'Existing records updated during reconciliation. May be 0 if reconciliation is not enabled for this feed.',
  skipped: 'Records skipped because they were unchanged, invalid, filtered, old cursor entries, or not importable.',
  suppressed: 'Records skipped because an active suppression policy matched them.',
  failed: 'Records that failed to parse or import.'
};

function feedMetricsHintPresentation(hint) {
  const map = {
    legacy_metrics: { label: 'Legacy metrics', color: '#fcd34d', title: 'Import breakdown unavailable until the feed runs again with granular metrics.' },
    no_delta: { label: 'No delta', color: '#94a3b8', title: 'Last run processed records but did not insert or update IOCs — often normal when feed content is unchanged.' },
    high_skipped: { label: 'High skipped', color: '#fdba74', title: 'Most records were skipped (unchanged, filtered, or already known). Review if unexpected.' },
    high_failed: { label: 'High failed', color: '#fca5a5', title: 'A significant share of records failed to import.' }
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
    disabled: { label: 'Disabled', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' },
    suppressed: { label: 'Suppressed', color: '#93c5fd', bg: 'rgba(30,58,138,0.25)', border: '#1d4ed8' },
    false_positive: { label: 'False Positive', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534' },
    fp: { label: 'False Positive', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534' }
  };
  const hit = map[s] || map.active;
  return (
    <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: hit.color, background: hit.bg, border: `1px solid ${hit.border}`, whiteSpace: 'nowrap' }}>
      {hit.label}
    </span>
  );
}

function defaultExpirationDraft(policy) {
  const p = policy || {};
  return {
    enabled: Boolean(p.enabled),
    expiration_mode: p.expiration_mode || 'never',
    ttl_days: p.ttl_days ?? '',
    grace_days: p.grace_days ?? ''
  };
}

function FeedHealthModal({ title, children, onClose, actions }) {
  return (
    <ModalOverlay onClose={onClose}>
      <h3 style={{ margin: '0 0 10px', color: '#f1f5f9', fontSize: 18 }}>{title}</h3>
      {children}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 18 }}>
        {actions}
      </div>
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

const AUTH_KEY_FEED_CONFIG = {
  [URLHAUS_FEED_KEY]: {
    title: 'URLHaus Auth-Key',
    placeholder: 'Enter URLHaus Auth-Key',
    helpText: 'Required for URLHaus file exports. Do not include it in the URL.',
    saveSuccess: 'URLHaus Auth-Key saved.',
    saveError: 'Failed to save URLHaus Auth-Key'
  },
  [MALWAREBAZAAR_FEED_KEY]: {
    title: 'MalwareBazaar Auth-Key',
    placeholder: 'Enter MalwareBazaar Auth-Key',
    helpText: 'Required for MalwareBazaar file exports. Do not include it in the URL.',
    saveSuccess: 'MalwareBazaar Auth-Key saved.',
    saveError: 'Failed to save MalwareBazaar Auth-Key'
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
  draftAuthKey,
  onAuthKeyChange,
  maskedAuthKey,
  authKeyConfigured,
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
  canWrite
}) {
  const isActive = feed?.active !== false;
  const state = feedStatePresentation(isActive);
  const currentCron = feed?.schedule || '0 * * * *';
  const scheduleUnchanged = draftCron === currentCron;
  const exp = draftExpiration || defaultExpirationDraft();
  const showTtl = exp.enabled && ['fixed_ttl', 'last_seen_ttl'].includes(exp.expiration_mode);
  const showGrace = exp.enabled && exp.expiration_mode === 'missing_from_feed_ttl';

  return (
    <FeedHealthModal
      title="Feed settings"
      onClose={(savingSchedule || savingExpiration || savingConfidence || savingCredentials) ? undefined : onClose}
      actions={<button type="button" onClick={onClose} disabled={savingSchedule || savingExpiration || savingConfidence || savingCredentials}>Close</button>}
    >
      <div style={{ display: 'grid', gap: 16, fontSize: 13 }}>
        <div>
          <div style={{ color: '#94a3b8', marginBottom: 4 }}>Feed</div>
          <strong style={{ color: '#e2e8f0' }}>{feed?.name || feed?.key}</strong>
        </div>

        <div>
          <div style={{ color: '#94a3b8', marginBottom: 6 }}>Current state</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: state.color, background: state.bg, border: `1px solid ${state.border}` }}>
              {state.label}
            </span>
            {canWrite ? (
              <button
                type="button"
                onClick={onRequestActiveChange}
                style={{ fontSize: 12, padding: '4px 10px', borderRadius: 6, border: '1px solid #475569', background: 'transparent', color: isActive ? '#fca5a5' : '#86efac', cursor: 'pointer' }}
              >
                {isActive ? 'Disable feed' : 'Enable feed'}
              </button>
            ) : null}
          </div>
        </div>

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
            {canWrite ? (
              <button type="button" onClick={onSaveSchedule} disabled={savingSchedule || scheduleUnchanged}>
                {savingSchedule ? 'Saving...' : 'Save Schedule'}
              </button>
            ) : null}
          </div>
        </div>

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
              {canWrite ? (
                <button type="button" onClick={onSaveCredentials} disabled={savingCredentials || !draftAuthKey}>
                  {savingCredentials ? 'Saving...' : 'Save Auth Key'}
                </button>
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
            Expired IOCs are kept in database but excluded from publish/export and syslog correlation.
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
                <li>It will not be used in syslog correlation</li>
                <li>It will remain in database with status=expired</li>
              </ul>
            </div>
            {canWrite ? (
              <button type="button" onClick={onSaveExpiration} disabled={savingExpiration}>
                {savingExpiration ? 'Saving...' : 'Save Expiration Policy'}
              </button>
            ) : null}
          </div>
        </div>
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
  if (state === 'disabled') return { label: 'Disabled', color: '#94a3b8', bg: 'rgba(100,116,139,0.18)', border: '#475569' };
  if (state === 'failed') return { label: 'Failed', color: '#fca5a5', bg: 'rgba(127,29,29,0.25)', border: '#7f1d1d' };
  if (state === 'warning') return { label: 'Warning', color: '#fcd34d', bg: 'rgba(120,53,15,0.25)', border: '#854d0e' };
  if (state === 'success') return { label: 'Success', color: '#86efac', bg: 'rgba(20,83,45,0.25)', border: '#166534' };
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
    '0 * * * *': 'Every hour'
  };
  return map[String(cron || '').trim()] || String(cron || '-');
}

function truncateFeedError(text, max = 48) {
  const raw = String(text || '').trim();
  if (!raw) return '';
  if (raw.length <= max) return raw;
  return `${raw.slice(0, max - 1)}…`;
}

function LastRunMetricsCell({ metrics, hints = [] }) {
  const m = metrics || { available: false, processed: 0 };
  const processed = Number(m.processed || 0);
  const hintList = Array.isArray(hints) ? hints : [];

  if (processed <= 0 && m.available !== false) {
    return <span style={{ color: '#64748b', fontSize: 12 }}>No activity</span>;
  }

  if (m.available === false && processed > 0) {
    return (
      <div style={{ display: 'grid', gap: 4 }}>
        <span style={{ color: '#cbd5e1', fontSize: 12 }} title={FEED_METRIC_TOOLTIPS.processed}>Processed {processed}</span>
        <span style={{ color: '#fcd34d', fontSize: 11, lineHeight: 1.35 }}>
          Metrics breakdown unavailable until next run.
        </span>
      </div>
    );
  }

  const parts = [
    { key: 'processed', label: 'Processed', value: processed, always: true },
    { key: 'inserted', label: 'New', value: m.inserted, tone: '#86efac' },
    { key: 'duplicate', label: 'Duplicate', value: m.duplicate, tone: '#fcd34d' },
    { key: 'updated', label: 'Updated', value: m.updated },
    { key: 'skipped', label: 'Skipped', value: m.skipped },
    { key: 'suppressed', label: 'Suppressed', value: m.suppressed, tone: '#fb923c', hideZero: true },
    { key: 'failed', label: 'Failed', value: m.failed, tone: '#fca5a5', hideZero: true }
  ];

  const visible = parts.filter((p) => p.always || (Number(p.value || 0) > 0) || (p.key === 'updated' && m.available));
  const breakdownSum = ['inserted', 'duplicate', 'updated', 'skipped', 'suppressed', 'failed']
    .reduce((acc, key) => acc + Number(m[key] || 0), 0);
  const missingBreakdown = m.available && processed > 0 && breakdownSum === 0;

  return (
    <div style={{ display: 'grid', gap: 4 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
        {visible.map((p) => {
          const n = p.value === null || p.value === undefined ? 'N/A' : Number(p.value || 0);
          if (p.hideZero && n === 0) return null;
          const isAlert = p.key === 'failed' && Number(n) > 0;
          const isSupp = p.key === 'suppressed' && Number(n) > 0;
          return (
            <span
              key={p.key}
              title={FEED_METRIC_TOOLTIPS[p.key] || undefined}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                padding: '2px 8px',
                borderRadius: 999,
                fontSize: 11,
                fontWeight: 600,
                color: isAlert ? '#fecaca' : isSupp ? '#fdba74' : (p.tone || '#cbd5e1'),
                background: isAlert ? 'rgba(127,29,29,0.35)' : isSupp ? 'rgba(124,45,18,0.35)' : 'rgba(15,23,42,0.65)',
                border: `1px solid ${isAlert ? '#991b1b' : isSupp ? '#9a3412' : '#334155'}`
              }}
            >
              {p.label} {n}
            </span>
          );
        })}
        {hintList.map((hint) => {
          const h = feedMetricsHintPresentation(hint);
          return (
            <span
              key={hint}
              title={h.title}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                padding: '2px 8px',
                borderRadius: 999,
                fontSize: 10,
                fontWeight: 700,
                color: h.color,
                background: 'rgba(15,23,42,0.65)',
                border: `1px solid ${h.color}`
              }}
            >
              {h.label}
            </span>
          );
        })}
      </div>
      {missingBreakdown ? (
        <span style={{ color: '#fcd34d', fontSize: 11, lineHeight: 1.35 }}>
          Processed records are available, but import result breakdown is missing. Check importer metrics.
        </span>
      ) : null}
    </div>
  );
}

function IocEnvironmentImpactPanel({ impact }) {
  const imp = impact || {};
  const observed = imp.observed_in_environment === true || Number(imp.incident_count || 0) > 0;

  if (!observed) {
    return (
      <div style={{ marginBottom: 14, border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 6 }}>Environment Impact</div>
        <div style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.5 }}>
          This IOC has not been observed in environment telemetry yet.
        </div>
      </div>
    );
  }

  const cards = [
    { label: 'Incidents', value: imp.incident_count ?? 0 },
    { label: 'Detection Events', value: imp.detection_event_count ?? 0 },
    { label: 'Observed Hosts', value: imp.observed_host_count ?? 0 },
    { label: 'Evidence Logs', value: imp.evidence_log_count ?? 0 },
    { label: 'First Seen in Environment', value: formatUserDateTime(imp.first_seen_in_env), text: true },
    { label: 'Last Seen in Environment', value: formatUserDateTime(imp.last_seen_in_env), text: true },
    { label: 'Allowed / Blocked / Unknown', value: `${imp.allowed_count ?? 0} / ${imp.blocked_count ?? 0} / ${imp.unknown_action_count ?? 0}`, text: true },
    { label: 'Max Incident Risk', value: imp.max_incident_risk_score != null ? Number(imp.max_incident_risk_score).toFixed(2) : 'N/A', text: true },
    { label: 'Avg Incident Risk', value: imp.avg_incident_risk_score != null ? Number(imp.avg_incident_risk_score).toFixed(2) : 'N/A', text: true },
    { label: 'Open / Closed Incidents', value: `${imp.related_open_incidents ?? 0} / ${imp.related_closed_incidents ?? 0}`, text: true }
  ];

  const sources = Array.isArray(imp.source_breakdown) ? imp.source_breakdown : [];

  return (
    <div style={{ marginBottom: 14, border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
      <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>Environment Impact</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 10, marginBottom: sources.length ? 12 : 0 }}>
        {cards.map((c) => (
          <div key={c.label} style={{ border: '1px solid #1e293b', borderRadius: 8, padding: '8px 10px', background: '#111827' }}>
            <div style={{ fontSize: 11, color: '#94a3b8' }}>{c.label}</div>
            <div style={{ fontSize: c.text ? 13 : 20, fontWeight: 700, color: '#e2e8f0', marginTop: 4 }}>{c.value}</div>
          </div>
        ))}
      </div>
      {sources.length ? (
        <div>
          <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>Source Breakdown</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {sources.map((s) => (
              <span key={s.source_type} style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 600, color: '#cbd5e1', background: 'rgba(15,23,42,0.65)', border: '1px solid #334155' }}>
                {s.source_type} {s.count}
              </span>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function RiskExplanationPanel({ explanation, item }) {
  const ex = explanation || {};
  const components = Array.isArray(ex.components) ? ex.components : [];
  const notes = Array.isArray(ex.notes) ? ex.notes : [];

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a', display: 'grid', gap: 12 }}>
      <div>
        <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>Risk Explanation</div>
        <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.5 }}>
          Risk score reflects environment impact, evidence type, action outcome, analyst verdict, and IOC type.
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10 }}>
        <div style={{ border: '1px solid #1e293b', borderRadius: 8, padding: '8px 10px' }}>
          <div style={{ fontSize: 11, color: '#94a3b8' }}>Base Risk</div>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{ex.base_score != null ? Number(ex.base_score).toFixed(2) : '—'}</div>
        </div>
        <div style={{ border: '1px solid #1e293b', borderRadius: 8, padding: '8px 10px' }}>
          <div style={{ fontSize: 11, color: '#94a3b8' }}>Final Risk</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#93c5fd' }}>{ex.final_score != null ? Number(ex.final_score).toFixed(2) : Number(item?.risk_score || 0).toFixed(2)}</div>
        </div>
        {ex.ai_delta != null ? (
          <div style={{ border: '1px solid #1e293b', borderRadius: 8, padding: '8px 10px' }}>
            <div style={{ fontSize: 11, color: '#94a3b8' }}>AI Adjustment</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: Number(ex.ai_delta) > 0 ? '#fca5a5' : Number(ex.ai_delta) < 0 ? '#86efac' : '#cbd5e1' }}>
              {Number(ex.ai_delta) > 0 ? '+' : ''}{Number(ex.ai_delta).toFixed(2)}
            </div>
          </div>
        ) : null}
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {(ex.evidence_tier_label || ex.evidence_tier) ? (
          <span style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: '#cbd5e1', border: '1px solid #475569' }}>Evidence: {ex.evidence_tier_label || ex.evidence_tier}</span>
        ) : null}
        {(ex.action_outcome_label || ex.action_outcome) ? (
          <span style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: '#cbd5e1', border: '1px solid #475569' }}>Outcome: {ex.action_outcome_label || ex.action_outcome}</span>
        ) : null}
        {ex.verdict_effect ? (
          <span style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: '#fcd34d', border: '1px solid #854d0e' }}>{ex.verdict_effect}</span>
        ) : null}
      </div>

      {components.length ? (
        <div style={{ borderTop: '1px solid #1e293b', paddingTop: 10 }}>
          <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 8, fontWeight: 700 }}>Score Components</div>
          <div style={{ display: 'grid', gap: 8 }}>
            {components.map((c) => (
              <div key={c.name} style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, 160px) 80px 1fr', gap: 10, fontSize: 12, alignItems: 'start' }}>
                <strong style={{ color: '#e2e8f0' }}>{c.name}</strong>
                <span style={{ color: '#93c5fd' }}>{c.contribution != null ? `+${Number(c.contribution).toFixed(2)}` : '—'}</span>
                <span style={{ color: '#94a3b8', lineHeight: 1.45 }}>{c.explanation}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {ex.ai_reason ? (
        <div style={{ fontSize: 12, color: '#cbd5e1', lineHeight: 1.45 }}>
          <span style={{ color: '#94a3b8' }}>AI reason: </span>{ex.ai_reason}
        </div>
      ) : null}

      {notes.length ? (
        <ul style={{ margin: 0, paddingLeft: 18, color: '#94a3b8', fontSize: 12, lineHeight: 1.5 }}>
          {notes.map((n) => <li key={n}>{n}</li>)}
        </ul>
      ) : null}
    </div>
  );
}

function IntegrationsPage({ title = 'Feeds', onlyKeys = null, hideKeys = null, showRunAll = true } = {}) {
  const { canWrite } = useSession();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [integrations, setIntegrations] = useState([]);
  const [healthSummary, setHealthSummary] = useState(null);
  const [runningNowAll, setRunningNowAll] = useState(false);
  const [runningKeys, setRunningKeys] = useState({});
  const [togglingKeys, setTogglingKeys] = useState({});
  const [settingsModal, setSettingsModal] = useState(null);
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
  const [settingsDraftConfidence, setSettingsDraftConfidence] = useState('');
  const [settingsConfidenceError, setSettingsConfidenceError] = useState('');
  const [settingsConfidenceSuccess, setSettingsConfidenceSuccess] = useState('');
  const [savingConfidenceKey, setSavingConfidenceKey] = useState('');

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

  function syncSettingsModal(list) {
    const key = settingsModal?.key;
    const feed = key ? (list || []).find((i) => i.key === key) : null;
    setSettingsModal((prev) => {
      if (!prev) return prev;
      const f = (list || []).find((i) => i.key === prev.key);
      if (!f) return prev;
      return {
        key: f.key,
        name: f.name,
        schedule: f.schedule || '0 * * * *',
        active: f.active !== false,
        expiration_policy: f.expiration_policy,
        expiration_summary: f.expiration_summary,
        default_confidence: f.default_confidence
      };
    });
    if (feed?.expiration_policy) {
      setSettingsDraftExpiration(defaultExpirationDraft(feed.expiration_policy));
    }
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

  async function runNowOne(key, name) {
    if (!canWrite) return;
    const ok = window.confirm(`Queue run for ${name || key} now?`);
    if (!ok || runningKeys[key]) return;
    setRunningKeys((prev) => ({ ...prev, [key]: true }));
    try {
      await api.post(`/integrations/${encodeURIComponent(key)}/run-now`);
      await load();
      alert(`${key} queued`);
    } catch (err) {
      alert(apiErrorMessage(err, `Failed to queue ${key}`));
    } finally {
      setRunningKeys((prev) => ({ ...prev, [key]: false }));
    }
  }

  async function openSettingsModal(feed) {
    if (!canWrite) return;
    setSettingsError('');
    setSettingsExpirationError('');
    setSettingsExpirationSuccess('');
    setSettingsExpirationRefreshWarn('');
    setSettingsCredentialsError('');
    setSettingsCredentialsSuccess('');
    setSettingsConfidenceError('');
    setSettingsConfidenceSuccess('');
    setSettingsDraftAuthKey('');
    setSettingsDraftCron(feed.schedule || '0 * * * *');
    setSettingsDraftConfidence(String(feed.default_confidence || '').trim().toLowerCase());
    setSettingsDraftExpiration(defaultExpirationDraft(feed.expiration_policy));
    const credSummary = feed.credentials_summary || null;
    setSettingsMaskedAuthKey(credSummary?.masked_auth_key || null);
    setSettingsAuthKeyConfigured(Boolean(credSummary?.auth_key_configured));
    setSettingsModal({
      key: feed.key,
      name: feed.name,
      schedule: feed.schedule || '0 * * * *',
      active: feed.active !== false
    });
    try {
      const { data } = await api.get(`/threat-feeds/${encodeURIComponent(feed.key)}/expiration-policy`);
      setSettingsDraftExpiration(defaultExpirationDraft(data?.policy));
    } catch {
      setSettingsDraftExpiration(defaultExpirationDraft(feed.expiration_policy));
    }
    if (feedSupportsAuthKey(feed.key)) {
      try {
        const { data } = await api.get(`/integrations/${encodeURIComponent(feed.key)}/credentials`);
        setSettingsMaskedAuthKey(data?.masked_auth_key || null);
        setSettingsAuthKeyConfigured(Boolean(data?.auth_key_configured));
      } catch {
        // keep list summary if credentials endpoint unavailable
      }
    }
  }

  function closeSettingsModal() {
    if (savingScheduleKey || savingCredentialsKey || savingConfidenceKey) return;
    setSettingsModal(null);
    setSettingsError('');
  }

  async function saveSettingsConfidence() {
    if (!canWrite || !settingsModal || !settingsDraftConfidence) return;
    const { key } = settingsModal;
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
      syncSettingsModal(list);
    } catch (err) {
      setSettingsConfidenceError(apiErrorMessage(err, 'Failed to update default confidence'));
    } finally {
      setSavingConfidenceKey('');
    }
  }

  function requestActiveChange() {
    if (!canWrite || !settingsModal) return;
    setActiveConfirmError('');
    setActiveConfirm({
      key: settingsModal.key,
      name: settingsModal.name,
      mode: settingsModal.active ? 'disable' : 'enable'
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
      syncSettingsModal(list);
    } catch (err) {
      setActiveConfirmError(apiErrorMessage(err, 'Failed to update feed active state'));
    } finally {
      setTogglingKeys((prev) => ({ ...prev, [key]: false }));
    }
  }

  async function saveSettingsCredentials() {
    if (!canWrite || !settingsModal || !feedSupportsAuthKey(settingsModal.key)) return;
    const { key } = settingsModal;
    if (savingCredentialsKey || !settingsDraftAuthKey.trim()) return;

    setSettingsCredentialsError('');
    setSettingsCredentialsSuccess('');
    setSavingCredentialsKey(key);
    try {
      const { data } = await api.put(`/integrations/${encodeURIComponent(key)}/credentials`, {
        auth_key: settingsDraftAuthKey.trim()
      });
      setSettingsMaskedAuthKey(data?.masked_auth_key || null);
      setSettingsAuthKeyConfigured(Boolean(data?.auth_key_configured));
      setSettingsDraftAuthKey('');
      setSettingsCredentialsSuccess(AUTH_KEY_FEED_CONFIG[key]?.saveSuccess || 'Auth-Key saved.');
      await load();
    } catch (err) {
      setSettingsCredentialsError(apiErrorMessage(err, AUTH_KEY_FEED_CONFIG[key]?.saveError || 'Failed to save Auth-Key'));
    } finally {
      setSavingCredentialsKey('');
    }
  }

  async function saveSettingsSchedule() {
    if (!canWrite || !settingsModal) return;
    const { key } = settingsModal;
    if (savingScheduleKey) return;

    setSettingsError('');
    setSavingScheduleKey(key);
    try {
      await api.put(`/integrations/${encodeURIComponent(key)}/schedule`, { schedule_cron: settingsDraftCron });
      const list = await load();
      syncSettingsModal(list);
      setSettingsDraftCron(settingsDraftCron);
    } catch (err) {
      setSettingsError(apiErrorMessage(err, 'Failed to update schedule'));
    } finally {
      setSavingScheduleKey('');
    }
  }

  async function saveSettingsExpiration() {
    if (!canWrite || !settingsModal) return;
    const { key } = settingsModal;
    if (savingExpirationKey) return;
    setSettingsExpirationError('');
    setSettingsExpirationSuccess('');
    setSettingsExpirationRefreshWarn('');
    setSavingExpirationKey(key);

    let patchData;
    try {
      const { data } = await api.patch(
        `/threat-feeds/${encodeURIComponent(key)}/expiration-policy`,
        buildExpirationPatchPayload(settingsDraftExpiration)
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
      setSettingsDraftExpiration(defaultExpirationDraft(policy));
      setIntegrations((prev) => prev.map((i) => (
        i.key === key
          ? { ...i, expiration_policy: policy, expiration_summary: summary || i.expiration_summary }
          : i
      )));
    }

    setSettingsExpirationSuccess('Expiration policy updated');

    try {
      const list = await load();
      syncSettingsModal(list);
    } catch {
      setSettingsExpirationRefreshWarn('Policy saved, but refreshing the feed list failed. Values in this dialog are up to date.');
    }
  }

  const visibleIntegrations = integrations.filter((i) => {
    if (Array.isArray(onlyKeys) && onlyKeys.length) return onlyKeys.includes(i.key);
    if (Array.isArray(hideKeys) && hideKeys.length) return !hideKeys.includes(i.key);
    return true;
  });

  const metricFromFeed = (feed, key) => {
    const m = feed?.last_run_metrics;
    if (m && m.available === false && key !== 'processed') return 0;
    if (m && m[key] != null) return Number(m[key] || 0);
    const flatKey = {
      processed: 'last_records_processed',
      inserted: 'last_records_inserted',
      updated: 'last_records_updated',
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
      return String(i.health_state || '').toLowerCase() === 'failed' || Number(i.consecutive_failures || 0) > 0;
    }).length,
    last_run_new_total: visibleIntegrations.reduce((acc, i) => acc + metricFromFeed(i, 'inserted'), 0),
    last_run_inserted_total: visibleIntegrations.reduce((acc, i) => acc + metricFromFeed(i, 'inserted'), 0),
    last_run_processed_total: visibleIntegrations.reduce((acc, i) => acc + metricFromFeed(i, 'processed'), 0)
  };

  const showHealthDashboard = showRunAll && !onlyKeys;

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ marginTop: 0, marginBottom: 4, color: '#f1f5f9' }}>{title}</h2>
            {showHealthDashboard ? (
              <div style={{ color: '#94a3b8', fontSize: 13 }}>Feed health and last import results at a glance</div>
            ) : null}
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {showRunAll ? <button onClick={runNowAll} disabled={runningNowAll || !canWrite}>{runningNowAll ? 'Queueing...' : 'Run now (all)'}</button> : null}
            {showHealthDashboard ? <Link to="/threat-intelligence/runs" style={{ padding: '6px 10px', borderRadius: 8, border: '1px solid #475569', color: '#cbd5e1', textDecoration: 'none', fontSize: 13 }}>View recent runs</Link> : null}
            <button onClick={() => load().catch(() => {})}>Refresh</button>
          </div>
        </div>

        {loadError ? <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid #7f1d1d', color: '#fca5a5', background: 'rgba(127,29,29,0.2)', fontSize: 13 }}>{loadError}</div> : null}

        {showHealthDashboard ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10, marginTop: 14, marginBottom: 14 }}>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>Total Feeds</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{summary.total_feeds}</div>
            </div>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>Enabled Feeds</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#86efac' }}>{summary.enabled_feeds ?? summary.active_feeds}</div>
            </div>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>Failing Feeds</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: summary.failing_feeds > 0 ? '#fca5a5' : '#e2e8f0' }}>{summary.failing_feeds}</div>
            </div>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>Last Run Processed</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{summary.last_run_processed_total}</div>
            </div>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>Last Run New</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#93c5fd' }}>{summary.last_run_new_total ?? summary.last_run_inserted_total}</div>
            </div>
          </div>
        ) : null}

        {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
          <div style={{ overflowX: 'auto' }}>
            <table className="ioc-table" width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', background: '#0f172a', tableLayout: 'fixed', fontSize: 12, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace", minWidth: 980, width: '100%' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', background: '#1f2937', color: '#cbd5e1' }}>
                  <th style={{ width: 88 }}>State</th>
                  <th style={{ width: '16%' }}>Feed</th>
                  <th style={{ width: 88 }}>Health</th>
                  <th style={{ width: 110 }}>Schedule</th>
                  <th style={{ width: 96 }}>Confidence</th>
                  <th style={{ width: 120 }}>Expiration</th>
                  <th style={{ width: 130 }}>Last Success</th>
                  <th style={{ width: '34%' }}>Last Run Metrics</th>
                  <th style={{ width: 120 }}>Last Error</th>
                  <th style={{ width: 120 }}>Next Run</th>
                  <th style={{ width: 100 }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {visibleIntegrations.length ? visibleIntegrations.map((i) => {
                  const isActive = i.active !== false;
                  const lastErr = String(i.last_error || '').trim();
                  const health = feedHealthPresentation(i);
                  const confidence = feedConfidencePresentation(i.default_confidence);
                  const state = feedStatePresentation(isActive);
                  return (
                    <tr key={i.key} style={{ borderBottom: '1px solid #1e293b', opacity: isActive ? 1 : 0.78 }}>
                      <td>
                        <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: state.color, background: state.bg, border: `1px solid ${state.border}`, whiteSpace: 'nowrap' }}>
                          {state.label}
                        </span>
                      </td>
                      <td style={{ color: '#e2e8f0', fontWeight: 600, overflowWrap: 'anywhere' }}>{i.name}</td>
                      <td>
                        <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: health.color, background: health.bg, border: `1px solid ${health.border}` }}>
                          {health.label}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontSize: 11, color: isActive ? '#cbd5e1' : '#64748b', fontWeight: 600, whiteSpace: 'nowrap' }}>
                          {formatFeedScheduleLabel(i.schedule)}
                        </span>
                      </td>
                      <td>
                        <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: confidence.color, background: confidence.bg, border: `1px solid ${confidence.border}`, whiteSpace: 'nowrap' }}>
                          {confidence.label}
                        </span>
                      </td>
                      <td style={{ fontSize: 11, color: '#cbd5e1', whiteSpace: 'nowrap' }}>{i.expiration_summary || 'Never'}</td>
                      <td style={{ whiteSpace: 'nowrap', color: '#94a3b8', fontSize: 11 }}>{formatUserDateTime(i.last_success_at || (String(i.last_status || i.status).toLowerCase() === 'success' ? i.last_finished_at : null))}</td>
                      <td><LastRunMetricsCell metrics={i.last_run_metrics} hints={i.metrics_hints} /></td>
                      <td style={{ maxWidth: 120, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: lastErr ? '#fca5a5' : '#64748b', fontSize: 11 }} title={lastErr || undefined}>{lastErr ? truncateFeedError(lastErr) : '-'}</td>
                      <td style={{ whiteSpace: 'nowrap', color: '#94a3b8', fontSize: 11 }}>{isActive ? formatUserDateTime(i.next_run_at) : '-'}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-start' }}>
                          <button type="button" onClick={() => runNowOne(i.key, i.name)} disabled={Boolean(runningKeys[i.key]) || !canWrite || !isActive} style={{ fontSize: 11, padding: '4px 8px' }} title={!isActive ? 'Enable the feed before running manually.' : undefined}>
                            {runningKeys[i.key] ? 'Queueing...' : 'Run now'}
                          </button>
                          {canWrite ? (
                            <button type="button" onClick={() => openSettingsModal(i)} style={{ fontSize: 11, padding: '4px 8px', borderRadius: 6, border: '1px solid #475569', background: 'transparent', color: '#93c5fd', cursor: 'pointer' }}>
                              Edit
                            </button>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  );
                }) : (
                  <tr><td colSpan={11} style={{ color: '#94a3b8', padding: 12 }}>No feeds found.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {settingsModal ? (
        <FeedSettingsModal
          feed={settingsModal}
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
          draftAuthKey={settingsDraftAuthKey}
          onAuthKeyChange={setSettingsDraftAuthKey}
          maskedAuthKey={settingsMaskedAuthKey}
          authKeyConfigured={settingsAuthKeyConfigured}
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
    </AppShell>
  );
}


function IntegrationsQueueStatusPage() {
  const { isAdmin } = useSession();
  const [loading, setLoading] = useState(true);
  const [queue, setQueue] = useState({ counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [], pagination: { page: 1, page_size: 25, total: 0, total_pages: 1 } });
  const [tableWidths, setTableWidths] = useState({ id: 130, integration: 180, name: 140, state: 100, queued: 170, started: 170, reason: 320 });
  const [resizeState, setResizeState] = useState(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [search, setSearch] = useState('');
  const [windowValue, setWindowValue] = useState('24h');
  const [recoverPreview, setRecoverPreview] = useState(null);
  const [recoverLoading, setRecoverLoading] = useState(false);
  const [recoverError, setRecoverError] = useState('');

  async function load(targetPage = page, targetPageSize = pageSize, targetSearch = search, targetWindow = windowValue) {
    setLoading(true);
    try {
      const { data } = await api.get('/integrations', {
        params: {
          queue_page: targetPage,
          queue_page_size: targetPageSize,
          queue_search: targetSearch || undefined,
          queue_window: targetWindow
        }
      });
      setQueue(data?.queue || { counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [], pagination: { page: 1, page_size: 25, total: 0, total_pages: 1 } });
    } catch {
      setQueue({ counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [], pagination: { page: 1, page_size: targetPageSize, total: 0, total_pages: 1 } });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(page, pageSize, search, windowValue).catch(() => {}); }, [page, pageSize, search, windowValue]);

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
      await load(page, pageSize, search, windowValue);
    } catch (err) {
      setRecoverError(err?.response?.data?.message || 'Failed to recover queue');
    } finally {
      setRecoverLoading(false);
    }
  }

  const qh = queue.queue_health || {};

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
            <button type="button" onClick={() => load(page, pageSize, search, windowValue).catch(() => {})}>Refresh</button>
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
            </div>
            {(qh.warnings || []).length ? (
              <ul className="queue-health-warnings">
                {qh.warnings.map((w) => <li key={w}>{w}</li>)}
              </ul>
            ) : null}
          </div>
        ) : null}
        {recoverError ? <div className="queue-recover-error" style={{ marginBottom: 8, fontSize: 13 }}>{recoverError}</div> : null}
        {recoverPreview ? (
          <div className="queue-recover-preview" style={{ marginBottom: 12, padding: 12, borderRadius: 8, fontSize: 13 }}>
            <div><b>Dry-run:</b> would reconcile <b>{recoverPreview.reconciled_count || 0}</b> item(s).</div>
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
            style={{ minWidth: 260, ...queuePageInputStyle }}
          />
          <select value={windowValue} onChange={(e) => { setPage(1); setWindowValue(e.target.value); }} style={queuePageInputStyle}>
            <option value="24h">24 hours</option>
            <option value="1d">1 day</option>
            <option value="7d">7 days</option>
          </select>
          <select value={pageSize} onChange={(e) => { setPage(1); setPageSize(Number(e.target.value)); }} style={queuePageInputStyle}>
            <option value={25}>25 rows</option>
            <option value={50}>50 rows</option>
          </select>
        </div>
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
              <col style={{ width: tableWidths.reason }} />
            </colgroup>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', background: '#1f2937', color: '#e2e8f0' }}>
                <th style={{ position: 'relative' }}>Job ID<div onMouseDown={(e) => startResize('id', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Integration<div onMouseDown={(e) => startResize('integration', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Name<div onMouseDown={(e) => startResize('name', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>State<div onMouseDown={(e) => startResize('state', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Queued At<div onMouseDown={(e) => startResize('queued', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Started At<div onMouseDown={(e) => startResize('started', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Reason<div onMouseDown={(e) => startResize('reason', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              </tr>
            </thead>
            <tbody>
              {loading ? <tr><td colSpan={7}>Loading...</td></tr> : (queue.jobs?.length ? queue.jobs.map((j) => (
                <tr key={String(j.id)} style={{ borderBottom: '1px solid #334155' }}>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#e2e8f0' }}>{j.id}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#e2e8f0' }}>{j.integration_name || j.integration_key || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#e2e8f0' }}>{j.name}</td>
                  <td style={{ color: queueJobStateColor(j.state === 'fail' ? 'failed' : j.state), fontWeight: 700, textTransform: 'capitalize' }}>{j.state === 'fail' ? 'failed' : (j.state || '-')}{j.possibly_stuck ? ' ⚠' : ''}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#cbd5e1' }}>{formatUserDateTime(j.queued_at || j.timestamp)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#cbd5e1' }}>{formatUserDateTime(j.started_at)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: j.possibly_stuck ? '#fcd34d' : '#cbd5e1' }} title={integrationJobReasonLabel(j)}>{integrationJobReasonLabel(j)}</td>
                </tr>
              )) : <tr><td colSpan={7} style={{ color: '#94a3b8' }}>No queued jobs</td></tr>)}
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

function IntegrationsRecentRunsPage() {
  const [loading, setLoading] = useState(true);
  const [recentRuns, setRecentRuns] = useState([]);
  const [tableWidths, setTableWidths] = useState({ id: 130, integration: 180, name: 140, state: 100, queued: 170, started: 170, reason: 320 });
  const [resizeState, setResizeState] = useState(null);

  async function load() {
    setLoading(true);
    try {
      const { data } = await api.get('/integrations');
      setRecentRuns(data?.recent_runs || []);
    } catch {
      setRecentRuns([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load().catch(() => {}); }, []);

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

  const statusColor = (status) => {
    if (status === 'success') return '#166534';
    if (status === 'failed' || status === 'fail') return '#991b1b';
    if (status === 'running') return '#92400e';
    if (status === 'queued') return '#1d4ed8';
    return '#334155';
  };

  const statusLabel = (status) => {
    if (status === 'success') return 'success';
    if (status === 'failed' || status === 'fail') return 'fail';
    if (status === 'running') return 'running';
    if (status === 'queued') return 'queued';
    return 'never';
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
          <h2 style={{ marginTop: 0 }}>Recent Runs</h2>
          <button onClick={() => load().catch(() => {})}>Refresh</button>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
            <colgroup>
              <col style={{ width: tableWidths.id }} />
              <col style={{ width: tableWidths.integration }} />
              <col style={{ width: tableWidths.name }} />
              <col style={{ width: tableWidths.state }} />
              <col style={{ width: tableWidths.queued }} />
              <col style={{ width: tableWidths.started }} />
              <col style={{ width: tableWidths.reason }} />
            </colgroup>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
                <th style={{ position: 'relative' }}>Job ID<div onMouseDown={(e) => startResize('id', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Integration<div onMouseDown={(e) => startResize('integration', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Name<div onMouseDown={(e) => startResize('name', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>State<div onMouseDown={(e) => startResize('state', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Queued At<div onMouseDown={(e) => startResize('queued', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Started At<div onMouseDown={(e) => startResize('started', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Reason<div onMouseDown={(e) => startResize('reason', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              </tr>
            </thead>
            <tbody>
              {loading ? <tr><td colSpan={7}>Loading...</td></tr> : (recentRuns.length ? recentRuns.map((r) => (
                <tr key={String(r.job_id || r.id)} style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.job_id || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.integration_name || r.integration_key || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.name || r.job_type || '-'}</td>
                  <td style={{ color: statusColor(r.state || r.status), fontWeight: 700, textTransform: 'capitalize' }}>{statusLabel(r.state || r.status)}{r.possibly_stuck ? ' ⚠' : ''}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(r.queued_at || r.timestamp || r.started_at)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(r.started_at)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: r.possibly_stuck ? '#b45309' : undefined }} title={integrationJobReasonLabel(r)}>{integrationJobReasonLabel(r)}</td>
                </tr>
              )) : <tr><td colSpan={7} style={{ color: '#64748b' }}>No runs yet</td></tr>)}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}

const FEED_WINDOW_OPTIONS = [
  { value: '1d', label: 'Last 1 day' },
  { value: '3d', label: 'Last 3 days' },
  { value: '7d', label: 'Last 1 week' },
  { value: 'all', label: 'All' }
];

const FEED_VERDICT_FILTER_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'malicious', label: 'Malicious' },
  { value: 'suspicious', label: 'Suspicious' }
];

function verdictFilterFromFeed(feed) {
  const arr = Array.isArray(feed?.verdict_filter) ? feed.verdict_filter : [];
  if (!arr.length) return ['all'];
  const lower = arr.map((v) => String(v).trim().toLowerCase()).filter(Boolean);
  if (lower.includes('all')) return ['all'];
  const known = lower.filter((v) => v === 'malicious' || v === 'suspicious');
  return known.length ? known : ['all'];
}

function verdictFilterToPayload(selected) {
  const v = Array.isArray(selected) ? selected : [];
  if (!v.length || v.includes('all')) return null;
  return v.filter((x) => x !== 'all');
}

function normalizeVerdictFilterSelection(selected, previous = []) {
  if (!selected.length) return ['all'];
  if (selected.includes('all') && selected.length > 1) {
    if (!previous.includes('all')) return ['all'];
    return selected.filter((x) => x !== 'all');
  }
  if (selected.includes('all')) return ['all'];
  return selected;
}

function FeedVerdictMultiSelect({ ui, value, onChange }) {
  const selected = Array.isArray(value) && value.length ? value : ['all'];
  return (
    <select
      multiple
      size={FEED_VERDICT_FILTER_OPTIONS.length}
      value={selected}
      onChange={(e) => {
        const next = Array.from(e.target.selectedOptions, (o) => o.value);
        onChange(normalizeVerdictFilterSelection(next, selected));
      }}
      style={{ ...ui.select, minHeight: 88 }}
    >
      {FEED_VERDICT_FILTER_OPTIONS.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
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

function feedPullUrl(token) {
  const tok = token || '********';
  return `${window.location.origin}/public/feeds/${encodeURIComponent(tok)}/feed.txt`;
}

function PullUrlExamplesList({ ui, token, iocType, onCopy }) {
  const examples = feedUrlExamples(token, iocType);
  return (
    <ul style={{ margin: 0, paddingLeft: 0, listStyle: 'none', fontSize: 12 }}>
      {examples.map((ex) => (
        <li key={ex.label} style={{ marginBottom: 10, padding: 10, background: '#020617', borderRadius: 8, border: '1px solid #334155' }}>
          <div style={{ color: '#94a3b8', marginBottom: 4, fontSize: 11, fontWeight: 600 }}>{ex.label}</div>
          <code style={{ ...ui.code, marginBottom: token ? 6 : 0 }}>{ex.url}</code>
          {token && onCopy ? (
            <button type="button" style={{ ...ui.btn, fontSize: 11, padding: '4px 10px', marginTop: 6 }} onClick={() => onCopy(ex.url)}>Copy URL</button>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function feedUrlExamples(token, iocType = 'ip') {
  const base = feedPullUrl(token);
  const t = encodeURIComponent(iocType);
  return [
    { label: 'Default URL', url: base },
    { label: 'With limit', url: `${base}?limit=40000` },
    { label: 'With window', url: `${base}?window=7d` },
    { label: 'With ioc_type + window + limit', url: `${base}?ioc_type=${t}&window=7d&limit=40000` }
  ];
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
  const [showFormModal, setShowFormModal] = useState(false);
  const [editing, setEditing] = useState(null);
  const [regenerating, setRegenerating] = useState({});
  const [nextStep, setNextStep] = useState(null);
  const [form, setForm] = useState({
    name: '',
    description: '',
    enabled: true,
    ioc_type: 'ip',
    exclude_false_positive: true,
    exclude_expired: true,
    include_sources: '',
    include_tags: '',
    exclude_tags: '',
    verdict_filter: ['all'],
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

  useEffect(() => { loadFeeds().catch(() => {}); }, []);

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
      include_sources: '',
      include_tags: '',
      exclude_tags: '',
      verdict_filter: ['all'],
      time_window: 'all',
      max_items: '',
      refresh_interval_minutes: 15
    });
    setShowFormModal(true);
  }

  function openEditForm(feed) {
    setEditing(feed);
    setForm({
      name: feed.name || '',
      description: feed.description || '',
      enabled: Boolean(feed.enabled),
      ioc_type: feed.ioc_type || 'ip',
      exclude_false_positive: feed.exclude_false_positive !== false,
      exclude_expired: feed.exclude_expired !== false,
      include_sources: (feed.include_sources || []).join(', '),
      include_tags: (feed.include_tags || []).join(', '),
      exclude_tags: (feed.exclude_tags || []).join(', '),
      verdict_filter: verdictFilterFromFeed(feed),
      time_window: feed.time_window || 'all',
      max_items: feed.max_items ?? '',
      refresh_interval_minutes: feed.refresh_interval_minutes || 15
    });
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
      include_sources: splitCsv(form.include_sources),
      include_tags: splitCsv(form.include_tags),
      exclude_tags: splitCsv(form.exclude_tags),
      verdict_filter: verdictFilterToPayload(form.verdict_filter),
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
        setNextStep(null);
        await loadFeeds();
      } else {
        const { data } = await api.post('/published-feeds', payload);
        const created = data?.feed;
        closeFormModal();
        await loadFeeds();
        if (created?.id) {
          setNextStep({
            message: 'Feed created. Create a Feed Access Key from Administration > API Keys to generate a pull URL.',
            feedId: created.id
          });
        }
      }
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to save feed');
    }
  }

  async function deleteFeed(id) {
    if (!canWrite || !window.confirm('Delete this published feed?')) return;
    try {
      await api.delete(`/published-feeds/${id}`);
      setNextStep(null);
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

        {nextStep ? (
          <div style={ui.banner}>
            {nextStep.message}
            {nextStep.feedId && canWrite ? (
              <Link
                to={`/administration/api-keys?feed_id=${nextStep.feedId}`}
                style={{ ...ui.btnPrimary, marginLeft: 12, padding: '6px 12px', fontSize: 12, display: 'inline-block', textDecoration: 'none' }}
                onClick={() => setNextStep(null)}
              >
                Create API Key
              </Link>
            ) : null}
          </div>
        ) : null}

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
                      {canWrite ? (
                        <Link
                          to={`/administration/api-keys?feed_id=${f.id}`}
                          style={{ ...ui.btn, marginLeft: 6, display: 'inline-block', textDecoration: 'none', fontSize: 12 }}
                        >
                          Create API Key
                        </Link>
                      ) : null}
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
                : 'Create a filtered IOC snapshot feed. Add a Feed Access Key under Administration > API Keys to generate a pull URL.'}
            </p>
            {!editing ? (
              <p style={{ ...ui.modalSub, marginTop: -6 }}>
                Choose the IOC type, filters, default time window, and delivery limits. After creation, generate a Feed Access Key on Administration > API Keys.
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
                  label="Verdict Filter"
                  helper="Default is All (no verdict filter). Hold Ctrl or Cmd to select multiple types."
                  fullWidth
                >
                  <FeedVerdictMultiSelect
                    ui={ui}
                    value={form.verdict_filter}
                    onChange={(next) => setForm((x) => ({ ...x, verdict_filter: next }))}
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
                <FeedFormField ui={ui} label="Sources" helper="Optional. Comma-separated source names.">
                  <input value={form.include_sources} onChange={(e) => setForm((x) => ({ ...x, include_sources: e.target.value }))} style={ui.input} placeholder="source_a, source_b" />
                </FeedFormField>
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

    </AppShell>
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
      if (dateFrom) params.date_from = new Date(dateFrom).toISOString();
      if (dateTo) params.date_to = new Date(dateTo).toISOString();
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
      if (dateFrom) params.date_from = new Date(dateFrom).toISOString();
      if (dateTo) params.date_to = new Date(dateTo).toISOString();
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

function ApiKeysPage() {
  const { canWrite } = useSession();
  const [searchParams] = useSearchParams();
  const preselectedFeedId = searchParams.get('feed_id');
  const ui = PUBLISHED_FEEDS_UI;
  const [loading, setLoading] = useState(true);
  const [keys, setKeys] = useState([]);
  const [feeds, setFeeds] = useState([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [expandedKeyId, setExpandedKeyId] = useState(null);
  const [tokenReveal, setTokenReveal] = useState(null);
  const [form, setForm] = useState({
    name: '',
    key_type: 'feed_access',
    feed_id: '',
    enabled: true
  });
  const didAutoOpenFromQuery = useRef(false);

  async function loadAll() {
    setLoading(true);
    try {
      const [keysRes, feedsRes] = await Promise.all([
        api.get('/api-keys'),
        api.get('/published-feeds')
      ]);
      setKeys(keysRes.data?.api_keys || []);
      setFeeds(feedsRes.data?.feeds || []);
    } catch {
      setKeys([]);
      setFeeds([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAll().catch(() => {}); }, []);

  useEffect(() => {
    if (didAutoOpenFromQuery.current) return;
    if (!preselectedFeedId || !feeds.some((f) => String(f.id) === String(preselectedFeedId))) return;
    setForm((x) => ({ ...x, feed_id: String(preselectedFeedId) }));
    if (canWrite) {
      setShowCreateModal(true);
      didAutoOpenFromQuery.current = true;
    }
  }, [preselectedFeedId, feeds, canWrite]);

  function openCreateModal() {
    const presetFeedId = preselectedFeedId && feeds.some((f) => String(f.id) === String(preselectedFeedId))
      ? String(preselectedFeedId)
      : '';
    setForm({
      name: '',
      key_type: 'feed_access',
      feed_id: feeds.length === 1 ? String(feeds[0].id) : presetFeedId,
      enabled: true
    });
    setShowCreateModal(true);
  }

  function keyTypeLabel(t) {
    return t === 'feed_access' ? 'Feed Access Key' : t;
  }

  function copyText(text) {
    navigator.clipboard?.writeText(text).then(() => alert('Copied')).catch(() => alert(text));
  }

  async function createKey(e) {
    e.preventDefault();
    if (!canWrite) return;
    const feedId = Number(form.feed_id);
    if (!feedId) {
      alert('Select a published feed.');
      return;
    }
    try {
      const { data } = await api.post('/api-keys', {
        name: form.name.trim(),
        key_type: 'feed_access',
        feed_id: feedId,
        enabled: Boolean(form.enabled)
      });
      const feed = feeds.find((f) => f.id === feedId);
      setShowCreateModal(false);
      setTokenReveal({
        title: 'API key created',
        feed_url: data.feed_url,
        token: data.token,
        ioc_type: feed?.ioc_type || data.api_key?.feed_ioc_type
      });
      await loadAll();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to create API key');
    }
  }

  async function rotateKey(keyId) {
    if (!canWrite || !window.confirm('Rotate this key? The old token stops working immediately.')) return;
    try {
      const { data } = await api.post(`/api-keys/${keyId}/rotate`);
      const key = keys.find((k) => k.id === keyId);
      setTokenReveal({
        title: 'API key rotated',
        feed_url: data.feed_url,
        token: data.token,
        ioc_type: key?.feed_ioc_type
      });
      await loadAll();
    } catch {
      alert('Failed to rotate API key');
    }
  }

  async function revokeKey(keyId) {
    if (!canWrite || !window.confirm('Revoke this API key? Pull access stops immediately.')) return;
    try {
      await api.post(`/api-keys/${keyId}/revoke`);
      await loadAll();
    } catch {
      alert('Failed to revoke API key');
    }
  }

  async function toggleEnabled(key) {
    if (!canWrite || key.status === 'revoked') return;
    try {
      await api.patch(`/api-keys/${key.id}`, { enabled: !key.enabled });
      await loadAll();
    } catch {
      alert('Failed to update API key');
    }
  }

  const hasFeeds = feeds.length > 0;

  return (
    <AppShell>
      <section className="published-feeds-page api-keys-page" style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, marginBottom: 8, flexWrap: 'wrap' }}>
          <div>
            <h2 style={ui.pageTitle}>API Keys</h2>
            <p style={ui.pageSub}>
              Manage low-privilege access keys used by internal tools to pull published threat feeds. These keys do not grant access to admin APIs.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button type="button" style={ui.btn} onClick={() => loadAll().catch(() => {})}>Refresh</button>
            {canWrite && hasFeeds ? (
              <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Create API Key</button>
            ) : null}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table published-feeds-table" width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 13, background: 'transparent' }}>
            <thead>
              <tr style={ui.thead}>
                <th style={ui.th}>Name</th>
                <th style={ui.th}>Type</th>
                <th style={ui.th}>Published Feed</th>
                <th style={ui.th}>IOC Type</th>
                <th style={ui.th}>Status</th>
                <th style={ui.th}>Last Used</th>
                <th style={ui.th}>Last IP</th>
                <th style={ui.th}>Created At</th>
                <th style={ui.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr style={ui.tr}><td colSpan={9} style={ui.td}>Loading...</td></tr>
              ) : keys.length ? keys.map((k) => (
                <React.Fragment key={k.id}>
                  <tr style={ui.tr}>
                    <td style={ui.td}>{k.name}</td>
                    <td style={ui.td}>{keyTypeLabel(k.key_type)}</td>
                    <td style={ui.td}>{k.feed_name || '—'}</td>
                    <td style={ui.td}>{k.feed_ioc_type || '—'}</td>
                    <td style={ui.td}>{k.status}</td>
                    <td style={ui.td}>{formatUserDateTime(k.last_used_at)}</td>
                    <td style={ui.td}>{k.last_used_ip || '—'}</td>
                    <td style={ui.td}>{formatUserDateTime(k.created_at)}</td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>
                      <button type="button" style={ui.btn} onClick={() => setExpandedKeyId((prev) => (prev === k.id ? null : k.id))}>
                        {expandedKeyId === k.id ? 'Hide URLs' : 'URL examples'}
                      </button>
                      {canWrite && k.status !== 'revoked' ? (
                        <>
                          <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => rotateKey(k.id)}>Rotate</button>
                          <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => revokeKey(k.id)}>Revoke</button>
                          <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => toggleEnabled(k)}>
                            {k.enabled ? 'Disable' : 'Enable'}
                          </button>
                        </>
                      ) : null}
                    </td>
                  </tr>
                  {expandedKeyId === k.id ? (
                    <tr>
                      <td colSpan={9} style={ui.expandCell}>
                        <strong style={{ color: '#cbd5e1', fontSize: 13 }}>Pull URL examples</strong>
                        <p style={{ ...ui.helper, marginTop: 4, marginBottom: 8 }}>
                          Token is masked. Copy the full URL only right after create or rotate.
                        </p>
                        <PullUrlExamplesList ui={ui} token={null} iocType={k.feed_ioc_type || 'ip'} />
                      </td>
                    </tr>
                  ) : null}
                </React.Fragment>
              )) : (
                <tr>
                  <td colSpan={9} style={{ ...ui.td, padding: '28px 12px', textAlign: 'center' }}>
                    <p style={{ margin: '0 0 12px', color: '#94a3b8', lineHeight: 1.5 }}>
                      No API keys yet. Create a Feed Access Key to let internal tools pull a published feed.
                    </p>
                    {canWrite && hasFeeds ? (
                      <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Create API Key</button>
                    ) : null}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {!hasFeeds && !loading ? (
          <div style={{ ...ui.banner, marginTop: 16 }}>
            Create a Published Feed first before generating a Feed Access Key.{' '}
            <Link to="/threat-intelligence/published-feeds" style={{ color: '#93c5fd', fontWeight: 600 }}>Go to Published Feeds</Link>
          </div>
        ) : null}
      </section>

      {showCreateModal ? (
        <div
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}
          onClick={() => setShowCreateModal(false)}
        >
          <div style={ui.formModal} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
            <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>Create API Key</h3>
            {!hasFeeds ? (
              <p style={ui.modalSub}>
                Create a Published Feed first before generating a Feed Access Key.{' '}
                <Link to="/threat-intelligence/published-feeds">Go to Published Feeds</Link>
              </p>
            ) : (
              <form onSubmit={createKey}>
                <FeedFormField ui={ui} label="Key name" fullWidth>
                  <input required value={form.name} onChange={(e) => setForm((x) => ({ ...x, name: e.target.value }))} style={ui.input} placeholder="e.g. Fortigate-01" />
                </FeedFormField>
                <FeedFormField ui={ui} label="Key type" fullWidth>
                  <select value={form.key_type} style={ui.select} disabled>
                    <option value="feed_access">Feed Access Key</option>
                  </select>
                </FeedFormField>
                <FeedFormField ui={ui} label="Published Feed" helper="Feed this key can pull." fullWidth>
                  <select
                    required
                    value={form.feed_id}
                    onChange={(e) => setForm((x) => ({ ...x, feed_id: e.target.value }))}
                    style={ui.select}
                  >
                    <option value="">Select feed…</option>
                    {feeds.map((f) => (
                      <option key={f.id} value={f.id}>{f.name} ({f.ioc_type})</option>
                    ))}
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
                  <button type="submit" style={ui.btnPrimary} disabled={!canWrite}>Create API Key</button>
                </div>
              </form>
            )}
          </div>
        </div>
      ) : null}

      {tokenReveal ? (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1001, padding: 16 }}>
          <div style={{ ...ui.modal, maxWidth: 560, width: '100%' }}>
            <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>{tokenReveal.title}</h3>
            <p style={ui.modalSub}>Copy this URL now. The token will not be shown again.</p>
            <code style={ui.code}>{tokenReveal.feed_url}</code>
            <button type="button" style={{ ...ui.btnPrimary, marginTop: 10 }} onClick={() => copyText(tokenReveal.feed_url)}>Copy URL</button>
            <div style={{ marginTop: 20 }}>
              <strong style={{ color: '#cbd5e1', fontSize: 13 }}>Pull URL examples</strong>
              <div style={{ marginTop: 10 }}>
                <PullUrlExamplesList ui={ui} token={tokenReveal.token} iocType={tokenReveal.ioc_type} onCopy={copyText} />
              </div>
            </div>
            <button type="button" style={{ ...ui.btn, marginTop: 16, width: '100%' }} onClick={() => setTokenReveal(null)}>Done</button>
          </div>
        </div>
      ) : null}
    </AppShell>
  );
}

const TAG_CATEGORY_OPTIONS = ['malware', 'campaign', 'actor', 'behavior', 'source', 'custom'];

const EMPTY_TAG_FORM = {
  name: '',
  category: 'custom',
  description: '',
  color: '',
  is_active: true
};

function TagManagerPage() {
  const { isAdmin } = useSession();
  const ui = PUBLISHED_FEEDS_UI;
  const [tags, setTags] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showInactive, setShowInactive] = useState(true);
  const [showFormModal, setShowFormModal] = useState(false);
  const [editingTag, setEditingTag] = useState(null);
  const [form, setForm] = useState(EMPTY_TAG_FORM);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  const load = useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    setError('');
    try {
      const params = showInactive ? { include_inactive: true } : { include_inactive: false };
      const { data } = await api.get('/admin/tags', { params });
      setTags(Array.isArray(data?.tags) ? data.tags : []);
    } catch (err) {
      setTags([]);
      setError(apiErrorMessage(err, 'Failed to load tags'));
    } finally {
      setLoading(false);
    }
  }, [isAdmin, showInactive]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

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
      const payload = {
        name: form.name,
        category: form.category,
        description: form.description,
        color: form.color,
        is_active: form.is_active
      };
      if (editingTag?.id) {
        await api.put(`/admin/tags/${editingTag.id}`, payload);
      } else {
        await api.post('/admin/tags', payload);
      }
      setShowFormModal(false);
      setEditingTag(null);
      setForm(EMPTY_TAG_FORM);
      await load();
    } catch (err) {
      setFormError(apiErrorMessage(err, editingTag ? 'Update failed' : 'Create failed'));
    } finally {
      setSaving(false);
    }
  }

  async function disableTag(tag) {
    if (!tag?.id || !isAdmin) return;
    const ok = window.confirm(`Disable tag "${tag.name}"? Existing IOC assignments will remain visible, but the tag will no longer appear in pickers.`);
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
            <p style={ui.pageSub}>Manage central IOC tags used across detail, edit, and feed filtering workflows.</p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <label style={ui.checkLabel}>
              <input type="checkbox" checked={showInactive} onChange={(e) => setShowInactive(e.target.checked)} />
              Show inactive
            </label>
            <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Add Tag</button>
          </div>
        </div>

        {error ? <div style={{ ...ui.banner, marginTop: 12, borderColor: '#991b1b', color: '#fca5a5' }}>{error}</div> : null}

        <div style={{ marginTop: 16, overflowX: 'auto' }}>
          <table className="ioc-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={ui.th}>Name</th>
                <th style={ui.th}>Category</th>
                <th style={ui.th}>Description</th>
                <th style={ui.th}>Color</th>
                <th style={ui.th}>Active</th>
                <th style={ui.th}>Created At</th>
                <th style={ui.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} style={ui.td}>Loading…</td></tr>
              ) : !tags.length ? (
                <tr><td colSpan={7} style={ui.td}>No tags found.</td></tr>
              ) : tags.map((tag) => (
                <tr key={tag.id}>
                  <td style={ui.td}>
                    <div style={{ fontWeight: 600 }}>{tag.name}</div>
                    <div style={{ fontSize: 11, color: '#64748b' }}>{tag.slug || tag.name}</div>
                  </td>
                  <td style={ui.td}>{tag.category || '—'}</td>
                  <td style={{ ...ui.td, maxWidth: 280, whiteSpace: 'normal' }}>{tag.description || '—'}</td>
                  <td style={ui.td}>
                    {tag.color ? (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ width: 14, height: 14, borderRadius: 4, background: tag.color, border: '1px solid #475569' }} />
                        {tag.color}
                      </span>
                    ) : '—'}
                  </td>
                  <td style={ui.td}>{tag.is_active ? 'Yes' : 'No'}</td>
                  <td style={ui.td}>{formatUserDateTime(tag.created_at)}</td>
                  <td style={ui.td}>
                    <button type="button" style={ui.btn} onClick={() => openEditModal(tag)}>Edit</button>
                    {tag.is_active ? (
                      <button type="button" style={{ ...ui.btn, marginLeft: 6, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => disableTag(tag).catch(() => {})}>Disable</button>
                    ) : (
                      <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => enableTag(tag).catch(() => {})}>Enable</button>
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
          <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>{editingTag ? 'Edit Tag' : 'Add Tag'}</h3>
          <form onSubmit={submitForm}>
            <FeedFormField ui={ui} label="Name" fullWidth>
              <input required value={form.name} onChange={(e) => setForm((x) => ({ ...x, name: e.target.value }))} style={ui.input} placeholder="e.g. ransomware" />
            </FeedFormField>
            <FeedFormField ui={ui} label="Category" fullWidth>
              <select value={form.category} onChange={(e) => setForm((x) => ({ ...x, category: e.target.value }))} style={ui.select}>
                {TAG_CATEGORY_OPTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </FeedFormField>
            <FeedFormField ui={ui} label="Description" fullWidth>
              <textarea value={form.description} onChange={(e) => setForm((x) => ({ ...x, description: e.target.value }))} style={ui.textarea} placeholder="Optional description" />
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

function EnrichmentProvidersPage() {
  const { canWrite } = useSession();
  const [loading, setLoading] = useState(true);
  const [vt, setVt] = useState(null);
  const [ipinfo, setIpinfo] = useState(null);
  const [rdap, setRdap] = useState(null);
  const [vtForm, setVtForm] = useState({ enabled: true, ttl_hours: 24, timeout_ms: 12000, api_key: '' });
  const [ipForm, setIpForm] = useState({ enabled: true, token: '', base_url: 'https://api.ipinfo.io/lite', timeout_seconds: 6, usage_note: '' });
  const [feedback, setFeedback] = useState({ type: '', text: '' });
  const [busy, setBusy] = useState({ vtSave: false, vtTest: false, vtRemove: false, ipSave: false, ipTest: false, ipRemove: false });

  const statusMeta = (status) => {
    const s = String(status || '').toLowerCase();
    if (s === 'healthy') return { label: 'Healthy', bg: 'rgba(22,163,74,0.18)', color: '#86efac', border: '#166534' };
    if (s === 'error') return { label: 'Error', bg: 'rgba(220,38,38,0.18)', color: '#fca5a5', border: '#7f1d1d' };
    if (s === 'rate_limited') return { label: 'Rate limited', bg: 'rgba(217,119,6,0.18)', color: '#fcd34d', border: '#b45309' };
    if (s === 'configured') return { label: 'Configured', bg: 'rgba(37,99,235,0.18)', color: '#93c5fd', border: '#1d4ed8' };
    return { label: 'Not configured', bg: 'rgba(100,116,139,0.2)', color: '#cbd5e1', border: '#475569' };
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/admin/enrichment-providers');
      const vtRow = (data?.providers || []).find((x) => x.provider === 'virustotal') || null;
      const ipRow = (data?.providers || []).find((x) => x.provider === 'ipinfo_lite') || null;
      const rdapRow = (data?.providers || []).find((x) => x.provider === 'rdap') || null;
      setVt(vtRow);
      setIpinfo(ipRow);
      setRdap(rdapRow);
      if (vtRow) setVtForm((f) => ({ ...f, enabled: vtRow.enabled, ttl_hours: vtRow.ttl_hours || 24, timeout_ms: vtRow.timeout_ms || 12000 }));
      if (ipRow) {
        setIpForm((f) => ({
          ...f,
          enabled: ipRow.enabled,
          base_url: ipRow.base_url || 'https://api.ipinfo.io/lite',
          timeout_seconds: ipRow.timeout_seconds || 6
        }));
      }
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { load().catch(()=>{}); }, [load]);

  async function saveVt() {
    setBusy((b) => ({ ...b, vtSave: true }));
    setFeedback({ type: '', text: '' });
    try {
      await api.put('/admin/enrichment-providers/virustotal', vtForm);
      setFeedback({ type: 'success', text: 'VirusTotal settings saved.' });
      setVtForm((f) => ({ ...f, api_key: '' }));
      await load();
    } catch (e) {
      setFeedback({ type: 'error', text: e?.response?.data?.message || 'Save failed' });
    } finally { setBusy((b) => ({ ...b, vtSave: false })); }
  }

  async function testVt() {
    setBusy((b) => ({ ...b, vtTest: true }));
    setFeedback({ type: '', text: '' });
    try {
      const { data } = await api.post('/admin/enrichment-providers/virustotal/test');
      setFeedback({ type: 'success', text: data?.message || 'VirusTotal connection successful' });
      await load();
    } catch (e) {
      const msg = e?.response?.data?.message || 'Test failed';
      setFeedback({ type: /rate limit/i.test(msg) ? 'warn' : 'error', text: msg });
      await load();
    } finally { setBusy((b) => ({ ...b, vtTest: false })); }
  }

  async function removeVtKey() {
    setBusy((b) => ({ ...b, vtRemove: true }));
    try {
      await api.post('/admin/enrichment-providers/virustotal/remove-key');
      setFeedback({ type: 'success', text: 'VirusTotal API key removed.' });
      await load();
    } catch {
      setFeedback({ type: 'error', text: 'Remove failed' });
    } finally { setBusy((b) => ({ ...b, vtRemove: false })); }
  }

  async function saveIpinfo() {
    setBusy((b) => ({ ...b, ipSave: true }));
    setFeedback({ type: '', text: '' });
    try {
      await api.put('/admin/enrichment-providers/ipinfo-lite', ipForm);
      setFeedback({ type: 'success', text: 'IPinfo Lite settings saved.' });
      setIpForm((f) => ({ ...f, token: '' }));
      await load();
    } catch (e) {
      setFeedback({ type: 'error', text: e?.response?.data?.message || 'Save failed' });
    } finally { setBusy((b) => ({ ...b, ipSave: false })); }
  }

  async function testIpinfo() {
    setBusy((b) => ({ ...b, ipTest: true }));
    setFeedback({ type: '', text: '' });
    try {
      const { data } = await api.post('/admin/enrichment-providers/ipinfo-lite/test');
      setFeedback({ type: 'success', text: data?.message || 'IPinfo Lite connection successful' });
      await load();
    } catch (e) {
      const msg = e?.response?.data?.message || 'Test failed';
      setFeedback({ type: /rate limit/i.test(msg) ? 'warn' : 'error', text: msg });
      await load();
    } finally { setBusy((b) => ({ ...b, ipTest: false })); }
  }

  async function removeIpToken() {
    setBusy((b) => ({ ...b, ipRemove: true }));
    try {
      await api.post('/admin/enrichment-providers/ipinfo-lite/remove-key');
      setFeedback({ type: 'success', text: 'IPinfo Lite token removed.' });
      await load();
    } catch {
      setFeedback({ type: 'error', text: 'Remove failed' });
    } finally { setBusy((b) => ({ ...b, ipRemove: false })); }
  }

  const cardShell = { border:'1px solid #334155', borderRadius:12, padding:16, background:'#0f172a', marginBottom:16 };
  const vtSm = statusMeta(vt?.status);
  const ipSm = statusMeta(ipinfo?.status);
  const rdapSm = statusMeta(rdap?.status === 'disabled' ? 'not_configured' : (rdap?.status || 'healthy'));
  const anyBusy = Object.values(busy).some(Boolean);

  return <AppShell><section style={{ border:'1px solid #334155', borderRadius:12, background:'#111827', padding:20 }}>
    <h2 style={{ margin:'0 0 6px', color:'#f1f5f9' }}>Enrichment Providers</h2>
    <p style={{ margin:'0 0 18px', color:'#94a3b8', fontSize:14 }}>Manage external intelligence providers used for on-demand IOC enrichment.</p>

    {!canWrite ? <div style={{ marginBottom:12, padding:'10px 12px', borderRadius:8, border:'1px solid #475569', color:'#cbd5e1', background:'rgba(100,116,139,0.15)', fontSize:13 }}>Readonly users can view provider status but cannot modify settings.</div> : null}

    {feedback.text ? <div style={{ marginBottom:12, padding:'10px 12px', borderRadius:8, border:`1px solid ${feedback.type==='success' ? '#166534' : feedback.type==='warn' ? '#b45309' : '#7f1d1d'}`, color: feedback.type==='success' ? '#86efac' : feedback.type==='warn' ? '#fcd34d' : '#fca5a5', background: feedback.type==='success' ? 'rgba(22,163,74,0.18)' : feedback.type==='warn' ? 'rgba(217,119,6,0.18)' : 'rgba(220,38,38,0.18)', fontSize:13 }}>{feedback.text}</div> : null}

    {loading ? <div style={{ color:'#94a3b8' }}>Loading...</div> : <>
      {vt ? <div style={cardShell}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:12, flexWrap:'wrap' }}>
          <div>
            <h3 style={{ margin:'0 0 4px', color:'#e2e8f0' }}>VirusTotal</h3>
            <div style={{ color:'#94a3b8', fontSize:13 }}>IOC reputation and analysis enrichment</div>
          </div>
          <div style={{ display:'flex', gap:10, alignItems:'center' }}>
            <span style={{ border:`1px solid ${vtSm.border}`, background:vtSm.bg, color:vtSm.color, borderRadius:999, padding:'4px 10px', fontSize:12, fontWeight:700 }}>{vtSm.label}</span>
            <label style={{ color:'#cbd5e1', fontSize:13, display:'inline-flex', alignItems:'center', gap:6 }}><input type='checkbox' checked={vtForm.enabled} onChange={(e)=>setVtForm((x)=>({...x, enabled:e.target.checked}))} disabled={!canWrite}/> Enabled</label>
          </div>
        </div>
        <div style={{ marginTop:14 }}>
          <label style={{ display:'block', color:'#cbd5e1', fontSize:13, marginBottom:6 }}>VirusTotal API Key</label>
          <input type='password' value={vtForm.api_key} onChange={(e)=>setVtForm((x)=>({...x, api_key:e.target.value}))} placeholder={vt.masked_key ? 'Leave blank to keep current key' : 'Paste VirusTotal API key'} disabled={!canWrite} style={{ width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0', boxSizing:'border-box' }} />
          {vt.masked_key ? <div style={{ marginTop:6, color:'#94a3b8', fontSize:12 }}>Current key: {vt.masked_key}</div> : null}
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(180px, 1fr))', gap:10, marginTop:14 }}>
          <label style={{ color:'#cbd5e1', fontSize:13 }}>Cache TTL (hours)<input type='number' min='1' value={vtForm.ttl_hours} onChange={(e)=>setVtForm((x)=>({...x, ttl_hours:Number(e.target.value)}))} disabled={!canWrite} style={{ marginTop:6, width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0' }} /></label>
          <label style={{ color:'#cbd5e1', fontSize:13 }}>Timeout (ms)<input type='number' min='3000' value={vtForm.timeout_ms} onChange={(e)=>setVtForm((x)=>({...x, timeout_ms:Number(e.target.value)}))} disabled={!canWrite} style={{ marginTop:6, width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0' }} /></label>
        </div>
        <div style={{ display:'flex', gap:8, marginTop:14, flexWrap:'wrap' }}>
          <button onClick={()=>saveVt().catch(()=>{})} disabled={!canWrite || anyBusy} style={{ padding:'8px 14px', borderRadius:8, border:'1px solid #2563eb', background:'#2563eb', color:'#fff', fontWeight:600 }}>{busy.vtSave ? 'Saving...' : 'Save'}</button>
          <button onClick={()=>testVt().catch(()=>{})} disabled={!canWrite || anyBusy} style={{ padding:'8px 14px', borderRadius:8, border:'1px solid #475569', background:'#1f2937', color:'#e2e8f0' }}>{busy.vtTest ? 'Testing...' : 'Test Connection'}</button>
          <button onClick={()=>removeVtKey().catch(()=>{})} disabled={!canWrite || anyBusy} style={{ padding:'8px 14px', borderRadius:8, border:'1px solid #7f1d1d', background:'rgba(127,29,29,0.25)', color:'#fca5a5' }}>{busy.vtRemove ? 'Removing...' : 'Remove key'}</button>
        </div>
      </div> : null}

      {ipinfo ? <div style={cardShell}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:12, flexWrap:'wrap' }}>
          <div>
            <h3 style={{ margin:'0 0 4px', color:'#e2e8f0' }}>IPinfo Lite</h3>
            <div style={{ color:'#94a3b8', fontSize:13 }}>On-demand IP enrichment (ASN, country, continent). No bulk feed.</div>
          </div>
          <div style={{ display:'flex', gap:10, alignItems:'center' }}>
            <span style={{ border:`1px solid ${ipSm.border}`, background:ipSm.bg, color:ipSm.color, borderRadius:999, padding:'4px 10px', fontSize:12, fontWeight:700 }}>{ipSm.label}</span>
            <label style={{ color:'#cbd5e1', fontSize:13, display:'inline-flex', alignItems:'center', gap:6 }}><input type='checkbox' checked={ipForm.enabled} onChange={(e)=>setIpForm((x)=>({...x, enabled:e.target.checked}))} disabled={!canWrite}/> Enabled</label>
          </div>
        </div>
        <div style={{ marginTop:14 }}>
          <label style={{ display:'block', color:'#cbd5e1', fontSize:13, marginBottom:6 }}>API Token</label>
          <input type='password' value={ipForm.token} onChange={(e)=>setIpForm((x)=>({...x, token:e.target.value}))} placeholder={ipinfo.masked_key ? 'Leave blank to keep current token' : 'Paste IPinfo Lite token'} disabled={!canWrite} style={{ width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0', boxSizing:'border-box' }} />
          {ipinfo.masked_key ? <div style={{ marginTop:6, color:'#94a3b8', fontSize:12 }}>Current token: {ipinfo.masked_key}</div> : null}
          <div style={{ marginTop:4, color:'#64748b', fontSize:12 }}>Token is never returned in plaintext. Env fallback: IPINFO_LITE_TOKEN</div>
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(180px, 1fr))', gap:10, marginTop:14 }}>
          <label style={{ color:'#cbd5e1', fontSize:13 }}>Base URL<input value={ipForm.base_url} onChange={(e)=>setIpForm((x)=>({...x, base_url:e.target.value}))} disabled={!canWrite} style={{ marginTop:6, width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0' }} /></label>
          <label style={{ color:'#cbd5e1', fontSize:13 }}>Timeout (seconds)<input type='number' min='3' max='30' value={ipForm.timeout_seconds} onChange={(e)=>setIpForm((x)=>({...x, timeout_seconds:Number(e.target.value)}))} disabled={!canWrite} style={{ marginTop:6, width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0' }} /></label>
        </div>
        <label style={{ display:'block', color:'#cbd5e1', fontSize:13, marginTop:14 }}>Usage note (optional)<textarea value={ipForm.usage_note} onChange={(e)=>setIpForm((x)=>({...x, usage_note:e.target.value}))} disabled={!canWrite} rows={2} style={{ marginTop:6, width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0', resize:'vertical' }} /></label>
        <div style={{ display:'flex', gap:8, marginTop:14, flexWrap:'wrap' }}>
          <button onClick={()=>saveIpinfo().catch(()=>{})} disabled={!canWrite || anyBusy} style={{ padding:'8px 14px', borderRadius:8, border:'1px solid #2563eb', background:'#2563eb', color:'#fff', fontWeight:600 }}>{busy.ipSave ? 'Saving...' : 'Save'}</button>
          <button onClick={()=>testIpinfo().catch(()=>{})} disabled={!canWrite || anyBusy} style={{ padding:'8px 14px', borderRadius:8, border:'1px solid #475569', background:'#1f2937', color:'#e2e8f0' }}>{busy.ipTest ? 'Testing...' : 'Test Connection'}</button>
          <button onClick={()=>removeIpToken().catch(()=>{})} disabled={!canWrite || anyBusy} style={{ padding:'8px 14px', borderRadius:8, border:'1px solid #7f1d1d', background:'rgba(127,29,29,0.25)', color:'#fca5a5' }}>{busy.ipRemove ? 'Removing...' : 'Remove token'}</button>
        </div>
        {ipinfo.last_error_message ? <div style={{ marginTop:12, padding:'10px 12px', borderRadius:8, border:'1px solid #7f1d1d', background:'rgba(220,38,38,0.14)', color:'#fca5a5', fontSize:13 }}><b>Last error:</b> {ipinfo.last_error_message}</div> : null}
      </div> : null}

      {rdap ? <div style={cardShell}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:12, flexWrap:'wrap' }}>
          <div>
            <h3 style={{ margin:'0 0 4px', color:'#e2e8f0' }}>RDAP / WHOIS</h3>
            <div style={{ color:'#94a3b8', fontSize:13 }}>{rdap.description || 'Domain registration data via public RDAP. No API key required.'}</div>
          </div>
          <div style={{ display:'flex', gap:10, alignItems:'center' }}>
            <span style={{ border:`1px solid ${rdapSm.border}`, background:rdapSm.bg, color:rdapSm.color, borderRadius:999, padding:'4px 10px', fontSize:12, fontWeight:700 }}>{rdap.enabled ? (rdapSm.label === 'Healthy' ? 'Built-in' : rdapSm.label) : 'Disabled'}</span>
            <span style={{ border:'1px solid #475569', background:'rgba(100,116,139,0.2)', color:'#cbd5e1', borderRadius:999, padding:'4px 10px', fontSize:12 }}>No API key</span>
          </div>
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(180px, 1fr))', gap:10, marginTop:14 }}>
          <div style={{ color:'#cbd5e1', fontSize:13 }}>
            <div style={{ color:'#94a3b8', marginBottom:4 }}>RDAP base URL</div>
            <div style={{ color:'#e2e8f0', wordBreak:'break-all' }}>{rdap.rdap_base_url || 'https://rdap.org'}</div>
          </div>
          <div style={{ color:'#cbd5e1', fontSize:13 }}>
            <div style={{ color:'#94a3b8', marginBottom:4 }}>Domain cache TTL</div>
            <div style={{ color:'#e2e8f0' }}>{rdap.cache_ttl_hours || 24} hours</div>
          </div>
          <div style={{ color:'#cbd5e1', fontSize:13 }}>
            <div style={{ color:'#94a3b8', marginBottom:4 }}>Timeout</div>
            <div style={{ color:'#e2e8f0' }}>{rdap.timeout_ms || 10000} ms</div>
          </div>
        </div>
        <div style={{ marginTop:12, padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#0b1220', color:'#94a3b8', fontSize:13, lineHeight:1.5 }}>
          Used on-demand from <b style={{ color:'#e2e8f0' }}>IOC Details → Intelligence</b> for domain and URL observables. Lookups are cached by registrable root domain (e.g. tenant.wixstudio.com → wixstudio.com).
        </div>
      </div> : null}
    </>}
  </section></AppShell>;
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
  const { role, userId, refreshSession } = useSession();
  const ui = PUBLISHED_FEEDS_UI;
  const [timezone, setTimezone] = useState(localStorage.getItem('demo_timezone') || 'UTC');
  const [saving, setSaving] = useState(false);
  const [timezoneError, setTimezoneError] = useState('');
  const [timezoneSuccess, setTimezoneSuccess] = useState('');
  const [profile, setProfile] = useState({ first_name: '', last_name: '' });
  const [profileBusy, setProfileBusy] = useState(false);
  const [profileError, setProfileError] = useState('');
  const [profileSuccess, setProfileSuccess] = useState('');

  useEffect(() => {
    let mounted = true;
    async function loadPreference() {
      try {
        const { data } = await api.get('/users/me/preferences');
        if (!mounted) return;
        if (data?.timezone) {
          localStorage.setItem('demo_timezone', data.timezone);
          setTimezone(data.timezone);
        }
      } catch {
        /* keep local fallback */
      }
    }
    loadPreference().catch(() => {});
    return () => {
      mounted = false;
    };
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

  async function saveTimezone() {
    setSaving(true);
    setTimezoneError('');
    setTimezoneSuccess('');
    try {
      const { data } = await api.put('/users/me/preferences', { timezone });
      const tz = data?.timezone || timezone;
      localStorage.setItem('demo_timezone', tz);
      setTimezone(tz);
      setTimezoneSuccess('Timezone updated.');
    } catch (err) {
      setTimezoneError(apiErrorMessage(err, 'Failed to update timezone'));
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

  return (
    <AppShell>
      <section style={ui.section}>
        <h1 style={ui.pageTitle}>Settings</h1>
        <p style={ui.pageSub}>Manage platform-wide preferences and display settings.</p>

        <div style={{ ...ui.formPanel, marginTop: 8 }}>
          <h2 style={{ ...ui.formTitle, marginBottom: 6 }}>Timezone</h2>
          <p style={{ margin: '0 0 16px', fontSize: 13, color: '#94a3b8', lineHeight: 1.45 }}>
            Used for timestamps across the application.
          </p>
          <label htmlFor="admin-tz" style={ui.label}>Display timezone</label>
          <select
            id="admin-tz"
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            style={{ ...ui.select, maxWidth: 400 }}
          >
            {COMMON_TIMEZONES.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
          </select>
          <div style={{ marginTop: 16 }}>
            <button
              type="button"
              onClick={() => saveTimezone().catch(() => {})}
              disabled={saving}
              style={{
                ...ui.btnPrimary,
                opacity: saving ? 0.75 : 1,
                cursor: saving ? 'wait' : 'pointer'
              }}
            >
              {saving ? 'Saving…' : 'Save timezone'}
            </button>
          </div>
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
                      <span aria-hidden style={{ fontSize: 14, lineHeight: 1 }}>×</span>
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
    setStatusBusyId(targetId);
    setActionError('');
    try {
      await api.patch(`/users/${targetId}/status`, { status: next });
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

function isNewlyActiveHotIoc(firstSeenLog) {
  if (!firstSeenLog) return false;
  const t = new Date(firstSeenLog).getTime();
  if (Number.isNaN(t)) return false;
  return Date.now() - t <= 60 * 60 * 1000;
}

function IOCHotListPage() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [summary, setSummary] = useState({ total: 0, by_type: [], by_source: [] });
  const [loading, setLoading] = useState(false);
  const [banner, setBanner] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [typeFilter, setTypeFilter] = useState('');
  const [sinceFilter, setSinceFilter] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [pagination, setPagination] = useState({ page: 1, page_size: 50, total: 0, total_pages: 1 });

  const loadHot = useCallback(async () => {
    setLoading(true);
    setBanner('');
    try {
      const params = { page, limit: pageSize, suppressed: showSuppressed ? 'include' : 'hide' };
      if (typeFilter) params.type = typeFilter;
      if (sinceFilter) params.last_seen_since = sinceFilter;
      if (search) params.q = search;
      const { data } = await api.get('/ioc/hot', { params });
      setItems(data.items || []);
      setSummary(data.summary || { total: 0, by_type: [], by_source: [] });
      setPagination(data.pagination || { page: 1, page_size: pageSize, total: 0, total_pages: 1 });
    } catch {
      setItems([]);
      setSummary({ total: 0, by_type: [], by_source: [] });
      setBanner('Failed to load hot IOC list.');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, typeFilter, sinceFilter, search, showSuppressed]);

  useEffect(() => {
    loadHot();
  }, [loadHot]);

  const hotBadge = (bg, color) => ({
    display: 'inline-block',
    marginLeft: 6,
    marginTop: 4,
    padding: '2px 8px',
    borderRadius: 999,
    fontSize: 11,
    fontWeight: 700,
    background: bg,
    color
  });

  function applySearch() {
    setPage(1);
    setSearch(String(searchInput || '').trim());
  }

  const typeCounts = {
    ip: summary.by_type?.find((x) => x.observable_type === 'ip')?.count || 0,
    url: summary.by_type?.find((x) => x.observable_type === 'url')?.count || 0,
    domain: summary.by_type?.find((x) => x.observable_type === 'domain')?.count || 0,
    ip6: summary.by_type?.find((x) => x.observable_type === 'ip6')?.count || 0,
    hash: summary.by_type?.find((x) => x.observable_type === 'hash')?.count || 0
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
        <h2 style={{ marginTop: 0 }}>Hot IOC List</h2>
        <div style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
          Indicators with at least one environment match (hits &gt; 0), from PostgreSQL snapshot. Sorted by last seen in logs.
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(120px, 1fr))', gap: 10, marginBottom: 16 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Records</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{summary.total}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>IP</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.ip}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>URL</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.url}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Hash (MD5/SHA*)</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.hash}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Domain</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.domain}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>IPv6</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.ip6}</div>
          </div>
        </div>

        <div style={{ marginBottom: 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 8, background: '#0f172a' }}>
          <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8 }}>Top 5 sources</div>
          <div style={{ marginTop: 6, fontSize: 14, display: 'grid', gap: 6 }}>
            {summary.by_source?.length ? summary.by_source.map((s, idx) => (
              <div key={s.source_name || idx} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, borderBottom: '1px dashed #334155', paddingBottom: 4 }}>
                <span style={{ color: '#cbd5e1' }}>{idx + 1}. {s.source_name}</span>
                <b style={{ color: '#e2e8f0' }}>{s.count}</b>
              </div>
            )) : <span style={{ color: '#94a3b8' }}>No data</span>}
          </div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginBottom: 14, alignItems: 'center' }}>
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') applySearch(); }}
            placeholder="Search by IOC value or public ID"
            style={{ minWidth: 320 }}
          />
          <button onClick={applySearch}>Search</button>
          <button
            onClick={() => {
              setSearchInput('');
              setSearch('');
              setShowSuppressed(false);
              setPage(1);
            }}
          >
            Clear
          </button>

          <label style={{ fontSize: 14, color: '#cbd5e1' }}>
            Type{' '}
            <select
              value={typeFilter}
              onChange={(e) => {
                setPage(1);
                setTypeFilter(e.target.value);
              }}
              style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', fontWeight: 600, background: '#111827', color: '#e2e8f0', marginLeft: 6 }}
            >
              <option value="">All</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
            </select>
          </label>
          <label style={{ fontSize: 14, color: '#cbd5e1' }}>
            Last seen in logs{' '}
            <select
              value={sinceFilter}
              onChange={(e) => {
                setPage(1);
                setSinceFilter(e.target.value);
              }}
              style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', fontWeight: 600, background: '#111827', color: '#e2e8f0', marginLeft: 6 }}
            >
              <option value="">Any time</option>
              <option value="1h">Last hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
          </label>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 14, color: '#cbd5e1', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={showSuppressed}
              onChange={(e) => {
                setPage(1);
                setShowSuppressed(e.target.checked);
              }}
            />
            <span>Show suppressed IOCs</span>
            <span style={{ fontSize: 12, color: '#64748b' }}>Suppressed IOCs are hidden by default.</span>
          </label>
          <label style={{ fontSize: 14, color: '#cbd5e1' }}>
            Page size{' '}
            <select
              value={pageSize}
              onChange={(e) => {
                setPage(1);
                setPageSize(Number(e.target.value));
              }}
              style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', fontWeight: 600, background: '#111827', color: '#e2e8f0', marginLeft: 6 }}
            >
              {[25, 50, 100, 200].map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </label>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 10, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: '#e2e8f0' }}>
            Hot IOCs <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: 0.2 }}>{pagination.total}</span>
            <span style={{ margin: '0 8px', color: '#94a3b8' }}>|</span>
            Page <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.page}</span> / <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.total_pages}</span>
          </div>
        </div>

        {(loading || banner) && (
          <div style={{ marginBottom: 10, padding: 10, background: loading ? '#e0f2fe' : '#fee2e2', border: `1px solid ${loading ? '#7dd3fc' : '#fecaca'}`, borderRadius: 6, color: '#0f172a' }}>
            {loading ? 'Loading hot IOCs...' : banner}
          </div>
        )}

        {!loading && !banner && items.length === 0 && (
          <div style={{ marginBottom: 10, padding: 10, background: '#fff8e1', border: '1px solid #ffe0a3', borderRadius: 6, color: '#0f172a' }}>
            No hot IOCs yet — nothing in your environment has matched a listed indicator.
          </div>
        )}

        <div style={{ overflowX: 'auto', border: '1px solid #e5e7eb', borderRadius: 10 }}>
          <table
            className="ioc-table"
            width="100%"
            cellPadding="10"
            style={{
              borderCollapse: 'collapse',
              minWidth: 720,
              background: '#fff',
              tableLayout: 'fixed',
              fontSize: 13,
              fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace"
            }}
          >
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
                <th>IOC</th>
                <th style={{ width: 110 }}>Type</th>
                <th style={{ width: 110 }}>Evidence Logs</th>
                <th style={{ width: 96 }}>Sources</th>
                <th style={{ width: 200 }}>First Seen</th>
                <th style={{ width: 200 }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => {
                const isSuppressed = isSuppressionActiveRow(r.suppression);
                return (
                <tr
                  key={`${r.observable_type || ''}:${r.observable || ''}:${r.public_id || r.id}`}
                  style={{
                    borderBottom: '1px solid #f1f5f9',
                    cursor: r.public_id ? 'pointer' : 'default',
                    background: isSuppressed ? '#f8fafc' : '#fff',
                    opacity: isSuppressed ? 0.82 : 1
                  }}
                  onClick={() => {
                    if (r.public_id) navigate(`/ioc/details/${encodeURIComponent(r.public_id)}`);
                  }}
                >
                  <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                    <span style={{ color: isSuppressed ? '#64748b' : '#93c5fd', textDecoration: 'underline', fontWeight: 600 }}>{r.observable || '-'}</span>
                    <span style={{ display: 'block' }}>
                      {isSuppressed ? (
                        <>
                          <span style={hotBadge('#334155', '#cbd5e1')}>Suppressed</span>
                          <span style={hotBadge('#14532d', '#86efac')}>False Positive</span>
                        </>
                      ) : null}
                      {!isSuppressed && isNewlyActiveHotIoc(r.first_seen_log) ? (
                        <span style={hotBadge('#312e81', '#c7d2fe')}>Newly active</span>
                      ) : null}
                      {!isSuppressed && Number(r.evidence_logs ?? 0) > 100 ? (
                        <span style={hotBadge('#78350f', '#fcd34d')}>High activity</span>
                      ) : null}
                    </span>
                  </td>
                  <td style={{ textTransform: 'lowercase' }}>{r.observable_type || '-'}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{Number.isFinite(Number(r.evidence_logs)) ? Number(r.evidence_logs) : '-'}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{Number(r.source_count ?? 0)}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>{formatUserDateTime(r.first_seen_log)}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>{formatUserDateTime(r.last_seen_log)}</td>
                </tr>
              );})}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
          <button style={{ minWidth: 92, fontWeight: 600 }} disabled={pagination.page <= 1} onClick={() => setPage((p) => Math.max(p - 1, 1))}>
            Previous
          </button>
          <button
            style={{ minWidth: 92, fontWeight: 600 }}
            disabled={pagination.page >= pagination.total_pages}
            onClick={() => setPage((p) => Math.min(p + 1, pagination.total_pages))}
          >
            Next
          </button>
        </div>
      </section>
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
  const ui = PUBLISHED_FEEDS_UI;

  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(Math.max(1, Number(searchParams.get('page') || 1)));
  const [pageSize] = useState(25);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [searchInput, setSearchInput] = useState(String(searchParams.get('search') || ''));
  const [search, setSearch] = useState(String(searchParams.get('search') || ''));
  const [iocType, setIocType] = useState(String(searchParams.get('ioc_type') || 'all'));
  const [scope, setScope] = useState(String(searchParams.get('scope') || 'all'));
  const [statusFilter, setStatusFilter] = useState(String(searchParams.get('status') || 'all'));
  const [sourceName, setSourceName] = useState(String(searchParams.get('source_name') || ''));
  const [createdBy, setCreatedBy] = useState(String(searchParams.get('created_by') || ''));
  const [editItem, setEditItem] = useState(null);
  const [editReason, setEditReason] = useState('');
  const [editPreset, setEditPreset] = useState('never');
  const [editCustomDate, setEditCustomDate] = useState('');
  const [editSaving, setEditSaving] = useState(false);
  const [editError, setEditError] = useState('');
  const [removeItem, setRemoveItem] = useState(null);
  const [removeSaving, setRemoveSaving] = useState(false);
  const [removeError, setRemoveError] = useState('');
  const [toast, setToast] = useState('');

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = { page, pageSize, sort: 'created_at_desc' };
      if (search) params.search = search;
      if (iocType && iocType !== 'all') params.ioc_type = iocType;
      if (scope && scope !== 'all') params.scope = scope;
      if (createdBy.trim()) params.created_by = createdBy.trim();
      if (statusFilter === 'active') {
        params.active = 'true';
        params.expires = 'active';
      } else if (statusFilter === 'inactive') {
        params.active = 'false';
      } else if (statusFilter === 'expired') {
        params.active = 'true';
        params.expires = 'expired';
      }
      const { data } = await api.get('/ioc-suppressions', { params });
      let loaded = Array.isArray(data?.items) ? data.items : [];
      if (sourceName.trim()) {
        const q = sourceName.trim().toLowerCase();
        loaded = loaded.filter((x) => String(x.source_name || '').toLowerCase().includes(q));
      }
      setItems(loaded);
      setTotal(Number(data?.total || 0));
    } catch (err) {
      setItems([]);
      setTotal(0);
      setError(apiErrorMessage(err, 'Failed to load suppressions'));
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search, iocType, scope, statusFilter, sourceName, createdBy]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  useEffect(() => {
    const next = new URLSearchParams();
    if (search) next.set('search', search);
    if (page > 1) next.set('page', String(page));
    if (iocType !== 'all') next.set('ioc_type', iocType);
    if (scope !== 'all') next.set('scope', scope);
    if (statusFilter !== 'all') next.set('status', statusFilter);
    if (sourceName.trim()) next.set('source_name', sourceName.trim());
    if (createdBy.trim()) next.set('created_by', createdBy.trim());
    setSearchParams(next, { replace: true });
  }, [search, page, iocType, scope, statusFilter, sourceName, createdBy, setSearchParams]);

  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(() => setToast(''), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  const pageSummary = useMemo(() => {
    const active = items.filter((x) => String(x.status || '').toLowerCase() === 'active').length;
    const expired = items.filter((x) => String(x.status || '').toLowerCase() === 'expired').length;
    const global = items.filter((x) => String(x.scope || '').toLowerCase() === 'global').length;
    const sourceScoped = items.filter((x) => String(x.scope || '').toLowerCase() === 'source').length;
    const affected = items.reduce((acc, x) => acc + Number(x.affected_incidents || 0), 0);
    return { active, expired, global, sourceScoped, affected };
  }, [items]);

  function applyFilters() {
    setPage(1);
    setSearch(searchInput.trim());
  }

  function openEdit(item) {
    setEditItem(item);
    setEditReason(String(item?.reason || ''));
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
    if (!editItem?.id) return;
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
        active: true
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

  async function confirmRemove() {
    if (!removeItem?.id) return;
    setRemoveSaving(true);
    setRemoveError('');
    try {
      await api.delete(`/ioc-suppressions/${removeItem.id}`);
      setRemoveItem(null);
      setToast('Suppression removed');
      await load();
    } catch (err) {
      const msg = apiErrorMessage(err, 'Suppression failed');
      setRemoveError(msg.includes('Forbidden') ? 'You do not have permission to modify suppressions' : msg);
    } finally {
      setRemoveSaving(false);
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
        <h2 style={ui.pageTitle}>IOC Suppressions</h2>
        <p style={ui.pageSub}>Manage false positives and suppressed indicators to prevent recurring feed noise.</p>

        {!isAdmin ? (
          <div style={{ ...ui.banner, borderColor: '#475569', background: 'rgba(100,116,139,0.15)', color: '#cbd5e1', marginBottom: 16 }}>
            Readonly users can view suppression status but cannot modify it.
          </div>
        ) : null}

        {toast ? <div style={{ ...ui.banner, marginBottom: 12 }}>{toast}</div> : null}
        {error ? <div style={{ marginBottom: 12, padding: 12, borderRadius: 8, border: '1px solid #7f1d1d', background: 'rgba(127,29,29,0.25)', color: '#fca5a5' }}>{error}</div> : null}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(120px, 1fr))', gap: 10, marginBottom: 16 }}>
          {[
            ['Active (page)', pageSummary.active],
            ['Expired (page)', pageSummary.expired],
            ['Global (page)', pageSummary.global],
            ['Source-specific (page)', pageSummary.sourceScoped],
            ['Affected incidents (page)', pageSummary.affected]
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
                {['ip', 'ip6', 'domain', 'url', 'md5', 'sha1', 'sha256'].map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <span style={ui.label}>Scope</span>
              <select value={scope} onChange={(e) => { setScope(e.target.value); setPage(1); }} style={ui.select}>
                <option value="all">All</option>
                <option value="global">Global</option>
                <option value="source">Source-specific</option>
              </select>
            </div>
            <div>
              <span style={ui.label}>Status</span>
              <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }} style={ui.select}>
                <option value="all">All</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
                <option value="expired">Expired</option>
              </select>
            </div>
            <div>
              <span style={ui.label}>Source</span>
              <input value={sourceName} onChange={(e) => setSourceName(e.target.value)} placeholder="Optional" style={ui.input} />
            </div>
            <div>
              <span style={ui.label}>Created by</span>
              <input value={createdBy} onChange={(e) => setCreatedBy(e.target.value)} placeholder="Optional" style={ui.input} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button type="button" style={ui.btnPrimary} onClick={applyFilters}>Apply filters</button>
            <button type="button" style={ui.btn} onClick={() => { setSearchInput(''); setSearch(''); setIocType('all'); setScope('all'); setStatusFilter('all'); setSourceName(''); setCreatedBy(''); setPage(1); }}>Reset</button>
          </div>
          <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>Summary cards reflect the current page only. Source filter is client-side on the loaded page (backend has no source_name query param).</div>
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
            <table className="ioc-table published-feeds-table" width="100%" style={{ borderCollapse: 'collapse', minWidth: 1100 }}>
              <thead style={ui.thead}>
                <tr>
                  {['IOC', 'Type', 'Scope', 'Source', 'Reason', 'Created by', 'Created at', 'Expires', 'Status', 'Affected', 'Actions'].map((h) => (
                    <th key={h} style={ui.th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id} style={ui.tr}>
                    <td style={{ ...ui.td, maxWidth: 220, overflowWrap: 'anywhere' }}>{item.ioc_value}</td>
                    <td style={ui.td}>{item.ioc_type}</td>
                    <td style={ui.td}><span style={suppressionStatusBadgeStyle('active')}>{String(item.scope || 'global').toLowerCase() === 'source' ? 'Source-specific' : 'Global'}</span></td>
                    <td style={ui.td}>{item.source_name || '—'}</td>
                    <td style={{ ...ui.td, maxWidth: 260, overflowWrap: 'anywhere' }}>{item.reason}</td>
                    <td style={ui.td}>{item.created_by || '—'}</td>
                    <td style={ui.td}>{formatUserDateTime(item.created_at)}</td>
                    <td style={ui.td}>{item.expires_at ? formatUserDateTime(item.expires_at) : 'Never'}</td>
                    <td style={ui.td}><span style={suppressionStatusBadgeStyle(item.status)}>{item.status || 'unknown'}</span></td>
                    <td style={ui.td}>{Number(item.affected_incidents || 0)}</td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>
                      <button type="button" style={ui.linkBtn} onClick={() => resolveIocDetailsUrl(item).catch(() => {})}>View IOC</button>
                      {isAdmin ? (
                        <>
                          {' · '}
                          <button type="button" style={ui.linkBtn} onClick={() => openEdit(item)}>Edit</button>
                          {' · '}
                          <button type="button" style={{ ...ui.linkBtn, color: '#fca5a5' }} onClick={() => { setRemoveItem(item); setRemoveError(''); }}>Remove</button>
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

      {editItem ? (
        <ModalOverlay onClose={() => !editSaving && setEditItem(null)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Edit suppression</h3>
          <div style={{ display: 'grid', gap: 12 }}>
            <div><span style={ui.label}>IOC</span><input readOnly value={editItem.ioc_value} style={ui.input} /></div>
            <div><span style={ui.label}>Type</span><input readOnly value={editItem.ioc_type} style={ui.input} /></div>
            <div><span style={ui.label}>Scope</span><input readOnly value={editItem.scope || 'global'} style={ui.input} /></div>
            <div>
              <span style={ui.label}>Reason</span>
              <textarea value={editReason} onChange={(e) => setEditReason(e.target.value)} style={ui.textarea} disabled={!isAdmin || editSaving} />
            </div>
            <SuppressionExpirationFields ui={ui} preset={editPreset} setPreset={setEditPreset} customDate={editCustomDate} setCustomDate={setEditCustomDate} disabled={!isAdmin || editSaving} />
            {editError ? <div style={{ color: '#fca5a5', fontSize: 13 }}>{editError}</div> : null}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button type="button" style={ui.btn} onClick={() => setEditItem(null)} disabled={editSaving}>Cancel</button>
              <button type="button" style={ui.btnPrimary} onClick={() => saveEdit().catch(() => {})} disabled={!isAdmin || editSaving}>{editSaving ? 'Saving…' : 'Save changes'}</button>
            </div>
          </div>
        </ModalOverlay>
      ) : null}

      {removeItem ? (
        <ModalOverlay onClose={() => !removeSaving && setRemoveItem(null)}>
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Remove suppression</h3>
          <p style={ui.modalSub}>This will allow this IOC to become active again in future imports/correlation. Existing closed incidents will not be automatically reopened.</p>
          <div style={{ ...ui.code, marginBottom: 12 }}>{removeItem.ioc_value} ({removeItem.ioc_type})</div>
          {removeError ? <div style={{ color: '#fca5a5', fontSize: 13, marginBottom: 10 }}>{removeError}</div> : null}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button type="button" style={ui.btn} onClick={() => setRemoveItem(null)} disabled={removeSaving}>Cancel</button>
            <button type="button" style={{ ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => confirmRemove().catch(() => {})} disabled={!isAdmin || removeSaving}>{removeSaving ? 'Removing…' : 'Remove suppression'}</button>
          </div>
        </ModalOverlay>
      ) : null}
    </AppShell>
  );
}

function IOCListPage() {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState({ total: 0, unique_ips: 0, by_source: [], by_confidence: [] });
  const [pageSize, setPageSize] = useState(5);
  const [page, setPage] = useState(1);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [columnWidths, setColumnWidths] = useState({
    index: 52,
    ip: 360,
    asn: 84,
    country: 90,
    source: 260,
    confidence: 120,
    category: 120,
    timestamp: 170
  });
  const [sortState, setSortState] = useState({ key: null, dir: null });
  const [resizeState, setResizeState] = useState(null);
  const [pagination, setPagination] = useState({ page: 1, page_size: 5, total: 0, total_pages: 1 });
  const [detailObservable, setDetailObservable] = useState('');
  const [detailType, setDetailType] = useState('');
  const [detailSources, setDetailSources] = useState([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [listLoading, setListLoading] = useState(false);
  const [listStatusText, setListStatusText] = useState('');
  const [searchError, setSearchError] = useState('');
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [suppressionIndex, setSuppressionIndex] = useState(new Map());
  const [suppressionIndexLoading, setSuppressionIndexLoading] = useState(false);
  const [suppressionFilter, setSuppressionFilter] = useState('include');

  const loadSummary = useCallback(async () => {
    setSummaryLoading(true);
    try {
      const { data } = await api.get('/ioc/stats');
      setSummary(data || { total: 0, by_source: [], by_type: [] });
    } catch {
      setSummary({ total: 0, by_source: [], by_type: [] });
    } finally {
      setSummaryLoading(false);
    }
  }, []);

  const loadData = useCallback(async (targetPage, targetSize) => {
    setListLoading(true);
    setListStatusText('Query is running. Please wait while IOC results are being processed...');
    try {
      const listRes = await api.get('/ioc/list', {
        params: {
          page: targetPage,
          page_size: targetSize,
          q: search || undefined,
        }
      });
      const items = listRes.data.items || [];
      setRows(items);
      setPagination(listRes.data.pagination || { page: 1, page_size: 5, total: 0, total_pages: 1 });
      setListStatusText('');
    } catch {
      setRows([]);
      setListStatusText('Query failed. Please try again.');
    } finally {
      setListLoading(false);
    }
  }, [search]);

  useEffect(() => {
    loadSummary().catch(() => {});
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
    return sortState.dir === 'asc' ? ' ▲' : ' ▼';
  }

  const sortedRows = useMemo(() => {
    if (!sortState.key || !sortState.dir) return rows;

    const val = (r) => {
      if (sortState.key === 'ip') return String(r.ip || '');
      if (sortState.key === 'source') return String((r.source_names && r.source_names[0]) || '');
      if (sortState.key === 'confidence') return String((r.confidence_set && r.confidence_set[0]) || '');
      if (sortState.key === 'category') return String(r.observable_type || 'ip');
      if (sortState.key === 'timestamp') return new Date(r.last_seen_at || 0).getTime();
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

  const filteredRows = useMemo(() => {
    if (suppressionFilter === 'include') return sortedRows;
    return sortedRows.filter((r) => {
      const key = suppressionKey(r.observable || r.ip, r.observable_type || 'ip');
      const suppressed = suppressionIndex.has(key);
      if (suppressionFilter === 'only') return suppressed;
      return !suppressed;
    });
  }, [sortedRows, suppressionFilter, suppressionIndex]);

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

  const typeCounts = {
    ip: summary.by_type?.find((x) => x.observable_type === 'ip')?.count || 0,
    url: summary.by_type?.find((x) => x.observable_type === 'url')?.count || 0,
    domain: summary.by_type?.find((x) => x.observable_type === 'domain')?.count || 0,
    ip6: summary.by_type?.find((x) => x.observable_type === 'ip6')?.count || 0,
    hash: summary.by_type?.reduce((acc, x) => acc + (FILE_HASH_TYPES.has(x.observable_type) ? Number(x.count || 0) : 0), 0) || 0
  };

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

  function normalizeSearchQuery(rawInput) {
    const trimmed = String(rawInput || '').trim();
    if (!trimmed) return { ok: true, value: '' };

    const match = trimmed.match(/^(ip|sha1|sha256|md5|domain|ipv6|url)\s*:\s*(.+)$/i);
    if (!match) {
      return {
        ok: false,
        message: 'Syntax error. Use one of: ip:, sha1:, sha256:, md5:, domain:, ipv6:, url:'
      };
    }

    const prefix = match[1].toLowerCase();
    const value = String(match[2] || '').trim();
    if (!value) {
      return {
        ok: false,
        message: 'Syntax error. Query value cannot be empty.'
      };
    }

    const backendPrefix = prefix === 'ipv6' ? 'ip6' : prefix;
    return { ok: true, value: `${backendPrefix}:${value}` };
  }

  function applySearch() {
    const parsed = normalizeSearchQuery(searchInput);
    if (!parsed.ok) {
      setSearchError(parsed.message || 'Syntax error.');
      return;
    }

    setSearchError('');
    setPage(1);
    setSearch(parsed.value);
  }

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
      <h2 style={{ marginTop: 0 }}>IOC List</h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(120px, 1fr))', gap: 10, marginBottom: 16 }}>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Records</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{summary.total}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>IP</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.ip}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>URL</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.url}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>Hash (MD5/SHA*)</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.hash}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>Domain</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.domain}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>IPv6</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.ip6}</div>
        </div>
      </div>

      <div style={{ marginBottom: 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 8, background: '#0f172a' }}>
        <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8 }}>
          {summaryLoading ? 'Loading stats…' : 'Top 5 sources'}
        </div>
        <div style={{ marginTop: 6, fontSize: 14, display: 'grid', gap: 6 }}>
          {summary.by_source.length ? summary.by_source.slice(0, 5).map((s, idx) => (
            <div key={s.source_name} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, borderBottom: '1px dashed #334155', paddingBottom: 4 }}>
              <span style={{ color: '#cbd5e1' }}>{idx + 1}. {s.source_name}</span>
              <b style={{ color: '#e2e8f0' }}>{s.count}</b>
            </div>
          )) : <span style={{ color: '#94a3b8' }}>No data</span>}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: 8, marginBottom: 10, alignItems: 'center' }}>
        <input
          placeholder="Search (ip:, sha1:, sha256:, md5:, domain:, ipv6:, url:)"
          value={searchInput}
          onChange={(e) => {
            setSearchInput(e.target.value);
            if (searchError) setSearchError('');
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              applySearch();
            }
          }}
        />
        <button onClick={applySearch}>
          Search
        </button>
        <button
          onClick={() => {
            setSearchInput('');
            setSearchError('');
            setSearch('');
            setPage(1);
          }}
        >
          Clear
        </button>
      </div>

      {searchError && (
        <div style={{ marginBottom: 10, padding: 10, background: '#fee2e2', border: '1px solid #fecaca', borderRadius: 6, color: '#991b1b', fontWeight: 600 }}>
          {searchError}
        </div>
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
            {[5, 10, 25, 100].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>

          <label style={{ fontSize: 14, color: '#cbd5e1', marginLeft: 8 }}>Suppressed:</label>
          <select
            value={suppressionFilter}
            onChange={(e) => setSuppressionFilter(e.target.value)}
            style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', fontWeight: 600, background: '#111827', color: '#e2e8f0' }}
            title="Client-side filter on the current page only"
          >
            <option value="include">Include suppressed</option>
            <option value="exclude">Hide suppressed</option>
            <option value="only">Only suppressed</option>
          </select>
          {suppressionIndexLoading ? <span style={{ fontSize: 12, color: '#64748b' }}>Loading suppression index…</span> : null}

        </div>
        <div style={{ fontSize: 15, fontWeight: 600, color: '#e2e8f0' }}>
          Listed Items <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: 0.2 }}>{pagination.total}</span>
          <span style={{ margin: '0 8px', color: '#94a3b8' }}>|</span>
          Page <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.page}</span> / <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.total_pages}</span>
        </div>
      </div>

      {(listLoading || listStatusText) && (
        <div style={{ marginBottom: 10, padding: 10, background: listLoading ? '#e0f2fe' : '#fff8e1', border: `1px solid ${listLoading ? '#7dd3fc' : '#ffe0a3'}`, borderRadius: 6, color: '#0f172a' }}>
          {listLoading ? 'Query is running. Please wait while IOC results are being processed...' : listStatusText}
        </div>
      )}

      {!listLoading && !listStatusText && rows.length === 0 && (
        <div style={{ marginBottom: 10, padding: 10, background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#94a3b8' }}>
          No IOC records found.
        </div>
      )}

      {suppressionFilter !== 'include' ? (
        <div style={{ marginBottom: 10, padding: 10, border: '1px solid #334155', borderRadius: 8, background: '#111827', color: '#94a3b8', fontSize: 12 }}>
          Suppression filter applies to the current page only (backend list API does not expose suppression fields). For full suppressed IOC management use Operations → IOC Suppressions.
        </div>
      ) : null}

      <div style={{ overflowX: 'auto', border: '1px solid #e5e7eb', borderRadius: 10 }}>
        <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 980, background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
          <colgroup>
            <col style={{ width: columnWidths.index }} />
            <col style={{ width: columnWidths.ip }} />
            <col style={{ width: columnWidths.category }} />
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
              <th onClick={() => nextSort('source')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Source{sortIndicator('source')}<div onMouseDown={(e) => startResize('source', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('confidence')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Confidence{sortIndicator('confidence')}<div onMouseDown={(e) => startResize('confidence', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('timestamp')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Timestamp{sortIndicator('timestamp')}<div onMouseDown={(e) => startResize('timestamp', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
            </tr>
          </thead>
          <tbody>
            {filteredRows.map((r, idx) => {
              const obs = r.observable || r.ip;
              const obsType = r.observable_type || 'ip';
              const isSuppressed = suppressionIndex.has(suppressionKey(obs, obsType));
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
                </td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.observable_type || 'ip'}</td>
                <td title={(r.source_names && r.source_names[0]) || '-'} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                  {r.source_count > 1 ? (
                    <button onClick={() => openSourceDetails(r)} style={{ background: 'transparent', border: 'none', color: '#0f172a', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit', textAlign: 'left' }}>
                      {(r.source_names && r.source_names[0]) || '-'}{r.source_count > 1 ? ` +${r.source_count - 1}` : ''}
                    </button>
                  ) : (
                    <span>{(r.source_names && r.source_names[0]) || '-'}</span>
                  )}
                </td>
                <td><span style={confidenceBadgeStyle((r.confidence_set && r.confidence_set[0]) || 'low')}>{(r.confidence_set && r.confidence_set[0]) || 'low'}</span></td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontVariantNumeric: 'tabular-nums' }}>{formatUserDateTime(r.last_seen_at)}</td>
              </tr>
            );})}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
        <button style={{ minWidth: 92, fontWeight: 600 }} disabled={pagination.page <= 1} onClick={() => setPage((p) => Math.max(p - 1, 1))}>Previous</button>
        <button
          style={{ minWidth: 92, fontWeight: 600 }}
          disabled={pagination.page >= pagination.total_pages}
          onClick={() => setPage((p) => Math.min(p + 1, pagination.total_pages))}
        >
          Next
        </button>
      </div>

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
                    <td>{s.source_name}</td>
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

function VirusTotalEnrichmentCard({ iocId, active = true }) {
  const [state, setState] = useState({ status: 'loading', summary: null, message: '', fetchedAt: null, expiresAt: null });
  const [open, setOpen] = useState(true);
  const [showAll, setShowAll] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [hasLoaded, setHasLoaded] = useState(false);

  const load = useCallback(async () => {
    if (!iocId || !active) return;
    setState((s) => ({ ...s, status: 'loading' }));
    try {
      const { data } = await api.get(`/ioc/${iocId}/enrichments/virustotal`);
      if (data?.status === 'api_key_missing') return setState({ status: 'api_key_missing', summary: null, message: 'VirusTotal API key is not configured.', fetchedAt: null, expiresAt: null });
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
      setState({ status: 'success', summary: data?.summary || null, message: '', fetchedAt: data?.fetched_at || null, expiresAt: data?.expires_at || null });
    } catch (err) {
      const msg = err?.response?.status === 429 ? 'VirusTotal rate limit reached. Try again later.' : (err?.response?.data?.message || 'VirusTotal enrichment failed.');
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
  const compactCardStyle = { marginBottom: 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0b1220', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' };

  if (!active && !hasLoaded) return null;

  if (!hasDetails) {
    if (state.status === 'loading') return <div style={compactCardStyle}><span style={{ color:'#94a3b8', fontSize:13 }}>Loading VirusTotal enrichment...</span></div>;
    if (state.status === 'not_found') return <div style={compactCardStyle}><span style={{ color:'#cbd5e1', fontSize:13 }}>VirusTotal enrichment has not been run yet.</span><button onClick={() => refresh().catch(()=>{})} disabled={refreshing}>{refreshing ? 'Running VirusTotal enrichment...' : 'Enrich with VirusTotal'}</button></div>;
    if (state.status === 'api_key_missing') return <div style={{ ...compactCardStyle, borderColor:'#92400e' }}><span style={{ color:'#fcd34d', fontSize:13 }}>VirusTotal API key is not configured.</span><Link to="/administration/enrichment-providers" style={{ color:'#93c5fd', fontSize:13 }}>Configure in Administration</Link></div>;
    return <div style={{ ...compactCardStyle, borderColor:'#7f1d1d' }}><span style={{ color:'#fca5a5', fontSize:13 }}>{state.message || 'VirusTotal enrichment failed.'}</span><button onClick={() => refresh().catch(()=>{})} disabled={refreshing}>{refreshing ? 'Running VirusTotal enrichment...' : 'Retry'}</button></div>;
  }

  return <div style={{ marginBottom: 14, padding: 14, border: '1px solid #334155', borderRadius: 12, background: '#0f172a' }}>
    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:10 }}>
      <div>
        <div style={{ fontWeight:700, color:'#e2e8f0' }}>VirusTotal Intelligence <span style={{ marginLeft:8, border:'1px solid #1d4ed8', color:'#93c5fd', borderRadius:999, padding:'2px 8px', fontSize:11 }}>VirusTotal</span></div>
        <div style={{ color:'#94a3b8', fontSize:12, marginTop:4 }}>External reputation and analysis summary</div>
      </div>
      <button onClick={() => setOpen((v) => !v)} style={{ padding:'6px 10px' }}>{open ? 'Collapse' : 'Expand'}</button>
    </div>

    {open ? <>
      <div style={{ display:'grid', gridTemplateColumns:'1.2fr 1fr', gap:12, marginTop:12 }}>
        <div style={{ border:'1px solid #334155', borderRadius:10, padding:12, background:'#0b1220' }}>
          <div style={{ fontSize:30, fontWeight:800 }}>{detected} / {total}</div>
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
          <div style={{ marginTop:10, fontSize:12, color:'#94a3b8' }}>Last analysis: {formatUserDateTime(s.last_analysis_date)} • Fetched: {formatUserDateTime(state.fetchedAt)}</div>
        </div>
      </div>

      <div style={{ marginTop:12, border:'1px solid #334155', borderRadius:10, overflow:'hidden' }}>
        <div style={{ padding:10, background:'#111827', borderBottom:'1px solid #334155', fontWeight:700 }}>Top detections</div>
        {topDetections.length ? <table width='100%' cellPadding='8' style={{ borderCollapse:'collapse', fontSize:13 }}><thead><tr style={{ textAlign:'left', background:'#0b1220' }}><th>Engine</th><th>Category</th><th>Result</th></tr></thead><tbody>{topDetections.map((r, i)=><tr key={`${r.engine}-${i}`} style={{ borderTop:'1px solid #334155' }}><td>{r.engine}</td><td>{r.category || '-'}</td><td style={{ whiteSpace:'normal', overflowWrap:'anywhere' }}>{r.result || '-'}</td></tr>)}</tbody></table> : <div style={{ padding:10, color:'#94a3b8' }}>Top detections are not available for this IOC.</div>}
      </div>

      {vendorResults.length > 5 ? <div style={{ marginTop:8 }}><button onClick={() => setShowAll((v) => !v)}>{showAll ? 'Hide vendor results' : 'Show all vendor results'}</button></div> : null}
      {showAll ? <div style={{ marginTop:8, border:'1px solid #334155', borderRadius:10, maxHeight:260, overflow:'auto' }}><div style={{ padding:10, background:'#111827', borderBottom:'1px solid #334155', fontWeight:700 }}>Security vendors' analysis</div><table width='100%' cellPadding='8' style={{ borderCollapse:'collapse', fontSize:12 }}><thead><tr style={{ textAlign:'left', background:'#0b1220' }}><th>Vendor</th><th>Category</th><th>Result</th><th>Method</th></tr></thead><tbody>{vendorResults.map((r, i)=><tr key={`${r.engine}-${i}`} style={{ borderTop:'1px solid #334155' }}><td>{r.engine}</td><td>{r.category || '-'}</td><td style={{ maxWidth:360, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>{r.result || '-'}</td><td>{r.method || '-'}</td></tr>)}</tbody></table></div> : null}

      <div style={{ display:'flex', justifyContent:'flex-end', gap:8, marginTop:10 }}>
        <button onClick={() => refresh().catch(()=>{})} disabled={refreshing}>{refreshing ? 'Refreshing...' : 'Refresh'}</button>
        {s.permalink ? <a href={s.permalink} target='_blank' rel='noopener noreferrer' style={{ padding:'7px 10px', border:'1px solid #334155', borderRadius:8, textDecoration:'none', color:'#93c5fd' }}>Open in VirusTotal</a> : null}
      </div>
    </> : null}
  </div>;
}

const RDAP_IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const RDAP_IPV6_RE = /^([0-9a-f:]+:+)+[0-9a-f]+$/i;
const RDAP_HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const RDAP_TLD_OPTS = { allowPrivateDomains: false, detectIp: false };

function rdapStripHostPort(host) {
  let h = String(host || '').trim().toLowerCase();
  h = h.replace(/\.$/, '').replace(/^\[/, '').replace(/\]$/, '');
  const portIdx = h.indexOf(':');
  if (portIdx > 0 && /^\d+$/.test(h.slice(portIdx + 1))) h = h.slice(0, portIdx);
  return h;
}

function rdapIsIpHost(host) {
  const h = rdapStripHostPort(host);
  return RDAP_IPV4_RE.test(h) || RDAP_IPV6_RE.test(h);
}

function rdapExtractHost(iocValue, iocType) {
  const raw = String(iocValue || '').trim();
  const type = String(iocType || '').toLowerCase();
  if (!raw) return { ok: false, reason: 'empty' };

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) || raw.startsWith('//');
  const looksLikePath = raw.includes('/') && !raw.includes('@');
  let hostname = '';

  if (hasScheme || (looksLikePath && (type === 'url' || raw.includes('://')))) {
    try {
      const urlStr = raw.startsWith('//') ? `https:${raw}` : (hasScheme ? raw : `https://${raw}`);
      hostname = rdapStripHostPort(new URL(urlStr).hostname);
      if (!hostname) return { ok: false, reason: 'invalid_url' };
    } catch {
      return { ok: false, reason: 'invalid_url' };
    }
  } else if (looksLikePath) {
    try {
      hostname = rdapStripHostPort(new URL(`https://${raw}`).hostname);
    } catch {
      hostname = rdapStripHostPort(raw.split('/')[0].split('?')[0].split('#')[0]);
    }
  } else {
    hostname = rdapStripHostPort(raw.split('/')[0].split('?')[0].split('#')[0]);
  }

  if (!hostname) return { ok: false, reason: 'invalid_host' };
  return { ok: true, host: hostname };
}

const IP_ENRICH_IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function ipEnrichIsPrivateIpv4(host) {
  const parts = String(host || '').split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) return true;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true;
  return false;
}

function ipEnrichStripHostPort(host) {
  let h = String(host || '').trim().toLowerCase();
  h = h.replace(/\.$/, '').replace(/^\[/, '').replace(/\]$/, '');
  const portIdx = h.indexOf(':');
  if (portIdx > 0 && /^\d+$/.test(h.slice(portIdx + 1))) h = h.slice(0, portIdx);
  return h;
}

/**
 * UI eligibility for IP Enrichment card (IP IOC or URL with public IP host).
 */
function isIpEnrichmentEligible(iocValue, iocType) {
  const raw = String(iocValue || '').trim();
  const type = String(iocType || '').toLowerCase();
  if (!raw) return { eligible: false, ip: null, observable: null };
  if (type === 'domain' || type === 'hash' || type === 'file_hash' || type === 'email') {
    return { eligible: false, ip: null, observable: raw };
  }
  if (type === 'ip') {
    const ip = ipEnrichStripHostPort(raw.split('/')[0]);
    if (!IP_ENRICH_IPV4_RE.test(ip) && !ip.includes(':')) return { eligible: false, ip: null, observable: raw };
    if (IP_ENRICH_IPV4_RE.test(ip) && ipEnrichIsPrivateIpv4(ip)) return { eligible: false, ip, observable: raw };
    return { eligible: true, ip, observable: raw };
  }
  if (type === 'url') {
    try {
      const u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return { eligible: false, ip: null, observable: raw };
      const host = ipEnrichStripHostPort(u.hostname);
      if (!IP_ENRICH_IPV4_RE.test(host) && !host.includes(':')) return { eligible: false, ip: null, observable: raw };
      if (IP_ENRICH_IPV4_RE.test(host) && ipEnrichIsPrivateIpv4(host)) return { eligible: false, ip: host, observable: raw };
      return { eligible: true, ip: host, observable: raw };
    } catch {
      return { eligible: false, ip: null, observable: raw };
    }
  }
  return { eligible: false, ip: null, observable: raw };
}

/**
 * UI-only eligibility for RDAP card (backend validation unchanged).
 * @returns {{ eligible: boolean, host: string|null, rdapDomain: string|null, reason: string|null }}
 */
function isRdapEligibleObservable(iocValue, iocType) {
  const type = String(iocType || '').toLowerCase();
  if (type !== 'domain' && type !== 'url') {
    return { eligible: false, host: null, rdapDomain: null, reason: 'unsupported_type' };
  }

  const raw = String(iocValue || '').trim();
  if (!raw) {
    return { eligible: false, host: null, rdapDomain: null, reason: 'empty' };
  }

  if (RDAP_HASH_RE.test(raw)) {
    return { eligible: false, host: null, rdapDomain: null, reason: 'hash' };
  }

  if (type === 'domain' && rdapIsIpHost(raw)) {
    return { eligible: false, host: raw, rdapDomain: null, reason: 'ip_observable' };
  }

  const extracted = rdapExtractHost(raw, type);
  if (!extracted.ok) {
    return { eligible: false, host: null, rdapDomain: null, reason: extracted.reason || 'invalid' };
  }

  const host = extracted.host;
  if (rdapIsIpHost(host)) {
    return { eligible: false, host, rdapDomain: null, reason: 'ip_host' };
  }

  const parsed = parseTld(host, RDAP_TLD_OPTS);
  const rdapDomain = parsed.domain ? String(parsed.domain).toLowerCase() : null;
  if (!rdapDomain) {
    return { eligible: false, host, rdapDomain: null, reason: 'no_registrable_domain' };
  }

  return { eligible: true, host, rdapDomain, reason: null };
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

function IpEnrichmentCard({ iocValue, iocType, active = true, isAdmin = false }) {
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
      const { data } = await api.post(`/enrichment/ip/${encodeURIComponent(ip)}/refresh${force ? '?force=true' : ''}`);
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
      setState({
        status: notConfigured ? 'not_configured' : 'failed',
        data: err?.response?.data || null,
        message: msg,
        providerConfigured: !notConfigured
      });
    } finally {
      setEnriching(false);
    }
  }

  const compactCardStyle = { marginBottom: 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0b1220', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' };
  const d = state.data || {};
  const signals = d.derived_signals || {};

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
    <div style={{ marginBottom: 14, padding: 14, border: '1px solid #334155', borderRadius: 12, background: '#0f172a' }}>
      <EnrichmentIntelligenceStyles />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontWeight: 700, color: '#e2e8f0' }}>
            IP Enrichment
            <span style={{ marginLeft: 8, border: '1px solid #1d4ed8', color: '#93c5fd', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>IPinfo Lite</span>
            {d.cached ? <span style={{ marginLeft: 8, border: '1px solid #475569', color: '#94a3b8', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>Cached</span> : null}
          </div>
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>
            {d.last_enriched_at ? `Last enriched: ${formatUserDateTime(d.last_enriched_at)}` : 'On-demand IP intelligence'}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={() => enrich(false).catch(() => {})} disabled={enriching}>{enriching ? 'Enriching…' : 'Refresh'}</button>
          {isAdmin ? <button type="button" onClick={() => enrich(true).catch(() => {})} disabled={enriching} title="Admin force refresh (5 min cooldown)">Force</button> : null}
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

      <div style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {signalBadge('IPinfo Available', signals.ipinfo_available)}
        {signalBadge('ASN Available', signals.asn_available)}
        {signalBadge('Country Available', signals.country_available)}
        {d.cached ? signalBadge('Cached', true) : null}
      </div>
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

function RdapEnrichmentCard({ iocValue, iocType, active = true, isAdmin = false }) {
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
      if (data?.enriched) {
        setState({ status: 'success', data, message: '' });
      } else if (data?.last_enriched_at && data?.rdap_status && data.rdap_status !== 'success') {
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
      const { data } = await api.post('/enrichment/rdap/refresh', {
        value,
        force: force || undefined,
        ioc_type: type
      });
      if (data?.enriched || data?.rdap_status === 'success') {
        setState({ status: 'success', data, message: '' });
      } else {
        setState({
          status: 'failed',
          data,
          message: data?.error_message || data?.error || data?.message || 'RDAP lookup failed'
        });
      }
    } catch (err) {
      const msg = err?.response?.status === 429
        ? 'RDAP rate limit reached. Try again later.'
        : (err?.response?.data?.error || err?.response?.data?.message || err?.response?.data?.error_message || 'RDAP lookup failed');
      setState({ status: 'failed', data: err?.response?.data || null, message: msg });
    } finally {
      setEnriching(false);
    }
  }

  const compactCardStyle = { marginBottom: 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0b1220', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' };
  const d = state.data || {};
  const signals = d.derived_signals || {};

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

  return (
    <div style={{ marginBottom: 14, padding: 14, border: '1px solid #334155', borderRadius: 12, background: '#0f172a' }}>
      <EnrichmentIntelligenceStyles />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontWeight: 700, color: '#e2e8f0' }}>
            RDAP / WHOIS Enrichment
            {d.cached ? <span style={{ marginLeft: 8, border: '1px solid #475569', color: '#94a3b8', borderRadius: 999, padding: '2px 8px', fontSize: 11 }}>Cached</span> : null}
          </div>
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>
            {d.last_enriched_at ? `Domain cache last enriched: ${formatUserDateTime(d.last_enriched_at)}` : 'Registration data from RDAP'}
          </div>
          {d.last_enriched_at ? (
            <div style={{ color: '#64748b', fontSize: 11, marginTop: 4, lineHeight: 1.45, maxWidth: 420 }}>
              RDAP data is cached by root domain and may predate this specific IOC record.
            </div>
          ) : null}
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={() => enrich(false).catch(() => {})} disabled={enriching}>{enriching ? 'Enriching…' : 'Refresh'}</button>
          {isAdmin ? <button type="button" onClick={() => enrich(true).catch(() => {})} disabled={enriching} title="Admin force refresh (5 min cooldown)">Force</button> : null}
        </div>
      </div>

      <RdapTargetNote data={d} />

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
      </div>

      <div className="enrichment-detail-stack">
        <EnrichmentDetailBlock label="Nameservers" value={nsList.length ? nsList.join(', ') : '-'} />
        <EnrichmentDetailBlock label="Status Codes" value={statusList.length ? statusList.join(' • ') : '-'} />
      </div>

      <div style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {signalBadge('RDAP Available', signals.rdap_available, signals.rdap_available ? 'ok' : 'neutral')}
        {signals.newly_registered_domain ? signalBadge('Newly Registered', true, 'warn') : null}
        {signals.expiring_soon ? signalBadge('Expiring Soon', true, 'warn') : null}
        {signals.redacted_or_private ? signalBadge('Privacy / Redacted', true, 'neutral') : null}
        {signals.registrar_available ? signalBadge('Registrar Available', true, 'ok') : null}
        {signals.nameservers_available ? signalBadge('Nameservers Available', true, 'ok') : null}
      </div>
    </div>
  );
}

const TAG_PICKER_LIMIT = 5;
const TAG_PICKER_ITEM_HEIGHT = 34;
const TAG_PICKER_LIST_HEIGHT = TAG_PICKER_ITEM_HEIGHT * TAG_PICKER_LIMIT + 6 * (TAG_PICKER_LIMIT - 1);

const IOC_DETAIL_TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'intelligence', label: 'Intelligence' },
  { id: 'environment', label: 'Environment Impact' },
  { id: 'evidence', label: 'Evidence & Events' },
  { id: 'audit', label: 'Audit / History', adminOnly: true }
];

function IocDetailTabBar({ tabs, activeTab, onChange }) {
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14, borderBottom: '1px solid #334155', paddingBottom: 10 }}>
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onChange(t.id)}
          style={{
            padding: '8px 14px',
            borderRadius: 8,
            border: `1px solid ${activeTab === t.id ? '#93c5fd' : '#475569'}`,
            background: activeTab === t.id ? 'rgba(59,130,246,0.15)' : '#0f172a',
            color: activeTab === t.id ? '#93c5fd' : '#cbd5e1',
            fontWeight: activeTab === t.id ? 700 : 500,
            cursor: 'pointer'
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

function IocEnvironmentMiniSummary({ impact }) {
  const imp = impact || {};
  const observed = imp.observed_in_environment === true || Number(imp.incident_count || 0) > 0;
  const items = [
    { label: 'Incidents', value: imp.incident_count ?? 0 },
    { label: 'Detection Events', value: imp.detection_event_count ?? 0 },
    { label: 'Observed Hosts', value: imp.observed_host_count ?? 0 },
    { label: 'Allowed / Blocked / Unknown', value: `${imp.allowed_count ?? 0} / ${imp.blocked_count ?? 0} / ${imp.unknown_action_count ?? 0}`, text: true },
    { label: 'Max Incident Risk', value: imp.max_incident_risk_score != null ? Number(imp.max_incident_risk_score).toFixed(2) : 'N/A', text: true },
    { label: 'Avg Incident Risk', value: imp.avg_incident_risk_score != null ? Number(imp.avg_incident_risk_score).toFixed(2) : 'N/A', text: true },
    { label: 'Open / Closed Incidents', value: `${imp.related_open_incidents ?? 0} / ${imp.related_closed_incidents ?? 0}`, text: true }
  ];

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
      <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 8 }}>Environment Summary</div>
      {!observed ? (
        <div style={{ color: '#94a3b8', fontSize: 13 }}>Not observed in environment telemetry yet.</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 8 }}>
          {items.map((c) => (
            <div key={c.label} style={{ border: '1px solid #1e293b', borderRadius: 8, padding: '8px 10px', background: '#111827' }}>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>{c.label}</div>
              <div style={{ fontSize: c.text ? 13 : 18, fontWeight: 700, color: '#e2e8f0', marginTop: 4 }}>{c.value}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function IocDetectionEventsPanel({ observable, enabled }) {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!enabled || !observable) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError('');
      try {
        const { data } = await api.get('/ioc/match-events', { params: { limit: 100, q: observable } });
        if (cancelled) return;
        const items = Array.isArray(data?.items) ? data.items : [];
        const norm = String(observable || '').trim().toLowerCase();
        setRows(items.filter((r) => String(r.matched_ioc || '').trim().toLowerCase() === norm));
      } catch {
        if (!cancelled) {
          setRows([]);
          setError('Failed to load detection events');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })().catch(() => {});
    return () => { cancelled = true; };
  }, [enabled, observable]);

  if (!enabled) return null;

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>
        Detection Events {rows.length ? `(${rows.length})` : ''}
      </div>
      <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 1100, fontSize: 13 }}>
        <thead>
          <tr style={{ textAlign: 'left', background: '#111827' }}>
            <th style={{ width: 80 }}>ID</th>
            <th style={{ width: 170 }}>Detected At</th>
            <th style={{ width: 200 }}>Context</th>
            <th style={{ width: 130 }}>Detection</th>
            <th style={{ width: 120 }}>Verdict</th>
            <th style={{ width: 160 }}>Source</th>
            <th style={{ width: 120 }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {loading ? <tr><td colSpan={7} style={{ color: '#94a3b8' }}>Loading detection events...</td></tr> : error ? <tr><td colSpan={7} style={{ color: '#fca5a5' }}>{error}</td></tr> : rows.length ? rows.map((r) => {
            const verdict = String(r.verdict || '').toLowerCase();
            const vm = verdict === 'fp'
              ? { label: 'FP', color: '#ef4444' }
              : verdict === 'tp'
                ? { label: 'TP', color: '#22c55e' }
                : verdict === 'in_progress'
                  ? { label: 'In Progress', color: '#f59e0b' }
                  : { label: 'Unreviewed', color: '#94a3b8' };
            return (
              <tr key={r.id} style={{ borderTop: '1px solid #334155' }}>
                <td>{r.id}</td>
                <td>{formatUserDateTime(r.detected_at || r.event_time || r.created_at)}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{normalizeEventContext(r)}</td>
                <td>
                  <span style={{
                    display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                    border: `1px solid ${r.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e'}`,
                    color: r.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e', background: '#020617'
                  }}>
                    {r.detection_mode === 'retroactive' ? 'Retroactive' : 'Real-Time'}
                  </span>
                </td>
                <td>
                  <span style={{
                    display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                    border: `1px solid ${vm.color}`, color: vm.color, background: '#020617'
                  }}>{vm.label}</span>
                </td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {(r.source_names && r.source_names[0]) || r.source_name || '-'}
                </td>
                <td>
                  <button type="button" onClick={() => navigate(`/analytics/detection-events/${r.id}`)} title="View detail" style={{ minWidth: 32, padding: '4px 8px' }}>🔍</button>
                </td>
              </tr>
            );
          }) : <tr><td colSpan={7} style={{ color: '#94a3b8' }}>No detection events found for this IOC.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function IocRelatedLogsByIncidentsPanel({ incidents, enabled }) {
  if (!enabled) return null;
  const list = (incidents || []).filter((inc) => inc.incident_id || inc.id);
  if (!list.length) {
    return (
      <div style={{ padding: 12, border: '1px solid #334155', borderRadius: 10, color: '#94a3b8', fontSize: 13 }}>
        No related incidents — evidence logs are shown per incident when available.
      </div>
    );
  }
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {list.map((inc) => (
        <div key={`ioc-ev-${inc.id}-${inc.incident_id}`}>
          <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 8 }}>Incident #{inc.incident_id ?? '-'}</div>
          <IncidentRelatedLogsTable incidentId={inc.incident_id || inc.id} />
        </div>
      ))}
    </div>
  );
}

function iocAuditMetadataSummary(metadata) {
  if (!metadata || typeof metadata !== 'object') return '-';
  const confidenceText = formatConfidenceAuditMetadata(metadata);
  if (confidenceText) return confidenceText;
  const expirationParts = [];
  const iocValue = auditMetadataValue(metadata, 'ioc_value');
  const iocType = auditMetadataValue(metadata, 'ioc_observable_type', 'observable_type');
  if (iocValue) expirationParts.push(String(iocValue));
  if (iocType) expirationParts.push(String(iocType));
  const statusTransition = formatAuditStatusTransition(metadata);
  if (statusTransition && statusTransition !== '—') expirationParts.push(statusTransition);
  const reason = auditMetadataValue(metadata, 'reason');
  if (reason) expirationParts.push(formatExpirationAuditReasonLabel(reason));
  const feedName = auditMetadataValue(metadata, 'feed_name');
  if (feedName) expirationParts.push(String(feedName));
  if (expirationParts.length) return expirationParts.join(' · ');
  const parts = [];
  if (metadata.provider) parts.push(String(metadata.provider));
  if (metadata.cached === true) parts.push('cached');
  if (metadata.root_domain) parts.push(`root: ${metadata.root_domain}`);
  if (metadata.ip) parts.push(`ip: ${metadata.ip}`);
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
  const { isAdmin, canWrite } = useSession();
  const detailsPublicId = String(publicId || '').trim();
  const ui = PUBLISHED_FEEDS_UI;

  const [loading, setLoading] = useState(true);
  const [data, setData] = useState({ summary: null, sources: [], matches: [], suppression: { active: false } });
  const [iocTags, setIocTags] = useState([]);
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
  const [actionToast, setActionToast] = useState('');
  const [activeTab, setActiveTab] = useState('overview');
  const [pendingAction, setPendingAction] = useState(null);
  const [actionReason, setActionReason] = useState('');
  const [actionExpireAt, setActionExpireAt] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState('');
  const [actionRefreshWarn, setActionRefreshWarn] = useState(''); // page-level warning after modal closes
  const [showConfidenceModal, setShowConfidenceModal] = useState(false);
  const [confidenceDraft, setConfidenceDraft] = useState('medium');
  const [confidenceReason, setConfidenceReason] = useState('');
  const [confidenceSaving, setConfidenceSaving] = useState(false);
  const [confidenceError, setConfidenceError] = useState('');

  async function load() {
    setLoading(true);
    if (!detailsPublicId) {
      setData({ summary: null, sources: [], matches: [] });
      setLoading(false);
      return { ok: false };
    }
    try {
      const res = await api.get('/ioc/details', { params: { public_id: detailsPublicId } });
      setData(res.data || { summary: null, sources: [], matches: [], suppression: { active: false } });
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
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      setIocTags([]);
      return;
    }
    loadIocTags(iocId).catch(() => {});
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

  async function submitRemoveSuppression() {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) return;
    setRemoveSaving(true);
    setRemoveError('');
    try {
      await api.delete(`/ioc/${iocId}/suppress`);
      setShowRemoveConfirm(false);
      setActionToast('Suppression removed');
      await load();
    } catch (err) {
      const msg = apiErrorMessage(err, 'Suppression failed');
      setRemoveError(msg.includes('Forbidden') ? 'You do not have permission to modify suppressions' : msg);
    } finally {
      setRemoveSaving(false);
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

  async function removeIocTag(tagId) {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) return;

    setTagsSaving(true);
    try {
      await api.delete(`/ioc/${iocId}/tags/${Number(tagId)}`);
      setIocTags((prev) => prev.filter((t) => Number(t.id) !== Number(tagId)));
    } catch (err) {
      console.log('[ioc-tags] delete failed', err);
    } finally {
      setTagsSaving(false);
    }
  }

  const summary = data.summary;
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

  function openExpirationAction(type, membershipId = null) {
    const preset = IOC_EXPIRATION_ACTION_PRESETS[type];
    if (!preset) return;
    setActionError('');
    setActionRefreshWarn('');
    setActionReason('');
    setActionExpireAt('');
    setPendingAction({ type, membershipId, ...preset });
  }

  function cancelExpirationAction() {
    if (actionLoading) return;
    setPendingAction(null);
    setActionReason('');
    setActionExpireAt('');
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
      manualExpiresAt = d.toISOString();
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
        const { data } = await api.patch(`/ioc/${iocId}/status-override`, {
          observable_type: observableType,
          manual_status_override: true,
          manual_status: 'active',
          manual_expires_at: null,
          reason
        });
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
  const evidenceTabActive = activeTab === 'evidence';
  const intelligenceTabActive = activeTab === 'intelligence';
  const auditTabActive = activeTab === 'audit' && isAdmin;

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#0f172a', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <div>
            <h2 style={{ margin: 0, color: '#f1f5f9' }}>IOC Details</h2>
            <div style={{ marginTop: 6, color: '#94a3b8', fontSize: 13 }}>Analyst-focused detail page for faster triage</div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
            {summary && !suppressionActive && isAdmin ? (
              <button type="button" style={ui.btnPrimary} onClick={() => { setShowSuppressModal(true); setSuppressError(''); }}>Mark as False Positive</button>
            ) : null}
            <button onClick={() => navigate('/ioc')}>Back to IOC List</button>
            <button onClick={() => load().catch(() => {})}>Refresh</button>
          </div>
        </div>

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

        <div style={{ marginBottom: 14, padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>IOC</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <div style={{ fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace", fontSize: 15, overflowWrap: 'anywhere' }}><b>{displayObservable}</b></div>
            {summary ? iocStatusBadge(summary.status) : null}
          </div>
        </div>

        {loading ? <div>Loading...</div> : !summary ? (
          <div style={{ padding: 12, border: '1px solid #334155', borderRadius: 10 }}>No IOC detail found.</div>
        ) : (
          <>
            {suppressionActive ? (
              <div style={{ marginBottom: 14, padding: 14, borderRadius: 10, border: '1px solid #166534', background: 'rgba(34,197,94,0.08)' }}>
                <div style={{ fontWeight: 700, color: '#86efac', marginBottom: 8 }}>This IOC is marked as False Positive / Suppressed.</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, fontSize: 13, color: '#cbd5e1' }}>
                  <div><span style={{ color: '#94a3b8' }}>Reason:</span> {suppression.reason || '—'}</div>
                  <div><span style={{ color: '#94a3b8' }}>Scope:</span> {suppression.scope || 'global'}</div>
                  <div><span style={{ color: '#94a3b8' }}>Created by:</span> {suppression.created_by || '—'}</div>
                  <div><span style={{ color: '#94a3b8' }}>Created at:</span> {formatUserDateTime(suppression.created_at)}</div>
                  <div><span style={{ color: '#94a3b8' }}>Expires at:</span> {suppression.expires_at ? formatUserDateTime(suppression.expires_at) : 'Never'}</div>
                  <div><span style={{ color: '#94a3b8' }}>Risk contribution:</span> 0</div>
                </div>
                <div style={{ display: 'flex', gap: 10, marginTop: 12, flexWrap: 'wrap' }}>
                  <button type="button" style={ui.btn} onClick={() => navigate(`/operations/ioc-suppressions?search=${encodeURIComponent(summary.observable || '')}`)}>Manage suppression</button>
                  {isAdmin ? (
                    <button type="button" style={{ ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => { setShowRemoveConfirm(true); setRemoveError(''); }}>Remove suppression</button>
                  ) : null}
                </div>
              </div>
            ) : null}

            <IocDetailTabBar tabs={visibleTabs} activeTab={activeTab} onChange={setActiveTab} />

            {activeTab === 'overview' ? (
              <div style={{ display: 'grid', gap: 14 }}>
                {summary && iocStatusCard ? (
                  <div style={{ padding: 14, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
                    <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>IOC Status</div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, fontSize: 13, color: '#cbd5e1' }}>
                      {iocStatusCard.fields.map((field) => (
                        <div key={field.key}>
                          <span style={{ color: '#94a3b8' }}>{field.label}</span>{' '}
                          {field.kind === 'badge'
                            ? iocStatusBadge(field.status)
                            : field.kind === 'datetime'
                              ? formatUserDateTime(field.raw)
                              : field.value}
                        </div>
                      ))}
                    </div>
                    {isAdmin && iocStatusCard.buttons.length ? (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                        {iocStatusCard.buttons.map((actionType) => {
                          const def = IOC_STATUS_ACTION_BUTTONS[actionType];
                          if (!def) return null;
                          const btnStyle = def.danger
                            ? { ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }
                            : ui.btn;
                          return (
                            <button
                              key={actionType}
                              type="button"
                              style={btnStyle}
                              disabled={actionLoading}
                              onClick={() => openExpirationAction(actionType)}
                            >
                              {def.label}
                            </button>
                          );
                        })}
                      </div>
                    ) : null}
                  </div>
                ) : null}

                {feedMemberships.length ? (
                  <div style={{ padding: 14, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
                    <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>Feed Sources</div>
                    <div style={{ overflowX: 'auto' }}>
                      <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 12, color: '#e2e8f0' }}>
                        <thead>
                          <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                            <th>Feed</th><th>Status</th><th>First seen</th><th>Last seen</th><th>Policy expires</th><th>Effective expires</th><th>Override</th><th>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {feedMemberships.map((m) => (
                            <tr key={m.id} style={{ borderBottom: '1px solid #1e293b' }}>
                              <td>{m.feed_name || m.feed_key}</td>
                              <td>{iocStatusBadge(m.status)}</td>
                              <td>{formatUserDateTime(m.first_seen_in_feed)}</td>
                              <td>{formatUserDateTime(m.last_seen_in_feed)}</td>
                              <td>{formatUserDateTime(m.policy_expires_at)}</td>
                              <td>{formatUserDateTime(m.expires_at)}</td>
                              <td>{m.override_enabled ? 'Yes' : 'No'}</td>
                              <td>
                                {isAdmin ? (
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                                    <button type="button" style={{ fontSize: 11 }} disabled={actionLoading} onClick={() => openExpirationAction('reactivate_membership', m.id)}>Reactivate source</button>
                                    <button type="button" style={{ fontSize: 11 }} disabled={actionLoading} onClick={() => openExpirationAction('custom_expire_membership', m.id)}>Custom expire</button>
                                    <button type="button" style={{ fontSize: 11 }} disabled={actionLoading} onClick={() => openExpirationAction('expire_membership', m.id)}>Expire source</button>
                                    <button type="button" style={{ fontSize: 11 }} disabled={actionLoading} onClick={() => openExpirationAction('clear_membership_override', m.id)}>Clear override</button>
                                  </div>
                                ) : '—'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : null}

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 10 }}>
                  <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>Type</div><div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0' }}>{summary.observable_type || '-'}</div></div>
                  <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>Source Count</div><div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0' }}>{summary.source_count || 0}</div></div>
                  <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>First Seen</div><div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0' }}>{formatUserDateTime(summary.first_seen_at)}</div></div>
                  <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>Last Seen</div><div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0' }}>{formatUserDateTime(summary.last_seen_at)}</div></div>
                  <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#111827' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>Evidence Logs</div><div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0' }}>{Number(data.summary?.evidence_logs_count || 0)}</div></div>
                </div>

                <div style={{ padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 8 }}>
                    <div style={{ fontSize: 13, color: '#94a3b8' }}>Confidence</div>
                    {canWrite ? (
                      <button type="button" onClick={openConfidenceEditor} style={{ fontSize: 12, padding: '4px 10px' }}>
                        Edit
                      </button>
                    ) : null}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
                    <span style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      padding: '4px 10px',
                      borderRadius: 999,
                      fontSize: 13,
                      fontWeight: 700,
                      background: confidenceCard.badgeStyle.bg,
                      color: confidenceCard.badgeStyle.color,
                      border: `1px solid ${confidenceCard.badgeStyle.border}`
                    }}>
                      {confidenceCard.effectiveLabel}
                    </span>
                    {confidenceCard.hasOverride ? (
                      <span style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, background: '#312e81', color: '#c7d2fe', border: '1px solid #4338ca' }}>
                        Manual override
                      </span>
                    ) : null}
                  </div>
                  <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.5 }}>
                    {confidenceCard.hasOverride ? confidenceCard.overrideLine : `Source: ${confidenceCard.sourceLine.replace(/^Source: /, '')}`}
                  </div>
                  {confidenceCard.reasonLine ? (
                    <div style={{ fontSize: 12, color: '#cbd5e1', marginTop: 6 }}>{confidenceCard.reasonLine}</div>
                  ) : null}
                  {(summary.confidence_set || []).length > 1 ? (
                    <div style={{ marginTop: 10, display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                      <span style={{ fontSize: 11, color: '#64748b' }}>All sources:</span>
                      {summary.confidence_set.map((c) => (
                        <span key={c} style={{ padding: '2px 8px', borderRadius: 999, border: '1px solid #475569', color: '#e2e8f0', fontSize: 11 }}>{c}</span>
                      ))}
                    </div>
                  ) : null}
                </div>

                <div style={{ padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
                  <div style={{ fontSize: 13, marginBottom: 8, color: '#94a3b8' }}>Tags</div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                    {iocTags.length ? iocTags.map((tag) => (
                      <span
                        key={`tag-${tag.id}`}
                        title={tag.is_active === false ? 'Inactive tag (no longer available for new assignments)' : undefined}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 6,
                          padding: '4px 8px',
                          borderRadius: 999,
                          border: `1px solid ${tag.is_active === false ? '#64748b' : (tag.color || '#475569')}`,
                          fontSize: 12,
                          color: tag.is_active === false ? '#94a3b8' : '#e2e8f0',
                          background: tag.color && tag.is_active !== false ? `${tag.color}22` : 'transparent',
                          opacity: tag.is_active === false ? 0.85 : 1
                        }}
                      >
                        {tag.name}
                        <button
                          type="button"
                          onClick={() => removeIocTag(tag.id).catch(() => {})}
                          title="Remove tag"
                          aria-label={`Remove ${tag.name}`}
                          style={{ padding: 0, border: 'none', background: 'transparent', color: '#94a3b8', cursor: tagsSaving ? 'wait' : 'pointer', lineHeight: 1 }}
                          disabled={tagsSaving}
                        >
                          ×
                        </button>
                      </span>
                    )) : <span style={{ color: '#94a3b8', fontSize: 12 }}>No tags</span>}

                    <div style={{ position: 'relative' }} ref={tagDropdownRef}>
                      <button type="button" onClick={() => setTagDropdownOpen((v) => !v)} disabled={tagsSaving}>
                        + Add Tag {tagsLoading || tagsSaving ? '⏳' : ''}
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
                </div>

                <IocEnvironmentMiniSummary impact={data.impact} />
              </div>
            ) : null}

            {activeTab === 'intelligence' ? (
              <div style={{ display: 'grid', gap: 14 }}>
                <VirusTotalEnrichmentCard iocId={summary.id} active={intelligenceTabActive} />
                <IpEnrichmentCard iocValue={summary.observable} iocType={summary.observable_type} active={intelligenceTabActive} isAdmin={isAdmin} />
                {isRdapEligibleObservable(summary.observable, summary.observable_type).eligible ? (
                  <RdapEnrichmentCard iocValue={summary.observable} iocType={summary.observable_type} active={intelligenceTabActive} isAdmin={isAdmin} />
                ) : null}

            {isHashObservable && hasMeaningfulFileInfo ? (
              <div style={{ marginBottom: 14, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
                <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>File Information</div>
                <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', fontSize: 13 }}>
                  <tbody>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>File Name</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.file_name || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>File Type</th><td>{summary.file_information.file_type || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>MIME</th><td>{summary.file_information.mime || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>MD5</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.md5 || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SHA1</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.sha1 || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SHA256</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.sha256 || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>IMPHASH</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.imphash || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>TLSH</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.tlsh || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SSDEEP</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.ssdeep || '-'}</td></tr>
                  </tbody>
                </table>
              </div>
            ) : null}

                <div style={{ border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
              <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Source Evidence</div>
              <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 900, fontSize: 13 }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#111827' }}>
                    <th>Source</th><th>URL</th><th>Confidence</th><th>Category</th><th>Note</th><th>Created At</th>
                  </tr>
                </thead>
                <tbody>
                  {data.sources.map((s) => (
                    <tr key={`${s.id}-${s.created_at}`} style={{ borderTop: '1px solid #334155' }}>
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{s.source_name || '-'}</td>
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{s.source_url || '-'}</td>
                      <td>{s.confidence || '-'}</td>
                      <td>{s.category || '-'}</td>
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{sanitizeSourceNote(s.note)}</td>
                      <td>{formatUserDateTime(s.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
                </div>
              </div>
            ) : null}

            {activeTab === 'environment' ? (
              <div style={{ display: 'grid', gap: 14 }}>
                <IocEnvironmentImpactPanel impact={data.impact} />

                <div style={{ border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
                  <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Related Incidents</div>
                  <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 1380, fontSize: 13 }}>
                    <thead>
                      <tr style={{ textAlign: 'left', background: '#111827' }}>
                        <th style={{ width: 100 }}>Incident ID</th>
                        <th style={{ width: 160 }}>First Seen</th>
                        <th style={{ width: 160 }}>Last Seen</th>
                        <th style={{ width: 120 }}>Detection Events</th>
                        <th style={{ width: 110 }}>Evidence Logs</th>
                        <th style={{ width: 120 }}>Observed Hosts</th>
                        <th style={{ width: 120 }}>Verdict</th>
                        <th style={{ width: 100 }}>Status</th>
                        <th style={{ width: 100 }}>Risk Score</th>
                        <th style={{ width: 120 }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(data.incidents || []).length ? (data.incidents || []).map((inc) => (
                        <tr key={`inc-${inc.id}`} style={{ borderTop: '1px solid #334155' }}>
                          <td>#{inc.incident_id ?? '-'}</td>
                          <td>{formatUserDateTime(inc.first_seen)}</td>
                          <td>{formatUserDateTime(inc.last_seen)}</td>
                          <td>{Number(inc.detection_events || 0)}</td>
                          <td>{Number.isFinite(Number(inc.evidence_logs)) ? Number(inc.evidence_logs) : '-'}</td>
                          <td>{Number(inc.observed_hosts || 0)}</td>
                          <td>{inc.verdict || 'Unreviewed'}</td>
                          <td>{inc.status || '-'}</td>
                          <td>{Number.isFinite(Number(inc.risk_score)) ? Number(inc.risk_score).toFixed(2) : '-'}</td>
                          <td>
                            <button type="button" onClick={() => navigate(`/incidents/${inc.incident_id || inc.id}`)} title="View incident" aria-label="View incident" style={{ minWidth: 32, padding: '4px 8px' }}>🔍</button>
                          </td>
                        </tr>
                      )) : <tr><td colSpan={10} style={{ color: '#94a3b8' }}>No related incidents found for this IOC.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            {activeTab === 'evidence' ? (
              <div style={{ display: 'grid', gap: 14 }}>
                <IocDetectionEventsPanel observable={summary.observable} enabled={evidenceTabActive} />
                <IocRelatedLogsByIncidentsPanel incidents={data.incidents} enabled={evidenceTabActive} />
              </div>
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
          <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>Remove suppression</h3>
          <p style={ui.modalSub}>This will allow this IOC to become active again in future imports/correlation. Existing closed incidents will not be automatically reopened.</p>
          {removeError ? <div style={{ color: '#fca5a5', fontSize: 13, marginBottom: 10 }}>{removeError}</div> : null}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button type="button" style={ui.btn} onClick={() => setShowRemoveConfirm(false)} disabled={removeSaving}>Cancel</button>
            <button type="button" style={{ ...ui.btn, borderColor: '#7f1d1d', color: '#fca5a5' }} onClick={() => submitRemoveSuppression().catch(() => {})} disabled={removeSaving}>{removeSaving ? 'Removing…' : 'Remove suppression'}</button>
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
    </AppShell>
  );
}

function IOCAddPage() {
  const navigate = useNavigate();
  const { canWrite } = useSession();
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState(null);
  const [recentRows, setRecentRows] = useState([]);
  const [recentSort, setRecentSort] = useState({ key: null, dir: null });
  const [recentWidths, setRecentWidths] = useState({ idx: 50, observable: 420, type: 110, source: 220, confidence: 110, ts: 170 });
  const [recentResize, setRecentResize] = useState(null);
  const [iocValue, setIocValue] = useState('');
  const [confidenceValue, setConfidenceValue] = useState('medium');
  const iocFormRef = useRef(null);

  useEffect(() => {
    if (!message) return;
    const t = setTimeout(() => setMessage(null), 4000);
    return () => clearTimeout(t);
  }, [message]);


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

  function sourceBadgeStyle(source) {
    const seed = String(source || 'source').length;
    const hue = (seed * 23) % 360;
    return {
      color: '#cbd5e1',
      border: `1px solid hsl(${hue} 60% 35%)`,
      background: `hsla(${hue}, 75%, 20%, 0.45)`
    };
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
    return recentSort.dir === 'asc' ? ' ▲' : ' ▼';
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
      if (k === 'source') return r.source_name || '';
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

  async function onSubmit(e) {
    e.preventDefault();
    if (!canWrite || submitting) return;
    setSubmitting(true);

    const formEl = iocFormRef.current || e.currentTarget;
    const form = new FormData(formEl);
    const payload = {
      ip: String(form.get('ip') || '').trim(),
      source_name: String(form.get('source_name') || '').trim(),
      source_url: String(form.get('source_url') || '').trim(),
      confidence: form.get('confidence'),
      category: String(form.get('category') || '').trim(),
      note: String(form.get('note') || '').trim()
    };

    try {
      const { data } = await api.post('/ioc/ip', payload);
      formEl?.reset?.();
      setIocValue('');
      setConfidenceValue('medium');
      loadRecent().catch(() => {});
      if (data?.skipped) {
        setMessage({ type: 'duplicate', text: 'Already in list (duplicate).' });
      } else {
        setMessage({ type: 'success', text: 'IOC saved successfully.' });
      }
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.response?.data?.message || err?.message || 'Failed to save record';
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
                <label htmlFor="source-name" style={fieldLabelStyle}>Source Name</label>
                <input id="source-name" name="source_name" required disabled={!canWrite} style={inputStyle} />
              </div>
              <div>
                <label htmlFor="source-url" style={fieldLabelStyle}>Source URL</label>
                <input id="source-url" name="source_url" disabled={!canWrite} style={inputStyle} />
              </div>
            </div>

            <div style={twoColRowStyle}>
              <div>
                <label htmlFor="confidence" style={fieldLabelStyle}>Confidence</label>
                <select id="confidence" name="confidence" value={confidenceValue} onChange={(e) => setConfidenceValue(e.target.value)} disabled={!canWrite} style={{ ...inputStyle, background: confidenceStyle.bg, color: confidenceStyle.color, fontWeight: 700, fontSize: 12, textTransform: 'capitalize' }}>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div>
                <label htmlFor="category" style={fieldLabelStyle}>Category</label>
                <input id="category" name="category" disabled={!canWrite} style={inputStyle} />
              </div>
            </div>

            <div>
              <label htmlFor="note" style={fieldLabelStyle}>Note</label>
              <input id="note" name="note" disabled={!canWrite} style={inputStyle} />
            </div>

            <button type="submit" disabled={submitting || !canWrite} style={{ width: '100%', padding: '11px 14px', borderRadius: 10, border: '1px solid #1d4ed8', background: submitting || !canWrite ? '#1e3a8a' : '#2563eb', color: '#dbeafe', fontWeight: 700, letterSpacing: 0.3, cursor: submitting || !canWrite ? 'not-allowed' : 'pointer', opacity: submitting || !canWrite ? 0.7 : 1 }}>
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
                  const sourceStyle = sourceBadgeStyle(r.source_name);
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
                      <td title={r.source_name} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                        <span style={{ display: 'inline-flex', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700, ...sourceStyle }}>{r.source_name || '-'}</span>
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
  return <Navigate to="/analytics" replace />;
}

function App() {
  return (
    <>
      <style>{`
        :root { color-scheme: dark; }
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
      `}</style>
      <BrowserRouter>
        <SessionProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/system" element={<Protected><SystemStatusPage /></Protected>} />
          
          <Route path="/analytics" element={<Protected><AnalyticsPage /></Protected>} />
          <Route path="/analytics/statistics" element={<Protected><AnalyticsStatisticsPage /></Protected>} />
          <Route path="/analytics/detection-events" element={<Protected><IOCMatchEventsPage /></Protected>} />
          <Route path="/analytics/detection-events/:id" element={<Protected><IOCMatchEventDetailsPage /></Protected>} />
          <Route path="/risk-overview" element={<Protected><RiskOverviewPage /></Protected>} />
          <Route path="/incidents" element={<Protected><IncidentPage /></Protected>} />
          <Route path="/incidents/:id" element={<Protected><IncidentDetailsPage /></Protected>} />
          <Route path="/incident" element={<Navigate to="/incidents" replace />} />
          <Route path="/ioc" element={<Protected><IOCListPage /></Protected>} />
          <Route path="/ioc/hot" element={<Protected><IOCHotListPage /></Protected>} />
          <Route path="/ioc/details/:publicId" element={<Protected><IOCDetailsPage /></Protected>} />
          <Route path="/ioc/details/:type/:observable" element={<Protected><LegacyIOCDetailsRedirect /></Protected>} />
          <Route path="/ioc/new" element={<Protected><IOCAddPage /></Protected>} />
          <Route path="/operations/ioc-suppressions" element={<Protected><IOCSuppressionsPage /></Protected>} />
          <Route path="/threat-intelligence" element={<Navigate to="/threat-intelligence/feeds" replace />} />
          <Route path="/threat-intelligence/feeds" element={<Protected><IntegrationsPage /></Protected>} />
          <Route path="/threat-intelligence/enrichment" element={<Navigate to="/administration/enrichment-providers" replace />} />
          <Route path="/threat-intelligence/queue" element={<Protected><IntegrationsQueueStatusPage /></Protected>} />
          <Route path="/threat-intelligence/runs" element={<Protected><IntegrationsRecentRunsPage /></Protected>} />
          <Route path="/threat-intelligence/published-feeds" element={<Protected><PublishedFeedsPage /></Protected>} />
          <Route path="/administration/audit-logs" element={<Protected><AuditLogsPage /></Protected>} />
          <Route path="/administration/tags" element={<Protected><TagManagerPage /></Protected>} />
          <Route path="/administration/api-keys" element={<Protected><ApiKeysPage /></Protected>} />
          <Route path="/administration/enrichment-providers" element={<Protected><EnrichmentProvidersPage /></Protected>} />
          <Route path="/administration/users" element={<Protected><UsersPage /></Protected>} />
          <Route path="/administration" element={<Protected><AdministrationSettingsPage /></Protected>} />
          <Route path="/settings" element={<Navigate to="/administration" replace />} />
          <Route path="*" element={<DefaultRedirect />} />
        </Routes>
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
