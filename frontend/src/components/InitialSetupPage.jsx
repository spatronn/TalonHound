import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api.js';
import { setSystemTimezoneCache, notifyTimezoneChanged } from '../lib/formatDate.js';

const FALLBACK_ZONES = [
  'UTC',
  'Europe/Istanbul',
  'Europe/London',
  'Europe/Berlin',
  'America/New_York',
  'Asia/Dubai',
  'Asia/Tokyo',
  'Australia/Sydney'
];

function listIanaTimezones() {
  try {
    if (typeof Intl !== 'undefined' && typeof Intl.supportedValuesOf === 'function') {
      return Intl.supportedValuesOf('timeZone');
    }
  } catch {
    // ignore
  }
  return FALLBACK_ZONES;
}

/**
 * Mandatory first-run System Timezone setup.
 * Blocks access to the rest of the app until completed.
 */
export default function InitialSetupPage({ onCompleted }) {
  const [zones, setZones] = useState(() => listIanaTimezones());
  const [timezone, setTimezone] = useState('');
  const [filter, setFilter] = useState('');
  const [utcNow, setUtcNow] = useState('');
  const [systemNow, setSystemNow] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [configRequired, setConfigRequired] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await api.get('/setup/status');
        if (cancelled) return;
        if (data.initial_setup_completed && data.active_system_timezone && !data.timezone_configuration_required) {
          setSystemTimezoneCache(data.active_system_timezone || data.system_timezone);
          onCompleted?.(data);
          return;
        }
        setConfigRequired(Boolean(data.timezone_configuration_required));
        if (Array.isArray(data.common_timezones) && data.common_timezones.length) {
          const all = listIanaTimezones();
          const preferred = data.common_timezones.filter((z) => all.includes(z) || FALLBACK_ZONES.includes(z));
          const rest = all.filter((z) => !preferred.includes(z));
          setZones([...preferred, ...rest]);
        }
        setUtcNow(data.current_utc_time || new Date().toISOString());
      } catch (err) {
        if (!cancelled) setError(err?.response?.data?.message || err.message || 'Failed to load setup status');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [onCompleted]);

  useEffect(() => {
    if (!timezone) {
      setSystemNow('');
      return undefined;
    }
    let cancelled = false;
    const tick = async () => {
      try {
        const { data } = await api.get('/setup/preview', { params: { timezone } });
        if (cancelled) return;
        setUtcNow(data.utc_iso || '');
        setSystemNow(data.iso_with_offset || '');
      } catch {
        if (!cancelled) setSystemNow('');
      }
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [timezone]);

  const filteredZones = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return zones;
    return zones.filter((z) => z.toLowerCase().includes(q));
  }, [zones, filter]);

  async function confirm() {
    if (!timezone || saving) return;
    setSaving(true);
    setError('');
    try {
      const { data } = await api.post('/setup/complete', { timezone });
      setSystemTimezoneCache(data.system_timezone || timezone);
      notifyTimezoneChanged();
      onCompleted?.(data);
    } catch (err) {
      setError(err?.response?.data?.message || err.message || 'Failed to complete setup');
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div style={styles.page}>
        <div style={styles.card}>Loading setup…</div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <div style={styles.brand}>TalonHound</div>
        <h1 style={styles.title}>{configRequired ? 'Timezone Configuration Required' : 'System Timezone'}</h1>
        <p style={styles.lead}>
          {configRequired
            ? 'This existing TalonHound installation has no configured system timezone. An administrator must select a valid IANA timezone before feeds, schedulers, exports, and the rest of the application can run. Historical data is not changed.'
            : 'Choose the single timezone used across the entire TalonHound installation. Browser local time is never used for display, schedules, logs, or exports.'}
        </p>

        <label style={styles.label} htmlFor="setup-tz-filter">Search IANA timezones</label>
        <input
          id="setup-tz-filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="e.g. London, Istanbul, New_York"
          style={styles.input}
        />

        <label style={styles.label} htmlFor="setup-tz">System Timezone</label>
        <select
          id="setup-tz"
          value={timezone}
          onChange={(e) => setTimezone(e.target.value)}
          style={styles.select}
        >
          <option value="">Select a timezone…</option>
          {filteredZones.map((z) => (
            <option key={z} value={z}>{z}</option>
          ))}
        </select>

        <div style={styles.times}>
          <div><span style={styles.muted}>Current UTC time</span><div style={styles.mono}>{utcNow || '—'}</div></div>
          <div><span style={styles.muted}>Current system time</span><div style={styles.mono}>{systemNow || '—'}</div></div>
        </div>

        <div style={styles.warn}>
          TalonHound assumes host and Kubernetes node clocks are synchronized by your
          infrastructure to a reliable time source. The selected timezone will be used
          system-wide for application services, logs, scheduled jobs, exports, and every
          timestamp shown in the user interface.
        </div>

        {error ? <div style={styles.error}>{error}</div> : null}

        <button
          type="button"
          style={{ ...styles.button, opacity: !timezone || saving ? 0.55 : 1 }}
          disabled={!timezone || saving}
          onClick={() => confirm().catch(() => {})}
        >
          {saving ? 'Saving…' : 'Confirm and Continue'}
        </button>
      </div>
    </div>
  );
}

const styles = {
  page: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
    background: 'radial-gradient(1200px 600px at 20% -10%, #1e293b 0%, #0b1220 55%, #020617 100%)',
    fontFamily: 'Segoe UI, system-ui, sans-serif',
    color: '#e2e8f0'
  },
  card: {
    width: 'min(560px, 100%)',
    background: 'linear-gradient(180deg, #111827 0%, #0f172a 100%)',
    border: '1px solid #334155',
    borderRadius: 14,
    padding: 28,
    boxShadow: '0 24px 60px rgba(2, 6, 23, 0.55)'
  },
  brand: { fontSize: 13, letterSpacing: '0.08em', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700 },
  title: { margin: '8px 0 10px', fontSize: 28, fontWeight: 750, color: '#f8fafc' },
  lead: { margin: '0 0 20px', color: '#94a3b8', lineHeight: 1.5, fontSize: 14 },
  label: { display: 'block', fontSize: 13, color: '#cbd5e1', marginBottom: 6, fontWeight: 600 },
  input: {
    width: '100%', boxSizing: 'border-box', marginBottom: 14, padding: '10px 12px',
    borderRadius: 8, border: '1px solid #334155', background: '#0b1220', color: '#e2e8f0'
  },
  select: {
    width: '100%', boxSizing: 'border-box', marginBottom: 16, padding: '10px 12px',
    borderRadius: 8, border: '1px solid #334155', background: '#0b1220', color: '#e2e8f0'
  },
  times: {
    display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16
  },
  muted: { display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 4 },
  mono: { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: 13, color: '#e2e8f0' },
  warn: {
    background: 'rgba(245, 158, 11, 0.08)',
    border: '1px solid rgba(245, 158, 11, 0.35)',
    color: '#fde68a',
    borderRadius: 8,
    padding: 12,
    fontSize: 13,
    lineHeight: 1.5,
    marginBottom: 16
  },
  error: { color: '#fca5a5', marginBottom: 12, fontSize: 13 },
  button: {
    width: '100%', padding: '8px 14px', borderRadius: 8, border: '1px solid #475569',
    background: '#1f2937', color: '#e2e8f0', fontWeight: 600, cursor: 'pointer', fontSize: 13,
    minHeight: 36, lineHeight: 1.2
  }
};
