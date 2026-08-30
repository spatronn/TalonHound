import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { setSystemTimezoneCache, notifyTimezoneChanged } from '../lib/formatDate.js';
import TimezoneSelector from './TimezoneSelector.jsx';

const PRODUCT_VERSION = '0.1.0-beta.1';
const MIN_PASSWORD_LENGTH = 12;

/**
 * First-run Setup Wizard.
 *
 * Two branches, decided by the backend (never by browser state):
 *   - Greenfield install (no users): full wizard — optional one-time Setup Code, system
 *     check, create the System Administrator, select the system timezone, review, complete.
 *   - Existing install missing a timezone: the timezone-only configuration screen (an
 *     administrator must sign in first). No administrator is created in this branch.
 *
 * Blocks the rest of the app until setup is complete.
 */
export default function InitialSetupPage({ onCompleted }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [mode, setMode] = useState(null); // 'greenfield' | 'timezone_only'
  const [codeRequired, setCodeRequired] = useState(false);

  // greenfield step machine
  const [step, setStep] = useState('welcome'); // welcome | check | admin | timezone | review
  const [code, setCode] = useState('');
  const [codeVerified, setCodeVerified] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [timezone, setTimezone] = useState('');
  const [utcNow, setUtcNow] = useState('');
  const [systemNow, setSystemNow] = useState('');
  const [checks, setChecks] = useState(null);
  const [checking, setChecking] = useState(false);
  const [busy, setBusy] = useState(false);

  // existing-install timezone-only branch state
  const [configRequired, setConfigRequired] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await api.get('/setup/status');
        if (cancelled) return;
        const runtimeReady = data.initial_setup_completed
          && data.active_system_timezone
          && !data.timezone_configuration_required;
        if (runtimeReady && !data.admin_setup_required) {
          setSystemTimezoneCache(data.active_system_timezone || data.system_timezone);
          onCompleted?.(data);
          return;
        }
        if (data.admin_setup_required) {
          setMode('greenfield');
          setCodeRequired(Boolean(data.setup_code_required));
          setStep('welcome');
        } else {
          setMode('timezone_only');
          setConfigRequired(Boolean(data.timezone_configuration_required));
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

  // Live timezone preview.
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
    return () => { cancelled = true; clearInterval(id); };
  }, [timezone]);

  const runSystemCheck = useCallback(async () => {
    setChecking(true);
    const next = { postgres: 'checking', redis: 'checking', schema: 'checking', application: 'checking' };
    setChecks({ ...next });
    try {
      // /readyz reports component health. During first-run the date/time component is
      // intentionally "unhealthy" (that is what this wizard fixes), so it is not a blocker.
      const res = await fetch('/readyz', { headers: { accept: 'application/json' } });
      const body = await res.json().catch(() => ({}));
      const c = body.checks || body || {};
      next.postgres = c.postgres === 'ok' ? 'ok' : 'error';
      next.redis = c.redis === 'ok' ? 'ok' : 'error';
      // The status call below proves the schema is present and the app is responding.
      await api.get('/setup/status');
      next.schema = 'ok';
      next.application = 'ok';
    } catch {
      if (next.schema === 'checking') next.schema = 'error';
      if (next.application === 'checking') next.application = 'error';
      if (next.postgres === 'checking') next.postgres = 'error';
      if (next.redis === 'checking') next.redis = 'error';
    } finally {
      setChecks({ ...next });
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    if (mode === 'greenfield' && step === 'check' && !checks) {
      runSystemCheck().catch(() => {});
    }
  }, [mode, step, checks, runSystemCheck]);

  async function verifyCode() {
    setError('');
    setBusy(true);
    try {
      if (codeRequired) {
        await api.post('/setup/verify-code', { code });
      }
      setCodeVerified(true);
      setStep('check');
    } catch (err) {
      setError(err?.response?.data?.message || 'Invalid setup code');
    } finally {
      setBusy(false);
    }
  }

  const passwordProblem = (() => {
    if (!password) return 'Password is required';
    if (password.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
    if (confirmPassword && password !== confirmPassword) return 'Passwords do not match';
    return '';
  })();

  const adminValid = username.trim().length >= 3
    && password.length >= MIN_PASSWORD_LENGTH
    && password === confirmPassword;

  const checksReady = checks
    && checks.postgres === 'ok'
    && checks.redis === 'ok'
    && checks.schema === 'ok'
    && checks.application === 'ok';

  async function completeGreenfield() {
    setError('');
    setBusy(true);
    try {
      const { data } = await api.post('/setup/complete', {
        code: codeRequired ? code : undefined,
        username: username.trim(),
        password,
        confirm_password: confirmPassword,
        timezone
      });
      setSystemTimezoneCache(data.active_system_timezone || data.system_timezone || timezone);
      notifyTimezoneChanged();
      onCompleted?.(data);
    } catch (err) {
      setError(err?.response?.data?.message || err.message || 'Failed to complete setup');
      setBusy(false);
    }
  }

  // Existing-install timezone-only branch.
  async function completeTimezoneOnly() {
    if (!timezone || busy) return;
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/setup/complete', { timezone });
      setSystemTimezoneCache(data.system_timezone || timezone);
      notifyTimezoneChanged();
      onCompleted?.(data);
    } catch (err) {
      setError(err?.response?.data?.message || err.message || 'Failed to complete setup');
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <div style={styles.page}>
        <div style={styles.card}>Loading setup…</div>
      </div>
    );
  }

  if (mode === 'timezone_only') {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <div style={styles.brand}>TalonHound</div>
          <h1 style={styles.title}>{configRequired ? 'Timezone Configuration Required' : 'System Timezone'}</h1>
          <p style={styles.lead}>
            {configRequired
              ? 'This existing TalonHound installation has no configured system timezone. Sign in as an administrator, then select a valid IANA timezone before feeds, schedulers, exports, and the rest of the application can run. Historical data is not changed.'
              : 'Choose the single timezone used across the entire TalonHound installation.'}
          </p>
          {configRequired ? (
            <p style={{ ...styles.lead, marginTop: 0 }}>
              <a href="/login" style={{ color: '#93c5fd' }}>Sign in as administrator</a>
              {' '}if you have not already, then return here to complete configuration.
            </p>
          ) : null}

          <TimezoneSelector value={timezone} onChange={setTimezone} id="setup-tz" filterId="setup-tz-filter" styles={styles} />

          <div style={styles.times}>
            <div><span style={styles.muted}>Current UTC time</span><div style={styles.mono}>{utcNow || '—'}</div></div>
            <div><span style={styles.muted}>Current system time</span><div style={styles.mono}>{systemNow || '—'}</div></div>
          </div>

          {error ? <div style={styles.error}>{error}</div> : null}
          <button
            type="button"
            style={{ ...styles.button, opacity: !timezone || busy ? 0.55 : 1 }}
            disabled={!timezone || busy}
            onClick={() => completeTimezoneOnly().catch(() => {})}
          >
            {busy ? 'Saving…' : 'Confirm and Continue'}
          </button>
        </div>
      </div>
    );
  }

  // Greenfield wizard.
  const steps = ['welcome', 'check', 'admin', 'timezone', 'review'];
  const stepLabels = { welcome: 'Welcome', check: 'System Check', admin: 'Administrator', timezone: 'Timezone', review: 'Review' };
  const stepIndex = steps.indexOf(step);

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <div style={styles.brand}>TalonHound</div>

        <div style={styles.stepper}>
          {steps.map((s, i) => (
            <div key={s} style={styles.stepItem}>
              <div style={{ ...styles.stepDot, ...(i <= stepIndex ? styles.stepDotActive : {}) }}>{i + 1}</div>
              <span style={{ ...styles.stepLabel, color: i <= stepIndex ? '#e2e8f0' : '#64748b' }}>{stepLabels[s]}</span>
            </div>
          ))}
        </div>

        {step === 'welcome' && (
          <>
            <h1 style={styles.title}>Welcome to TalonHound</h1>
            <p style={styles.lead}>
              Self-hosted Threat Intelligence and IOC Management Platform
              <br />
              <span style={styles.muted}>Version {PRODUCT_VERSION}</span>
            </p>
            {codeRequired ? (
              <>
                <label style={styles.label} htmlFor="setup-code">Setup Code</label>
                <input
                  id="setup-code"
                  style={{ ...styles.input, fontFamily: 'ui-monospace, monospace', letterSpacing: '0.08em' }}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  autoComplete="off"
                  spellCheck={false}
                />
                <p style={{ ...styles.muted, marginTop: 0 }}>
                  The one-time setup code was printed by the installer when installation completed.
                </p>
              </>
            ) : (
              <div style={styles.warn}>
                No setup code is configured for this install. Ensure this server is on a trusted
                network until the System Administrator is created.
              </div>
            )}
            {error ? <div style={styles.error}>{error}</div> : null}
            <button
              type="button"
              style={{ ...styles.button, opacity: (codeRequired && !code) || busy ? 0.55 : 1 }}
              disabled={(codeRequired && !code) || busy}
              onClick={() => verifyCode().catch(() => {})}
            >
              {busy ? 'Verifying…' : 'Continue'}
            </button>
          </>
        )}

        {step === 'check' && (
          <>
            <h1 style={styles.title}>System Check</h1>
            <p style={styles.lead}>Validating the services required to finish setup.</p>
            <div style={styles.checkList}>
              <CheckRow label="PostgreSQL" state={checks?.postgres} />
              <CheckRow label="Redis" state={checks?.redis} />
              <CheckRow label="Database Schema" state={checks?.schema} />
              <CheckRow label="Application" state={checks?.application} />
            </div>
            {checks && !checksReady && !checking ? (
              <div style={styles.error}>
                One or more required services are not ready. Confirm the containers are running,
                then retry.
              </div>
            ) : null}
            <div style={styles.row}>
              <button type="button" style={styles.buttonGhost} onClick={() => setStep('welcome')}>Back</button>
              <button
                type="button"
                style={styles.buttonGhost}
                disabled={checking}
                onClick={() => { setChecks(null); }}
              >
                {checking ? 'Checking…' : 'Re-check'}
              </button>
              <button
                type="button"
                style={{ ...styles.button, flex: 1, opacity: checksReady ? 1 : 0.55 }}
                disabled={!checksReady}
                onClick={() => setStep('admin')}
              >
                Continue
              </button>
            </div>
          </>
        )}

        {step === 'admin' && (
          <>
            <h1 style={styles.title}>Create System Administrator</h1>
            <p style={styles.lead}>This is the protected administrator account for this installation.</p>
            <label style={styles.label} htmlFor="su-username">Username</label>
            <input
              id="su-username"
              style={styles.input}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin@yourcompany.com"
              autoComplete="username"
              spellCheck={false}
            />
            <label style={styles.label} htmlFor="su-password">Password</label>
            <input
              id="su-password"
              type="password"
              style={styles.input}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
            />
            <label style={styles.label} htmlFor="su-confirm">Confirm Password</label>
            <input
              id="su-confirm"
              type="password"
              style={styles.input}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
            />
            <p style={{ ...styles.muted, marginTop: 0 }}>Minimum {MIN_PASSWORD_LENGTH} characters. You choose this password now — it is valid immediately.</p>
            {password && passwordProblem ? <div style={styles.error}>{passwordProblem}</div> : null}
            <div style={styles.row}>
              <button type="button" style={styles.buttonGhost} onClick={() => setStep('check')}>Back</button>
              <button
                type="button"
                style={{ ...styles.button, flex: 1, opacity: adminValid ? 1 : 0.55 }}
                disabled={!adminValid}
                onClick={() => setStep('timezone')}
              >
                Continue
              </button>
            </div>
          </>
        )}

        {step === 'timezone' && (
          <>
            <h1 style={styles.title}>System Timezone</h1>
            <p style={styles.lead}>
              The single timezone used across the entire installation — logs, schedules, exports,
              and every timestamp in the UI. Browser local time is never used.
            </p>
            <TimezoneSelector value={timezone} onChange={setTimezone} id="setup-tz" filterId="setup-tz-filter" styles={styles} />
            <div style={styles.times}>
              <div><span style={styles.muted}>Current UTC time</span><div style={styles.mono}>{utcNow || '—'}</div></div>
              <div><span style={styles.muted}>Current system time</span><div style={styles.mono}>{systemNow || '—'}</div></div>
            </div>
            <div style={styles.row}>
              <button type="button" style={styles.buttonGhost} onClick={() => setStep('admin')}>Back</button>
              <button
                type="button"
                style={{ ...styles.button, flex: 1, opacity: timezone ? 1 : 0.55 }}
                disabled={!timezone}
                onClick={() => setStep('review')}
              >
                Continue
              </button>
            </div>
          </>
        )}

        {step === 'review' && (
          <>
            <h1 style={styles.title}>Ready to initialize TalonHound</h1>
            <div style={styles.summary}>
              <SummaryRow label="Administrator" value={username.trim()} />
              <SummaryRow label="Timezone" value={timezone} />
              <SummaryRow label="Database" value="Ready" />
              <SummaryRow label="Redis" value="Ready" />
              <SummaryRow label="Version" value={PRODUCT_VERSION} />
            </div>
            {error ? <div style={styles.error}>{error}</div> : null}
            <div style={styles.row}>
              <button type="button" style={styles.buttonGhost} disabled={busy} onClick={() => setStep('timezone')}>Back</button>
              <button
                type="button"
                style={{ ...styles.button, flex: 1, opacity: busy ? 0.55 : 1 }}
                disabled={busy}
                onClick={() => completeGreenfield().catch(() => {})}
              >
                {busy ? 'Completing…' : 'Complete Setup'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function CheckRow({ label, state }) {
  const map = {
    ok: { text: 'Ready', color: '#4ade80' },
    error: { text: 'Not ready', color: '#fca5a5' },
    checking: { text: 'Checking…', color: '#94a3b8' }
  };
  const s = map[state] || { text: '—', color: '#64748b' };
  return (
    <div style={styles.checkRow}>
      <span>{label}</span>
      <span style={{ color: s.color, fontWeight: 600 }}>{s.text}</span>
    </div>
  );
}

function SummaryRow({ label, value }) {
  return (
    <div style={styles.summaryRow}>
      <span style={styles.muted}>{label}</span>
      <span style={styles.mono}>{value || '—'}</span>
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
  stepper: { display: 'flex', gap: 6, margin: '14px 0 18px', flexWrap: 'wrap' },
  stepItem: { display: 'flex', alignItems: 'center', gap: 6 },
  stepDot: {
    width: 22, height: 22, borderRadius: '50%', background: '#1f2937', border: '1px solid #334155',
    display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: '#94a3b8'
  },
  stepDotActive: { background: '#2563eb', borderColor: '#3b82f6', color: '#fff' },
  stepLabel: { fontSize: 11, marginRight: 6 },
  title: { margin: '8px 0 10px', fontSize: 26, fontWeight: 750, color: '#f8fafc' },
  lead: { margin: '0 0 18px', color: '#94a3b8', lineHeight: 1.5, fontSize: 14 },
  label: { display: 'block', fontSize: 13, color: '#cbd5e1', marginBottom: 6, fontWeight: 600 },
  input: {
    width: '100%', boxSizing: 'border-box', marginBottom: 14, padding: '10px 12px',
    borderRadius: 8, border: '1px solid #334155', background: '#0b1220', color: '#e2e8f0'
  },
  select: {
    width: '100%', boxSizing: 'border-box', marginBottom: 16, padding: '10px 12px',
    borderRadius: 8, border: '1px solid #334155', background: '#0b1220', color: '#e2e8f0'
  },
  times: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 },
  muted: { display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 4 },
  mono: { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: 13, color: '#e2e8f0' },
  warn: {
    background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.35)',
    color: '#fde68a', borderRadius: 8, padding: 12, fontSize: 13, lineHeight: 1.5, marginBottom: 16
  },
  error: { color: '#fca5a5', marginBottom: 12, fontSize: 13 },
  checkList: { display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 },
  checkRow: {
    display: 'flex', justifyContent: 'space-between', padding: '10px 12px', borderRadius: 8,
    background: '#0b1220', border: '1px solid #1f2a3b', fontSize: 14
  },
  summary: {
    display: 'flex', flexDirection: 'column', gap: 2, marginBottom: 16, padding: '8px 12px',
    borderRadius: 8, background: '#0b1220', border: '1px solid #1f2a3b'
  },
  summaryRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid #16202f' },
  row: { display: 'flex', gap: 10, marginTop: 6 },
  button: {
    padding: '10px 14px', borderRadius: 8, border: '1px solid #2563eb',
    background: '#2563eb', color: '#fff', fontWeight: 600, cursor: 'pointer', fontSize: 14,
    minHeight: 40, lineHeight: 1.2, width: '100%'
  },
  buttonGhost: {
    padding: '10px 14px', borderRadius: 8, border: '1px solid #475569',
    background: '#1f2937', color: '#e2e8f0', fontWeight: 600, cursor: 'pointer', fontSize: 14, minHeight: 40
  }
};
