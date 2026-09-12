import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import { ui } from './styles.js';

const PROVIDERS = [
  { value: 'openai', label: 'OpenAI' },
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'ollama', label: 'Ollama (local)' },
  { value: 'openai_compatible', label: 'OpenAI-compatible' }
];

export default function ThreatLibraryAiSettings({ AppShell, useSession }) {
  const { isAdmin } = useSession();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [settings, setSettings] = useState(null);
  const [form, setForm] = useState({
    enabled: false,
    provider: 'openai_compatible',
    base_url: '',
    model: '',
    timeout_ms: 60000,
    max_input_chars: 120000,
    api_key: '',
    privacy_ack: false
  });

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get('/threat-library/ai-settings');
      const s = data?.settings || null;
      setSettings(s);
      setForm((f) => ({
        ...f,
        enabled: s?.enabled === true,
        provider: s?.provider || 'openai_compatible',
        base_url: s?.base_url || '',
        model: s?.model || '',
        timeout_ms: s?.timeout_ms || 60000,
        max_input_chars: s?.max_input_chars || 120000,
        api_key: '',
        privacy_ack: Boolean(s?.privacy_ack_at)
      }));
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load AI settings');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    load().catch(() => {});
  }, [isAdmin, load]);

  function setField(key, value) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  async function save() {
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const body = {
        enabled: form.enabled,
        provider: form.provider,
        base_url: form.base_url || null,
        model: form.model || null,
        timeout_ms: Number(form.timeout_ms) || 60000,
        max_input_chars: Number(form.max_input_chars) || 120000,
        privacy_ack: form.privacy_ack === true
      };
      if (form.api_key.trim()) body.api_key = form.api_key.trim();
      const { data } = await api.put('/threat-library/ai-settings', body);
      setSettings(data?.settings || null);
      setForm((f) => ({ ...f, api_key: '' }));
      setSuccess('AI settings saved. The API key is stored encrypted and never shown in full again.');
      await load();
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to save AI settings');
    } finally {
      setSaving(false);
    }
  }

  async function clearKey() {
    setClearing(true);
    setError('');
    setSuccess('');
    try {
      const { data } = await api.delete('/threat-library/ai-settings/api-key');
      setSettings(data?.settings || null);
      setForm((f) => ({ ...f, api_key: '' }));
      setSuccess('API key cleared.');
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to clear API key');
    } finally {
      setClearing(false);
    }
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <section style={ui.section}>
          <h1 style={ui.pageTitle}>Threat Library AI Settings</h1>
          <p style={ui.muted}>Admin access is required.</p>
          <Link to="/threat-intelligence/threat-library" style={{ ...ui.btn, textDecoration: 'none', marginTop: 12, display: 'inline-flex' }}>
            Back to Threat Library
          </Link>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
          <div>
            <h1 style={ui.pageTitle}>Threat Library AI Settings</h1>
            <p style={{ margin: '8px 0 0', fontSize: 13, color: '#94a3b8', maxWidth: 720, lineHeight: 1.5 }}>
              Configure the model used to extract entities and assess IOC candidates from imported reports.
            </p>
          </div>
          <Link to="/threat-intelligence/threat-library" style={{ ...ui.btn, textDecoration: 'none' }}>
            Back to Threat Library
          </Link>
        </div>

        <div style={ui.warnBanner} role="note">
          External AI providers receive report text (titles, extracted document content, and candidate evidence).
          Only enable providers you trust with that material. Prefer local Ollama or an approved enterprise endpoint when handling sensitive TLP reports.
        </div>

        {loading ? <div style={ui.muted}>Loading…</div> : null}
        {error ? <div style={{ ...ui.error, marginBottom: 10 }} role="alert">{error}</div> : null}
        {success ? <div style={{ ...ui.infoBanner, marginBottom: 10 }}>{success}</div> : null}

        {!loading ? (
          <div style={ui.formPanel}>
            <label style={{ ...ui.checkLabel || {}, display: 'inline-flex', alignItems: 'center', gap: 8, marginBottom: 14, color: '#e2e8f0', fontSize: 14 }}>
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setField('enabled', e.target.checked)}
              />
              Enable AI analysis for URL / PDF imports
            </label>

            <div style={{ display: 'grid', gap: 14, gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
              <div>
                <label style={ui.label} htmlFor="tl-ai-provider">Provider</label>
                <select
                  id="tl-ai-provider"
                  style={ui.select}
                  value={form.provider}
                  onChange={(e) => setField('provider', e.target.value)}
                >
                  {PROVIDERS.map((p) => (
                    <option key={p.value} value={p.value}>{p.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label style={ui.label} htmlFor="tl-ai-model">Model</label>
                <input
                  id="tl-ai-model"
                  style={ui.input}
                  value={form.model}
                  onChange={(e) => setField('model', e.target.value)}
                  placeholder="e.g. gpt-4.1-mini"
                />
              </div>
              <div>
                <label style={ui.label} htmlFor="tl-ai-base">Base URL</label>
                <input
                  id="tl-ai-base"
                  style={ui.input}
                  value={form.base_url}
                  onChange={(e) => setField('base_url', e.target.value)}
                  placeholder="Optional for OpenAI / Anthropic"
                />
                <span style={ui.helper}>Required for Ollama and most OpenAI-compatible gateways.</span>
              </div>
              <div>
                <label style={ui.label} htmlFor="tl-ai-timeout">Timeout (ms)</label>
                <input
                  id="tl-ai-timeout"
                  style={ui.input}
                  type="number"
                  min={1000}
                  value={form.timeout_ms}
                  onChange={(e) => setField('timeout_ms', e.target.value)}
                />
              </div>
              <div>
                <label style={ui.label} htmlFor="tl-ai-max">Max input characters</label>
                <input
                  id="tl-ai-max"
                  style={ui.input}
                  type="number"
                  min={1000}
                  value={form.max_input_chars}
                  onChange={(e) => setField('max_input_chars', e.target.value)}
                />
              </div>
            </div>

            <div style={{ marginTop: 16 }}>
              <label style={ui.label} htmlFor="tl-ai-key">API key</label>
              <input
                id="tl-ai-key"
                style={ui.input}
                type="password"
                autoComplete="new-password"
                value={form.api_key}
                onChange={(e) => setField('api_key', e.target.value)}
                placeholder={settings?.api_key_configured ? '•••• leave blank to keep current key' : 'Paste API key'}
              />
              <span style={ui.helper}>
                {settings?.api_key_configured
                  ? `Configured key (masked): ${settings.masked_key || '••••'}. Enter a new value only to rotate.`
                  : 'No API key configured yet.'}
              </span>
            </div>

            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginTop: 16, color: '#cbd5e1', fontSize: 13, lineHeight: 1.45 }}>
              <input
                type="checkbox"
                checked={form.privacy_ack}
                onChange={(e) => setField('privacy_ack', e.target.checked)}
                style={{ marginTop: 3 }}
              />
              <span>
                I acknowledge that enabling an external provider may send report content to that service.
                {settings?.privacy_ack_at ? (
                  <span style={{ display: 'block', color: '#64748b', marginTop: 4 }}>
                    Previously acknowledged {formatUserDateTime(settings.privacy_ack_at)}.
                  </span>
                ) : null}
              </span>
            </label>

            <div style={{ display: 'flex', gap: 8, marginTop: 18, flexWrap: 'wrap' }}>
              <button type="button" style={ui.btnPrimary} disabled={saving || clearing} onClick={() => save().catch(() => {})}>
                {saving ? 'Saving…' : 'Save settings'}
              </button>
              {settings?.api_key_configured ? (
                <button type="button" style={ui.btnDanger} disabled={saving || clearing} onClick={() => clearKey().catch(() => {})}>
                  {clearing ? 'Clearing…' : 'Clear API key'}
                </button>
              ) : null}
            </div>
          </div>
        ) : null}
      </section>
    </AppShell>
  );
}
