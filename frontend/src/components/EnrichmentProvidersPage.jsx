import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api.js';
import { formatUserDateTime } from '../lib/formatDate.js';
import {
  ProviderAccordionCard,
  ProviderActionBar,
  ProviderConfigForm,
  ProviderField,
  ProviderSummaryStats,
  ConfirmRemoveKeyModal,
  ConfirmActionModal,
  useRemoveKeyConfirm,
  useConfirmAction,
  PROVIDER_ORDER,
  getProviderMeta,
  resolveProviderStatus
} from './enrichmentProviders/index.js';
import './enrichmentProviders/enrichmentProviders.css';

export default function EnrichmentProvidersPage({ AppShell, useSession, useReasonPrompt }) {
  const { isAdmin } = useSession();
  const requestRequiredReason = useReasonPrompt();
  const { state: removeConfirm, controller: removeKey } = useRemoveKeyConfirm();
  const { state: disableConfirm, controller: disableAction } = useConfirmAction();
  const [loading, setLoading] = useState(true);
  const [vt, setVt] = useState(null);
  const [ipinfo, setIpinfo] = useState(null);
  const [abuseipdb, setAbuseipdb] = useState(null);
  const [rdap, setRdap] = useState(null);
  const [dnsmania, setDnsmania] = useState(null);
  const [spamhaus, setSpamhaus] = useState(null);
  const [openCards, setOpenCards] = useState(() => new Set());
  const [vtForm, setVtForm] = useState({ enabled: true, ttl_hours: 24, timeout_ms: 12000, api_key: '' });
  const [ipForm, setIpForm] = useState({ enabled: true, token: '', base_url: 'https://api.ipinfo.io/lite', timeout_seconds: 6, usage_note: '' });
  const [abuseForm, setAbuseForm] = useState({ enabled: false, api_key: '', cache_ttl_hours: 24, timeout_ms: 8000, max_age_days: 90, verbose: false, test_ip: '' });
  const [spamhausForm, setSpamhausForm] = useState({ enabled: false, sync_interval_hours: 24, timeout_ms: 30000 });
  const [feedback, setFeedback] = useState({ type: '', text: '' });
  const [busy, setBusy] = useState({
    vtSave: false, vtTest: false, vtRemove: false,
    ipSave: false, ipTest: false, ipRemove: false,
    abuseSave: false, abuseTest: false, abuseRemove: false,
    spamSave: false, spamSync: false
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/admin/enrichment-providers');
      const rows = data?.providers || [];
      const vtRow = rows.find((x) => x.provider === 'virustotal') || null;
      const ipRow = rows.find((x) => x.provider === 'ipinfo_lite') || null;
      const abuseRow = rows.find((x) => x.provider === 'abuseipdb') || null;
      const rdapRow = rows.find((x) => x.provider === 'rdap') || null;
      const dnsRow = rows.find((x) => x.provider === 'dnsmania') || null;
      const spamRow = rows.find((x) => x.provider === 'spamhaus_drop') || null;
      setVt(vtRow);
      setIpinfo(ipRow);
      setAbuseipdb(abuseRow);
      setRdap(rdapRow);
      setDnsmania(dnsRow);
      setSpamhaus(spamRow);
      if (vtRow) setVtForm((f) => ({ ...f, enabled: vtRow.enabled, ttl_hours: vtRow.ttl_hours || 24, timeout_ms: vtRow.timeout_ms || 12000 }));
      if (ipRow) {
        setIpForm((f) => ({
          ...f,
          enabled: ipRow.enabled,
          base_url: ipRow.base_url || 'https://api.ipinfo.io/lite',
          timeout_seconds: ipRow.timeout_seconds || 6
        }));
      }
      if (abuseRow) {
        setAbuseForm((f) => ({
          ...f,
          enabled: abuseRow.enabled,
          cache_ttl_hours: abuseRow.cache_ttl_hours || abuseRow.ttl_hours || 24,
          timeout_ms: abuseRow.timeout_ms || 8000,
          max_age_days: abuseRow.max_age_days || 90,
          verbose: abuseRow.verbose === true
        }));
      }
      if (spamRow) {
        setSpamhausForm((f) => ({
          ...f,
          enabled: spamRow.enabled,
          sync_interval_hours: spamRow.sync_interval_hours || 24,
          timeout_ms: spamRow.timeout_ms || 30000
        }));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load().catch(() => {}); }, [load]);

  const providersForStats = useMemo(() => {
    return [vt, ipinfo, abuseipdb, rdap, dnsmania, spamhaus].filter(Boolean).map((row) => ({
      ...row,
      status: resolveProviderStatus(row)
    }));
  }, [vt, ipinfo, abuseipdb, rdap, dnsmania, spamhaus]);

  const anyBusy = Object.values(busy).some(Boolean);

  function toggleCard(key) {
    setOpenCards((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function headerStatus(row, formEnabled) {
    const status = resolveProviderStatus({ ...row, enabled: formEnabled ?? row?.enabled });
    const labels = {
      healthy: 'Healthy',
      degraded: 'Degraded',
      unhealthy: 'Unhealthy',
      unknown: 'Unknown'
    };
    return { status, label: labels[status] || 'Unknown' };
  }

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
    } finally {
      setBusy((b) => ({ ...b, vtSave: false }));
    }
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
    } finally {
      setBusy((b) => ({ ...b, vtTest: false }));
    }
  }

  // Confirmed remove actions. These run only after the shared confirmation
  // modal is accepted; they rethrow on failure so the modal stays open and
  // surfaces the error instead of closing.
  async function removeVtKey() {
    setBusy((b) => ({ ...b, vtRemove: true }));
    setFeedback({ type: '', text: '' });
    try {
      await api.post('/admin/enrichment-providers/virustotal/remove-key');
      setFeedback({ type: 'success', text: 'VirusTotal API key removed.' });
      await load();
    } catch (e) {
      throw new Error(e?.response?.data?.message || 'Remove failed');
    } finally {
      setBusy((b) => ({ ...b, vtRemove: false }));
    }
  }

  async function saveIpinfo() {
    const reason = await requestRequiredReason('Update IPinfo Lite provider settings');
    if (!reason) return;
    setBusy((b) => ({ ...b, ipSave: true }));
    setFeedback({ type: '', text: '' });
    try {
      await api.put('/admin/enrichment-providers/ipinfo-lite', { ...ipForm, reason });
      setFeedback({ type: 'success', text: 'IPinfo Lite settings saved.' });
      setIpForm((f) => ({ ...f, token: '' }));
      await load();
    } catch (e) {
      setFeedback({ type: 'error', text: e?.response?.data?.message || 'Save failed' });
    } finally {
      setBusy((b) => ({ ...b, ipSave: false }));
    }
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
    } finally {
      setBusy((b) => ({ ...b, ipTest: false }));
    }
  }

  async function removeIpToken() {
    setBusy((b) => ({ ...b, ipRemove: true }));
    setFeedback({ type: '', text: '' });
    try {
      await api.post('/admin/enrichment-providers/ipinfo-lite/remove-key');
      setFeedback({ type: 'success', text: 'IPinfo Lite token removed.' });
      await load();
    } catch (e) {
      throw new Error(e?.response?.data?.message || 'Remove failed');
    } finally {
      setBusy((b) => ({ ...b, ipRemove: false }));
    }
  }

  async function saveAbuseipdb() {
    setBusy((b) => ({ ...b, abuseSave: true }));
    setFeedback({ type: '', text: '' });
    try {
      const reason = await requestRequiredReason('Update AbuseIPDB provider settings');
      if (!reason) return;
      await api.put('/admin/enrichment-providers/abuseipdb', { ...abuseForm, reason });
      setFeedback({ type: 'success', text: 'AbuseIPDB settings saved.' });
      setAbuseForm((f) => ({ ...f, api_key: '' }));
      await load();
    } catch (e) {
      setFeedback({ type: 'error', text: e?.response?.data?.message || 'Save failed' });
    } finally {
      setBusy((b) => ({ ...b, abuseSave: false }));
    }
  }

  async function testAbuseipdb() {
    setBusy((b) => ({ ...b, abuseTest: true }));
    setFeedback({ type: '', text: '' });
    try {
      const body = abuseForm.test_ip?.trim() ? { ip: abuseForm.test_ip.trim() } : {};
      const { data } = await api.post('/admin/enrichment-providers/abuseipdb/test', body);
      setFeedback({ type: 'success', text: data?.message || `AbuseIPDB connection successful (${data?.ip || '8.8.8.8'})` });
      await load();
    } catch (e) {
      const msg = e?.response?.data?.message || 'Test failed';
      setFeedback({ type: /rate limit/i.test(msg) ? 'warn' : 'error', text: msg });
      await load();
    } finally {
      setBusy((b) => ({ ...b, abuseTest: false }));
    }
  }

  async function removeAbuseKey() {
    setBusy((b) => ({ ...b, abuseRemove: true }));
    setFeedback({ type: '', text: '' });
    try {
      await api.post('/admin/enrichment-providers/abuseipdb/remove-key');
      setFeedback({ type: 'success', text: 'AbuseIPDB API key removed.' });
      await load();
    } catch (e) {
      throw new Error(e?.response?.data?.message || 'Remove failed');
    } finally {
      setBusy((b) => ({ ...b, abuseRemove: false }));
    }
  }

  async function saveSpamhaus() {
    setBusy((b) => ({ ...b, spamSave: true }));
    setFeedback({ type: '', text: '' });
    try {
      const reason = await requestRequiredReason('Update Spamhaus DROP provider settings');
      if (!reason) return;
      await api.put('/admin/enrichment-providers/spamhaus-drop', { ...spamhausForm, reason });
      setFeedback({ type: 'success', text: 'Spamhaus DROP settings saved.' });
      await load();
    } catch (e) {
      setFeedback({ type: 'error', text: e?.response?.data?.message || 'Save failed' });
    } finally {
      setBusy((b) => ({ ...b, spamSave: false }));
    }
  }

  async function runSpamhausSync() {
    setBusy((b) => ({ ...b, spamSync: true }));
    setFeedback({ type: '', text: '' });
    try {
      const reason = await requestRequiredReason('Trigger immediate Spamhaus DROP sync');
      if (!reason) return;
      await api.post('/admin/enrichment-providers/spamhaus-drop/sync', { reason });
      setFeedback({ type: 'success', text: 'Spamhaus DROP sync job queued.' });
      await load();
    } catch (e) {
      setFeedback({ type: 'error', text: e?.response?.data?.message || 'Sync failed' });
    } finally {
      setBusy((b) => ({ ...b, spamSync: false }));
    }
  }

  // Central disable persistence: one request per provider, enabled=false, without
  // touching stored keys. Reused by the shared disable confirmation modal for all
  // key/toggle providers. Throws on failure so the modal stays open with the error.
  const DISABLE_REASON = 'Disabled from Enrichment Providers page';
  async function commitProviderDisable(providerKey) {
    const name = getProviderMeta(providerKey).name;
    if (providerKey === 'virustotal') {
      await api.put('/admin/enrichment-providers/virustotal', { ...vtForm, enabled: false, api_key: '' });
    } else if (providerKey === 'ipinfo_lite') {
      await api.put('/admin/enrichment-providers/ipinfo-lite', { ...ipForm, enabled: false, token: '', reason: DISABLE_REASON });
    } else if (providerKey === 'abuseipdb') {
      await api.put('/admin/enrichment-providers/abuseipdb', { ...abuseForm, enabled: false, api_key: '', reason: DISABLE_REASON });
    } else if (providerKey === 'spamhaus_drop') {
      await api.put('/admin/enrichment-providers/spamhaus-drop', { ...spamhausForm, enabled: false, reason: DISABLE_REASON });
    } else {
      throw new Error('Unsupported provider');
    }
    setFeedback({ type: 'success', text: `${name} disabled. Existing results remain viewable; new enrichment is blocked.` });
    await load();
  }

  // Disabling opens the shared confirmation modal; enabling applies immediately.
  function handleEnabledChange(providerKey, nextEnabled, setForm) {
    if (nextEnabled) {
      setForm((x) => ({ ...x, enabled: true }));
      return;
    }
    disableAction.request({
      payload: { providerKey, name: getProviderMeta(providerKey).name },
      onConfirm: () => commitProviderDisable(providerKey)
    });
  }

  const byKey = {
    virustotal: vt,
    ipinfo_lite: ipinfo,
    abuseipdb,
    rdap,
    dnsmania,
    spamhaus_drop: spamhaus
  };

  const visibleKeys = PROVIDER_ORDER.filter((key) => byKey[key]);

  return (
    <AppShell>
      <section className="ep-page">
        <h2 className="ep-page-title">Enrichment Providers</h2>
        <p className="ep-page-subtitle">Manage external intelligence providers used for on-demand IOC enrichment.</p>

        {!isAdmin ? (
          <div className="ep-banner ep-banner--info">
            Provider credentials and security-sensitive settings require the admin role. Other signed-in users can view status only.
          </div>
        ) : null}

        {feedback.text ? (
          <div className={`ep-banner ep-banner--${feedback.type || 'info'}`}>{feedback.text}</div>
        ) : null}

        {loading ? (
          <div style={{ color: '#94a3b8' }}>Loading...</div>
        ) : (
          <>
            <ProviderSummaryStats providers={providersForStats} />

            <div className="ep-list">
              {visibleKeys.map((key) => {
                const row = byKey[key];
                const meta = getProviderMeta(key);
                const open = openCards.has(key);

                if (key === 'virustotal') {
                  const hs = headerStatus(row, vtForm.enabled);
                  return (
                    <ProviderAccordionCard
                      key={key}
                      providerKey={key}
                      name={meta.name}
                      description={meta.shortDescription}
                      status={hs.status}
                      statusLabel={hs.label}
                      enabled={vtForm.enabled}
                      open={open}
                      onToggle={() => toggleCard(key)}
                    >
                      <ProviderConfigForm
                        status={hs.status}
                        statusLabel={hs.label}
                        enabled={vtForm.enabled}
                        onEnabledChange={(v) => handleEnabledChange('virustotal', v, setVtForm)}
                        enabledDisabled={!isAdmin}
                        health={row.health}
                        description={meta.longDescription}
                        errorMessage={row.last_error_message}
                        left={(
                          <>
                            <ProviderField
                              id="vt-api-key"
                              label="API Key"
                              hint={row.masked_key ? `Current key: ${row.masked_key}` : 'Paste VirusTotal API key'}
                            >
                              <input
                                id="vt-api-key"
                                type="password"
                                value={vtForm.api_key}
                                onChange={(e) => setVtForm((x) => ({ ...x, api_key: e.target.value }))}
                                placeholder={row.masked_key ? 'Leave blank to keep current key' : 'Paste VirusTotal API key'}
                                disabled={!isAdmin}
                              />
                            </ProviderField>
                            <div className="ep-field-grid">
                              <ProviderField id="vt-ttl" label="Cache TTL (hours)">
                                <input id="vt-ttl" type="number" min="1" value={vtForm.ttl_hours} onChange={(e) => setVtForm((x) => ({ ...x, ttl_hours: Number(e.target.value) }))} disabled={!isAdmin} />
                              </ProviderField>
                              <ProviderField id="vt-timeout" label="Timeout (ms)">
                                <input id="vt-timeout" type="number" min="3000" value={vtForm.timeout_ms} onChange={(e) => setVtForm((x) => ({ ...x, timeout_ms: Number(e.target.value) }))} disabled={!isAdmin} />
                              </ProviderField>
                            </div>
                          </>
                        )}
                        actions={(
                          <ProviderActionBar
                            onTest={() => testVt().catch(() => {})}
                            onSave={() => saveVt().catch(() => {})}
                            onRemove={() => removeKey.request({
                              providerKey: key,
                              providerName: meta.name,
                              keyNoun: 'API key',
                              confirmLabel: 'Remove key',
                              onConfirm: removeVtKey
                            })}
                            removeLabel="Remove key"
                            disabled={!isAdmin || anyBusy}
                            busy={{ save: busy.vtSave, test: busy.vtTest, remove: busy.vtRemove }}
                          />
                        )}
                      />
                    </ProviderAccordionCard>
                  );
                }

                if (key === 'ipinfo_lite') {
                  const hs = headerStatus(row, ipForm.enabled);
                  return (
                    <ProviderAccordionCard
                      key={key}
                      providerKey={key}
                      name={meta.name}
                      description={meta.shortDescription}
                      status={hs.status}
                      statusLabel={hs.label}
                      enabled={ipForm.enabled}
                      open={open}
                      onToggle={() => toggleCard(key)}
                    >
                      <ProviderConfigForm
                        status={hs.status}
                        statusLabel={hs.label}
                        enabled={ipForm.enabled}
                        onEnabledChange={(v) => handleEnabledChange('ipinfo_lite', v, setIpForm)}
                        enabledDisabled={!isAdmin}
                        health={row.health}
                        description={meta.longDescription}
                        errorMessage={row.last_error_message}
                        left={(
                          <>
                            <ProviderField
                              id="ip-token"
                              label="API Token"
                              hint={row.masked_key ? `Current token: ${row.masked_key}. Env fallback: IPINFO_LITE_TOKEN` : 'Token is never returned in plaintext. Env fallback: IPINFO_LITE_TOKEN'}
                            >
                              <input
                                id="ip-token"
                                type="password"
                                value={ipForm.token}
                                onChange={(e) => setIpForm((x) => ({ ...x, token: e.target.value }))}
                                placeholder={row.masked_key ? 'Leave blank to keep current token' : 'Paste IPinfo Lite token'}
                                disabled={!isAdmin}
                              />
                            </ProviderField>
                            <div className="ep-field-grid">
                              <ProviderField id="ip-base-url" label="Base URL (fixed)">
                                <input id="ip-base-url" value={ipForm.base_url} readOnly disabled title="Trusted IPinfo Lite origin is fixed for SSRF protection" />
                              </ProviderField>
                              <ProviderField id="ip-timeout" label="Timeout (seconds)">
                                <input id="ip-timeout" type="number" min="3" max="30" value={ipForm.timeout_seconds} onChange={(e) => setIpForm((x) => ({ ...x, timeout_seconds: Number(e.target.value) }))} disabled={!isAdmin} />
                              </ProviderField>
                            </div>
                            <ProviderField id="ip-note" label="Usage note (optional)">
                              <textarea id="ip-note" value={ipForm.usage_note} onChange={(e) => setIpForm((x) => ({ ...x, usage_note: e.target.value }))} disabled={!isAdmin} rows={2} />
                            </ProviderField>
                          </>
                        )}
                        actions={(
                          <ProviderActionBar
                            onTest={() => testIpinfo().catch(() => {})}
                            onSave={() => saveIpinfo().catch(() => {})}
                            onRemove={() => removeKey.request({
                              providerKey: key,
                              providerName: meta.name,
                              keyNoun: 'token',
                              confirmLabel: 'Remove token',
                              onConfirm: removeIpToken
                            })}
                            removeLabel="Remove token"
                            disabled={!isAdmin || anyBusy}
                            busy={{ save: busy.ipSave, test: busy.ipTest, remove: busy.ipRemove }}
                          />
                        )}
                      />
                    </ProviderAccordionCard>
                  );
                }

                if (key === 'abuseipdb') {
                  const hs = headerStatus(row, abuseForm.enabled);
                  return (
                    <ProviderAccordionCard
                      key={key}
                      providerKey={key}
                      name={meta.name}
                      description={meta.shortDescription}
                      status={hs.status}
                      statusLabel={hs.label}
                      enabled={abuseForm.enabled}
                      open={open}
                      onToggle={() => toggleCard(key)}
                    >
                      <ProviderConfigForm
                        status={hs.status}
                        statusLabel={hs.label}
                        enabled={abuseForm.enabled}
                        onEnabledChange={(v) => handleEnabledChange('abuseipdb', v, setAbuseForm)}
                        enabledDisabled={!isAdmin}
                        health={row.health}
                        description={meta.longDescription}
                        errorMessage={row.last_error_message}
                        left={(
                          <>
                            <ProviderField
                              id="abuse-api-key"
                              label="API Key"
                              hint={row.masked_key ? `Current key: ${row.masked_key}. Env fallback: ABUSEIPDB_API_KEY` : 'Env fallback: ABUSEIPDB_API_KEY. Key is never returned in plaintext.'}
                            >
                              <input
                                id="abuse-api-key"
                                type="password"
                                value={abuseForm.api_key}
                                onChange={(e) => setAbuseForm((x) => ({ ...x, api_key: e.target.value }))}
                                placeholder={row.masked_key ? 'Leave blank to keep current key' : 'Paste AbuseIPDB API key'}
                                disabled={!isAdmin}
                              />
                            </ProviderField>
                            <div className="ep-field-grid">
                              <ProviderField id="abuse-ttl" label="Cache TTL (hours)">
                                <input id="abuse-ttl" type="number" min="1" value={abuseForm.cache_ttl_hours} onChange={(e) => setAbuseForm((x) => ({ ...x, cache_ttl_hours: Number(e.target.value) }))} disabled={!isAdmin} />
                              </ProviderField>
                              <ProviderField id="abuse-timeout" label="Timeout (ms)">
                                <input id="abuse-timeout" type="number" min="3000" value={abuseForm.timeout_ms} onChange={(e) => setAbuseForm((x) => ({ ...x, timeout_ms: Number(e.target.value) }))} disabled={!isAdmin} />
                              </ProviderField>
                              <ProviderField id="abuse-max-age" label="Max age (days)">
                                <input id="abuse-max-age" type="number" min="1" max="365" value={abuseForm.max_age_days} onChange={(e) => setAbuseForm((x) => ({ ...x, max_age_days: Number(e.target.value) }))} disabled={!isAdmin} />
                              </ProviderField>
                            </div>
                            <label htmlFor="abuse-verbose" className="ep-check-card">
                              <input id="abuse-verbose" type="checkbox" checked={abuseForm.verbose} onChange={(e) => setAbuseForm((x) => ({ ...x, verbose: e.target.checked }))} disabled={!isAdmin} />
                              <span>
                                <strong>Verbose reports</strong>
                                <span>Include summarized recent report categories in enrichment results.</span>
                              </span>
                            </label>
                            <ProviderField id="abuse-test-ip" label="Test IP (optional, public IPv4/IPv6)">
                              <input id="abuse-test-ip" value={abuseForm.test_ip} onChange={(e) => setAbuseForm((x) => ({ ...x, test_ip: e.target.value }))} placeholder="Defaults to 8.8.8.8" disabled={!isAdmin} />
                            </ProviderField>
                          </>
                        )}
                        actions={(
                          <ProviderActionBar
                            onTest={() => testAbuseipdb().catch(() => {})}
                            onSave={() => saveAbuseipdb().catch(() => {})}
                            onRemove={() => removeKey.request({
                              providerKey: key,
                              providerName: meta.name,
                              keyNoun: 'API key',
                              confirmLabel: 'Remove key',
                              onConfirm: removeAbuseKey
                            })}
                            removeLabel="Remove key"
                            disabled={!isAdmin || anyBusy}
                            busy={{ save: busy.abuseSave, test: busy.abuseTest, remove: busy.abuseRemove }}
                          />
                        )}
                      />
                    </ProviderAccordionCard>
                  );
                }

                if (key === 'rdap') {
                  const hs = headerStatus(row, row.enabled);
                  return (
                    <ProviderAccordionCard
                      key={key}
                      providerKey={key}
                      name={meta.name}
                      description={meta.shortDescription}
                      status={hs.status}
                      statusLabel={hs.label}
                      enabled={row.enabled !== false}
                      open={open}
                      onToggle={() => toggleCard(key)}
                    >
                      <ProviderConfigForm
                        status={hs.status}
                        statusLabel={hs.label}
                        enabled={row.enabled !== false}
                        showEnabledToggle={false}
                        health={row.health}
                        description={row.description || meta.longDescription}
                        left={(
                          <>
                            <div className="ep-readonly-grid">
                              <div className="ep-readonly-item"><div className="k">RDAP base URL</div><div className="v">{row.rdap_base_url || 'https://rdap.org'}</div></div>
                              <div className="ep-readonly-item"><div className="k">Domain cache TTL</div><div className="v">{row.cache_ttl_hours || 24} hours</div></div>
                              <div className="ep-readonly-item"><div className="k">Timeout</div><div className="v">{row.timeout_ms || 10000} ms</div></div>
                            </div>
                            <div className="ep-note">
                              Used on-demand from <b style={{ color: '#e2e8f0' }}>IOC Details → Intelligence</b> for domain and URL observables. Lookups are cached by registrable root domain.
                            </div>
                          </>
                        )}
                        extraRight={(
                          <div className="ep-side-row">
                            <span className="ep-side-label">Auth</span>
                            <div className="ep-side-value ep-side-muted">No API key</div>
                          </div>
                        )}
                      />
                    </ProviderAccordionCard>
                  );
                }

                if (key === 'dnsmania') {
                  const hs = headerStatus(row, row.enabled);
                  return (
                    <ProviderAccordionCard
                      key={key}
                      providerKey={key}
                      name={meta.name}
                      description={meta.shortDescription}
                      status={hs.status}
                      statusLabel={hs.label}
                      enabled={row.enabled !== false && row.configured !== false}
                      open={open}
                      onToggle={() => toggleCard(key)}
                    >
                      <ProviderConfigForm
                        status={hs.status}
                        statusLabel={hs.label}
                        enabled={row.enabled !== false && row.configured !== false}
                        showEnabledToggle={false}
                        health={row.health}
                        description={row.description || meta.longDescription}
                        left={(
                          <>
                            <div className="ep-readonly-grid">
                              <div className="ep-readonly-item"><div className="k">Base URL</div><div className="v">{row.dnsmania_base_url || '—'}</div></div>
                              <div className="ep-readonly-item"><div className="k">Timeout</div><div className="v">{row.timeout_ms || '—'} ms</div></div>
                              <div className="ep-readonly-item"><div className="k">Max concurrency</div><div className="v">{row.max_concurrency ?? '—'}</div></div>
                            </div>
                            <div className="ep-note">
                              Env-configured provider. Manual on-demand enrichment from <b style={{ color: '#e2e8f0' }}>IOC Details → Intelligence</b>. No API key required.
                            </div>
                          </>
                        )}
                        extraRight={(
                          <div className="ep-side-row">
                            <span className="ep-side-label">Auth</span>
                            <div className="ep-side-value ep-side-muted">No API key</div>
                          </div>
                        )}
                      />
                    </ProviderAccordionCard>
                  );
                }

                if (key === 'spamhaus_drop') {
                  const hs = headerStatus(row, spamhausForm.enabled);
                  return (
                    <ProviderAccordionCard
                      key={key}
                      providerKey={key}
                      name={meta.name}
                      description={meta.shortDescription}
                      status={hs.status}
                      statusLabel={hs.label}
                      enabled={spamhausForm.enabled}
                      open={open}
                      onToggle={() => toggleCard(key)}
                    >
                      <ProviderConfigForm
                        status={hs.status}
                        statusLabel={hs.label}
                        enabled={spamhausForm.enabled}
                        onEnabledChange={(v) => handleEnabledChange('spamhaus_drop', v, setSpamhausForm)}
                        enabledDisabled={!isAdmin}
                        health={row.health}
                        lastTestLabel="Last successful sync"
                        description={meta.longDescription}
                        left={(
                          <>
                            <div className="ep-field-grid">
                              <ProviderField id="spam-interval" label="Sync interval (hours)">
                                <select id="spam-interval" value={spamhausForm.sync_interval_hours} onChange={(e) => setSpamhausForm((x) => ({ ...x, sync_interval_hours: Number(e.target.value) }))} disabled={!isAdmin}>
                                  <option value={6}>Every 6 hours</option>
                                  <option value={12}>Every 12 hours</option>
                                  <option value={24}>Every 24 hours</option>
                                </select>
                              </ProviderField>
                              <ProviderField id="spam-timeout" label="Fetch timeout (ms)">
                                <input id="spam-timeout" type="number" min="5000" value={spamhausForm.timeout_ms} onChange={(e) => setSpamhausForm((x) => ({ ...x, timeout_ms: Number(e.target.value) }))} disabled={!isAdmin} />
                              </ProviderField>
                            </div>
                            {row.sync_state?.length ? (
                              <div className="ep-sync-grid">
                                {row.sync_state.map((s) => (
                                  <div key={s.list_type} className="ep-sync-card">
                                    <div className="t">{s.list_type}</div>
                                    <div className="v">Status: {s.status}</div>
                                    {s.entry_count != null ? <div className="m">Entries: {s.entry_count.toLocaleString()}</div> : null}
                                    {s.last_success_at ? <div className="m">Last sync: {formatUserDateTime(s.last_success_at)}</div> : null}
                                    {s.error_message ? <div className="e">Error: {s.error_message}</div> : null}
                                  </div>
                                ))}
                              </div>
                            ) : null}
                          </>
                        )}
                        actions={(
                          <ProviderActionBar
                            onSave={() => saveSpamhaus().catch(() => {})}
                            onSync={() => runSpamhausSync().catch(() => {})}
                            disabled={!isAdmin || anyBusy}
                            syncDisabled={!spamhausForm.enabled}
                            busy={{ save: busy.spamSave, sync: busy.spamSync }}
                          />
                        )}
                      />
                    </ProviderAccordionCard>
                  );
                }

                return null;
              })}
            </div>

            <div className="ep-footer">
              Showing 1 to {visibleKeys.length} of {visibleKeys.length} providers
            </div>
          </>
        )}
      </section>

      <ConfirmRemoveKeyModal
        open={removeConfirm.open}
        providerName={removeConfirm.providerName}
        keyNoun={removeConfirm.keyNoun}
        confirmLabel={removeConfirm.confirmLabel}
        submitting={removeConfirm.submitting}
        error={removeConfirm.error}
        onCancel={() => removeKey.cancel()}
        onConfirm={() => removeKey.confirm()}
      />

      <ConfirmActionModal
        open={disableConfirm.open}
        title={`Disable ${disableConfirm.payload?.name || 'provider'}?`}
        description="Existing enrichment results will remain visible, but new enrichment and refresh operations will be blocked."
        confirmLabel="Disable provider"
        submittingLabel="Disabling..."
        destructive
        submitting={disableConfirm.submitting}
        error={disableConfirm.error}
        onCancel={() => disableAction.cancel()}
        onConfirm={() => disableAction.confirm()}
      />
    </AppShell>
  );
}
