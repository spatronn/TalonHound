import React, { useState } from 'react';
import { api } from '../../lib/api.js';
import ThreatLibraryModal, { ModalCancelButton } from './ThreatLibraryModal.jsx';
import { ui } from './styles.js';

const TABS = [
  { id: 'url', label: 'URL' },
  { id: 'pdf', label: 'PDF' },
  { id: 'thib', label: 'TalonHound Bundle' }
];

export default function ImportIntelligenceModal({ open, onClose, onImported }) {
  const [tab, setTab] = useState('url');
  const [url, setUrl] = useState('');
  const [pdfFile, setPdfFile] = useState(null);
  const [thibFile, setThibFile] = useState(null);
  const [thibPreview, setThibPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  function reset() {
    setTab('url');
    setUrl('');
    setPdfFile(null);
    setThibFile(null);
    setThibPreview(null);
    setBusy(false);
    setError('');
  }

  function handleClose() {
    if (busy) return;
    reset();
    onClose?.();
  }

  async function submitUrl() {
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/threat-library/import/url', { url: url.trim() });
      onImported?.(data?.report);
      reset();
      onClose?.();
    } catch (err) {
      setError(err?.response?.data?.message || 'URL import failed');
    } finally {
      setBusy(false);
    }
  }

  async function submitPdf() {
    if (!pdfFile) {
      setError('Choose a PDF file');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const form = new FormData();
      form.append('file', pdfFile);
      const { data } = await api.post('/threat-library/import/pdf', form, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      onImported?.(data?.report);
      reset();
      onClose?.();
    } catch (err) {
      setError(err?.response?.data?.message || 'PDF import failed');
    } finally {
      setBusy(false);
    }
  }

  async function validateThib(file) {
    setThibFile(file || null);
    setThibPreview(null);
    setError('');
    if (!file) return;
    setBusy(true);
    try {
      const form = new FormData();
      form.append('file', file);
      const { data } = await api.post('/threat-library/import/thib/validate', form, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setThibPreview(data);
    } catch (err) {
      setThibPreview(null);
      setError(err?.response?.data?.message || 'Bundle validation failed');
    } finally {
      setBusy(false);
    }
  }

  async function submitThib() {
    if (!thibFile) {
      setError('Choose a .thib.json bundle file');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const form = new FormData();
      form.append('file', thibFile);
      const { data } = await api.post('/threat-library/import/thib', form, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      onImported?.(data?.report, { alreadyImported: data?.already_imported === true });
      reset();
      onClose?.();
    } catch (err) {
      setError(err?.response?.data?.message || 'Bundle import failed');
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(e) {
    e.preventDefault();
    if (tab === 'url') submitUrl().catch(() => {});
    else if (tab === 'pdf') submitPdf().catch(() => {});
    else submitThib().catch(() => {});
  }

  const canSubmit =
    tab === 'url' ? Boolean(url.trim())
      : tab === 'pdf' ? Boolean(pdfFile)
        : Boolean(thibFile) && thibPreview?.ok !== false;

  return (
    <ThreatLibraryModal
      open={open}
      title="Import Intelligence"
      description="Ingest a public report URL, PDF, or TalonHound Intelligence Bundle (THIB)."
      onClose={handleClose}
      closeDisabled={busy}
      width={680}
      footer={(
        <>
          <ModalCancelButton onClick={handleClose} disabled={busy} />
          <button type="submit" form="threat-library-import-form" style={ui.btnPrimary} disabled={busy || !canSubmit}>
            {busy ? 'Working…' : tab === 'thib' ? 'Import Bundle' : 'Start Import'}
          </button>
        </>
      )}
    >
      <div style={ui.tabRow}>
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            style={ui.tab(tab === t.id)}
            disabled={busy}
            onClick={() => { setTab(t.id); setError(''); }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {error ? <div style={{ ...ui.error, marginBottom: 10 }} role="alert">{error}</div> : null}

      <form id="threat-library-import-form" onSubmit={onSubmit}>
        {tab === 'url' ? (
          <div>
            <label style={ui.label} htmlFor="tl-import-url">Report URL</label>
            <input
              id="tl-import-url"
              style={ui.input}
              type="url"
              placeholder="https://…"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={busy}
              autoFocus
            />
            <span style={ui.helper}>
              Only public http(s) URLs are allowed. Private, localhost, and metadata addresses are blocked.
            </span>
          </div>
        ) : null}

        {tab === 'pdf' ? (
          <div>
            <label style={ui.label} htmlFor="tl-import-pdf">PDF file</label>
            <input
              id="tl-import-pdf"
              type="file"
              accept="application/pdf,.pdf"
              disabled={busy}
              onChange={(e) => setPdfFile(e.target.files?.[0] || null)}
            />
            <span style={ui.helper}>
              Text is extracted server-side, then analyzed for IOC candidates. Do not upload documents you are not authorized to share with configured AI providers.
            </span>
          </div>
        ) : null}

        {tab === 'thib' ? (
          <div>
            <label style={ui.label} htmlFor="tl-import-thib">TalonHound Bundle (.thib.json)</label>
            <input
              id="tl-import-thib"
              type="file"
              accept=".json,application/json"
              disabled={busy}
              onChange={(e) => validateThib(e.target.files?.[0] || null).catch(() => {})}
            />
            <span style={ui.helper}>
              Bundle imports skip AI analysis and restore portable report metadata, candidates, and relationships.
            </span>
            {thibPreview?.ok ? (
              <div style={{ ...ui.infoBanner, marginTop: 12, marginBottom: 0 }}>
                {thibPreview.already_imported
                  ? 'This bundle was already imported.'
                  : 'Bundle validated.'}
                {thibPreview.report_preview?.title ? (
                  <div style={{ marginTop: 4 }}>Title: {thibPreview.report_preview.title}</div>
                ) : null}
                {thibPreview.summary ? (
                  <div style={{ marginTop: 4, color: '#99f6e4' }}>
                    {typeof thibPreview.summary === 'string'
                      ? thibPreview.summary
                      : JSON.stringify(thibPreview.summary)}
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : null}
      </form>
    </ThreatLibraryModal>
  );
}
