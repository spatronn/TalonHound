import React, { useState } from 'react';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import ThreatLibraryModal, { ModalCancelButton } from './ThreatLibraryModal.jsx';
import { describeImportOutcome } from './importOutcome.js';
import { formatUploadBytes, importErrorMessage, multipartFormConfig } from './multipartUpload.js';
import { ui } from './styles.js';

/** Keep in sync with backend PDF_MAX_BYTES default (25_165_824). */
const PDF_MAX_BYTES_UI = 25_165_824;

const TABS = [
  { id: 'url', label: 'URL' },
  { id: 'pdf', label: 'PDF' },
  { id: 'thib', label: 'TalonHound Bundle' }
];

export default function ImportIntelligenceModal({ open, onClose, onImported, onOpenReport }) {
  const [tab, setTab] = useState('url');
  const [url, setUrl] = useState('');
  const [pdfFile, setPdfFile] = useState(null);
  const [thibFile, setThibFile] = useState(null);
  const [thibPreview, setThibPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState('');
  const [error, setError] = useState('');
  const [errorCode, setErrorCode] = useState('');
  // Duplicate URL / PDF (already in the library): informational, not an error.
  const [duplicate, setDuplicate] = useState(null);

  function reset() {
    setTab('url');
    setUrl('');
    setPdfFile(null);
    setThibFile(null);
    setThibPreview(null);
    setBusy(false);
    setBusyLabel('');
    setError('');
    setErrorCode('');
    setDuplicate(null);
  }

  function handleClose() {
    if (busy) return;
    reset();
    onClose?.();
  }

  function setImportError(err, fallback) {
    const data = err?.response?.data;
    setError(importErrorMessage(err, fallback));
    setErrorCode(typeof data?.code === 'string' ? data.code : '');
  }

  /** Duplicate -> stay open with the notice; new import -> hand off and close. */
  function finishImport(data) {
    const outcome = describeImportOutcome(data);
    if (outcome.kind === 'duplicate') {
      setDuplicate(outcome);
      return;
    }
    onImported?.(outcome.report);
    reset();
    onClose?.();
  }

  function openExistingReport() {
    const reportId = duplicate?.reportId;
    reset();
    onClose?.();
    if (reportId) onOpenReport?.(reportId);
  }

  async function submitUrl() {
    setBusy(true);
    setBusyLabel('Importing URL…');
    setError('');
    setErrorCode('');
    setDuplicate(null);
    try {
      const { data } = await api.post('/threat-library/import/url', { url: url.trim() });
      finishImport(data);
    } catch (err) {
      setImportError(err, 'URL import failed');
    } finally {
      setBusy(false);
      setBusyLabel('');
    }
  }

  async function submitPdf() {
    if (!pdfFile) {
      setError('Choose a PDF file');
      setErrorCode('pdf_upload_failed');
      return;
    }
    if (pdfFile.size > PDF_MAX_BYTES_UI) {
      setError(`PDF exceeds maximum size (${formatUploadBytes(PDF_MAX_BYTES_UI)}).`);
      setErrorCode('pdf_too_large');
      return;
    }
    setBusy(true);
    setBusyLabel('Uploading PDF…');
    setError('');
    setErrorCode('');
    setDuplicate(null);
    try {
      const form = new FormData();
      form.append('file', pdfFile);
      // Do NOT set Content-Type manually — boundary must come from the browser.
      const { data } = await api.post('/threat-library/import/pdf', form, multipartFormConfig());
      finishImport(data);
    } catch (err) {
      setImportError(err, 'PDF import failed');
    } finally {
      setBusy(false);
      setBusyLabel('');
    }
  }

  async function validateThib(file) {
    setThibFile(file || null);
    setThibPreview(null);
    setError('');
    setErrorCode('');
    if (!file) return;
    setBusy(true);
    setBusyLabel('Validating bundle…');
    try {
      const form = new FormData();
      form.append('file', file);
      const { data } = await api.post('/threat-library/import/thib/validate', form, multipartFormConfig());
      setThibPreview(data);
    } catch (err) {
      setThibPreview(null);
      setImportError(err, 'Bundle validation failed');
    } finally {
      setBusy(false);
      setBusyLabel('');
    }
  }

  async function submitThib() {
    if (!thibFile) {
      setError('Choose a .thib.json bundle file');
      return;
    }
    setBusy(true);
    setBusyLabel('Importing bundle…');
    setError('');
    setErrorCode('');
    try {
      const form = new FormData();
      form.append('file', thibFile);
      const { data } = await api.post('/threat-library/import/thib', form, multipartFormConfig());
      onImported?.(data?.report, { alreadyImported: data?.already_imported === true });
      reset();
      onClose?.();
    } catch (err) {
      setImportError(err, 'Bundle import failed');
    } finally {
      setBusy(false);
      setBusyLabel('');
    }
  }

  function onSubmit(e) {
    e.preventDefault();
    if (busy) return;
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
            {busy ? (busyLabel || 'Working…') : tab === 'thib' ? 'Import Bundle' : 'Start Import'}
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
            onClick={() => { setTab(t.id); setError(''); setErrorCode(''); setDuplicate(null); }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {error ? (
        <div style={{ ...ui.error, marginBottom: 10 }} role="alert">
          {errorCode ? <strong style={{ display: 'block', marginBottom: 4 }}>{errorCode}</strong> : null}
          {error}
        </div>
      ) : null}

      {duplicate ? (
        <div style={{ ...ui.infoBanner, marginBottom: 10 }} role="status" data-testid="tl-import-duplicate">
          <strong style={{ display: 'block', marginBottom: 4 }}>{duplicate.message}</strong>
          <div style={{ color: '#e2e8f0' }}>{duplicate.title}</div>
          {duplicate.importedAt ? (
            <div style={{ marginTop: 2, fontSize: 12 }}>Imported: {formatUserDateTime(duplicate.importedAt)}</div>
          ) : null}
          {onOpenReport ? (
            <button type="button" style={{ ...ui.btn, marginTop: 8 }} onClick={openExistingReport}>
              Open report
            </button>
          ) : null}
        </div>
      ) : null}

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
              onChange={(e) => { setUrl(e.target.value); setDuplicate(null); }}
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
              onChange={(e) => { setPdfFile(e.target.files?.[0] || null); setDuplicate(null); }}
            />
            <span style={ui.helper}>
              Maximum size {formatUploadBytes(PDF_MAX_BYTES_UI)}. Text is extracted server-side, then analyzed for IOC candidates.
              Browser “Print to PDF” exports are supported. Password-protected and image-only/scanned PDFs are rejected with a specific error.
              Do not upload documents you are not authorized to share with configured AI providers.
            </span>
            {pdfFile ? (
              <div style={{ marginTop: 8, fontSize: 12, color: '#94a3b8' }}>
                Selected: {pdfFile.name} ({formatUploadBytes(pdfFile.size)})
              </div>
            ) : null}
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
