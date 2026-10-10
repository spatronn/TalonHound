import React, { useEffect, useId, useState } from 'react';
import { IocDetailIcons } from '../iocDetails/IocDetailIcons.jsx';
import { formatUserDateTime, formatUserDateParts } from '../../lib/formatDate.js';
import { buttonClassName } from '../../lib/uiButtons.js';
import {
  copyTextToClipboard,
  IOC_COPY_FEEDBACK_MS,
  IOC_COPY_SUCCESS_COLOR
} from '../../lib/iocCopyFeedback.js';

/*
 * urlscan.io Intelligence body — pure presentation of buildUrlscanView().
 * Order: assessment (conclusion) → analysis findings (explanation) →
 * page & hosting → collapsible technical evidence.
 */

const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";

const C = {
  text: '#e2e8f0',
  sub: '#cbd5e1',
  muted: '#94a3b8',
  faint: '#64748b',
  line: '#1e293b',
  panel: '#0f172a',
  caution: '#fcd34d',
  cautionLine: '#b45309',
  malicious: '#fca5a5',
  maliciousLine: '#7f1d1d'
};

const TONE_COLOR = {
  malicious: C.malicious,
  caution: C.caution,
  neutral: C.text,
  muted: C.muted
};

const fieldLabelStyle = {
  color: C.muted,
  fontSize: 11,
  fontWeight: 700,
  textTransform: 'uppercase',
  letterSpacing: '0.04em'
};

const sectionGapStyle = { marginTop: 14 };

const srOnlyStyle = {
  position: 'absolute',
  width: 1,
  height: 1,
  padding: 0,
  margin: -1,
  overflow: 'hidden',
  clip: 'rect(0, 0, 0, 0)',
  whiteSpace: 'nowrap',
  border: 0
};

export function CopyButton({ value, label }) {
  const [copied, setCopied] = useState(false);
  const [epoch, setEpoch] = useState(0);
  useEffect(() => {
    if (!copied) return undefined;
    const id = globalThis.setTimeout(() => setCopied(false), IOC_COPY_FEEDBACK_MS);
    return () => globalThis.clearTimeout(id);
  }, [copied, epoch]);
  if (!value) return null;
  const aria = copied ? 'Copied' : (label || `Copy ${value}`);
  return (
    <button
      type="button"
      className={buttonClassName({ variant: 'ghost', size: 'sm', className: 'th-btn--icon' })}
      style={{ width: 26, height: 26, minWidth: 26, minHeight: 26, flexShrink: 0 }}
      aria-label={aria}
      title={copied ? 'Copied' : 'Copy'}
      onClick={async () => {
        const result = await copyTextToClipboard(value);
        if (!result.ok) return;
        setCopied(true);
        setEpoch((n) => n + 1);
      }}
    >
      {copied ? <IocDetailIcons.check size={13} color={IOC_COPY_SUCCESS_COLOR} /> : <IocDetailIcons.copy size={13} />}
    </button>
  );
}

function ToneIcon({ tone, size = 14 }) {
  if (tone === 'caution' || tone === 'malicious') {
    return <IocDetailIcons.alert size={size} color={TONE_COLOR[tone]} />;
  }
  return null;
}

function Flag({ children }) {
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 4,
      marginLeft: 8,
      padding: '0 6px',
      border: `1px solid ${C.cautionLine}`,
      borderRadius: 999,
      color: C.caution,
      fontSize: 11,
      lineHeight: '18px',
      whiteSpace: 'nowrap',
      verticalAlign: 'middle'
    }}
    >
      <IocDetailIcons.alert size={11} />
      {children}
    </span>
  );
}

export function KeyValueList({ rows }) {
  if (!rows?.length) return null;
  return (
    <dl style={{
      display: 'grid',
      gridTemplateColumns: 'minmax(104px, 34%) minmax(0, 1fr)',
      columnGap: 12,
      rowGap: 6,
      margin: 0,
      fontSize: 13,
      lineHeight: 1.45
    }}
    >
      {rows.map((row) => (
        <React.Fragment key={row.label}>
          <dt style={{ color: C.muted }}>{row.label}</dt>
          <dd style={{ margin: 0, minWidth: 0, color: C.text, display: 'flex', alignItems: 'flex-start', gap: 6 }}>
            <span style={{
              minWidth: 0,
              overflowWrap: 'anywhere',
              fontFamily: row.mono ? MONO : undefined,
              fontSize: row.mono ? 12 : undefined
            }}
            >
              {row.date ? formatUserDateTime(row.value) : row.value}
              {row.flag ? <Flag>{row.flag}</Flag> : null}
            </span>
            {row.copy ? <CopyButton value={row.value} label={`Copy ${row.label.toLowerCase()}`} /> : null}
          </dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

function SectionHeading({ id, children }) {
  return <div id={id} style={{ ...fieldLabelStyle, marginBottom: 8 }}>{children}</div>;
}

/** Accessible disclosure: native button, aria-expanded/controls, labelled region. */
export function DisclosureSection({ title, summary, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  const uid = useId();
  const buttonId = `${uid}-trigger`;
  const panelId = `${uid}-panel`;
  return (
    <div style={{ borderTop: `1px solid ${C.line}` }}>
      <button
        type="button"
        id={buttonId}
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          width: '100%',
          minHeight: 0,
          padding: '9px 2px',
          border: 'none',
          borderRadius: 6,
          background: 'transparent',
          color: C.text,
          textAlign: 'left',
          fontWeight: 600,
          fontSize: 13,
          flexWrap: 'wrap',
          justifyContent: 'flex-start'
        }}
      >
        <span style={{ display: 'inline-flex', color: C.muted, transform: open ? 'rotate(90deg)' : 'none', transition: 'transform 120ms ease' }}>
          <IocDetailIcons.chevron size={14} />
        </span>
        <span>{title}</span>
        {summary ? (
          <span style={{ color: C.muted, fontWeight: 400, fontSize: 12, minWidth: 0, overflowWrap: 'anywhere' }}>
            {summary}
          </span>
        ) : null}
      </button>
      <div id={panelId} role="region" aria-labelledby={buttonId} hidden={!open} style={{ padding: '2px 2px 12px 24px' }}>
        {open ? children : null}
      </div>
    </div>
  );
}

function AssessmentTile({ tile }) {
  const color = TONE_COLOR[tile.tone] || C.text;
  return (
    <div style={{ minWidth: 0 }} title={tile.title || undefined}>
      <div style={fieldLabelStyle}>{tile.label}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4, color, fontSize: 15, fontWeight: 650, lineHeight: 1.3, overflowWrap: 'anywhere' }}>
        <ToneIcon tone={tile.tone} />
        <span>{tile.date ? formatUserDateTime(tile.value) : tile.value}</span>
      </div>
      {tile.hint ? <div style={{ color: C.muted, fontSize: 12, marginTop: 2 }}>{tile.hint}</div> : null}
    </div>
  );
}

export function AssessmentSummary({ view }) {
  const otherSources = view.verdictSources.filter((s) => s.source !== 'Engines (ML)');
  const malicious = view.classification.state === 'malicious';
  return (
    <div
      role="group"
      aria-label="urlscan assessment"
      style={{
        marginTop: 12,
        padding: '12px 14px',
        border: '1px solid #334155',
        // Global CSS forces div border-color, so the malicious accent is an inset ring.
        boxShadow: malicious ? `inset 0 0 0 1px ${C.maliciousLine}, inset 3px 0 0 ${C.maliciousLine}` : 'none',
        borderRadius: 10,
        background: C.panel
      }}
    >
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(104px, 1fr))', gap: '12px 14px' }}>
        {view.tiles.map((tile) => <AssessmentTile key={tile.key} tile={tile} />)}
      </div>
      {view.summarySentence ? (
        <p style={{ margin: '12px 0 0', color: C.sub, fontSize: 13, lineHeight: 1.5 }}>{view.summarySentence}</p>
      ) : null}
      <div style={{ marginTop: 8, color: C.muted, fontSize: 12, lineHeight: 1.5, overflowWrap: 'anywhere' }}>
        {otherSources.length ? (
          <div>
            Verdict sources: {otherSources.map((s, i) => (
              <span key={s.source}>{i ? ' · ' : ''}{s.source} — <span style={{ color: s.caution ? C.caution : C.sub }}>{s.value}</span></span>
            ))}
          </div>
        ) : null}
        <div>{view.sampleLine}</div>
      </div>
    </div>
  );
}

function FindingItem({ finding, compact = false }) {
  const caution = finding.tone === 'caution';
  return (
    <li style={{
      display: 'flex',
      gap: 8,
      padding: compact ? '4px 0' : '8px 10px',
      borderLeft: compact ? 'none' : `3px solid ${caution ? C.cautionLine : '#475569'}`,
      background: compact ? 'transparent' : (caution ? 'rgba(217,119,6,0.08)' : 'rgba(71,85,105,0.12)'),
      borderRadius: compact ? 0 : '0 6px 6px 0'
    }}
    >
      <span style={{ marginTop: 2, display: 'inline-flex' }}>
        {caution
          ? <IocDetailIcons.alert size={14} color={C.caution} />
          : <IocDetailIcons.info size={14} color={C.muted} />}
      </span>
      <div style={{ minWidth: 0 }}>
        <div style={{ color: caution ? C.caution : C.text, fontWeight: 600, fontSize: 13 }}>
          {caution ? <span style={srOnlyStyle}>Caution: </span> : null}
          {finding.title}
        </div>
        {finding.detail ? (
          <div style={{ color: C.muted, fontSize: 12, lineHeight: 1.5, overflowWrap: 'anywhere' }}>{finding.detail}</div>
        ) : null}
      </div>
    </li>
  );
}

export function AnalysisFindings({ findings, needsRefreshForDetail }) {
  const [showTechnical, setShowTechnical] = useState(false);
  const uid = useId();
  const { primary, technical } = findings;
  if (!primary.length && !technical.length && !needsRefreshForDetail) return null;
  const headingId = `${uid}-findings`;
  const techId = `${uid}-technical`;
  return (
    <div role="group" aria-labelledby={headingId} style={sectionGapStyle}>
      <SectionHeading id={headingId}>Analysis findings</SectionHeading>
      {primary.length ? (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 }}>
          {primary.map((f) => <FindingItem key={f.code} finding={f} />)}
        </ul>
      ) : null}
      {needsRefreshForDetail ? (
        <div style={{ color: C.muted, fontSize: 12, marginTop: primary.length ? 8 : 0 }}>
          Stored before detailed scan parsing. Refresh to load the verdict, network activity, TLS and related observables.
        </div>
      ) : null}
      {technical.length ? (
        <div style={{ marginTop: 6 }}>
          <button
            type="button"
            aria-expanded={showTechnical}
            aria-controls={techId}
            onClick={() => setShowTechnical((v) => !v)}
            style={{
              display: 'flex',
              alignItems: 'baseline',
              justifyContent: 'flex-start',
              flexWrap: 'wrap',
              gap: '0 6px',
              width: '100%',
              minHeight: 0,
              padding: '4px 2px',
              border: 'none',
              background: 'transparent',
              color: C.muted,
              fontSize: 12,
              fontWeight: 600,
              textAlign: 'left'
            }}
          >
            <span style={{ display: 'inline-flex', alignSelf: 'center', transform: showTechnical ? 'rotate(90deg)' : 'none' }}><IocDetailIcons.chevron size={12} /></span>
            <span>{technical.length} technical observation{technical.length === 1 ? '' : 's'}</span>
            {!showTechnical ? <span style={{ fontWeight: 400 }}>· {technical.map((t) => t.title).join(' · ')}</span> : null}
          </button>
          <ul id={techId} hidden={!showTechnical} style={{ listStyle: 'none', margin: '2px 0 0', padding: '0 0 0 4px' }}>
            {showTechnical ? technical.map((f) => <FindingItem key={f.code} finding={f} compact />) : null}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function PageHosting({ view }) {
  const uid = useId();
  if (!view.pageRows.length && !view.hostingRows.length) return null;
  return (
    <div role="group" aria-labelledby={`${uid}-page`} style={sectionGapStyle}>
      <SectionHeading id={`${uid}-page`}>Page &amp; hosting</SectionHeading>
      <KeyValueList rows={[...view.pageRows, ...view.hostingRows]} />
    </div>
  );
}

function StatGroup({ group }) {
  return (
    <div style={{ minWidth: 0 }}>
      <div style={{ ...fieldLabelStyle, fontSize: 10, marginBottom: 4 }}>{group.label}</div>
      <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', rowGap: 3, columnGap: 10, fontSize: 13 }}>
        {group.rows.map((r) => (
          <React.Fragment key={r.label}>
            <dt style={{ color: C.muted }}>{r.label}</dt>
            <dd style={{ margin: 0, textAlign: 'right', fontVariantNumeric: 'tabular-nums', fontWeight: 600, color: r.tone === 'caution' ? C.caution : (r.tone === 'muted' ? C.faint : C.text) }}>
              {r.value}
            </dd>
          </React.Fragment>
        ))}
      </dl>
    </div>
  );
}

function Chips({ label, items, tone }) {
  if (!items.length) return null;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center', fontSize: 12 }}>
      <span style={{ color: C.muted, marginRight: 2 }}>{label}</span>
      {items.map((t) => (
        <span key={t} style={{ border: '1px solid #334155', borderRadius: 999, padding: '1px 8px', color: tone === 'caution' ? C.caution : C.sub }}>{t}</span>
      ))}
    </div>
  );
}

function NetworkActivity({ view }) {
  return (
    <div style={{ display: 'grid', gap: 10 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '10px 24px' }}>
        {view.networkGroups.map((g) => <StatGroup key={g.key} group={g} />)}
      </div>
      <Chips label="Response codes" items={view.statusCodes} />
      <Chips label="Resource types" items={view.resourceTypes} />
      <Chips label="Failed loads" items={view.failedErrors} tone="caution" />
      {view.redirects.length ? (
        <div>
          <div style={{ ...fieldLabelStyle, fontSize: 10, marginBottom: 4 }}>Redirect chain</div>
          <ol style={{ margin: 0, paddingLeft: 18, color: C.sub, fontSize: 12, fontFamily: MONO, display: 'grid', gap: 2 }}>
            {view.redirects.map((r, i) => (
              <li key={`${r.from}-${i}`} style={{ overflowWrap: 'anywhere' }}>
                {r.status ? <span style={{ color: C.muted }}>{r.status} </span> : null}
                {r.from} <span style={{ color: C.muted }} aria-label="redirects to">→</span> {r.to}
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </div>
  );
}

function Technologies({ items }) {
  return (
    <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
      {items.map((t) => (
        <li
          key={t.name}
          style={{ border: '1px solid #334155', borderRadius: 999, padding: '2px 10px', fontSize: 12, color: C.sub }}
        >
          {t.name}
          {t.categories.length ? <span style={{ color: C.faint }}> · {t.categories.join(', ')}</span> : null}
        </li>
      ))}
    </ul>
  );
}

const TYPE_BADGE = { ip: 'IP', domain: 'Domain', url: 'URL', sha256: 'SHA256', filename: 'File' };

function RelatedObservables({ view }) {
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {view.relatedGroups.map((g) => (
        <div key={g.key}>
          <div style={{ ...fieldLabelStyle, fontSize: 10, marginBottom: 4 }}>{g.label}</div>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {g.items.map((r) => (
              <li key={`${r.type}|${r.value}`} style={{ padding: '5px 0', borderTop: `1px solid ${C.line}`, fontSize: 12 }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                  <span style={{ flexShrink: 0, minWidth: 48, marginTop: 4, color: C.muted, fontSize: 10, fontWeight: 700, letterSpacing: '0.04em' }}>
                    {TYPE_BADGE[r.type] || r.type}
                  </span>
                  <span style={{ flex: 1, minWidth: 0, marginTop: 3, color: C.text, fontFamily: MONO, overflowWrap: 'anywhere' }}>{r.value}</span>
                  <CopyButton value={r.value} label={`Copy ${TYPE_BADGE[r.type] || r.type} ${r.value}`} />
                </div>
                <div style={{ marginLeft: 56, color: C.muted, overflowWrap: 'anywhere' }}>
                  {r.relationship}
                  {r.role ? ` · ${r.role}` : ''}
                  {r.note ? ` · ${r.note}` : ''}
                  {r.origin ? <span style={{ color: C.faint }}> · from {r.origin}</span> : null}
                </div>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <div style={{ color: C.faint, fontSize: 11 }}>
        {view.primaryScan.scanned_at ? `Observed in the scan of ${formatUserDateTime(view.primaryScan.scanned_at)}. ` : ''}
        Not added to TalonHound and not enriched automatically.
        {view.hashTotal !== null && view.hashTotal > view.related.filter((r) => r.type === 'sha256').length
          ? ` ${view.hashTotal} response-body hashes in the scan; the largest are shown.`
          : ''}
      </div>
    </div>
  );
}

function ScanHistory({ history }) {
  const [showAll, setShowAll] = useState(false);
  if (!history.rows.length) {
    return <div style={{ color: C.muted, fontSize: 12 }}>No scans in the retrieved sample.</div>;
  }
  const rows = showAll ? history.rows : history.rows.slice(0, 5);
  const total = history.total ?? history.retrieved;
  return (
    <div style={{ display: 'grid', gap: 8 }}>
      {history.changes.length ? (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 2, fontSize: 12 }}>
          {history.changes.map((c) => (
            <li key={c.label} style={{ color: C.caution, overflowWrap: 'anywhere' }}>
              {c.label} changed: <span style={{ color: C.sub }}>{c.values.join(' · ')}</span>
            </li>
          ))}
        </ul>
      ) : history.compared !== null && history.compared > 1 ? (
        <div style={{ color: C.muted, fontSize: 12 }}>
          No IP, ASN, title, status or TLS-issuer change across {history.compared} directly matching scans.
        </div>
      ) : null}
      <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
        {rows.map((row) => (
          <li key={row.scan_id} style={{ padding: '6px 0', borderTop: `1px solid ${C.line}`, fontSize: 12, overflowWrap: 'anywhere' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px 8px', alignItems: 'baseline' }}>
              <span style={{ color: C.text, fontWeight: 600 }}>{row.scanned_at ? formatUserDateTime(row.scanned_at) : 'Unknown date'}</span>
              <span style={{ color: row.malicious ? C.malicious : C.sub }}>{row.verdict}</span>
              {row.relation ? <span style={{ color: C.muted }}>{row.relation}</span> : null}
              {row.href ? (
                <a href={row.href} target="_blank" rel="noopener noreferrer" aria-label={`Open urlscan.io report for scan ${row.scan_id} (opens in a new tab)`} style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  Report <IocDetailIcons.external size={12} />
                </a>
              ) : null}
            </div>
            <div style={{ color: C.muted }}>
              {[row.status ? `HTTP ${row.status}` : null, row.title ? `“${row.title}”` : null, row.ip, row.asn].filter(Boolean).join(' · ') || '—'}
            </div>
          </li>
        ))}
      </ul>
      {history.rows.length > 5 ? (
        <button type="button" className={buttonClassName({ variant: 'ghost', size: 'sm' })} style={{ justifySelf: 'start' }} aria-expanded={showAll} onClick={() => setShowAll((v) => !v)}>
          {showAll ? 'Show fewer scans' : `Show all ${history.rows.length} retrieved scans`}
        </button>
      ) : null}
      <div style={{ color: C.faint, fontSize: 11 }}>
        {history.retrieved} of {total} scan{total === 1 ? '' : 's'} in the configured lookback window retrieved
        {history.bounded ? ' (bounded sample — not a complete history)' : ''}. Verdicts are retrieved only for the top detailed scans.
      </div>
    </div>
  );
}

/**
 * @param {{ view: object, defaultOpen?: string[] }} props  defaultOpen lists section keys
 *   (network, tls, technologies, related, history) to start expanded; all start collapsed by default.
 */
export default function UrlscanIntelligenceBody({ view, defaultOpen = [] }) {
  const startsOpen = (key) => defaultOpen.includes(key);
  if (!view) return null;
  const historySummary = [
    `${view.history.rows.length} scan${view.history.rows.length === 1 ? '' : 's'}`,
    view.history.latestAt ? `latest ${formatUserDateParts(view.history.latestAt)?.date || ''}`.trim() : null,
    view.history.changes.length ? 'changes detected' : null
  ].filter(Boolean).join(' · ');

  return (
    <>
      <AssessmentSummary view={view} />
      <AnalysisFindings findings={view.findings} needsRefreshForDetail={view.needsRefreshForDetail} />
      <PageHosting view={view} />
      <div style={{ ...sectionGapStyle, borderBottom: `1px solid ${C.line}` }}>
        {view.networkGroups.length ? (
          <DisclosureSection title="Network activity" summary={view.networkSummary} defaultOpen={startsOpen('network')}>
            <NetworkActivity view={view} />
          </DisclosureSection>
        ) : null}
        {view.tlsRows.length ? (
          <DisclosureSection title="TLS certificate" summary={view.tlsSummary} defaultOpen={startsOpen('tls')}>
            <KeyValueList rows={view.tlsRows} />
          </DisclosureSection>
        ) : null}
        {view.technologies.length ? (
          <DisclosureSection title="Technologies" summary={view.technologiesSummary} defaultOpen={startsOpen('technologies')}>
            <Technologies items={view.technologies} />
          </DisclosureSection>
        ) : null}
        {view.related.length ? (
          <DisclosureSection title="Related observables" summary={view.relatedSummary} defaultOpen={startsOpen('related')}>
            <RelatedObservables view={view} />
          </DisclosureSection>
        ) : null}
        <DisclosureSection title="Scan history" summary={historySummary} defaultOpen={startsOpen('history')}>
          <ScanHistory history={view.history} />
        </DisclosureSection>
      </div>
    </>
  );
}
